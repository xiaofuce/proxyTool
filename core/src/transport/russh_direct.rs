//! 标准模式传输: sshd 原生 `tcpip_forward` 转发通道 (等价原生 ssh -R, 开销最小)
//!
//! 职责:
//! - `establish`: 新 SSH 连接 + tcpip_forward + 污染探测 (与 python_bridge::establish
//!   同签名, 传输选择依据);
//! - `establish_forward`: 在**已有**连接上注册转发 (共享连接复用的入口 ——
//!   路由表注册 + tcpip_forward + 探测, 失败路径取消转发并摘除路由);
//! - 连接与 Handler 统一在 `transport::shared` (同档案共享连接的前提)。
//!
//! 污染检测 (libonion 兼容, 见 frame.rs 协议文档): 云主机安全组件注入 sshd,
//! 会在 forwarded-tcpip 通道建立时写入审计数据。探测 = 建立转发后让服务器连
//! 一次转发端口并写 1 字节, 检查通道首字节 (本地端一定是 SOCKS5, 应为 0x05;
//! 被注入时是审计数据长度前缀的 0x00)。运行期漏检的注入由 handler 的同一
//! 检查兜底置位 corrupted, 引擎 (start_tunnel) 监控并重建为兼容模式。

use tokio::io::AsyncReadExt;

use crate::model::TunnelError;
use crate::ssh::Logger;
use crate::transport::shared::{self, ChannelGuard, SharedState};
use crate::tunnel::{TunnelConfig, TunnelSession};

/// 标准模式建立: 新 SSH 连接 + tcpip_forward + 污染探测。
/// 返回 (会话, 服务器实际监听端口) —— `remote_port=0` 时由 sshd 动态分配,
/// 实际端口在返回值里 (等价 `ssh -R 0:` 的语义)。
/// 与 `python_bridge::establish` 同签名 (传输层公共接口, 见 transport/mod.rs)。
///
/// Err 语义 (调用方 run_tunnel 据此决定是否回退兼容模式):
/// - `Connect/AuthIo/AuthRejected`: 连接阶段失败, 与转发模式无关 —— **不回退**
///   (兼容模式用同样的连接, 重试必然同样失败; 错误密码不做无谓二次连接);
/// - `ForwardRejected/ChannelOpen/Protocol`: 转发不可用 (sshd 拒绝/地址族/端口
///   被占) 或探测确认被注入 —— **回退兼容模式**。
/// 成功后污染仍可能在运行期暴露 (探测漏检), 由 handler 首字节检查置位
/// corrupted 标志, 引擎监控后重建为兼容模式。
pub async fn establish(
    cfg: &TunnelConfig,
    logger: &Logger,
) -> Result<(TunnelSession, u16), TunnelError> {
    let state = shared::connect(
        &cfg.server_host,
        cfg.server_port,
        &cfg.username,
        &cfg.auth,
        cfg.keepalive,
        &cfg.known_hosts,
        shared::DEFAULT_MAX_SESSIONS,
        logger,
    )
    .await?;
    let bound_port = establish_forward(&state, cfg, logger).await?;
    Ok(((state.handle, state.corrupted), bound_port))
}

/// 在已认证连接上注册反向转发: 路由表注册 + tcpip_forward + 污染探测,
/// 返回服务器实际监听端口。共享连接的复用入口 (专用连接走 establish 同路)。
///
/// 路由注册时序 (共享连接上按端口区分各隧道的转发):
/// - 固定端口: **先注册再转发** (消除「转发已生效、远端连接先到、路由未就绪」
///   的竞态 —— 固定端口在转发前就被人知晓);
/// - 端口 0: 转发后按 sshd 回告的实际端口注册 (动态端口只有 sshd 知晓,
///   回告前无人能连, 无竞态)。
///
/// 失败路径: 取消转发 (cancel_tcpip_forward) + 摘除路由 —— 连接可能被其他
/// 隧道继续使用, 不能留下残留监听。
pub(crate) async fn establish_forward(
    state: &SharedState,
    cfg: &TunnelConfig,
    logger: &Logger,
) -> Result<u16, TunnelError> {
    let landing = (cfg.local_proxy_host.clone(), cfg.local_proxy_port);
    if cfg.remote_port != 0 {
        state
            .routes
            .write()
            .unwrap()
            .insert(cfg.remote_port as u16, landing.clone());
    }

    let result = forward_and_probe(state, cfg, logger).await;
    match result {
        Ok(bound_port) => Ok(bound_port),
        Err(e) => {
            // 失败清理: 摘除本次注册的路由; 转发若已生效则取消。
            // (cancel 的 address 必须与 tcpip_forward 同字面值 "localhost",
            // 见下方 GatewayPorts 注释)
            if cfg.remote_port != 0 {
                state.routes.write().unwrap().remove(&(cfg.remote_port as u16));
            }
            if let Some(bound) = e.bound_port {
                let h = state.handle.lock().await;
                let _ = h.cancel_tcpip_forward("localhost", bound as u32).await;
                state.routes.write().unwrap().remove(&bound);
            }
            Err(e.error)
        }
    }
}

/// 失败时的清理线索: 转发已生效到哪个端口 (探测失败的场景)
struct ForwardFail {
    error: TunnelError,
    bound_port: Option<u16>,
}

async fn forward_and_probe(
    state: &SharedState,
    cfg: &TunnelConfig,
    logger: &Logger,
) -> Result<u16, ForwardFail> {
    // bind_address 必须用 "localhost": OpenSSH 的 GatewayPorts 检查只放行
    // "localhost" 字面值 ("127.0.0.1"/"0.0.0.0" 会被拒绝或行为不稳定)。
    // 若 sshd 把 localhost 解析成 IPv6, 探测会失败并自动切换兼容模式。
    // russh 0.62 tcpip_forward 返回服务器实际分配的端口 (remote_port=0 时
    // 为动态分配值, 其余等于请求值)
    let actual_port = {
        let h = state.handle.lock().await;
        h.tcpip_forward("localhost", cfg.remote_port).await
    }
    .map_err(|e| ForwardFail {
        error: TunnelError::ForwardRejected {
            port: cfg.remote_port,
            reason: e.to_string(),
        },
        bound_port: None,
    })?;
    let bound_port: u16 = actual_port.try_into().map_err(|_| ForwardFail {
        error: TunnelError::Protocol(format!("服务器返回异常端口: {actual_port}")),
        bound_port: None,
    })?;

    // 端口 0 (或服务器改派): 按实际端口注册路由, 摘除预注册的请求端口键
    if bound_port != cfg.remote_port as u16 {
        let mut routes = state.routes.write().unwrap();
        if cfg.remote_port != 0 {
            routes.remove(&(cfg.remote_port as u16));
        }
        routes.insert(bound_port, (cfg.local_proxy_host.clone(), cfg.local_proxy_port));
    }
    (logger)(&format!(
        "服务器已监听 127.0.0.1:{bound_port} (转发到 127.0.0.1:{})",
        cfg.local_proxy_port
    ));

    // 探测: 让服务器连一次转发端口并写入 1 字节, 主动触发转发通道与可能的注入:
    // - PROBE_FAIL (连不上): 转发不可用 (地址族/端口被占) -> 切换兼容模式
    // - PROBE_OK 且 corrupted (首字节 0x00 = 注入特征): 通道被审计数据污染 -> 切换兼容模式
    // - PROBE_OK 且未 corrupted (探测的 'X' 等任意字节被正常转发到本地落地): 干净, 标准模式可用
    // 写数据探测比被动等待可靠: 注入发生在"进程首次写"时, 探测写入必然触发。
    // 注意端口用 sshd 实际分配的 bound_port (remote_port=0 时两者不同)。
    let probe = {
        let h = state.handle.lock().await;
        h.channel_open_session().await
    }
    .map_err(|e| ForwardFail {
        error: TunnelError::ChannelOpen {
            what: "探测通道".into(),
            reason: e.to_string(),
        },
        bound_port: Some(bound_port),
    })?;
    // probe 通道存活期间计数 (打开成功 -> 流读尽/drop)
    let _probe_guard = ChannelGuard::acquire(&state.open_channels);
    probe
        .exec(
            true,
            format!(
                "exec 3<>/dev/tcp/127.0.0.1/{0} && echo PROBE_OK && echo X >&3 || echo PROBE_FAIL",
                bound_port
            ),
        )
        .await
        .map_err(|e| ForwardFail {
            error: TunnelError::Protocol(format!("执行探测命令失败: {e}")),
            bound_port: Some(bound_port),
        })?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let mut probe_out = Vec::new();
    let mut stream = probe.into_stream();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut probe_out),
    )
    .await;
    let out = String::from_utf8_lossy(&probe_out);
    (logger)(&format!("端口探测结果: {}", out.trim()));
    if !out.contains("PROBE_OK") {
        return Err(ForwardFail {
            error: TunnelError::Protocol(format!(
                "转发端口探测失败, 服务器输出: {}",
                out.trim()
            )),
            bound_port: Some(bound_port),
        });
    }
    Ok(bound_port)
}
