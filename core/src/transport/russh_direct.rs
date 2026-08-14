//! 标准模式传输: sshd 原生 `tcpip_forward` 转发通道 (等价原生 ssh -R, 开销最小)
//!
//! 职责:
//! - `TunnelHandler`: 接收服务器转发的反向连接 —— 首字节污染检查 → 连本地
//!   SOCKS → 双向桥接 (每连接独立任务, 并发服务)
//! - `connect_and_auth`: 连接 + 密码认证 (标准/兼容两种模式共用, 桥接模式
//!   不请求 tcpip_forward, handler 的转发回调不会被触发)
//! - `establish`: 连接 + tcpip_forward + 污染探测 (与 python_bridge::establish
//!   同签名, 传输选择依据)
//!
//! 污染检测 (libonion 兼容, 见 frame.rs 协议文档): 云主机安全组件注入 sshd,
//! 会在 forwarded-tcpip 通道建立时写入审计数据。探测 = 建立转发后让服务器连
//! 一次转发端口并写 1 字节, 检查通道首字节 (本地端一定是 SOCKS5, 应为 0x05;
//! 被注入时是审计数据长度前缀的 0x00)。运行期漏检的注入由 handler 的同一
//! 检查兜底置位 corrupted, 引擎 (start_tunnel) 监控并重建为兼容模式。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use russh::client::{self, ChannelOpenHandle, Msg, Session};
use russh::Channel;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::known_hosts::HostKeyCheck;
use crate::model::TunnelError;
use crate::ssh::Logger;
use crate::tunnel::{TunnelConfig, TunnelSession};

/// russh 客户端 Handler: 接收服务器转发的反向连接并桥接到本地 SOCKS
pub struct TunnelHandler {
    pub(crate) cfg: TunnelConfig,
    pub(crate) logger: Logger,
    /// 首字节检查发现通道被注入审计数据时置位 (云主机安全组件场景)
    pub(crate) corrupted: Arc<AtomicBool>,
    /// 主机密钥 TOFU 校验 (P6; 指纹变更详情经 take_error 取回)
    pub(crate) host_check: Arc<HostKeyCheck>,
}

impl client::Handler for TunnelHandler {
    type Error = russh::Error;

    /// known_hosts TOFU 校验 (首次记住 / 一致放行 / 变更拒绝, 见 known_hosts.rs)
    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(self.host_check.verify(server_public_key))
    }

    /// 服务器有流量要转发回来时被调用:
    /// 1. 检查通道首字节是否被服务器端组件注入审计数据
    /// 2. 确认通道 (reply.accept)
    /// 3. 连本地 SOCKS 代理, 双向桥接 SSH channel <-> SOCKS socket
    ///
    /// 注意: 桥接必须放进独立任务。russh 的连接消息循环会 await 本 handler
    /// 返回的 future, 若在这里 copy_bidirectional 直到结束, 通道数据永远不会被投递。
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let target = format!(
            "{}:{}",
            self.cfg.local_proxy_host, self.cfg.local_proxy_port
        );
        let logger = self.logger.clone();
        let corrupted = self.corrupted.clone();
        // 与 russh 自身测试相同: 先在任务里 into_stream, handler 再 accept
        tokio::spawn(async move {
            let mut chan = channel.into_stream();

            // 首字节检查: 本地端一定是 SOCKS5, 每个代理连接的首字节应为 0x05。
            // 云主机安全组件 (如腾讯云 libonion) 在转发通道建立时注入审计数据,
            // 首字节是其长度前缀的 0x00 — 据此识别并标记污染, 由上层切换兼容模式。
            // 其他首字节 (如探测命令写入的 0x58 'X') 是探测数据, 静默丢弃, 不算污染。
            let mut head = [0u8; 1];
            let verdict =
                match tokio::time::timeout(std::time::Duration::from_secs(2), chan.read(&mut head))
                    .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                        // 无数据: 探测连接或对端已断开, 静默关闭
                        (logger)("转发通道无数据, 关闭");
                        None
                    }
                    Ok(Ok(_)) if head[0] == 0x05 => Some(true), // SOCKS5 握手, 正常
                    Ok(Ok(_)) if head[0] == 0x00 => {
                        // 首字节 0x00: 服务器端注入的审计数据 (长度前缀特征)
                        (logger)(
                            "检测到转发通道首字节 0x00, 疑似服务器端注入审计数据 (云主机安全组件)",
                        );
                        corrupted.store(true, Ordering::Relaxed);
                        None
                    }
                    Ok(Ok(_)) => {
                        // 其他首字节: 探测数据 (如 0x58 'X'), 静默丢弃
                        (logger)(&format!(
                            "转发通道首字节 0x{:02x} 非 SOCKS5 (探测数据?), 关闭",
                            head[0]
                        ));
                        None
                    }
                };
            if verdict.is_none() {
                return;
            }

            // 桥接: 先连本地 SOCKS, 首字节写回流, 再双向复制
            let mut stream = match TcpStream::connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    (logger)(&format!("连接本地代理 {target} 失败: {e}"));
                    return;
                }
            };
            (logger)(&format!("已连接本地代理 {target}"));
            if let Err(e) = stream.write_all(&head).await {
                (logger)(&format!("写回首字节失败: {e}"));
                return;
            }

            let r = copy_bidirectional(&mut stream, &mut chan).await;
            (logger)(&format!("连接关闭 ({r:?})"));
        });
        reply.accept().await;
        Ok(())
    }
}

/// 连接 + 密码认证 (标准/兼容两种模式共用), 返回会话与污染标记。
/// 认证逻辑共用 ssh::connect_auth; 主机密钥经 known_hosts TOFU 校验,
/// 指纹变更 → `TunnelError::HostKeyChanged` (致命, 见 known_hosts.rs)。
pub(crate) async fn connect_and_auth(
    cfg: &TunnelConfig,
    logger: &Logger,
) -> Result<(client::Handle<TunnelHandler>, Arc<AtomicBool>), TunnelError> {
    let corrupted = Arc::new(AtomicBool::new(false));
    let host_check = HostKeyCheck::new(
        cfg.known_hosts.clone(),
        &cfg.server_host,
        cfg.server_port,
        logger.clone(),
    );
    let handler = TunnelHandler {
        cfg: cfg.clone(),
        logger: logger.clone(),
        corrupted: corrupted.clone(),
        host_check: host_check.clone(),
    };
    let session = match crate::ssh::connect_auth(
        &cfg.server_host,
        cfg.server_port,
        &cfg.username,
        &cfg.password,
        cfg.keepalive,
        handler,
        logger,
    )
    .await
    {
        Ok(s) => s,
        // 指纹被拒 (russh::Error::UnknownKey) → 致命的 HostKeyChanged,
        // 避免落入可重试的 Connect 误分类
        Err(e) => return Err(host_check.take_error().unwrap_or(e)),
    };
    Ok((session, corrupted))
}

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
    let (session, corrupted) = connect_and_auth(cfg, logger).await?;
    let bound_port = establish_forward(&session, cfg, logger).await?;
    Ok((
        (Arc::new(tokio::sync::Mutex::new(session)), corrupted),
        bound_port,
    ))
}

/// 在已认证会话上: 请求服务器监听 remote_port + 污染探测, 返回实际监听端口。
async fn establish_forward(
    session: &client::Handle<TunnelHandler>,
    cfg: &TunnelConfig,
    logger: &Logger,
) -> Result<u16, TunnelError> {
    // bind_address 必须用 "localhost": OpenSSH 的 GatewayPorts 检查只放行
    // "localhost" 字面值 ("127.0.0.1"/"0.0.0.0" 会被拒绝或行为不稳定)。
    // 若 sshd 把 localhost 解析成 IPv6, 探测会失败并自动切换兼容模式。
    // russh 0.62 tcpip_forward 返回服务器实际分配的端口 (remote_port=0 时
    // 为动态分配值, 其余等于请求值)
    let actual_port = session
        .tcpip_forward("localhost", cfg.remote_port)
        .await
        .map_err(|e| TunnelError::ForwardRejected {
            port: cfg.remote_port,
            reason: e.to_string(),
        })?;
    let bound_port: u16 = actual_port
        .try_into()
        .map_err(|_| TunnelError::Protocol(format!("服务器返回异常端口: {actual_port}")))?;
    (logger)(&format!(
        "服务器已监听 127.0.0.1:{bound_port} (转发到 127.0.0.1:{})",
        cfg.local_proxy_port
    ));

    // 探测: 让服务器连一次转发端口并写入 1 字节, 主动触发转发通道与可能的注入:
    // - PROBE_FAIL (连不上): 转发不可用 (地址族/端口被占) -> 切换兼容模式
    // - PROBE_OK 且 corrupted (首字节 0x00 = 注入特征): 通道被审计数据污染 -> 切换兼容模式
    // - PROBE_OK 且未 corrupted (首字节 0x58 = 探测的 X, 干净): 标准模式可用
    // 写数据探测比被动等待可靠: 注入发生在"进程首次写"时, 探测写入必然触发。
    // 注意端口用 sshd 实际分配的 bound_port (remote_port=0 时两者不同)。
    let probe = session
        .channel_open_session()
        .await
        .map_err(|e| TunnelError::ChannelOpen {
            what: "探测通道".into(),
            reason: e.to_string(),
        })?;
    probe
        .exec(
            true,
            format!(
                "exec 3<>/dev/tcp/127.0.0.1/{0} && echo PROBE_OK && echo X >&3 || echo PROBE_FAIL",
                bound_port
            ),
        )
        .await
        .map_err(|e| TunnelError::Protocol(format!("执行探测命令失败: {e}")))?;
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
        return Err(TunnelError::Protocol(format!(
            "转发端口探测失败, 服务器输出: {}",
            out.trim()
        )));
    }
    Ok(bound_port)
}
