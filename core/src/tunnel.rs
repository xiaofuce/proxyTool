//! 反向 SSH 隧道引擎 (组装层)
//!
//! 拓扑: 远程服务器监听 <remote_port> --SSH--> 本机 --TCP--> 本地SOCKS代理(如 v2cloud 127.0.0.1:7892)
//!
//! 等价于 `ssh -R <remote_port>:127.0.0.1:<local_socks_port> user@server`
//! 由 russh (纯 Rust) 实现, 无需外部 ssh/sshpass, 密码由 GUI 传入、仅存内存。
//!
//! # 职责 (P2b 后: 本文件只剩「组装」)
//!
//! 两种传输实现 (建立转发 + 桥接的具体机制) 在 `transport`:
//! - 标准模式 `transport::russh_direct`: sshd 原生 `tcpip_forward` 转发通道,
//!   开销最小, 等价原生 `ssh -R`;
//! - 兼容模式 `transport::python_bridge`: 会话通道 + 服务器端 python3 stdio
//!   桥接助手, 帧协议复用单通道 (云主机安全组件注入转发通道时的回退路径)。
//!
//! 本文件: `run_tunnel` 选择传输 (先标准, 污染/不可用则回退兼容), 加上
//! 会话管理 (`TunnelSession`/`TunnelSlot`/`close_session`) 与引擎入口
//! `start_tunnel` (运行期发现污染自动重建为兼容模式)。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::model::TunnelError;
use crate::transport::russh_direct::TunnelHandler;
use crate::transport::{python_bridge, russh_direct};

/// 隧道连接配置
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    /// 密码仅用于内存中的认证, 不落盘
    pub password: String,
    /// 服务器上监听的端口 (相当于 ssh -R 的远端端口; 0 = 服务器动态分配)
    pub remote_port: u32,
    /// 本机 SOCKS 代理地址
    pub local_proxy_host: String,
    pub local_proxy_port: u16,
    /// SSH 保活 (来自隧道 ReconnectPolicy, 判死时延 = interval × max)
    pub keepalive: crate::ssh::Keepalive,
}

/// 日志回调 (定义在 ssh.rs, 三种隧道模式共用)
pub use crate::ssh::Logger;

/// 隧道会话句柄与污染标记 (标记在运行期被 handler 置位, 由 start_tunnel 监控)
pub type TunnelSession = (
    Arc<tokio::sync::Mutex<russh::client::Handle<TunnelHandler>>>,
    Arc<AtomicBool>,
);

/// 反向隧道会话槽: 调用方 (GUI 的 AppState) 与引擎共享的会话存放处。
/// GUI 从中取走句柄以断开; 引擎轮询其存在性与 is_closed 判断会话结束。
/// 引擎经此与 GUI 解耦 —— 不感知 tauri。
pub type TunnelSlot = Arc<tokio::sync::Mutex<Option<TunnelSession>>>;

/// 向会话发送 SSH DISCONNECT 真正关闭连接。
/// 仅 drop Arc 不够: 后台任务持有同一 Arc 的 clone, Handle 不会 drop (旧 bug)。
pub async fn close_session(session: &TunnelSession) {
    let h = session.0.lock().await;
    let _ = h
        .disconnect(russh::Disconnect::ByApplication, "user disconnect", "")
        .await;
}

/// 引擎关心的隧道运行事件 (start_tunnel → 引擎回调)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelEvent {
    /// 会话建立并开始服务 (含运行期重建为兼容模式后)
    Connected,
    /// 服务器实际监听端口 (remote_port=0 动态分配时与请求值不同,
    /// 引擎据此回填 TunnelSpec 并持久化)
    BoundPort(u16),
}

pub type OnTunnelEvent = Arc<dyn Fn(TunnelEvent) + Send + Sync>;

/// 建立隧道会话并返回句柄与服务器实际监听端口 (remote_port=0 时由服务器
/// 动态分配)。调用方负责保持句柄存活 (drop 即断开)。
///
/// 传输选择策略 (P2b: 策略集中于此, 两种传输对调用方不感知模式差异):
/// 1. 先试标准模式 (开销最小): 建立转发 + 主动探测注入;
/// 2. 探测确认污染 / 转发不可用 → 回退兼容模式;
/// 3. 连接/认证失败与模式无关, 直接透传 (兼容模式用同一条 SSH 连接,
///    重试必然同样失败; 错误密码不做无谓二次连接)。
pub async fn run_tunnel(
    cfg: TunnelConfig,
    logger: Logger,
) -> Result<(TunnelSession, u16), TunnelError> {
    match russh_direct::establish(&cfg, &logger).await {
        Ok((session, bound_port)) => {
            if session.1.load(Ordering::Relaxed) {
                (logger)(
                    "检测到服务器转发通道被注入审计数据 (常见于云主机安全组件), 切换兼容模式...",
                );
                return python_bridge::establish(cfg, logger).await;
            }
            Ok((session, bound_port))
        }
        Err(e) => {
            // 连接/认证阶段的失败与转发模式无关, 直接透传 ——
            // 兼容模式用的是同一条 SSH 连接, 重试必然同样失败 (错误密码不做无谓二次连接)。
            if matches!(
                e,
                TunnelError::Connect { .. }
                    | TunnelError::AuthIo { .. }
                    | TunnelError::AuthRejected
            ) {
                return Err(e);
            }
            (logger)(&format!("标准转发模式不可用 ({e}), 改用兼容模式"));
            python_bridge::establish(cfg, logger).await
        }
    }
}

/// 引擎入口: 建立隧道并常驻后台直到断开。
/// 标准模式下若运行期检测到转发通道被注入 (探测漏检的兜底), 自动重建为兼容模式。
/// 会话句柄存入调用方提供的 `session_slot` (GUI 经它取句柄断开);
/// 事件经 `on_event` 回调 (与具体事件格式解耦)。
pub async fn start_tunnel(
    session_slot: TunnelSlot,
    cfg: TunnelConfig,
    logger: Logger,
    on_event: OnTunnelEvent,
) -> Result<(), TunnelError> {
    let ((mut session, corrupted), bound_port) = run_tunnel(cfg.clone(), logger.clone()).await?;
    let mut rebuilt = corrupted.load(Ordering::Relaxed); // 已在 run_tunnel 内切过兼容模式

    // 端口 0 动态分配: 实际端口回告引擎 (回填 spec + 持久化)
    if bound_port != cfg.remote_port as u16 {
        on_event(TunnelEvent::BoundPort(bound_port));
    }

    // 存入会话槽以便调用方断开
    {
        let mut guard = session_slot.lock().await;
        *guard = Some((session.clone(), corrupted.clone()));
    }
    on_event(TunnelEvent::Connected);

    // 保持会话: 直到 is_closed (连接断开或手动 drop), 或运行期检测到注入后重建
    loop {
        let (closed, polluted) = {
            let guard = session_slot.lock().await;
            let closed = match guard.as_ref() {
                Some((arc, _)) => arc.lock().await.is_closed(),
                None => true,
            };
            (closed, corrupted.load(Ordering::Relaxed))
        };
        if closed {
            break;
        }
        if polluted && !rebuilt {
            rebuilt = true;
            (logger)("标准转发通道运行期检测到注入, 自动重建为兼容模式...");
            // 断开标准模式会话 (drop 即关闭), 重建兼容模式
            *session_slot.lock().await = None;
            drop(session);
            let ((new_session, _), new_bound) =
                python_bridge::establish(cfg.clone(), logger.clone()).await?;
            if new_bound != cfg.remote_port as u16 {
                on_event(TunnelEvent::BoundPort(new_bound));
            }
            session = new_session;
            {
                let mut guard = session_slot.lock().await;
                *guard = Some((session.clone(), corrupted.clone()));
            }
            on_event(TunnelEvent::Connected);
            continue;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    // 不在此 emit disconnected: 终态由调用方 (引擎重连循环) 统一控制,
    // 否则会与重连循环的 disconnected/reconnecting 重复发射。
    Ok(())
}
