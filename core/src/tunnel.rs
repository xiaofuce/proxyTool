//! 反向 SSH 隧道引擎 (组装层)
//!
//! 拓扑: 远程服务器监听 <remote_port> --SSH--> 本机 --TCP--> 本地落地
//! (SOCKS 代理如 v2cloud 127.0.0.1:7892, 或固定 TCP 地址)
//!
//! 等价于 `ssh -R <remote_port>:127.0.0.1:<local_port> user@server`,
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
//! 本文件: `establish_on` 选择传输 (**先标准, 污染/不可用则同连接切兼容**),
//! 会话管理 (`ReverseSession`/`TunnelSlot`), 引擎入口 `start_tunnel_on`
//! (运行期发现污染自动同连接重建为兼容模式) 与 e2e 包装 `run_tunnel`。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh::Disconnect;

use crate::known_hosts::KnownHosts;
use crate::model::TunnelError;
use crate::transport::python_bridge::CompatSession;
use crate::transport::shared::{self, SharedHandle, SharedState};
use crate::transport::{python_bridge, russh_direct};

/// 隧道连接配置
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    /// 认证方式 (密码/私钥; 凭据仅存内存)
    pub auth: crate::ssh::AuthMethod,
    /// 服务器上监听的端口 (相当于 ssh -R 的远端端口; 0 = 服务器动态分配)
    pub remote_port: u32,
    /// 本机 SOCKS 代理地址
    pub local_proxy_host: String,
    pub local_proxy_port: u16,
    /// SSH 保活 (来自隧道 ReconnectPolicy, 判死时延 = interval × max)
    pub keepalive: crate::ssh::Keepalive,
    /// 主机密钥记忆库 (TOFU; Arc 共享, 引擎注册表提供)
    pub known_hosts: Arc<KnownHosts>,
}

/// 日志回调 (定义在 ssh.rs, 三种隧道模式共用)
pub use crate::ssh::Logger;

/// 隧道会话句柄与污染标记 (e2e/展示路径用; 引擎槽内是结构化的 `ReverseSession`)
pub type TunnelSession = (SharedHandle, Arc<AtomicBool>);

/// 反向隧道会话: 所在连接状态 + 按模式的拆除信息。
/// Clone 浅共享 (句柄/污染标志/AbortHandle 均可克隆); teardown 幂等。
#[derive(Clone)]
pub struct ReverseSession {
    /// 所在连接 (句柄/污染标志/路由表) —— 共享连接的兄弟隧道同源
    state: SharedState,
    mode: ReverseMode,
}

#[derive(Clone)]
enum ReverseMode {
    /// 标准模式: sshd 原生转发 (拆除 = cancel + 摘路由)
    Std { bound_port: u16 },
    /// 兼容模式: 会话通道桥接助手 (拆除 = abort 两个桥接任务)
    Compat(CompatSession),
}

impl ReverseSession {
    fn handle(&self) -> &SharedHandle {
        &self.state.handle
    }

    fn corrupted(&self) -> &Arc<AtomicBool> {
        &self.state.corrupted
    }

    /// 拆除本隧道在连接上的痕迹 (转发/助手), **不动连接本身** ——
    /// 共享连接可能还有兄弟租约, 连接生死由租约 (engine::pool) 决定。
    /// `force` = 模拟掉线, 再整连 DISCONNECT。
    pub async fn teardown(self, force: bool) {
        match self.mode {
            ReverseMode::Std { bound_port } => {
                tear_std_forward(&self.state, bound_port).await;
            }
            ReverseMode::Compat(c) => c.stop(),
        }
        if force {
            let h = self.state.handle.lock().await;
            let _ = h
                .disconnect(Disconnect::ByApplication, "forced disconnect", "")
                .await;
        }
    }
}

/// 撤销标准模式转发: cancel + 摘路由 (失败清理 / 污染切兼容 / 停止拆除共用)。
/// cancel 的 address 必须与 tcpip_forward 同字面值 "localhost" (GatewayPorts 约束)。
async fn tear_std_forward(state: &SharedState, bound_port: u16) {
    {
        let h = state.handle.lock().await;
        let _ = h.cancel_tcpip_forward("localhost", bound_port as u32).await;
    }
    state.routes.write().unwrap().remove(&bound_port);
}

/// 反向隧道会话槽: 引擎注册表与状态机任务共享。
/// 注册表停止时从中取走会话执行 teardown (轮询循环见槽空即退出)。
pub type TunnelSlot = Arc<tokio::sync::Mutex<Option<ReverseSession>>>;

/// 引擎关心的隧道运行事件 (start_tunnel_on → 引擎回调)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelEvent {
    /// 会话建立并开始服务 (含运行期重建为兼容模式后)
    Connected,
    /// 服务器实际监听端口 (remote_port=0 动态分配时与请求值不同,
    /// 引擎据此回填 TunnelSpec 并持久化)
    BoundPort(u16),
}

pub type OnTunnelEvent = Arc<dyn Fn(TunnelEvent) + Send + Sync>;

/// 在**已有连接**上建立反向转发 (共享/专用统一入口): 先试标准模式
/// (转发 + 主动探测注入), 污染/转发不可用则**同连接**切兼容模式 ——
/// 不丢连接 (共享连接上兄弟隧道还在用), 也不再二次认证。
///
/// 注: 连接/认证失败不会出现在这里 (连接由上游 pool/run_tunnel 建立),
/// establish_forward 的错误全部来自转发阶段, 均可回退兼容。
/// 连接级污染标志 (SharedState.corrupted) 一旦置位, 该连接上的新隧道
/// 直接走兼容 (跳过注定被注入的标准探测)。
async fn establish_on(
    state: &SharedState,
    cfg: &TunnelConfig,
    logger: &Logger,
) -> Result<(ReverseSession, u16), TunnelError> {
    let poisoned = state.corrupted.load(Ordering::Relaxed);
    if !poisoned {
        match russh_direct::establish_forward(state, cfg, logger).await {
            Ok(bound_port) => {
                if !state.corrupted.load(Ordering::Relaxed) {
                    return Ok((
                        ReverseSession {
                            state: state.clone(),
                            mode: ReverseMode::Std { bound_port },
                        },
                        bound_port,
                    ));
                }
                (logger)(
                    "探测确认转发通道被注入审计数据 (常见于云主机安全组件), 同连接切换兼容模式...",
                );
                tear_std_forward(state, bound_port).await;
            }
            Err(e) => {
                (logger)(&format!("标准转发模式不可用 ({e}), 同连接改用兼容模式"));
            }
        }
    } else {
        (logger)("本连接已检测过转发通道注入, 直接使用兼容模式");
    }
    let (compat, bound_port) = python_bridge::open_helper(state, cfg, logger.clone()).await?;
    Ok((
        ReverseSession {
            state: state.clone(),
            mode: ReverseMode::Compat(compat),
        },
        bound_port,
    ))
}

/// 建立隧道会话并返回句柄与服务器实际监听端口 (remote_port=0 时由服务器
/// 动态分配)。e2e/展示路径: 自建专用连接; 引擎路径走 pool + start_tunnel_on。
pub async fn run_tunnel(
    cfg: TunnelConfig,
    logger: Logger,
) -> Result<(TunnelSession, u16), TunnelError> {
    let state = shared::connect(
        &cfg.server_host,
        cfg.server_port,
        &cfg.username,
        &cfg.auth,
        cfg.keepalive,
        &cfg.known_hosts,
        shared::DEFAULT_MAX_SESSIONS,
        &logger,
    )
    .await?;
    let (session, bound_port) = establish_on(&state, &cfg, &logger).await?;
    // CompatSession 句柄随 session 丢弃 (abort 句柄 drop 不 abort):
    // 桥接任务常驻到通道/连接关闭, 与旧行为一致
    Ok((
        (session.state.handle.clone(), session.state.corrupted.clone()),
        bound_port,
    ))
}

/// 引擎入口: 在已有连接上建立反向隧道并常驻直到断开/停止。
/// - 标准模式运行期检测到注入 (探测漏检的兜底) → 撤销本隧道转发,
///   **同连接**重建为兼容模式 (端口 0 时助手重新动态分配, 重发 BoundPort);
/// - 停止 = 注册表从槽取走会话并 teardown → 本循环见槽空退出;
///   建连窗口的停止由 `stop` 轮询覆盖 (探测含 2s 等待)。
/// 返回 Ok(()) = 会话结束 (断线或停止), Err = 建立失败 (引擎进退避)。
/// 会话清理交给调用方 (attempt 统一 take + teardown)。
pub async fn start_tunnel_on(
    session_slot: TunnelSlot,
    state: &SharedState,
    cfg: TunnelConfig,
    logger: Logger,
    on_event: OnTunnelEvent,
    stop: &AtomicBool,
) -> Result<(), TunnelError> {
    let (mut session, bound_port) = establish_on(state, &cfg, &logger).await?;
    // 已是兼容模式 (建连即切 / 连接过往已检出注入) 则不再重建;
    // 只盯标准模式的运行期注入兜底
    let mut rebuilt = matches!(session.mode, ReverseMode::Compat(_));

    if stop.load(Ordering::SeqCst) {
        session.teardown(false).await;
        return Ok(());
    }

    // 端口 0 动态分配: 实际端口回告引擎 (回填 spec + 持久化)
    if bound_port != cfg.remote_port as u16 {
        on_event(TunnelEvent::BoundPort(bound_port));
    }

    *session_slot.lock().await = Some(session.clone());
    on_event(TunnelEvent::Connected);

    // 保持会话: 直到连接断开 / 槽被取走 (停止) / 运行期注入后同连接重建
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let (closed, polluted) = {
            let guard = session_slot.lock().await;
            match guard.as_ref() {
                // 槽被注册表取走 (停止/删除) → 退出
                None => (true, false),
                Some(s) => (
                    s.handle().lock().await.is_closed(),
                    s.corrupted().load(Ordering::Relaxed),
                ),
            }
        };
        if closed {
            break;
        }
        if polluted && !rebuilt {
            rebuilt = true;
            (logger)("标准转发通道运行期检测到注入, 同连接重建为兼容模式...");
            // 撤销本隧道的标准转发, 同连接起兼容助手 (连接保持 —— 兄弟在用);
            // 端口 0 时助手重新动态分配端口, BoundPort 重发
            let old = session_slot.lock().await.take();
            if let Some(old) = old {
                old.teardown(false).await;
            }
            let (compat, new_bound) =
                python_bridge::open_helper(&session.state, &cfg, logger.clone()).await?;
            session = ReverseSession {
                state: session.state.clone(),
                mode: ReverseMode::Compat(compat),
            };
            if new_bound != cfg.remote_port as u16 {
                on_event(TunnelEvent::BoundPort(new_bound));
            }
            *session_slot.lock().await = Some(session.clone());
            on_event(TunnelEvent::Connected);
            continue;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // 不在此 emit disconnected: 终态由调用方 (引擎重连循环) 统一控制
    Ok(())
}
