//! 本地端口转发 (ssh -L) 与 动态隧道 (ssh -D)
//!
//! 两种模式共用一个 SSH 会话, 都用 `channel_open_direct_tcpip` 由服务器代连目标:
//! - **本地转发**: 本机监听一个端口, 每个连接经 SSH 转发到 固定目标 (host:port),
//!   用于访问远程服务器上的服务 (如 MySQL/Web)。等价 `ssh -L <listen>:<host>:<port> user@server`
//! - **动态隧道**: 本机监听 SOCKS5, 客户端请求的任意目标都经 SSH 转发,
//!   可访问远程服务器内网任意主机。等价 `ssh -D <listen> user@server`
//!
//! 目标地址在服务器端解析 (host 传原始主机名), 即 socks5h 语义。
//!
//! `*_on` 变体 = 在**已有**连接上启动 (共享连接复用入口, connect/use 分离);
//! 旧签名 (`run_local_forward` / `run_dynamic_forward`) = 建连 + `*_on` 的包装。

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use russh::client::Msg;
use russh::{Channel, Disconnect};
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::sync::Notify;

use crate::known_hosts::KnownHosts;
use crate::model::TunnelError;
use crate::socks::{Connector, SocksServerHandle};
use crate::ssh::Logger;
use crate::transport::shared::{self, ChannelGuard, SharedHandle, SharedState};

/// 本地/动态隧道的服务器连接配置
#[derive(Debug, Clone)]
pub struct DirectConfig {
    pub server_host: String,
    pub server_port: u16,
    pub username: String,
    /// 认证方式 (密码/私钥; 凭据仅存内存)
    pub auth: crate::ssh::AuthMethod,
    /// 本机监听地址 (当前固定 127.0.0.1)
    pub listen_host: String,
    /// 本机监听端口
    pub listen_port: u16,
    /// SSH 保活 (来自隧道 ReconnectPolicy, 判死时延 = interval × max)
    pub keepalive: crate::ssh::Keepalive,
    /// 主机密钥记忆库 (TOFU; Arc 共享, 引擎注册表提供)
    pub known_hosts: Arc<KnownHosts>,
}

/// 活动中的本地/动态隧道会话
pub struct DirectSession {
    pub handle: SharedHandle,
    /// 通知后台任务退出 (断开时置位)
    pub stop: Arc<Notify>,
    /// 实际监听端口 (动态模式 = SOCKS 端口)
    pub listen_port: u16,
    /// 动态模式: 内置 SOCKS5 服务器句柄 (需要显式停止)
    pub socks: Option<Arc<SocksServerHandle>>,
    /// 共享连接租约模式: 断开只停本隧道 (listener/SOCKS), 不发整连 DISCONNECT
    pub shared: bool,
}

impl DirectSession {
    /// 断开 (用户停止语义): 停止监听; 专用连接发 SSH DISCONNECT 真正关闭,
    /// 共享连接不动 (连接生死由租约决定, 可能还有兄弟隧道在用)
    pub async fn disconnect(&self) {
        self.teardown(false).await;
    }

    /// 强制断开 (模拟网络掉线): 无论共享与否整连 DISCONNECT ——
    /// 共享连接的同档案成员各自触发重连
    pub async fn disconnect_forced(&self) {
        self.teardown(true).await;
    }

    async fn teardown(&self, force: bool) {
        self.stop.notify_one();
        if let Some(s) = &self.socks {
            s.stop();
        }
        if self.shared && !force {
            return;
        }
        let h = self.handle.lock().await;
        let _ = h
            .disconnect(Disconnect::ByApplication, "user disconnect", "")
            .await;
    }
}

/// 打开 SSH direct_tcpip 通道 (服务器代连目标)
async fn open_direct(
    handle: &SharedHandle,
    host: &str,
    port: u16,
) -> Result<Channel<Msg>, russh::Error> {
    handle
        .lock()
        .await
        .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
        .await
}

/// 轮询 SSH 连接是否关闭 (挂起直到关闭, 供 select! 使用)
async fn wait_closed(handle: &SharedHandle) {
    loop {
        if handle.lock().await.is_closed() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// 连接 + 认证 (本地/动态共用): 统一 Handler 带 known_hosts TOFU 校验,
/// 失败时优先返回指纹变更的致命错误 (见 known_hosts.rs 的 take_error 手法)。
async fn connect_direct(cfg: &DirectConfig, logger: &Logger) -> Result<SharedState, TunnelError> {
    shared::connect(
        &cfg.server_host,
        cfg.server_port,
        &cfg.username,
        &cfg.auth,
        cfg.keepalive,
        &cfg.known_hosts,
        shared::DEFAULT_MAX_SESSIONS,
        logger,
    )
    .await
}

/// 本地端口转发 (ssh -L): 新 SSH 连接 + 监听转发。
pub async fn run_local_forward(
    cfg: DirectConfig,
    target_host: String,
    target_port: u16,
    logger: Logger,
) -> Result<(Arc<DirectSession>, tokio::task::JoinHandle<()>), TunnelError> {
    let state = connect_direct(&cfg, &logger).await?;
    run_local_forward_on(&state, &cfg, target_host, target_port, logger, false).await
}

/// 在已有连接上启动本地端口转发 (共享连接复用入口)。
/// `shared = true` 时后台任务退出**不**断开连接 (由租约决定连接生死)。
/// 返回会话句柄 + 后台任务 (任务结束 = 隧道已停止)。
pub async fn run_local_forward_on(
    state: &SharedState,
    cfg: &DirectConfig,
    target_host: String,
    target_port: u16,
    logger: Logger,
    shared: bool,
) -> Result<(Arc<DirectSession>, tokio::task::JoinHandle<()>), TunnelError> {
    let handle = state.handle.clone();
    let counter: Arc<AtomicUsize> = state.open_channels.clone();

    let listener = TcpListener::bind((cfg.listen_host.as_str(), cfg.listen_port))
        .await
        .map_err(|e| TunnelError::PortInUse {
            port: cfg.listen_port,
            reason: e.to_string(),
        })?;
    let actual_port = listener
        .local_addr()
        .map_err(|e| TunnelError::PortInUse {
            port: cfg.listen_port,
            reason: format!("获取监听端口失败: {e}"),
        })?
        .port();
    (logger)(&format!(
        "本地转发: 本机监听 127.0.0.1:{actual_port} -> 经 SSH 隧道 -> {target_host}:{target_port}"
    ));

    let stop = Arc::new(Notify::new());
    let session = Arc::new(DirectSession {
        handle,
        stop: stop.clone(),
        listen_port: actual_port,
        socks: None,
        shared,
    });

    let h = session.handle.clone();
    let logger2 = logger.clone();
    let session2 = session.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.notified() => break,
                _ = wait_closed(&h) => {
                    (logger2)("SSH 连接已断开, 本地转发停止");
                    break;
                }
                accepted = listener.accept() => match accepted {
                    Ok((mut stream, _)) => {
                        let h2 = h.clone();
                        let lg = logger2.clone();
                        let tgt = target_host.clone();
                        let counter2 = counter.clone();
                        tokio::spawn(async move {
                            // 打开 SSH 直连通道 (10s 超时)
                            let chan = match tokio::time::timeout(
                                Duration::from_secs(10),
                                open_direct(&h2, &tgt, target_port),
                            )
                            .await
                            {
                                Ok(Ok(c)) => c,
                                Ok(Err(e)) => {
                                    (lg)(&format!("打开直连通道失败: {e}"));
                                    return;
                                }
                                Err(_) => {
                                    (lg)("打开直连通道超时");
                                    return;
                                }
                            };
                            // 通道存活期间计数 (打开成功 -> 连接关闭)
                            let _g = ChannelGuard::acquire(&counter2);
                            let r = copy_bidirectional(&mut stream, &mut chan.into_stream()).await;
                            (lg)(&format!("转发连接关闭 ({r:?})"));
                        });
                    }
                    Err(e) => {
                        (logger2)(&format!("监听器错误: {e}"));
                        break;
                    }
                },
            }
        }
        // 清理: 专用连接发送 SSH DISCONNECT 关闭连接; 共享连接不动
        if !shared {
            let _ = session2
                .handle
                .lock()
                .await
                .disconnect(Disconnect::ByApplication, "tunnel closed", "")
                .await;
        }
    });

    Ok((session, task))
}

/// 动态隧道 (ssh -D): 新 SSH 连接 + 本机 SOCKS5。
pub async fn run_dynamic_forward(
    cfg: DirectConfig,
    logger: Logger,
) -> Result<(Arc<DirectSession>, tokio::task::JoinHandle<()>), TunnelError> {
    let state = connect_direct(&cfg, &logger).await?;
    run_dynamic_forward_on(&state, &cfg, logger, false).await
}

/// 在已有连接上启动动态隧道 (共享连接复用入口)。
/// 返回会话句柄 + 后台任务 (任务结束 = 隧道已停止)。
pub async fn run_dynamic_forward_on(
    state: &SharedState,
    cfg: &DirectConfig,
    logger: Logger,
    shared: bool,
) -> Result<(Arc<DirectSession>, tokio::task::JoinHandle<()>), TunnelError> {
    let handle = state.handle.clone();
    let connector = Connector::Ssh {
        handle: handle.clone(),
    };
    let server = crate::socks::start_socks_server_with(cfg.listen_port, connector).await?;
    (logger)(&format!(
        "动态隧道: 本机 SOCKS5 127.0.0.1:{} (经 SSH 隧道访问服务器内网, 等价 ssh -D)",
        server.port
    ));

    let stop = Arc::new(Notify::new());
    let session = Arc::new(DirectSession {
        handle,
        stop: stop.clone(),
        listen_port: server.port,
        socks: Some(server),
        shared,
    });

    let h = session.handle.clone();
    let session2 = session.clone();
    let logger2 = logger.clone();
    let task = tokio::spawn(async move {
        tokio::select! {
            _ = stop.notified() => {}
            _ = wait_closed(&h) => {
                (logger2)("SSH 连接已断开, 动态隧道停止");
            }
        }
        // 清理: 停止 SOCKS 服务器; 专用连接发送 SSH DISCONNECT, 共享连接不动
        if let Some(s) = &session2.socks {
            s.stop();
        }
        if !shared {
            let _ = session2
                .handle
                .lock()
                .await
                .disconnect(Disconnect::ByApplication, "tunnel closed", "")
                .await;
        }
    });

    Ok((session, task))
}
