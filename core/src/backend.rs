//! 本地端后端 (设计 §3.2 `Backend` / 分层图 backend 模块):
//! 反向隧道的流量落地处。
//!
//! - `Tcp`: 固定本机地址, 无状态直接返回
//! - `SocksAuto`: 自动探测 VPN SOCKS 端口, 探测不到时启动内置 SOCKS5 ——
//!   内置服务器在 `BackendPool` 常驻缓存, 多条反向隧道共用一个实例/端口,
//!   重连不重建 (与旧 resolve_local_proxy 的「循环外解析一次」语义一致)。

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::model::{Backend, TunnelError};
use crate::probe;
use crate::socks;
use crate::ssh::Logger;

/// 内置 SOCKS5 服务器缓存 (进程内共享)
pub struct BackendPool {
    socks: Mutex<Option<Arc<socks::SocksServerHandle>>>,
}

impl Default for BackendPool {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendPool {
    pub fn new() -> Self {
        Self {
            socks: Mutex::new(None),
        }
    }

    /// 解析反向隧道的本地落地地址 (host, port)。
    /// 失败 = 致命 (如内置 SOCKS 端口被占, 重连无法解决)。
    pub async fn resolve_reverse(
        &self,
        backend: &Backend,
        logger: &Logger,
    ) -> Result<(String, u16), TunnelError> {
        match backend {
            Backend::Tcp(host, port) => Ok((host.clone(), *port)),
            Backend::SocksAuto { fallback_port } => {
                // 1. 优先复用 VPN 自带的端口 (探测确认是 SOCKS5)
                let vpn = probe::probe_local_proxy().await;
                if let Some(found) = vpn.iter().find(|r| r.socks5_confirmed) {
                    (logger)(&format!(
                        "发现 VPN 自带 SOCKS 端口 {} (SOCKS5 确认), 直接复用",
                        found.port
                    ));
                    return Ok(("127.0.0.1".into(), found.port));
                }

                // 2. 探测不到 -> 启动内置 SOCKS5 (已在监听同端口则复用)
                let mut guard = self.socks.lock().await;
                if let Some(server) = guard.as_ref() {
                    if server.port == *fallback_port {
                        return Ok(("127.0.0.1".into(), server.port));
                    }
                    // 端口变了, 停掉旧的
                    server.stop();
                    *guard = None;
                }
                (logger)(&format!(
                    "未发现 VPN 代理端口, 启动内置 SOCKS5 服务器 (127.0.0.1:{fallback_port})"
                ));
                let server = socks::start_socks_server(*fallback_port).await?;
                let port = server.port;
                *guard = Some(server);
                Ok(("127.0.0.1".into(), port))
            }
        }
    }
}
