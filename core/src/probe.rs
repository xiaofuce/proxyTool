//! 本地代理端口自动探测
//!
//! VPN 客户端(如 v2cloud/Xray/V2Ray/Clash)通常会在本地开一个 SOCKS5 监听端口。
//! 探测策略: 依次尝试常见端口, 先测 TCP 连通, 再做 SOCKS5 握手确认。

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 常见 SOCKS 代理端口候选 (v2ray 默认 10808/10809, clash 7890/7892, v2cloud 等)
const CANDIDATES: &[u16] = &[
    10808, 10809, 7890, 7892, 7891, 1080, 1081, 20170, 20171, 20172, 2080, 2081, 9090,
];

/// 一次 SOCKS5 握手探测: 发 `\x05\x01\x00` (v5, 1种认证: no-auth), 期待 `\x05\x00`
async fn probe_socks5(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return false;
    };
    let _ = stream.set_nodelay(true);
    let fut = async {
        stream.write_all(b"\x05\x01\x00").await?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(buf == [0x05, 0x00])
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(3), fut).await,
        Ok(Ok(true))
    )
}

/// 探测本地是否有可用的 SOCKS5 代理, 返回 (端口, 是否确认是SOCKS5)。
/// 候选并发探测 (R8: 原串行最坏 13×(2s+3s)≈65s, 并发最坏 ≈5s)。
/// tokio 无 join_all —— 全 spawn 后按候选序 await (JoinHandle 保序收集)。
pub async fn probe_local_proxy() -> Vec<ProbeResult> {
    let handles: Vec<_> = CANDIDATES
        .iter()
        .map(|&port| {
            tokio::spawn(async move {
                let addr: SocketAddr = match format!("127.0.0.1:{port}").parse() {
                    Ok(a) => a,
                    Err(_) => return None,
                };
                // 1) TCP 连通性
                let tcp_ok =
                    tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
                        .await
                        .map(|r| r.is_ok())
                        .unwrap_or(false);
                if !tcp_ok {
                    return None;
                }
                // 2) SOCKS5 握手确认
                let socks_ok = probe_socks5(addr).await;
                Some(ProbeResult {
                    port,
                    tcp_reachable: true,
                    socks5_confirmed: socks_ok,
                })
            })
        })
        .collect();
    let mut results = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(r) = h.await {
            results.push(r);
        }
    }
    results.into_iter().flatten().collect()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeResult {
    pub port: u16,
    pub tcp_reachable: bool,
    pub socks5_confirmed: bool,
}
