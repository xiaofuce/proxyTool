//! 内置 SOCKS5 服务器
//!
//! 两种用途 (由 Connector 决定出口):
//! 1. **Plain**: VPN 无端口 (如 TUN 模式) 时, 工具自备 SOCKS5 入口:
//!    服务器流量 -> SSH隧道 -> 本机SOCKS5 -> 系统路由(经VPN出网) -> 外网
//! 2. **Ssh**: 动态隧道 (ssh -D), 本机 SOCKS5 入口, 每个连接经 SSH
//!    direct_tcpip 通道由服务器代为连接目标 (可访问服务器内网任意主机)
//!
//! 仅支持 CONNECT 方法, 只绑定 127.0.0.1, 无认证(本机专用)。
//! 性能: 本机回环内一次 TCP 转发, 延迟 <0.1ms, 开销可忽略。

use std::sync::Arc;

use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};

/// 桥接用的统一流类型 (TCP 连接或 SSH 通道)
pub trait DynIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DynIo for T {}
pub type DynStream = Box<dyn DynIo>;

/// SOCKS5 出口连接器
#[derive(Clone)]
pub enum Connector {
    /// 直接 TCP 连接 (本机系统路由出网)
    Plain,
    /// 经 SSH direct_tcpip 通道, 由服务器代连目标 (动态隧道)
    Ssh {
        handle: Arc<Mutex<russh::client::Handle<crate::ssh::ConnectHandler>>>,
    },
}

impl Connector {
    /// 连接目标 (host, port), 返回可桥接的流
    pub async fn connect(&self, host: &str, port: u16) -> std::io::Result<DynStream> {
        match self {
            Connector::Plain => {
                let stream = TcpStream::connect((host, port)).await?;
                Ok(Box::new(stream))
            }
            Connector::Ssh { handle } => {
                let chan = handle
                    .lock()
                    .await
                    .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
                    .await
                    .map_err(|e| std::io::Error::other(format!("SSH 直连通道打开失败: {e}")))?;
                Ok(Box::new(chan.into_stream()))
            }
        }
    }
}

/// 内置 SOCKS5 服务器句柄: 查询端口 / 停止服务
pub struct SocksServerHandle {
    pub port: u16,
    stop: Arc<Notify>,
}

impl SocksServerHandle {
    /// 停止接收新连接 (已建立的连接不受影响)
    pub fn stop(&self) {
        self.stop.notify_one();
    }
}

/// 在 127.0.0.1:<port> 启动 SOCKS5 服务器 (Plain 出口, 系统路由), 返回句柄
pub async fn start_socks_server(port: u16) -> Result<Arc<SocksServerHandle>, String> {
    start_socks_server_with(port, Connector::Plain).await
}

/// 在 127.0.0.1:<port> 启动 SOCKS5 服务器, 自定义出口连接器, 返回句柄
pub async fn start_socks_server_with(
    port: u16,
    connector: Connector,
) -> Result<Arc<SocksServerHandle>, String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("绑定内置 SOCKS 端口 {port} 失败: {e}"))?;

    let bound = listener
        .local_addr()
        .map_err(|e| format!("获取内置 SOCKS 端口失败: {e}"))?
        .port();

    let stop = Arc::new(Notify::new());
    let stop_task = stop.clone();
    // 用 tokio::spawn: tauri 的异步运行时就是 tokio, 测试环境(#[tokio::test])也可直接调用
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_task.notified() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let conn = connector.clone();
                        tokio::spawn(async move {
                            let _ = handle_socks_client(stream, &conn).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    });

    Ok(Arc::new(SocksServerHandle { port: bound, stop }))
}

/// 处理单个 SOCKS5 客户端: 握手 -> CONNECT -> 双向转发
async fn handle_socks_client(mut stream: TcpStream, connector: &Connector) -> std::io::Result<()> {
    // --- 握手: 客户端发 VER(0x05) NMETHODS [METHODS...] ---
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        return Ok(()); // 非 SOCKS5, 丢弃
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        // 不支持无认证, 拒绝
        stream.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    }
    // 选择无认证
    stream.write_all(&[0x05, 0x00]).await?;

    // --- 请求: VER CMD RSV ATYP [ADDR] [PORT] ---
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let cmd = head[1];
    let atyp = head[3];
    if cmd != 0x01 {
        // 只支持 CONNECT
        send_reply(&mut stream, 0x07).await?;
        return Ok(());
    }

    let target = read_target(&mut stream, atyp).await?;
    let Some((host, port)) = target else {
        send_reply(&mut stream, 0x08).await?;
        return Ok(());
    };

    // --- 连接目标地址 (10s 超时, 避免目标被墙时挂死) ---
    let mut upstream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connector.connect(&host, port),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => {
            send_reply(&mut stream, 0x05).await?; // connection refused
            return Ok(());
        }
        Err(_) => {
            send_reply(&mut stream, 0x04).await?; // host unreachable
            return Ok(());
        }
    };
    send_reply(&mut stream, 0x00).await?; // success

    // --- 双向转发 ---
    copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(())
}

/// 读取目标地址, 返回 (主机, 端口)
async fn read_target(stream: &mut TcpStream, atyp: u8) -> std::io::Result<Option<(String, u16)>> {
    let host: String = match atyp {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            // 域名
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => return Ok(None), // 不支持的类型
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Some((host, u16::from_be_bytes(port))))
}

/// 发送 SOCKS5 回复 (VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0)
async fn send_reply(stream: &mut TcpStream, rep: u8) -> std::io::Result<()> {
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}
