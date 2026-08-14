//! 端到端验收测试: 本地转发 (ssh -L) 与 动态隧道 (ssh -D)
//!
//! 目标选择 127.0.0.1:22 (服务器自身 SSH): 无需在服务器上额外起服务,
//! 读到 "SSH-2.0-..." banner 即证明 本机 -> SSH隧道 -> 服务器 链路完整。
//!
//! 前提: 测试服务器可达。
//! 运行: cargo test --test e2e_direct -- --nocapture

use std::sync::Arc;
use std::time::Duration;

use proxy_tool_core::direct::{run_dynamic_forward, run_local_forward, DirectConfig};
use proxy_tool_core::known_hosts::KnownHosts;
use proxy_tool_core::ssh::{AuthMethod, Logger};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SERVER: &str = "203.0.113.20";
const USER: &str = "tester";
fn pass() -> &'static str {
    proxy_tool_core::creds::pass()
}

fn silent_logger() -> Logger {
    Arc::new(|msg: &str| println!("[tunnel] {msg}"))
}

fn cfg(listen_port: u16) -> DirectConfig {
    DirectConfig {
        server_host: SERVER.into(),
        server_port: 22,
        username: USER.into(),
        auth: AuthMethod::Password(pass().into()),
        listen_host: "127.0.0.1".into(),
        listen_port,
        keepalive: Default::default(),
        known_hosts: KnownHosts::in_memory(),
    }
}

/// 分配一个空闲的本地端口 (绑定后立即释放, 由被测代码接管绑定)
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// 从连接上读取一行 (期望 SSH banner), 超时/EOF 时返回已有内容
async fn read_line(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tokio::time::timeout(Duration::from_secs(15), stream.read(&mut byte)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(_)) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' || buf.len() > 200 {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn local_forward_reaches_server_ssh() {
    let listen_port = free_port().await;
    let (session, task) =
        run_local_forward(cfg(listen_port), "127.0.0.1".into(), 22, silent_logger())
            .await
            .expect("本地转发启动失败");

    // 等待监听就绪
    tokio::time::sleep(Duration::from_millis(800)).await;
    let mut s = TcpStream::connect(("127.0.0.1", listen_port))
        .await
        .expect("连接本地转发端口失败");
    let banner = read_line(&mut s).await;
    let _ = s.shutdown().await;
    println!("== 本地转发 banner: {banner:?}");
    assert!(
        banner.starts_with("SSH-2.0-"),
        "应读到服务器 SSH banner, 实际: {banner:?}"
    );

    session.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// 错误密码: 连接失败且错误被类型化为「认证被拒」——
/// 重连循环 (lib.rs::run_with_reconnect) 按 retryable() 分类立即停止重试,
/// 本测试锁住 connect_auth → TunnelError::AuthRejected 的契约 (P1 起取代字符串匹配)。
#[tokio::test]
async fn wrong_password_is_reported_as_auth_rejection() {
    let mut c = cfg(0); // 监听端口不会被用到 (认证在绑定前失败)
    c.auth = AuthMethod::Password(format!("{}-wrong", pass()));
    let err = match run_local_forward(c, "127.0.0.1".into(), 22, silent_logger()).await {
        Err(e) => e,
        Ok(_) => panic!("错误密码应连接失败"),
    };
    println!("== 错误密码错误信息: {err:?}");
    assert!(
        matches!(err, proxy_tool_core::model::TunnelError::AuthRejected),
        "应识别为认证被拒 (停止重连), 实际: {err:?}"
    );
}

/// 私钥认证 (P6): 本地生成 ed25519 密钥对 → 公钥经密码会话上传 authorized_keys →
/// `AuthMethod::KeyFile` 建立本地转发并读到 SSH banner → 清理公钥行。
/// 私钥随机生成仅存临时目录 (不入 git); authorized_keys 行带唯一标记, 结束删除。
#[tokio::test]
async fn key_auth_establishes_tunnel() {
    // 1. 生成密钥对, openssh pem 写临时目录
    let key = ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519)
        .expect("生成 ed25519 密钥失败");
    let dir = std::env::temp_dir().join(format!("pt-key-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("id_ed25519");
    std::fs::write(
        &key_path,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_str(),
    )
    .unwrap();
    let pubkey = key.public_key().to_openssh().unwrap();
    let marker = format!("pt-e2e-{}", uuid::Uuid::new_v4().simple());

    let known = Arc::new(KnownHosts::in_memory());
    let admin = |cmd: String| {
        let known = known.clone();
        async move {
            proxy_tool_core::ssh::remote_exec(
                SERVER,
                22,
                USER,
                &AuthMethod::Password(pass().into()),
                &cmd,
                Duration::from_secs(30),
                &known,
            )
            .await
        }
    };

    // 2. 上传公钥 (密码会话)
    let out = admin(format!(
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{pubkey} {marker}' >> ~/.ssh/authorized_keys && echo INSTALLED"
    ))
    .await
    .expect("上传公钥失败");
    assert!(out.contains("INSTALLED"), "应确认已写入: {out}");

    // 3. KeyFile 认证建立本地转发, 读服务器 SSH banner
    let result = async {
        let listen_port = free_port().await;
        let kcfg = DirectConfig {
            auth: AuthMethod::KeyFile {
                path: key_path.clone(),
                passphrase: None,
            },
            ..cfg(listen_port)
        };
        let (session, task) = run_local_forward(kcfg, "127.0.0.1".into(), 22, silent_logger())
            .await
            .expect("私钥认证隧道建立失败");
        tokio::time::sleep(Duration::from_millis(800)).await;
        let mut s = TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .expect("连接本地转发端口失败");
        let banner = read_line(&mut s).await;
        let _ = s.shutdown().await;
        session.disconnect().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        banner
    }
    .await;

    // 4. 清理: 无论成败都删公钥行 + 删临时目录
    let cleanup = admin(format!(
        "sed -i '/{marker}/d' ~/.ssh/authorized_keys && echo CLEANED"
    ))
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        cleanup.unwrap_or_default().contains("CLEANED"),
        "公钥行清理应成功"
    );

    assert!(
        result.starts_with("SSH-2.0-"),
        "私钥认证应读到服务器 SSH banner, 实际: {result:?}"
    );
}

#[tokio::test]
async fn dynamic_socks_reaches_server_ssh() {
    let listen_port = free_port().await;
    let (session, task) = run_dynamic_forward(cfg(listen_port), silent_logger())
        .await
        .expect("动态隧道启动失败");
    let socks_port = session.listen_port;

    // 等待 SOCKS 服务器就绪
    tokio::time::sleep(Duration::from_millis(800)).await;
    let mut s = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .expect("连接 SOCKS 端口失败");

    // SOCKS5 握手: 无认证
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [0x05, 0x00], "SOCKS 握手失败: {r:02x?}");

    // CONNECT 127.0.0.1:22 (服务器自身 SSH)
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&22u16.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "CONNECT 被拒: {rep:02x?}");

    let banner = read_line(&mut s).await;
    let _ = s.shutdown().await;
    println!("== 动态隧道 banner: {banner:?}");
    assert!(
        banner.starts_with("SSH-2.0-"),
        "应经动态隧道读到服务器 SSH banner, 实际: {banner:?}"
    );

    session.disconnect().await;
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}
