//! 共享 SSH 连接工具
//!
//! 三种隧道模式 (反向转发 / 本地转发 / 动态隧道) 共用:
//! - `Logger`: 日志回调 (GUI 转发到前端, 测试直接打印)
//! - `ConnectHandler`: 本地转发/动态隧道使用的极简 handler (信任任意服务器公钥)
//! - `connect_auth`: 连接 + 密码认证 (泛型, 可带任意 Handler)
//! - `remote_exec`: 独立连接上执行远程命令 (验证隧道 / 部署脚本用)

use std::sync::Arc;
use std::time::Duration;

use russh::client;

/// 日志回调: GUI 中转发到前端, 测试中直接打印
pub type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// 极简客户端 Handler: 本地转发 / 动态隧道使用。
/// 不需要接收反向转发连接 (server_channel_open_forwarded_tcpip 用默认拒绝行为)。
pub struct ConnectHandler {
    pub logger: Logger,
}

impl client::Handler for ConnectHandler {
    type Error = russh::Error;

    /// 信任任意服务器公钥 (MVP; 后续可升级为 known_hosts 校验)
    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// 连接服务器 + 密码认证, 返回会话句柄。密码仅用于内存认证, 不落盘。
pub async fn connect_auth<H: client::Handler<Error = russh::Error> + Send + 'static>(
    server_host: &str,
    server_port: u16,
    username: &str,
    password: &str,
    handler: H,
    logger: &Logger,
) -> Result<client::Handle<H>, String> {
    let mut config = client::Config::default();
    config.keepalive_interval = Some(Duration::from_secs(10));
    let config = Arc::new(config);

    let addr = format!("{server_host}:{server_port}");
    logger(&format!("连接 {addr} ..."));

    let mut session = client::connect(config, &addr[..], handler)
        .await
        .map_err(|e| format!("SSH 连接失败: {e}"))?;
    let auth = session
        .authenticate_password(username, password)
        .await
        .map_err(|e| format!("认证失败: {e}"))?;
    if !auth.success() {
        return Err("密码认证被拒绝".into());
    }
    logger("SSH 认证成功");
    Ok(session)
}

/// 独立连接并在服务器上执行命令, 返回 stdout (含超时)。
/// 与隧道连接分离: 验证 / 部署场景无需持有隧道句柄。
pub async fn remote_exec(
    server_host: &str,
    server_port: u16,
    username: &str,
    password: &str,
    cmd: &str,
    timeout: Duration,
) -> Result<String, String> {
    use tokio::io::AsyncReadExt;
    let silent: Logger = Arc::new(|_| {});
    let session = connect_auth(
        server_host,
        server_port,
        username,
        password,
        ConnectHandler {
            logger: silent.clone(),
        },
        &silent,
    )
    .await?;
    let chan = session
        .channel_open_session()
        .await
        .map_err(|e| format!("打开会话通道失败: {e}"))?;
    chan.exec(true, cmd)
        .await
        .map_err(|e| format!("发送执行请求失败: {e}"))?;
    let mut stream = chan.into_stream();
    let mut out = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut out))
        .await
        .map_err(|_| format!("命令执行超时 (>{}s)", timeout.as_secs()))?
        .map_err(|e| format!("读取命令输出失败: {e}"))?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}
