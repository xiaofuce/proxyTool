//! 共享 SSH 连接工具
//!
//! 三种隧道模式 (反向转发 / 本地转发 / 动态隧道) 共用:
//! - `Logger`: 日志回调 (GUI 转发到前端, 测试直接打印)
//! - `ConnectHandler`: 本地转发/动态隧道使用的极简 handler
//!   (主机密钥经 `known_hosts` TOFU 校验, 见 known_hosts.rs)
//! - `connect_auth`: 连接 + 密码认证 (泛型, 可带任意 Handler)
//! - `remote_exec`: 独立连接上执行远程命令 (验证隧道 / 部署脚本用)

use std::sync::Arc;
use std::time::Duration;

use russh::client;

use crate::known_hosts::{HostKeyCheck, KnownHosts};
use crate::model::TunnelError;

/// 日志回调: GUI 中转发到前端, 测试中直接打印
pub type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// SSH 保活参数 (OpenSSH ServerAliveInterval × CountMax 语义)。
/// 判死时延 ≈ interval × max——网络静默时在该窗口内检测到断线并触发重连,
/// 否则要等 TCP 超时 (可达数分钟)。值来自隧道的 ReconnectPolicy。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keepalive {
    /// 探测间隔 (russh keepalive_interval)
    pub interval: Duration,
    /// 无响应次数上限 (russh keepalive_max), 超过即判定连接死亡
    pub max: u32,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            max: 3,
        }
    }
}

impl Keepalive {
    /// 判死时延 (展示用): interval × max
    pub fn dead_after(&self) -> Duration {
        self.interval * self.max
    }
}

/// 极简客户端 Handler: 本地转发 / 动态隧道使用。
/// 不需要接收反向转发连接 (server_channel_open_forwarded_tcpip 用默认拒绝行为),
/// 但主机密钥同样走 known_hosts TOFU 校验 (P6 起, 不再信任任意公钥)。
pub struct ConnectHandler {
    pub logger: Logger,
    pub host_check: Arc<HostKeyCheck>,
}

impl ConnectHandler {
    /// 统一构造: 记忆库 + 目标地址 + 日志
    pub fn new(logger: Logger, known_hosts: Arc<KnownHosts>, host: &str, port: u16) -> Self {
        Self {
            host_check: HostKeyCheck::new(known_hosts, host, port, logger.clone()),
            logger,
        }
    }
}

impl client::Handler for ConnectHandler {
    type Error = russh::Error;

    /// known_hosts TOFU 校验 (首次记住 / 一致放行 / 变更拒绝, 见 known_hosts.rs)
    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(self.host_check.verify(server_public_key))
    }
}

/// 认证方式 (连接时注入, 凭据仅存内存)
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// 密码认证
    Password(String),
    /// 私钥文件认证 (path + 可选口令; 加载失败 = 致命配置错误)
    KeyFile {
        path: std::path::PathBuf,
        passphrase: Option<String>,
    },
}

/// 认证失败的错误归类: 私钥加载失败是配置错误 (致命), 不应混入网络类
fn key_load_error(path: &std::path::Path, e: russh::keys::Error) -> TunnelError {
    TunnelError::KeyLoad {
        path: path.display().to_string(),
        reason: e.to_string(),
    }
}

/// 私钥按路径缓存 (R8): 加密私钥 KDF 每次重连都重算 (~数百 ms), 同路径密钥不变。
/// 加载失败不缓存 (口令可能输错, 下次重试重载); 换钥后重启进程即清 (桌面工具可接受)。
static KEY_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, Arc<russh::keys::PrivateKey>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 连接服务器 + 认证 (密码或私钥), 返回会话句柄。凭据仅用于内存认证, 不落盘。
/// 错误为 TunnelError: Connect(网络)/AuthIo(认证阶段通信失败) 可重试,
/// AuthRejected(密码被拒)/KeyLoad(私钥文件问题) 致命 —— 重连循环按 retryable() 决策。
pub async fn connect_auth<H: client::Handler<Error = russh::Error> + Send + 'static>(
    server_host: &str,
    server_port: u16,
    username: &str,
    auth: &AuthMethod,
    keepalive: Keepalive,
    handler: H,
    logger: &Logger,
) -> Result<client::Handle<H>, TunnelError> {
    let config = Arc::new(client::Config {
        keepalive_interval: Some(keepalive.interval),
        // russh keepalive_max: usize; policy 用 u32, 收敛并至少 1
        keepalive_max: (keepalive.max as usize).max(1),
        ..Default::default()
    });

    let addr = format!("{server_host}:{server_port}");
    logger(&format!("连接 {addr} ..."));

    let mut session = client::connect(config, &addr[..], handler)
        .await
        .map_err(|e| TunnelError::Connect {
            addr: addr.clone(),
            source: e,
        })?;
    let result = match auth {
        AuthMethod::Password(password) => session
            .authenticate_password(username, password)
            .await
            .map_err(|e| TunnelError::AuthIo { source: e })?,
        AuthMethod::KeyFile { path, passphrase } => {
            let path_str = path.display().to_string();
            // 缓存命中复用; 未命中才读盘解析 (KDF 昂贵)
            let cached = KEY_CACHE.lock().unwrap().get(&path_str).cloned();
            let key = match cached {
                Some(k) => k,
                None => {
                    let k = Arc::new(
                        russh::keys::load_secret_key(path, passphrase.as_deref())
                            .map_err(|e| key_load_error(path, e))?,
                    );
                    KEY_CACHE.lock().unwrap().insert(path_str, k.clone());
                    k
                }
            };
            // RSA 需要显式哈希 (russh 直传 None 会落到 SHA-1), 其余算法忽略
            let hash_alg = if key.algorithm().is_rsa() {
                Some(russh::keys::HashAlg::Sha256)
            } else {
                None
            };
            let key = russh::keys::PrivateKeyWithHashAlg::new(key, hash_alg);
            session
                .authenticate_publickey(username, key)
                .await
                .map_err(|e| TunnelError::AuthIo { source: e })?
        }
    };
    if !result.success() {
        return Err(TunnelError::AuthRejected);
    }
    logger("SSH 认证成功");
    Ok(session)
}

/// 独立连接并在服务器上执行命令, 返回 stdout (含超时)。
/// 与隧道连接分离: 验证 / 部署场景无需持有隧道句柄。
/// 错误保持 String (展示型路径, 不参与重连决策); TunnelError 经 Display 转换。
/// 主机密钥同样经 known_hosts 校验 (指纹变更时返回其 Display 文案)。
#[allow(clippy::too_many_arguments)]
pub async fn remote_exec(
    server_host: &str,
    server_port: u16,
    username: &str,
    auth: &AuthMethod,
    cmd: &str,
    timeout: Duration,
    known_hosts: &Arc<KnownHosts>,
) -> Result<String, String> {
    use tokio::io::AsyncReadExt;
    let silent: Logger = Arc::new(|_| {});
    let handler = ConnectHandler::new(
        silent.clone(),
        known_hosts.clone(),
        server_host,
        server_port,
    );
    // 校验器克隆: connect 失败时取指纹变更详情 (handler 本体已 move 进连接)
    let host_check = handler.host_check.clone();
    let session = match connect_auth(
        server_host,
        server_port,
        username,
        auth,
        Keepalive::default(),
        handler,
        &silent,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            // 指纹变更 → 专用致命文案; 其余按原样展示
            return Err(host_check
                .take_error()
                .map_or_else(|| e.to_string(), |fatal| fatal.to_string()));
        }
    };
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
