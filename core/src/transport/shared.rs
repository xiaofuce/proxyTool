//! 共享 SSH 连接的统一 Handler 与建连入口
//!
//! 同档案共享连接 (P6 遗留项落地): 三种隧道形态 (反向/本地/动态) 共用一个
//! Handler 类型, 连接才能进入连接池被多条隧道复用 (ControlMaster 语义):
//! - `check_server_key`: known_hosts TOFU 校验 (与旧 TunnelHandler /
//!   ConnectHandler 行为一致);
//! - `server_channel_open_forwarded_tcpip`: 按 `connected_port` 查路由表
//!   (每条反向隧道注册自己的监听端口 -> 本地落地; 专用连接 = 单条路由),
//!   桥接逻辑 (首字节 0x00 污染检查 + 连本地落地 + 双向复制) 逐字迁移自
//!   旧 TunnelHandler;
//! - 客户端发起的通道 (direct_tcpip / 会话通道) 不需要 Handler 状态。
//!
//! 通道计数 (`open_channels`): sshd 的 MaxSessions (默认 10) **计入转发通道**,
//! 共享连接须跟踪并发通道数做准入与告警 (策略/回退在 engine::pool, 此处只计数)。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use russh::client::{self, ChannelOpenHandle, Msg};
use russh::Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::known_hosts::{HostKeyCheck, KnownHosts};
use crate::model::TunnelError;
use crate::ssh::Logger;

/// MaxSessions 预算默认值 (sshd 默认 10; 可经 ProfileDefaults.max_sessions 调整)
pub const DEFAULT_MAX_SESSIONS: usize = 10;

/// 统一 handler 的连接句柄 (专用与共享同一类型)
pub type SharedHandle = Arc<tokio::sync::Mutex<client::Handle<SharedHandler>>>;

/// 反向转发路由表: 服务器监听端口 -> 本地落地 (host, port)
pub type RouteMap = Arc<RwLock<HashMap<u16, (String, u16)>>>;

/// russh 客户端 Handler: 接收服务器转发的反向连接, 按端口路由到本地落地。
pub struct SharedHandler {
    pub(crate) logger: Logger,
    /// 主机密钥 TOFU 校验 (P6; 指纹变更详情经 take_error 取回)
    pub(crate) host_check: Arc<HostKeyCheck>,
    /// 首字节检查发现通道被注入审计数据时置位 (云主机安全组件场景)
    pub(crate) corrupted: Arc<AtomicBool>,
    pub(crate) routes: RouteMap,
    /// 当前打开的通道数 (forwarded + 客户端发起; MaxSessions 准入的启发式计数)
    pub(crate) open_channels: Arc<AtomicUsize>,
    /// 通道数预算 (计数达到时的告警阈值; 准入与回退策略在 engine::pool)
    pub(crate) budget: usize,
}

/// 路由查找: 精确匹配优先; 无匹配且表里只有一条路由时回退用它 ——
/// 兼容个别 sshd 对 connected_port 上报异常的情况 (旧实现完全不区分端口,
/// 单隧道场景必须保持可用), 多路由时查不到即拒绝。
fn lookup_route(routes: &HashMap<u16, (String, u16)>, port: u16) -> Option<(String, u16)> {
    if let Some(t) = routes.get(&port) {
        return Some(t.clone());
    }
    if routes.len() == 1 {
        return routes.values().next().cloned();
    }
    None
}

impl client::Handler for SharedHandler {
    type Error = russh::Error;

    /// known_hosts TOFU 校验 (首次记住 / 一致放行 / 变更拒绝, 见 known_hosts.rs)
    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(self.host_check.verify(server_public_key))
    }

    /// 服务器有流量要转发回来时被调用: 按端口查路由 -> 桥接到本地落地。
    ///
    /// 注意: 桥接必须放进独立任务。russh 的连接消息循环会 await 本 handler
    /// 返回的 future, 若在这里 copy_bidirectional 直到结束, 通道数据永远不会被投递。
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let target = match lookup_route(&self.routes.read().unwrap(), connected_port as u16) {
            Some(t) => t,
            None => {
                // 未注册的转发端口: 拒绝 (drop 未消费的 reply = AdministrativelyProhibited)
                (self.logger)(&format!("转发端口 {connected_port} 无路由, 拒绝通道"));
                return Ok(());
            }
        };
        let count = self.open_channels.fetch_add(1, Ordering::Relaxed) + 1;
        warn_exhausted(count, self.budget, &self.logger);
        let logger = self.logger.clone();
        let corrupted = self.corrupted.clone();
        let counter = self.open_channels.clone();
        // 与 russh 自身测试相同: 先在任务里 into_stream, handler 再 accept
        tokio::spawn(async move {
            bridge_forwarded(
                channel,
                format!("{}:{}", target.0, target.1),
                corrupted,
                logger,
            )
            .await;
            counter.fetch_sub(1, Ordering::Relaxed);
        });
        reply.accept().await;
        Ok(())
    }
}

/// 转发通道桥接 (逐字迁移自旧 TunnelHandler): 首字节污染检查 → 连本地落地
/// → 双向复制。每连接独立任务, 并发服务。
async fn bridge_forwarded(
    channel: Channel<Msg>,
    target: String,
    corrupted: Arc<AtomicBool>,
    logger: Logger,
) {
    let mut chan = channel.into_stream();

    // 首字节检查 (污染探测的运行期兜底): 云主机安全组件 (如腾讯云
    // libonion) 在转发通道建立时注入审计数据, 首字节是其长度前缀的
    // 0x00 — 仅拦截这一注入特征并标记污染 (上层据此重建为兼容模式)。
    // 其余任意首字节一律放行桥接: 本地落地不一定是 SOCKS (Tcp 落地
    // 如 HTTP 首字节 'G'), 不能假设 0x05 (干净服务器上误丢会断业务)。
    // 探测连接写入的 0x58 'X' 等杂字节被转发到本地落地后由其自行
    // 按坏请求关闭, 无害。
    let mut head = [0u8; 1];
    match tokio::time::timeout(std::time::Duration::from_secs(2), chan.read(&mut head)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // 无数据: 探测连接或对端已断开, 静默关闭
            (logger)("转发通道无数据, 关闭");
            return;
        }
        Ok(Ok(_)) if head[0] == 0x00 => {
            // 首字节 0x00: 服务器端注入的审计数据 (长度前缀特征)
            (logger)("检测到转发通道首字节 0x00, 疑似服务器端注入审计数据 (云主机安全组件)");
            corrupted.store(true, Ordering::Relaxed);
            return;
        }
        Ok(Ok(_)) => {} // 正常应用数据 (含 SOCKS5 的 0x05), 放行
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

    let r = tokio::io::copy_bidirectional(&mut stream, &mut chan).await;
    (logger)(&format!("连接关闭 ({r:?})"));
}

/// 通道计数达到预算时告警 (服务器发起的转发 / 客户端发起的直连共用文案)。
/// 计数是启发式 —— sshd 才是权威执法者, 这里只提示用户预算将满。
pub(crate) fn warn_exhausted(count: usize, budget: usize, logger: &Logger) {
    if count >= budget {
        (logger)(&format!(
            "⚠️ 连接通道数 {count} 已达预算 {budget} —— 服务器 MaxSessions 可能拒绝新转发通道, \
             可在默认值中上调 MaxSessions 或关闭共享连接"
        ));
    }
}

/// 客户端发起通道 (probe / helper / direct_tcpip) 的计数 RAII:
/// 构造即 +1, Drop 即 -1 (覆盖错误早退路径)
pub(crate) struct ChannelGuard(Arc<AtomicUsize>);

impl ChannelGuard {
    pub(crate) fn acquire(counter: &Arc<AtomicUsize>, budget: usize, logger: &Logger) -> Self {
        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
        warn_exhausted(count, budget, logger);
        Self(counter.clone())
    }
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 建连产物: 连接句柄 + handler 共享状态 (establish 侧注册路由 / 计数用)。
/// 字段全 Arc, 浅克隆即共享同一连接的状态。
#[derive(Clone)]
pub struct SharedState {
    pub handle: SharedHandle,
    pub corrupted: Arc<AtomicBool>,
    pub routes: RouteMap,
    pub open_channels: Arc<AtomicUsize>,
    /// MaxSessions 预算 (告警阈值; 建连时定死, 与 handler 同源)
    pub budget: usize,
}

/// 建连入口: 构造 SharedHandler 并完成连接 + 认证。
/// 主机密钥经 known_hosts TOFU 校验, 指纹变更 → `TunnelError::HostKeyChanged`
/// (致命, 见 known_hosts.rs 的 take_error 手法)。
pub async fn connect(
    server_host: &str,
    server_port: u16,
    username: &str,
    auth: &crate::ssh::AuthMethod,
    keepalive: crate::ssh::Keepalive,
    known_hosts: &Arc<KnownHosts>,
    budget: usize,
    logger: &Logger,
) -> Result<SharedState, TunnelError> {
    let corrupted = Arc::new(AtomicBool::new(false));
    let routes: RouteMap = Arc::new(RwLock::new(HashMap::new()));
    let open_channels = Arc::new(AtomicUsize::new(0));
    let host_check = HostKeyCheck::new(known_hosts.clone(), server_host, server_port, logger.clone());
    let handler = SharedHandler {
        logger: logger.clone(),
        host_check: host_check.clone(),
        corrupted: corrupted.clone(),
        routes: routes.clone(),
        open_channels: open_channels.clone(),
        budget,
    };
    let session = match crate::ssh::connect_auth(
        server_host,
        server_port,
        username,
        auth,
        keepalive,
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
    Ok(SharedState {
        handle: Arc::new(tokio::sync::Mutex::new(session)),
        corrupted,
        routes,
        open_channels,
        budget,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn landing(port: u16) -> (String, u16) {
        ("127.0.0.1".into(), port)
    }

    /// 精确匹配: 多路由时各端口查到各自落地
    #[test]
    fn route_exact_match() {
        let mut m = HashMap::new();
        m.insert(1081, landing(7892));
        m.insert(1082, landing(1080));
        assert_eq!(lookup_route(&m, 1081), Some(landing(7892)));
        assert_eq!(lookup_route(&m, 1082), Some(landing(1080)));
    }

    /// 单路由回退: 端口对不上但只有一条路由时仍放行 (兼容 connected_port
    /// 上报异常的 sshd; 旧实现完全不区分端口, 单隧道必须保持可用)
    #[test]
    fn route_single_fallback() {
        let mut m = HashMap::new();
        m.insert(1081, landing(7892));
        assert_eq!(lookup_route(&m, 9999), Some(landing(7892)));
    }

    /// 多路由且无匹配: 拒绝 (None)
    #[test]
    fn route_multi_miss_rejected() {
        let mut m = HashMap::new();
        m.insert(1081, landing(7892));
        m.insert(1082, landing(1080));
        assert_eq!(lookup_route(&m, 9999), None);
        assert_eq!(lookup_route(&m, 0), None);
    }

    /// 空表: 拒绝
    #[test]
    fn route_empty_rejected() {
        let m = HashMap::<u16, (String, u16)>::new();
        assert_eq!(lookup_route(&m, 1081), None);
    }

    /// 路由表插拔 (establish 注册 / 拆除摘除)
    #[test]
    fn route_insert_remove() {
        let m: RouteMap = Arc::new(RwLock::new(HashMap::new()));
        m.write().unwrap().insert(1081, landing(7892));
        assert_eq!(lookup_route(&m.read().unwrap(), 1081), Some(landing(7892)));
        m.write().unwrap().remove(&1081);
        assert!(lookup_route(&m.read().unwrap(), 1081).is_none());
    }
}
