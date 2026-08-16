//! 同档案共享 SSH 连接池 (P6 遗留可选项落地, 设计 §3.6)
//!
//! ControlMaster 语义: 同一档案 (profile_id) 的多条隧道复用一条 SSH 连接,
//! N 条隧道 1 次认证。**租约生命周期 = 一次 attempt** —— 起于建连, 终于
//! attempt 返回 (退避期不持有); 末位租约释放即整连断开 (v1 无驻留)。
//!
//! 共享/专用统一: `share = false` 返回**游离**租约 (不入池表, close 即断连),
//! 引擎只面向 `Lease` 一套代码, 不分叉。
//!
//! Single-flight 重建: 共享连接掉线后各成员隧道独立退避重试, `connecting`
//! 锁只在 connect+auth 期间持有; 等待者拿锁后先复查已有活连接则复用 ——
//! 无惊群重认证 (回归断言: 掉线重连全员建连次数只 +1)。
//!
//! MaxSessions 约束: sshd 会话上限 (默认 10) **计入转发通道**。成本常量
//! 见顶部 (按形态估); 通道计数在 transport::shared (SharedState.open_channels)。
//! **准入** (acquire): Σ租约 cost + 本次 ≤ 预算 且 活通道 + 本次 ≤ 预算,
//! 否则自动回退游离专用连接并告警; **运行期耗尽**的回退走同一入口 —— 客户端
//! 打开通道被 sshd 拒 → attempt Err → 1s 快试退避 → 再取租约准入被拒 → 游离。
//! 服务器发起的转发通道 (forwarded-tcpip) 不拒收只计数: sshd 才是权威执法者。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use russh::Disconnect;
use tokio::sync::{Mutex as AsyncMutex, RwLock};

use crate::known_hosts::KnownHosts;
use crate::model::TunnelError;
use crate::ssh::{Keepalive, Logger};
use crate::transport::shared::{self, SharedHandle, SharedState};

use super::SshCreds;

/// 同档案共享连接默认开关 (档案层/全局层都未设置时的兜底)
pub const DEFAULT_SHARE_CONNECTION: bool = true;

/// MaxSessions 预算下的通道占用成本 (启发式; C4 准入用):
/// 标准反向 = 转发通道按并发连接计, 留余量; 兼容反向 = 恒 1 条会话通道;
/// 本地/动态 = 每活动连接 1 条 direct-tcpip, 按 2 条估。
pub const COST_STD_REVERSE: usize = 4;
pub const COST_COMPAT_REVERSE: usize = 1;
pub const COST_DIRECT: usize = 2;

/// 连接池: 按档案 id 一条共享连接
pub struct ConnPool {
    map: Mutex<HashMap<String, Arc<PooledConn>>>,
}

struct PooledConn {
    /// single-flight: 只在 connect+auth 期间持有
    connecting: AsyncMutex<()>,
    /// 当前连接 (None = 无活连接, 下个租约者重建)
    inner: RwLock<Option<ConnState>>,
    /// 活跃租约 (按隧道 id; 末位释放即断连)。cost = 该隧道占用的
    /// MaxSessions 预算 (准入用, 按最重形态估)
    leases: Mutex<Vec<LeaseInfo>>,
    /// 累计建连次数 (single-flight 回归断言)
    connect_count: AtomicU64,
    /// 代际号: 每 (重)建 +1。旧代际租约释放时不误断他人重建的新连接
    generation: AtomicU64,
}

/// 单条租约的预算占用
struct LeaseInfo {
    tunnel_id: String,
    cost: usize,
}

struct ConnState {
    state: SharedState,
    generation: u64,
}

/// 连接租约: attempt 全程持有, 结束时 `close()`。
/// 共享 = 释放计数 (末位才断连); 游离 (专用) = 立即断连。
pub struct Lease {
    kind: LeaseKind,
    tunnel_id: String,
}

enum LeaseKind {
    Pooled {
        conn: Arc<PooledConn>,
        generation: u64,
        state: SharedState,
    },
    Dedicated(SharedState),
}

impl Lease {
    /// 是否池内共享连接 (决定 *_on 的断开是否发整连 DISCONNECT)
    pub fn is_shared(&self) -> bool {
        matches!(self.kind, LeaseKind::Pooled { .. })
    }

    /// 租约对应的连接状态 (handle/路由表/通道计数)
    pub fn state(&self) -> &SharedState {
        match &self.kind {
            LeaseKind::Pooled { state, .. } => state,
            LeaseKind::Dedicated(state) => state,
        }
    }

    /// 释放租约 (显式收尾, 不走 Drop —— 断连是异步操作)。
    /// 末位租约释放 → 立即整连断开 (v1 无驻留); 代际不匹配 (连接已被他人
    /// 重建) 则只释放, 新连接留给即将入列的新租约。
    pub async fn close(self) {
        match self.kind {
            LeaseKind::Dedicated(state) => {
                disconnect_handle(&state.handle, "lease closed").await;
            }
            LeaseKind::Pooled {
                conn,
                generation,
                ..
            } => {
                conn.leases.lock().unwrap().retain(|l| l.tunnel_id != self.tunnel_id);
                // **末位租约** → 整连断开 (兄弟租约仍在则连接保留, 停一条隧道
                // 绝不能断掉同档案其他隧道 —— e2e shared_conn_data_path 回归锁死)。
                // R8: 原实现持写锁跨 disconnect await, 网络差时阻塞同档案其他
                // 租约的准入/释放; 改先摘表再 await —— 并发 acquire 见 None
                // 立即建新连接; 新旧连接短暂并存的端口竞争由 sshd 拒绝 +
                // 1s 快退避自愈。**注意重构时勿删 is_empty 守卫** (曾删掉导致
                // 停一条断全部, 已修)。
                if !conn.leases.lock().unwrap().is_empty() {
                    return;
                }
                let victim = {
                    let mut guard = conn.inner.write().await;
                    let v = guard
                        .as_ref()
                        .filter(|cs| cs.generation == generation)
                        .map(|cs| cs.state.handle.clone());
                    if v.is_some() {
                        *guard = None;
                    }
                    v
                };
                if let Some(handle) = victim {
                    disconnect_handle(&handle, "last lease released").await;
                }
            }
        }
    }
}

async fn disconnect_handle(handle: &SharedHandle, reason: &str) {
    let h = handle.lock().await;
    let _ = h.disconnect(Disconnect::ByApplication, reason, "").await;
}

/// 游离专用连接 (share=false 或预算准入拒绝): 不入池表, 释放即断
async fn connect_dedicated(
    creds: &SshCreds,
    keepalive: Keepalive,
    known_hosts: &Arc<KnownHosts>,
    logger: &Logger,
) -> Result<SharedState, TunnelError> {
    shared::connect(
        &creds.host,
        creds.port,
        &creds.username,
        &creds.auth,
        keepalive,
        known_hosts,
        creds.max_sessions as usize,
        logger,
    )
    .await
}

/// 池快照条目 (诊断/测试: single-flight 与租约归属断言)
#[derive(Debug, Clone)]
pub struct ConnStats {
    pub profile_id: String,
    /// 当前连接代际 (0 = 无活连接)
    pub generation: u64,
    /// 累计建连次数
    pub connect_count: u64,
    /// 当前连接的打开通道数 (MaxSessions 启发式计数)
    pub open_channels: usize,
    /// 活跃租约的隧道 id
    pub leases: Vec<String>,
}

impl ConnPool {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// 获取租约: `share = false` → 游离专用连接; 否则按 profile_id 入池
    /// (无活连接则建连 —— single-flight, 已有则复用)。
    /// `cost` = 本隧道的 MaxSessions 预算占用 (按形态, pool 顶部常量);
    /// **准入拒绝 → 也返回游离连接** (预算已满, 自动回退专用并告警)。
    /// 运行期耗尽的回退同走此处: 客户端打开通道被拒 → attempt Err → 1s 退避
    /// → 再取租约时活通道计数已超 → 准入拒绝 → 游离连接, 无需额外管线。
    /// 建连/认证失败原样上抛 (attempt 据此进退避)。
    #[allow(clippy::too_many_arguments)]
    pub async fn acquire(
        &self,
        profile_id: &str,
        tunnel_id: &str,
        creds: &SshCreds,
        keepalive: Keepalive,
        known_hosts: &Arc<KnownHosts>,
        logger: &Logger,
        cost: usize,
    ) -> Result<Lease, TunnelError> {
        if !creds.share {
            let state = connect_dedicated(creds, keepalive, known_hosts, logger).await?;
            return Ok(Lease {
                kind: LeaseKind::Dedicated(state),
                tunnel_id: tunnel_id.to_string(),
            });
        }
        let conn = {
            let mut map = self.map.lock().unwrap();
            map.entry(profile_id.to_string())
                .or_insert_with(|| Arc::new(PooledConn::new()))
                .clone()
        };
        // 准入 (启发式: sshd 才是权威执法者, 客户端计数只防患未然):
        // 存量租约已承诺 Σcost + 本次 ≤ 预算, 且活通道 + 本次 ≤ 预算。
        // 拒绝 → 游离专用连接 (独立 sshd 连接有自己的 MaxSessions 预算)。
        let budget = creds.max_sessions as usize;
        let committed: usize = conn.leases.lock().unwrap().iter().map(|l| l.cost).sum();
        let live = conn.live_channels().await;
        if committed + cost > budget || live + cost > budget {
            (logger)(&format!(
                "⚠️ 共享连接预算已满 (租约已承诺 {committed} + 本次 {cost}, 活通道 {live}, 预算 {budget}) —— 本隧道自动回退为独立连接"
            ));
            let state = connect_dedicated(creds, keepalive, known_hosts, logger).await?;
            return Ok(Lease {
                kind: LeaseKind::Dedicated(state),
                tunnel_id: tunnel_id.to_string(),
            });
        }
        let (state, generation, created) = conn
            .ensure_connected(creds, keepalive, known_hosts, logger)
            .await?;
        if created {
            (logger)(&format!(
                "共享连接: 为档案 {profile_id} 建立第 {generation} 代连接"
            ));
        } else {
            (logger)(&format!(
                "共享连接: 复用档案 {profile_id} 现有连接 (代际 {generation})"
            ));
        }
        conn.leases.lock().unwrap().push(LeaseInfo {
            tunnel_id: tunnel_id.to_string(),
            cost,
        });
        Ok(Lease {
            kind: LeaseKind::Pooled {
                conn,
                generation,
                state,
            },
            tunnel_id: tunnel_id.to_string(),
        })
    }

    /// 整连硬断 (模拟网络掉线): 该档案的共享连接立即断开, 成员隧道各自
    /// 走退避重连 (single-flight 重建)。无活连接则无操作。
    pub async fn force_disconnect(&self, profile_id: &str) {
        let conn = self.map.lock().unwrap().get(profile_id).cloned();
        if let Some(conn) = conn {
            let victim = {
                let mut guard = conn.inner.write().await;
                let v = guard.as_ref().map(|cs| cs.state.handle.clone());
                if v.is_some() {
                    *guard = None; // 同 Lease::close: 先摘表再断开, 不持锁跨 await
                }
                v
            };
            if let Some(handle) = victim {
                disconnect_handle(&handle, "forced disconnect").await;
            }
        }
    }

    /// 池快照 (按档案 id 稳定排序)
    pub async fn stats(&self) -> Vec<ConnStats> {
        let conns: Vec<(String, Arc<PooledConn>)> = {
            let map = self.map.lock().unwrap();
            let mut ids: Vec<String> = map.keys().cloned().collect();
            ids.sort();
            ids.into_iter()
                .filter_map(|id| map.get(&id).map(|c| (id, c.clone())))
                .collect()
        };
        let mut out = Vec::new();
        for (profile_id, conn) in conns {
            let guard = conn.inner.read().await;
            let (generation, open_channels) = match guard.as_ref() {
                Some(cs) => (
                    cs.generation,
                    cs.state.open_channels.load(Ordering::Relaxed),
                ),
                None => (0, 0),
            };
            out.push(ConnStats {
                profile_id,
                generation,
                connect_count: conn.connect_count.load(Ordering::Relaxed),
                open_channels,
                leases: conn
                    .leases
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|l| l.tunnel_id.clone())
                    .collect(),
            });
        }
        out
    }
}

impl PooledConn {
    fn new() -> Self {
        Self {
            connecting: AsyncMutex::new(()),
            inner: RwLock::new(None),
            leases: Mutex::new(Vec::new()),
            connect_count: AtomicU64::new(0),
            generation: AtomicU64::new(0),
        }
    }

    /// 活连接快照 (无连接或已断开 → None)。
    /// 锁序: inner → handle (全池一致, 无反向)
    async fn live(&self) -> Option<(SharedState, u64)> {
        let guard = self.inner.read().await;
        if let Some(cs) = guard.as_ref() {
            if !cs.state.handle.lock().await.is_closed() {
                return Some((cs.state.clone(), cs.generation));
            }
        }
        None
    }

    /// 当前活通道数快照 (无连接 → 0; 竞态容忍 —— 预算本就是启发式)
    async fn live_channels(&self) -> usize {
        self.inner
            .read()
            .await
            .as_ref()
            .map(|cs| cs.state.open_channels.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// 确保有活连接: 快路径复用 → 拿 single-flight 锁后复查 (他人可能已
    /// 重建) → 都没有则自己建连。返回 (状态, 代际, 是否新建)。
    async fn ensure_connected(
        &self,
        creds: &SshCreds,
        keepalive: Keepalive,
        known_hosts: &Arc<KnownHosts>,
        logger: &Logger,
    ) -> Result<(SharedState, u64, bool), TunnelError> {
        if let Some((s, g)) = self.live().await {
            return Ok((s, g, false));
        }
        let _guard = self.connecting.lock().await;
        if let Some((s, g)) = self.live().await {
            return Ok((s, g, false));
        }
        let state = shared::connect(
            &creds.host,
            creds.port,
            &creds.username,
            &creds.auth,
            keepalive,
            known_hosts,
            creds.max_sessions as usize,
            logger,
        )
        .await?;
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.connect_count.fetch_add(1, Ordering::SeqCst);
        *self.inner.write().await = Some(ConnState {
            state: state.clone(),
            generation,
        });
        Ok((state, generation, true))
    }
}

/// 解析共享连接开关: 档案层覆盖 > 全局默认 > 引擎默认 (开)
pub fn resolve_share(
    profile: Option<&crate::profiles::ServerProfile>,
    defaults: &crate::store::ProfileDefaults,
) -> bool {
    profile
        .and_then(|p| p.share_connection)
        .or(defaults.share_connection)
        .unwrap_or(DEFAULT_SHARE_CONNECTION)
}

/// 解析 MaxSessions 预算: 仅全局层 (None = sshd 默认 10)
pub fn resolve_max_sessions(defaults: &crate::store::ProfileDefaults) -> u32 {
    defaults
        .max_sessions
        .unwrap_or(shared::DEFAULT_MAX_SESSIONS as u32)
}

impl Default for ConnPool {
    fn default() -> Self {
        Self::new()
    }
}
