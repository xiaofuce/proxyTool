//! 隧道引擎 (L2, 设计 §3.2/§3.7): 注册表 + 每隧道状态机任务
//!
//! `Registry`: `map<id, Entry>` —— 隧道是一等实体, 可多条并存、持久化
//! (store::tunnels.json, 密码永不落盘 —— 启动时只恢复列表, 凭据由调用方
//! 在 start 时注入)。每条运行中的隧道一个状态机任务 (engine/tunnel.rs,
//! actor 式: 停止 = 停止标志 + 关闭会话槽, 任务自行收尾退出)。

mod tunnel;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{watch, Mutex as AsyncMutex};

use crate::backend::BackendPool;
use crate::known_hosts::KnownHosts;
use crate::model::{TunnelKind, TunnelSpec, TunnelState};
use crate::store;
use crate::TunnelEvents;

/// 建连凭据 (每次启动时由调用方注入; 密码/口令仅存内存)
#[derive(Debug, Clone)]
pub struct SshCreds {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: crate::ssh::AuthMethod,
}

/// 会话槽: 任务与注册表共享同一底层槽 (Arc 包裹, 浅克隆即共享)。
/// 任务连接成功时填入、结束时清空; 注册表 stop 时从中取走句柄硬断开
/// (仅 drop Arc 不够: 后台任务持有 clone, 见 tunnel::close_session 注释)。
pub enum SessionSlot {
    Reverse(crate::tunnel::TunnelSlot),
    Direct(Arc<AsyncMutex<Option<Arc<crate::direct::DirectSession>>>>),
}

impl SessionSlot {
    fn new(spec: &TunnelSpec) -> Self {
        match spec.kind {
            TunnelKind::Reverse { .. } => SessionSlot::Reverse(Arc::new(AsyncMutex::new(None))),
            _ => SessionSlot::Direct(Arc::new(AsyncMutex::new(None))),
        }
    }

    /// 浅克隆: 共享同一底层槽
    fn shallow(&self) -> SessionSlot {
        match self {
            SessionSlot::Reverse(s) => SessionSlot::Reverse(s.clone()),
            SessionSlot::Direct(s) => SessionSlot::Direct(s.clone()),
        }
    }

    /// 硬断开当前会话 (无会话则无操作)
    async fn close_current(&self) {
        match self {
            SessionSlot::Reverse(slot) => {
                if let Some(session) = slot.lock().await.take() {
                    crate::tunnel::close_session(&session).await;
                }
            }
            SessionSlot::Direct(slot) => {
                if let Some(session) = slot.lock().await.take() {
                    session.disconnect().await;
                }
            }
        }
    }

    /// 清槽 (任务收尾用; 不触发断开 —— 会话已结束)
    pub(super) async fn clear(&self) {
        match self {
            SessionSlot::Reverse(slot) => *slot.lock().await = None,
            SessionSlot::Direct(slot) => *slot.lock().await = None,
        }
    }
}

/// 注册表内的单条隧道
struct Entry {
    spec: TunnelSpec,
    state_tx: watch::Sender<TunnelState>,
    /// 持有接收端: watch 通道在所有 Receiver drop 后关闭, 之后 send 静默失败
    /// (状态会永远停在初值 —— 曾踩过的坑), 注册表查询也用它快照
    state_rx: watch::Receiver<TunnelState>,
    stop: Arc<AtomicBool>,
    /// 「立即重试」请求 (Backoff 等待期间置位, 状态机跳过剩余等待)
    retry_now: Arc<AtomicBool>,
    slot: SessionSlot,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Entry {
    fn state(&self) -> TunnelState {
        self.state_rx.borrow().clone()
    }

    fn running(&self) -> bool {
        self.task.as_ref().is_some_and(|t| !t.is_finished())
    }
}

/// 建表条目的公共部分 (spec 之外的运行部件)
fn new_entry_parts(spec: &TunnelSpec) -> Entry {
    let (state_tx, state_rx) = watch::channel(TunnelState::Stopped);
    Entry {
        spec: spec.clone(),
        state_tx,
        state_rx,
        stop: Arc::new(AtomicBool::new(false)),
        retry_now: Arc::new(AtomicBool::new(false)),
        slot: SessionSlot::new(spec),
        task: None,
    }
}

/// 隧道注册表: 多条隧道并存, 持久化到 `<dir>/tunnels.json`。
/// `dir = None` 时不持久化 (测试用)。
pub struct Registry {
    dir: Option<PathBuf>,
    /// Arc 包裹: 端口回填回调 (状态机任务触发) 需要跨任务访问条目表
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    backend: Arc<BackendPool>,
    /// 主机密钥记忆库 (TOFU): 全部隧道共享, 持久化时随 dir 落盘
    known_hosts: Arc<KnownHosts>,
}

impl Registry {
    /// 不持久化的注册表 (测试; known_hosts 亦仅内存)
    pub fn new() -> Self {
        Self {
            dir: None,
            entries: Arc::new(Mutex::new(HashMap::new())),
            backend: Arc::new(BackendPool::new()),
            known_hosts: KnownHosts::in_memory(),
        }
    }

    /// 持久化注册表 (GUI: app_data_dir; known_hosts.json 同目录)
    pub fn persistent(dir: PathBuf) -> Self {
        let known_hosts = KnownHosts::load(&dir);
        Self {
            dir: Some(dir),
            entries: Arc::new(Mutex::new(HashMap::new())),
            backend: Arc::new(BackendPool::new()),
            known_hosts,
        }
    }

    /// 主机密钥记忆库 (TOFU 校验 / UI 列表与清除)
    pub fn known_hosts(&self) -> &Arc<KnownHosts> {
        &self.known_hosts
    }

    /// 应用启动: 从 tunnels.json 恢复隧道列表 (只恢复配置, 不自动启动 ——
    /// 凭据不落盘, 由用户启动时输入; P6 密钥认证后可真自动启动)
    pub fn restore(&self) -> Vec<TunnelSpec> {
        let Some(dir) = &self.dir else {
            return Vec::new();
        };
        let specs = store::load_tunnels(dir);
        let mut entries = self.entries.lock().unwrap();
        for spec in specs {
            let entry = new_entry_parts(&spec);
            entries.insert(spec.id.clone(), entry);
        }
        let restored: Vec<TunnelSpec> = entries.values().map(|e| e.spec.clone()).collect();
        restored
    }

    /// 全量快照: (spec, 当前状态)
    pub fn list(&self) -> Vec<(TunnelSpec, TunnelState)> {
        self.entries
            .lock()
            .unwrap()
            .values()
            .map(|e| (e.spec.clone(), e.state()))
            .collect()
    }

    /// 新建隧道 (校验 + 入表 + 落盘)
    pub fn create(&self, spec: TunnelSpec) -> Result<(), String> {
        spec.validate()?;
        {
            let mut entries = self.entries.lock().unwrap();
            if entries.contains_key(&spec.id) {
                return Err(format!("隧道 id 已存在: {}", spec.id));
            }
            entries.insert(spec.id.clone(), new_entry_parts(&spec));
        }
        self.persist();
        Ok(())
    }

    /// 启动隧道 (已在运行则报错)。凭据由调用方注入 (密码不落盘)。
    pub async fn start(
        &self,
        id: &str,
        creds: SshCreds,
        events: Arc<dyn TunnelEvents>,
    ) -> Result<(), String> {
        let (spec, slot, stop, retry_now, state_tx) = {
            let mut entries = self.entries.lock().unwrap();
            let entry = entries
                .get_mut(id)
                .ok_or_else(|| format!("隧道不存在: {id}"))?;
            if entry.running() {
                return Err("隧道已在运行".into());
            }
            entry.stop.store(false, Ordering::SeqCst);
            entry.retry_now.store(false, Ordering::SeqCst);
            (
                entry.spec.clone(),
                entry.slot.shallow(),
                entry.stop.clone(),
                entry.retry_now.clone(),
                entry.state_tx.clone(),
            )
        };
        let on_bound_port = self.bound_port_updater(id, &events);
        let known_hosts = self.known_hosts.clone();
        let task = tokio::spawn(tunnel::run_task(
            spec,
            creds,
            slot,
            stop,
            retry_now,
            state_tx,
            self.backend.clone(),
            known_hosts,
            events,
            on_bound_port,
        ));
        self.entries
            .lock()
            .unwrap()
            .get_mut(id)
            .expect("启动期间条目不会消失")
            .task = Some(task);
        Ok(())
    }

    /// 停止隧道: 置停止意图 + 硬断开当前会话 (任务检测到后收尾退出)
    pub async fn stop(&self, id: &str) -> Result<(), String> {
        let (stop, slot) = {
            let entries = self.entries.lock().unwrap();
            let entry = entries.get(id).ok_or_else(|| format!("隧道不存在: {id}"))?;
            (entry.stop.clone(), entry.slot.shallow())
        };
        stop.store(true, Ordering::SeqCst);
        slot.close_current().await; // 未运行时无会话, 无操作
        Ok(())
    }

    /// 立即重试 (autossh SIGHUP 语义): Backoff 等待期间跳过剩余等待。
    /// 非等待状态置位无害 (下次退避等待前由 start 清零)。
    pub fn retry_now(&self, id: &str) -> Result<(), String> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(id).ok_or_else(|| format!("隧道不存在: {id}"))?;
        entry.retry_now.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// 硬断当前会话但**不**置停止意图——对引擎等价于网络掉线 (触发自动重连)。
    /// (测试模拟断线; 高级用途: 用户手动强制重连)
    pub async fn drop_connection(&self, id: &str) -> Result<(), String> {
        let slot = {
            let entries = self.entries.lock().unwrap();
            let entry = entries.get(id).ok_or_else(|| format!("隧道不存在: {id}"))?;
            entry.slot.shallow()
        };
        slot.close_current().await;
        Ok(())
    }

    /// 端口回填回调 (状态机任务持有): 反向隧道端口 0 动态分配后,
    /// 把实际端口写回 spec + 持久化 + 日志。端口未变 (显式端口) 则只记日志。
    fn bound_port_updater(
        &self,
        id: &str,
        events: &Arc<dyn TunnelEvents>,
    ) -> Arc<dyn Fn(u16) + Send + Sync> {
        let entries = self.entries.clone();
        let dir = self.dir.clone();
        let id = id.to_string();
        let events = events.clone();
        Arc::new(move |port: u16| {
            let changed = {
                let mut map = entries.lock().unwrap();
                match map.get_mut(&id) {
                    Some(entry) => match &mut entry.spec.kind {
                        TunnelKind::Reverse { port: p, .. } if *p != port => {
                            *p = port;
                            true
                        }
                        _ => false,
                    },
                    None => return, // 已删除
                }
            };
            if changed {
                if let Some(dir) = &dir {
                    let specs: Vec<TunnelSpec> = {
                        let map = entries.lock().unwrap();
                        map.values().map(|e| e.spec.clone()).collect()
                    };
                    if let Err(e) = store::save_tunnels(dir, &specs) {
                        eprintln!("[registry] tunnels.json 保存失败: {e}");
                    }
                }
                events.log(
                    &id,
                    "remote",
                    &format!("服务器分配端口 {port}, 已回填并保存"),
                );
            }
        })
    }

    /// 删除隧道 (运行中先停止; 条目移出, 任务自行收尾退出)
    pub async fn delete(&self, id: &str) -> Result<(), String> {
        self.stop(id).await.ok(); // 不存在时下面统一报
        let removed = {
            let mut entries = self.entries.lock().unwrap();
            entries.remove(id)
        };
        removed.ok_or_else(|| format!("隧道不存在: {id}"))?;
        self.persist();
        Ok(())
    }

    /// 落盘全部持久化隧道 (legacy 除外)
    fn persist(&self) {
        let Some(dir) = &self.dir else {
            return;
        };
        let specs: Vec<TunnelSpec> = {
            let entries = self.entries.lock().unwrap();
            entries.values().map(|e| e.spec.clone()).collect()
        };
        if let Err(e) = store::save_tunnels(dir, &specs) {
            // 持久化失败不阻断运行, 但必须可见 (下次启动列表会丢失)
            eprintln!("[registry] tunnels.json 保存失败: {e}");
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
