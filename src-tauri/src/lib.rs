//! GUI 薄桥接层 (Tauri v2)
//!
//! 隧道引擎在 `proxy-tool-core` crate (零 GUI 依赖); 本层职责仅剩:
//! - Tauri 命令 (前端 invoke 入口) + AppState (注册表 + 档案)
//! - `TauriEmitter`: 把引擎事件 (TunnelEvents) 转发为 Tauri 事件给 WebView
//!
//! 命令面 (P5, 旧三页兼容命令已移除):
//! - 隧道: `tunnels_list/tunnel_create/tunnel_start/tunnel_stop/tunnel_retry_now/tunnel_delete`
//! - 预设向导: `presets_list/tunnel_from_preset`
//! - 我的场景 (用户保存的模板): `scenarios_list/scenario_save/scenario_delete/
//!   tunnel_from_scenario`
//! - 命令生成页落盘 (我的命令 + 最近输入, 加密文件): `cmdgen_list/cmdgen_save/
//!   cmdgen_delete/cmdgen_set_last`
//! - 凭据记忆 (密码/口令按档案 id 加密落盘 secrets.enc): `secrets_status/
//!   secret_forget` (记住走 `tunnel_start` 的 remember 参数)
//! - 档案: `list_profiles/save_profile/delete_profile` + 分层默认值
//!   `profile_defaults_get/profile_defaults_save`
//! - 场景动作: `verify_remote_tunnel/deploy_wrapper` (vpn_share 预设附带)
//! - 主机密钥: `known_hosts_list/known_hosts_forget` (TOFU 记忆, 服务器页)
//! - 工具: `probe_local_proxy`
//!
//! 事件: `tunnel-status {id,kind,state,message?}` / `tunnel-log {id,kind,msg}`
//! (前端按 id 键控; kind tag 保留兼容)。

use std::sync::Arc;

use proxy_tool_core::engine::pool::{resolve_max_sessions, resolve_share};
use proxy_tool_core::engine::{Registry, SshCreds};
use proxy_tool_core::model::{TunnelKind, TunnelSpec, TunnelState};
use proxy_tool_core::cmd_recipes::{self, CmdParams, CmdRecipe, CmdRecipeStore};
use proxy_tool_core::scenarios::Scenario;
use proxy_tool_core::secrets::{self, SecretStore};
use proxy_tool_core::{presets, probe, profiles, ssh, store, TunnelEvents};
use serde::Serialize;
use tauri::Manager;
use tauri_plugin_autostart::ManagerExt;
use tokio::sync::Mutex;

/// R9 诊断: 滚动文件日志 + 内存自监控 + 诊断包导出
mod diag;

/// 共享应用状态: 隧道注册表 + 服务器档案 (store v2)。
/// 会话槽/重连循环/内置 SOCKS 生命周期都在 core 引擎里, 这里只持有注册表。
pub struct AppState {
    /// 隧道注册表 (持久化目录 = app_data_dir)
    pub registry: Registry,
    /// 档案存储 (v2: defaults + profiles; save/delete 经此落盘)
    pub profile_store: Mutex<store::ProfileStore>,
    /// 我的场景 (用户保存的隧道模板; scenarios.json)
    pub scenario_store: Mutex<store::ScenarioStore>,
    /// 命令生成页用户数据 (我的命令 + 最近输入; cmd_recipes.enc 加密落盘)
    pub cmd_store: Mutex<CmdRecipeStore>,
    /// 记住的凭据 (档案 id → 密码/口令; secrets.enc 加密落盘, 跨平台统一)
    pub secret_store: Mutex<SecretStore>,
}

/// 隧道状态事件负载: { id, kind, state, message? }
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct StatusPayload {
    id: String,
    kind: String,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// 隧道日志事件负载: { id, kind, msg }
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct LogPayload {
    id: String,
    kind: String,
    msg: String,
}

/// 引擎事件的 GUI 实现: 转发为 Tauri 事件 (前端 listen 的名字不变)。
/// id = 隧道 id (旧页面 = kind tag, 与 kind 同值; 新命令面 = uuid)。
struct TauriEmitter(tauri::AppHandle);

impl TunnelEvents for TauriEmitter {
    fn status(&self, id: &str, kind: &str, state: &str, message: Option<&str>) {
        use tauri::Emitter;
        let _ = self.0.emit(
            "tunnel-status",
            &StatusPayload {
                id: id.into(),
                kind: kind.into(),
                state: state.into(),
                message: message.map(|m| m.into()),
            },
        );
        // R9 双写: 状态迁移落文件日志 (前端面板 500 行环形缓冲, 重启即清零)
        let tag = format!("tunnel:{}", &id[..id.len().min(8)]);
        diag::log(
            if state == "error" { "error" } else { "info" },
            &tag,
            &match message {
                Some(m) => format!("状态 → {state} | {m}"),
                None => format!("状态 → {state}"),
            },
        );
        // 凭据失效即作废记住的密码 (与前端会话缓存逐出同语义):
        // 认证被拒 / 私钥加载失败(口令不对) → 删掉加密落盘的那份,
        // 下次启动重新询问, 不静默复用坏凭据。事件是同步回调 → spawn 处理。
        if state == "error" {
            let msg = message.unwrap_or_default();
            if msg.contains("认证被拒") || msg.contains("加载私钥") {
                let app = self.0.clone();
                let tunnel_id = id.to_string();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<AppState>();
                    let profile_id = state
                        .registry
                        .list()
                        .into_iter()
                        .find(|(s, _)| s.id == tunnel_id)
                        .map(|(s, _)| s.profile_id);
                    let Some(profile_id) = profile_id else { return };
                    let snapshot = {
                        let mut guard = state.secret_store.lock().await;
                        if !guard.contains(&profile_id) {
                            return;
                        }
                        guard.remove(&profile_id);
                        guard.clone()
                    };
                    if let Ok(dir) = data_dir(&app) {
                        if let Err(e) = persist(dir, snapshot, secrets::save_secret_store).await {
                            diag::log("error", "secrets", &format!("保存失败: {e}"));
                        }
                    }
                });
            }
        }
    }
    fn log(&self, id: &str, kind: &str, msg: &str) {
        use tauri::Emitter;
        // R9 双写: 隧道日志同时落文件 (级别判定与前端 logLevel 同语义)
        diag::log(
            diag::level_of(msg),
            &format!("tunnel:{}", &id[..id.len().min(8)]),
            msg,
        );
        let _ = self.0.emit(
            "tunnel-log",
            &LogPayload {
                id: id.into(),
                kind: kind.into(),
                msg: msg.into(),
            },
        );
    }
}

fn emitter(app: &tauri::AppHandle) -> Arc<dyn TunnelEvents> {
    Arc::new(TauriEmitter(app.clone()))
}

/// 应用数据目录 (注册表/档案等持久化文件的根)
fn data_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("获取应用数据目录失败: {e}"))
}

/// R8: 配置落盘统一走 spawn_blocking。调用方先 clone 快照并**丢锁**再调度 ——
/// 避免 async 命令持 tokio Mutex 跨磁盘 IO (阻塞其他命令) 以及运行时线程
/// 做同步文件写。save 为普通函数指针 (各 store 的 save_* 签名一致)。
async fn persist<T: Send + 'static>(
    dir: std::path::PathBuf,
    snapshot: T,
    save: fn(&std::path::Path, &T) -> Result<(), String>,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || save(&dir, &snapshot))
        .await
        .map_err(|e| format!("落盘任务异常: {e}"))?
}

/// 日志便捷函数 (命令层直接发, 不经过引擎; 发到指定隧道的日志流)
fn events_log(app: &tauri::AppHandle, id: &str, msg: &str) {
    TauriEmitter(app.clone()).log(id, "remote", msg);
}

// ---------- 隧道命令面 ----------

/// 隧道 DTO (spec 展开 + 状态), 状态词汇与前端一致
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct TunnelDto {
    #[serde(flatten)]
    spec: TunnelSpec,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

fn state_to_dto(st: &TunnelState) -> (String, Option<String>) {
    match st {
        TunnelState::Stopped => ("disconnected".into(), None),
        TunnelState::Starting => ("connecting".into(), None),
        TunnelState::Running => ("connected".into(), None),
        TunnelState::Backoff { attempt, wait_secs } => (
            "reconnecting".into(),
            Some(format!("第 {attempt} 次重连, {wait_secs}s 后重试")),
        ),
        TunnelState::Failed { message, .. } => ("error".into(), Some(message.clone())),
    }
}

/// 命令: 隧道列表 (spec + 状态)
#[tauri::command]
async fn tunnels_list(state: tauri::State<'_, AppState>) -> Result<Vec<TunnelDto>, String> {
    Ok(state
        .registry
        .list()
        .into_iter()
        .map(|(spec, st)| {
            let (state, message) = state_to_dto(&st);
            TunnelDto {
                spec,
                state,
                message,
            }
        })
        .collect())
}

/// 命令: 新建隧道 (校验 + 持久化), 返回最新列表
#[tauri::command]
async fn tunnel_create(
    state: tauri::State<'_, AppState>,
    spec: TunnelSpec,
) -> Result<Vec<TunnelDto>, String> {
    state.registry.create(spec)?;
    tunnels_list(state).await
}

/// 档案 + 会话密码 → 认证方式。
/// 密钥档案: 密码框充当密钥口令 (未加密私钥可留空);
/// 密码档案: 密码必填 (本次注入或已记住的加密落盘凭据)。
fn resolve_auth(
    profile: &profiles::ServerProfile,
    password: Option<String>,
) -> Result<ssh::AuthMethod, String> {
    let nonempty = password.filter(|p| !p.is_empty());
    match &profile.identity_file {
        Some(path) => Ok(ssh::AuthMethod::KeyFile {
            path: path.into(),
            passphrase: nonempty,
        }),
        None => Ok(ssh::AuthMethod::Password(
            nonempty.ok_or("该服务器使用密码认证, 请输入密码 (或勾选记住密码)")?,
        )),
    }
}

/// 从凭据记忆取回已记住的密码/口令 (档案 id 键控; 密钥档案记住空口令 = None)
async fn stored_secret(state: &AppState, profile_id: &str) -> Option<String> {
    state
        .secret_store
        .lock()
        .await
        .get(profile_id)
        .map(|s| s.to_string())
}

/// 按档案启动隧道 (tunnel_start 命令与开机自启动共用):
/// 查关联档案 → 解析认证方式 (本次注入的密码优先, 缺省用已记住的加密凭据) → 启动。
async fn start_by_profile(
    app: &tauri::AppHandle,
    id: &str,
    password: Option<String>,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let spec = state
        .registry
        .list()
        .into_iter()
        .find(|(s, _)| s.id == id)
        .map(|(s, _)| s)
        .ok_or_else(|| format!("隧道不存在: {id}"))?;
    let (profile, defaults) = {
        let store_guard = state.profile_store.lock().await;
        let profile = store_guard
            .profiles
            .iter()
            .find(|p| p.id == spec.profile_id)
            .cloned()
            .ok_or_else(|| format!("隧道关联的档案不存在 (id: {})", spec.profile_id))?;
        (profile, store_guard.defaults.clone())
    };
    // 本次输入优先; 未输入 → 已记住的加密凭据 (密码档案免输, 开机自启全覆盖)
    let password = match password.filter(|p| !p.is_empty()) {
        Some(p) => Some(p),
        None => stored_secret(&state, &spec.profile_id).await,
    };
    let auth = resolve_auth(&profile, password)?;
    // 共享连接: 档案层覆盖 > 全局默认值 > 引擎默认 (开)
    let (share, max_sessions) = (
        resolve_share(Some(&profile), &defaults),
        resolve_max_sessions(&defaults),
    );
    let creds = SshCreds {
        host: profile.host,
        port: profile.port,
        username: profile.username,
        auth,
        share,
        max_sessions,
    };
    state.registry.start(id, creds, emitter(app)).await
}

/// 命令: 启动隧道 (按 spec.profile_id 查档案; 密码/口令本次注入,
/// remember=Some(true) 且认证字段非空 → 记住 (加密落盘); Some(false) → 清除记住)
#[tauri::command]
async fn tunnel_start(
    app: tauri::AppHandle,
    id: String,
    password: Option<String>,
    remember: Option<bool>,
) -> Result<(), String> {
    if let (Some(remember), Some(pw)) = (remember, password.as_deref().filter(|p| !p.is_empty())) {
        let spec_profile = {
            let state = app.state::<AppState>();
            state
                .registry
                .list()
                .into_iter()
                .find(|(s, _)| s.id == id)
                .map(|(s, _)| s.profile_id)
        };
        if let Some(profile_id) = spec_profile {
            let state = app.state::<AppState>();
            let snapshot = {
                let mut guard = state.secret_store.lock().await;
                if remember {
                    guard.set(&profile_id, pw);
                } else {
                    guard.remove(&profile_id);
                }
                guard.clone()
            };
            if let Err(e) = persist(data_dir(&app)?, snapshot, secrets::save_secret_store).await {
                diag::log("error", "secrets", &format!("保存失败: {e}"));
            }
        }
    }
    start_by_profile(&app, &id, password).await
}

/// 命令: 停止隧道
#[tauri::command]
async fn tunnel_stop(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    state.registry.stop(&id).await
}

/// 命令: 立即重试 (Backoff 等待期间跳过剩余等待, autossh SIGHUP 语义)
#[tauri::command]
async fn tunnel_retry_now(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    state.registry.retry_now(&id)
}

/// 命令: 删除隧道 (运行中先停止), 返回最新列表
#[tauri::command]
async fn tunnel_delete(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<Vec<TunnelDto>, String> {
    state.registry.delete(&id).await?;
    tunnels_list(state).await
}

/// 命令: 更新隧道「开机自启」开关 (enabled 字段), 返回最新列表
#[tauri::command]
async fn tunnel_set_enabled(
    state: tauri::State<'_, AppState>,
    id: String,
    enabled: bool,
) -> Result<Vec<TunnelDto>, String> {
    state.registry.set_enabled(&id, enabled)?;
    tunnels_list(state).await
}

// ---------- 开机自启 (P6; tauri-plugin-autostart, Windows 写 HKCU Run 键) ----------

/// 命令: 读开机自启状态
#[tauri::command]
fn autostart_get(app: tauri::AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

/// 命令: 设置/取消开机自启 (注册 `--autostart` 参数拉起)
/// R8: async fn —— 自动移到 tokio worker, 不占主线程 (Windows 写 HKCU Run 键)
#[tauri::command]
async fn autostart_set(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
    let autolaunch = app.autolaunch();
    if enabled {
        autolaunch.enable()
    } else {
        autolaunch.disable()
    }
    .map_err(|e| e.to_string())
}

// ---------- 场景预设 (P5 新 UI 向导用) ----------

/// 预设 DTO (UI 向导卡片)
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PresetDto {
    id: String,
    name: String,
    description: String,
    /// 场景专属动作 id (vpn_share: verify_internet / deploy_wrapper)
    actions: Vec<String>,
}

/// 命令: 场景预设列表 (选预设卡片 → 表单)
#[tauri::command]
fn presets_list() -> Vec<PresetDto> {
    presets::list()
        .into_iter()
        .map(|p| PresetDto {
            id: p.id.into(),
            name: p.name.into(),
            description: p.description.into(),
            actions: p.actions.iter().map(|a| a.to_string()).collect(),
        })
        .collect()
}

/// 命令: 按预设生成隧道模板 (表单预填; 重连策略继承档案层默认值)
#[tauri::command]
async fn tunnel_from_preset(
    state: tauri::State<'_, AppState>,
    preset_id: String,
    name: String,
    profile_id: String,
) -> Result<TunnelSpec, String> {
    let mut spec = presets::template(&preset_id, &name, &profile_id)?;
    apply_profile_defaults(&state, &mut spec).await;
    Ok(spec)
}

/// 分层默认值: 档案层的重连策略覆盖模板内置默认 (表单仍可再改)。
/// 预设/我的场景两条模板生成路径共用。
async fn apply_profile_defaults(state: &tauri::State<'_, AppState>, spec: &mut TunnelSpec) {
    if let Some(reconnect) = state.profile_store.lock().await.defaults.reconnect.clone() {
        spec.policy = reconnect;
    }
}

// ---------- 我的场景 (用户保存的隧道模板; Termius 式向导「我的场景」卡片) ----------

/// 命令: 我的场景列表
#[tauri::command]
async fn scenarios_list(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<Scenario>, String> {
    Ok(state.scenario_store.lock().await.scenarios.clone())
}

/// 命令: 保存/更新场景 (id 相同则覆盖; 空描述自动生成), 返回最新列表
#[tauri::command]
async fn scenario_save(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    mut scenario: Scenario,
) -> Result<Vec<Scenario>, String> {
    if scenario.name.trim().is_empty() {
        return Err("场景名称不能为空".into());
    }
    if scenario.id.trim().is_empty() {
        scenario.id = TunnelSpec::new_id();
    }
    if scenario.description.trim().is_empty() {
        scenario.description = scenario.describe();
    }
    let (snapshot, result) = {
        let mut store_guard = state.scenario_store.lock().await;
        if let Some(s) = store_guard.scenarios.iter_mut().find(|s| s.id == scenario.id) {
            *s = scenario;
        } else {
            store_guard.scenarios.push(scenario);
        }
        (store_guard.clone(), store_guard.scenarios.clone())
    };
    persist(data_dir(&app)?, snapshot, store::save_scenarios).await?;
    Ok(result)
}

/// 命令: 删除场景, 返回最新列表
#[tauri::command]
async fn scenario_delete(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<Vec<Scenario>, String> {
    let (snapshot, result) = {
        let mut store_guard = state.scenario_store.lock().await;
        store_guard.scenarios.retain(|s| s.id != id);
        (store_guard.clone(), store_guard.scenarios.clone())
    };
    persist(data_dir(&app)?, snapshot, store::save_scenarios).await?;
    Ok(result)
}

// ---------- 命令生成页落盘 (我的命令 + 最近输入; AES-GCM 加密, 无凭据) ----------

/// 命令: 我的命令 + 最近输入 (页面初始化恢复用)
#[tauri::command]
async fn cmdgen_list(state: tauri::State<'_, AppState>) -> Result<CmdRecipeStore, String> {
    Ok(state.cmd_store.lock().await.clone())
}

/// 命令: 保存/更新一条我的命令 (id 相同覆盖, 空 id 新建), 返回最新列表
#[tauri::command]
async fn cmdgen_save(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    mut recipe: CmdRecipe,
) -> Result<Vec<CmdRecipe>, String> {
    if recipe.name.trim().is_empty() {
        return Err("命令名称不能为空".into());
    }
    if recipe.id.trim().is_empty() {
        recipe.id = TunnelSpec::new_id();
    }
    let (snapshot, result) = {
        let mut store_guard = state.cmd_store.lock().await;
        if let Some(r) = store_guard.recipes.iter_mut().find(|r| r.id == recipe.id) {
            *r = recipe;
        } else {
            store_guard.recipes.push(recipe);
        }
        (store_guard.clone(), store_guard.recipes.clone())
    };
    persist(data_dir(&app)?, snapshot, cmd_recipes::save_cmd_store).await?;
    Ok(result)
}

/// 命令: 删除一条我的命令, 返回最新列表
#[tauri::command]
async fn cmdgen_delete(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<Vec<CmdRecipe>, String> {
    let (snapshot, result) = {
        let mut store_guard = state.cmd_store.lock().await;
        store_guard.recipes.retain(|r| r.id != id);
        (store_guard.clone(), store_guard.recipes.clone())
    };
    persist(data_dir(&app)?, snapshot, cmd_recipes::save_cmd_store).await?;
    Ok(result)
}

/// 命令: 记住最近一次输入 (前端防抖调用; 打开页面时恢复)
#[tauri::command]
async fn cmdgen_set_last(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    params: CmdParams,
) -> Result<(), String> {
    let snapshot = {
        let mut store_guard = state.cmd_store.lock().await;
        store_guard.last = Some(params);
        store_guard.clone()
    };
    persist(data_dir(&app)?, snapshot, cmd_recipes::save_cmd_store).await
}

/// 命令: 按我的场景生成隧道模板 (克隆 kind/backend; 重连策略继承档案层默认值)
#[tauri::command]
async fn tunnel_from_scenario(
    state: tauri::State<'_, AppState>,
    scenario_id: String,
    name: String,
    profile_id: String,
) -> Result<TunnelSpec, String> {
    let scenario = state
        .scenario_store
        .lock()
        .await
        .scenarios
        .iter()
        .find(|s| s.id == scenario_id)
        .cloned()
        .ok_or_else(|| format!("场景不存在: {scenario_id}"))?;
    let mut spec = TunnelSpec {
        id: TunnelSpec::new_id(),
        name,
        enabled: true,
        profile_id,
        kind: scenario.kind,
        backend: scenario.backend,
        policy: Default::default(),
    };
    spec.validate()?;
    apply_profile_defaults(&state, &mut spec).await;
    Ok(spec)
}

// ---------- 场景动作 (vpn_share 预设附带; 反向隧道需已连接) ----------

/// 反向隧道 → (档案, 服务器监听端口[含 -R 0 回填值])。
/// 验证/部署命令据此免传全套连接参数 (凭据除外, 不落盘)。
async fn resolve_reverse(
    state: &tauri::State<'_, AppState>,
    id: &str,
) -> Result<(profiles::ServerProfile, u32), String> {
    let spec = state
        .registry
        .list()
        .into_iter()
        .find(|(s, _)| s.id == id)
        .map(|(s, _)| s)
        .ok_or_else(|| format!("隧道不存在: {id}"))?;
    let TunnelKind::Reverse { port, .. } = spec.kind else {
        return Err("仅反向隧道支持此操作".into());
    };
    let profile = {
        let store_guard = state.profile_store.lock().await;
        store_guard
            .profiles
            .iter()
            .find(|p| p.id == spec.profile_id)
            .cloned()
            .ok_or_else(|| format!("隧道关联的档案不存在 (id: {})", spec.profile_id))?
    };
    Ok((profile, port as u32))
}

/// 探测本地代理端口的结果
#[derive(Serialize, Clone)]
struct ProbeResultPayload {
    port: u16,
    socks5_confirmed: bool,
}

/// 命令: 探测本机可用的 SOCKS 代理端口
#[tauri::command]
async fn probe_local_proxy() -> Result<Vec<ProbeResultPayload>, String> {
    let results = probe::probe_local_proxy().await;
    Ok(results
        .into_iter()
        .map(|r| ProbeResultPayload {
            port: r.port,
            socks5_confirmed: r.socks5_confirmed,
        })
        .collect())
}

/// 命令: 验证反向隧道端到端可用性 (需已连接)。
/// 在服务器上分别测试 直连 与 经隧道 (socks5-hostname 127.0.0.1:<端口>) 访问 google。
#[tauri::command]
async fn verify_remote_tunnel(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
    password: Option<String>,
) -> Result<String, String> {
    let (profile, remote_port) = resolve_reverse(&state, &id).await?;
    let password = match password.filter(|p| !p.is_empty()) {
        Some(p) => Some(p),
        None => stored_secret(&state, &profile.id).await,
    };
    let auth = resolve_auth(&profile, password)?;
    let cmd = format!(
        "echo '--- 直连(不经隧道) ---'; curl -s -o /dev/null -m 8 -w '直连: http_code=%{{http_code}} time=%{{time_total}}s\\n' https://www.google.com || echo '直连失败(预期: 服务器网络无法访问被墙站点)'; echo '--- 经隧道 ---'; curl -s -o /dev/null -m 10 -w '隧道: http_code=%{{http_code}} time=%{{time_total}}s\\n' --socks5-hostname 127.0.0.1:{remote_port} https://www.google.com || echo '隧道访问失败'"
    );
    let out = ssh::remote_exec(
        &profile.host,
        profile.port,
        &profile.username,
        &auth,
        &cmd,
        std::time::Duration::from_secs(45),
        state.registry.known_hosts(),
    )
    .await?;
    events_log(&app, &id, &format!("验证隧道:\n{out}"));
    Ok(out)
}

/// 命令: 部署 proxy wrapper 到服务器 (服务器可用 `proxy <命令>` 走隧道出网)。
/// 优先写 /usr/local/bin (需 root), 无权限时写 ~/.local/bin。
#[tauri::command]
async fn deploy_wrapper(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
    password: Option<String>,
) -> Result<String, String> {
    let (profile, remote_port) = resolve_reverse(&state, &id).await?;
    let password = match password.filter(|p| !p.is_empty()) {
        Some(p) => Some(p),
        None => stored_secret(&state, &profile.id).await,
    };
    let auth = resolve_auth(&profile, password)?;
    let cmd = format!(
        r#"set -e
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/proxy" <<'PROXYEOF'
#!/bin/bash
ALL_PROXY=socks5h://127.0.0.1:{remote_port} HTTP_PROXY=http://127.0.0.1:{remote_port} HTTPS_PROXY=http://127.0.0.1:{remote_port} exec "$@"
PROXYEOF
chmod +x "$HOME/.local/bin/proxy"
echo "已部署: $HOME/.local/bin/proxy"
if [ -w /usr/local/bin ]; then
  cp "$HOME/.local/bin/proxy" /usr/local/bin/proxy
  chmod +x /usr/local/bin/proxy
  echo "已部署: /usr/local/bin/proxy (全局可用)"
  echo "用法示例: proxy curl google.com"
else
  echo "无权限写 /usr/local/bin (需 root), 仅用户级可用"
  echo "用法示例: $HOME/.local/bin/proxy curl google.com"
  echo "提示: 若 PATH 不含 ~/.local/bin, 可把它加入 .bashrc"
fi"#,
        remote_port = remote_port
    );
    let out = ssh::remote_exec(
        &profile.host,
        profile.port,
        &profile.username,
        &auth,
        &cmd,
        std::time::Duration::from_secs(30),
        state.registry.known_hosts(),
    )
    .await?;
    events_log(&app, &id, &format!("部署 proxy wrapper:\n{out}"));
    Ok(out)
}

// ---------- 主机密钥记忆 (TOFU; P6) ----------

/// 已记住指纹的 DTO (服务器页展示)
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct KnownHostDto {
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
}

/// 命令: 已记住的服务器指纹列表
#[tauri::command]
fn known_hosts_list(state: tauri::State<'_, AppState>) -> Vec<KnownHostDto> {
    state
        .registry
        .known_hosts()
        .list()
        .into_iter()
        .map(|(host, port, entry)| KnownHostDto {
            host,
            port,
            algorithm: entry.algorithm,
            fingerprint: entry.fingerprint,
        })
        .collect()
}

/// 命令: 清除一条指纹记忆 (服务器重装/换机后, 用户确认变更时;
/// 清除后下次连接重新 TOFU 记住新指纹)
#[tauri::command]
async fn known_hosts_forget(
    state: tauri::State<'_, AppState>,
    host: String,
    port: u16,
) -> Result<Vec<KnownHostDto>, String> {
    state
        .registry
        .known_hosts()
        .forget(&host, port)
        .then_some(())
        .ok_or_else(|| format!("没有 {host}:{port} 的指纹记录"))?;
    Ok(known_hosts_list(state))
}

// ---------- 档案命令 (v2 存储) ----------

/// 命令: 列出服务器配置档案
#[tauri::command]
async fn list_profiles(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<profiles::ServerProfile>, String> {
    Ok(state.profile_store.lock().await.profiles.clone())
}

/// 命令: 保存/更新服务器配置档案 (id 相同则覆盖), 返回最新列表
#[tauri::command]
async fn save_profile(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    profile: profiles::ServerProfile,
) -> Result<Vec<profiles::ServerProfile>, String> {
    let (snapshot, result) = {
        let mut store_guard = state.profile_store.lock().await;
        if let Some(p) = store_guard.profiles.iter_mut().find(|p| p.id == profile.id) {
            *p = profile;
        } else {
            store_guard.profiles.push(profile);
        }
        (store_guard.clone(), store_guard.profiles.clone())
    };
    persist(data_dir(&app)?, snapshot, store::save_profiles).await?;
    Ok(result)
}

/// 命令: 删除服务器配置档案, 返回最新列表
#[tauri::command]
async fn delete_profile(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<Vec<profiles::ServerProfile>, String> {
    // 连带清除记住的凭据 (加密落盘那份; 档案没了凭据也不应残留)
    let secrets_snapshot = {
        let mut secrets_guard = state.secret_store.lock().await;
        if !secrets_guard.contains(&id) {
            None
        } else {
            secrets_guard.remove(&id);
            Some(secrets_guard.clone())
        }
    };
    if let Some(snapshot) = secrets_snapshot {
        if let Err(e) = persist(data_dir(&app)?, snapshot, secrets::save_secret_store).await {
            diag::log("error", "secrets", &format!("保存失败: {e}"));
        }
    }
    // 连带停止并删除关联隧道 (运行中的先停, 否则引擎任务残留占端口,
    // 且档案删除后隧道在 UI 中不可见无法再删 → 孤儿)
    for (spec, _) in state.registry.list() {
        if spec.profile_id == id {
            if let Err(e) = state.registry.delete(&spec.id).await {
                diag::log(
                    "error",
                    "delete_profile",
                    &format!("停止/删除隧道 {} 失败: {e}", spec.id),
                );
            }
        }
    }
    let (snapshot, result) = {
        let mut store_guard = state.profile_store.lock().await;
        store_guard.profiles.retain(|p| p.id != id);
        (store_guard.clone(), store_guard.profiles.clone())
    };
    persist(data_dir(&app)?, snapshot, store::save_profiles).await?;
    Ok(result)
}

// ---------- 凭据记忆 (密码/口令加密落盘, R6) ----------

/// 命令: 已记住凭据的档案 id 列表 (详情页显示状态用; 不回传密码本身)
#[tauri::command]
async fn secrets_status(state: tauri::State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.secret_store.lock().await.secrets.keys().cloned().collect())
}

/// 命令: 清除某档案记住的凭据 (详情页「清除密码」)
#[tauri::command]
async fn secret_forget(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    profile_id: String,
) -> Result<(), String> {
    let snapshot = {
        let mut guard = state.secret_store.lock().await;
        guard.remove(&profile_id);
        guard.clone()
    };
    persist(data_dir(&app)?, snapshot, secrets::save_secret_store).await
}

/// 命令: 读取分层默认值 (档案层, 所有档案共享)
#[tauri::command]
async fn profile_defaults_get(
    state: tauri::State<'_, AppState>,
) -> Result<store::ProfileDefaults, String> {
    Ok(state.profile_store.lock().await.defaults.clone())
}

/// 命令: 保存分层默认值 (档案层); 新建隧道 (预设模板) 生成时继承
#[tauri::command]
async fn profile_defaults_save(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    defaults: store::ProfileDefaults,
) -> Result<store::ProfileDefaults, String> {
    let snapshot = {
        let mut store_guard = state.profile_store.lock().await;
        store_guard.defaults = defaults;
        store_guard.clone()
    };
    let saved_defaults = snapshot.defaults.clone();
    persist(data_dir(&app)?, snapshot, store::save_profiles).await?;
    Ok(saved_defaults)
}

// ---------- 托盘 + 开机自启 (P6) ----------

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn toggle_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
        } else {
            show_main_window(app);
        }
    }
}

/// 建托盘: 菜单 (显示/退出) + 左键切换窗口显隐。
/// 关闭按钮 = 收进托盘 (隧道常驻), 真正退出走托盘菜单「退出」。
// ---------- 诊断 (R9: 文件日志 / 诊断包) ----------

/// 命令: 打开日志目录 (explorer/finder)
#[tauri::command]
async fn open_logs_dir(app: tauri::AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?.join("logs");
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建日志目录失败: {e}"))?;
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(dir.to_string_lossy().as_ref(), None::<&str>)
        .map_err(|e| format!("打开目录失败: {e}"))
}

/// 命令: 导出诊断包 (运行时摘要 + 全部轮转日志) 到 logs 目录并揭示。
/// 摘要只含隧道名/形态/状态与连接池计数 —— 不含主机地址与凭据 (红线)。
#[tauri::command]
async fn diag_export(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let logs = data_dir(&app)?.join("logs");
    std::fs::create_dir_all(&logs).map_err(|e| format!("创建日志目录失败: {e}"))?;

    let mut summary = String::from("==== 运行时摘要 ====\n");
    for (spec, st) in state.registry.list() {
        let (state_name, msg) = state_to_dto(&st);
        summary.push_str(&format!(
            "- 隧道「{}」[{}] 状态: {}{}\n",
            spec.name,
            spec.kind.tag(),
            state_name,
            msg.map(|m| format!(" | {m}")).unwrap_or_default()
        ));
    }
    for cs in state.registry.conn_stats().await {
        summary.push_str(&format!(
            "- 共享连接 [{}] 代际 {} 建连 {} 次, 活跃通道 {}, 租约 {}\n",
            &cs.profile_id[..cs.profile_id.len().min(8)],
            cs.generation,
            cs.connect_count,
            cs.open_channels,
            cs.leases.len()
        ));
    }
    if let Some(rss) = diag::rss_bytes() {
        summary.push_str(&format!("当前内存 RSS: {}\n", diag::fmt_mb(rss)));
    }

    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let dest = logs.join(format!("diag-{ts}.txt"));
    diag::export_bundle(&logs, &dest, &summary).map_err(|e| format!("导出失败: {e}"))?;
    // 磁盘占用上限: 诊断包只留最近 3 份 (单个含全部轮转日志, 不清理会累积)
    diag::prune_bundles(&logs, 3);

    use tauri_plugin_opener::OpenerExt;
    let _ = app.opener().reveal_item_in_dir(&dest);
    Ok(dest.to_string_lossy().into_owned())
}

fn setup_tray(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().ok_or("缺少应用图标")?.clone())
        .tooltip("proxyTool — SSH 隧道")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                toggle_main_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // app_data_dir 需要已初始化的 app handle, 故状态在 setup 里构建 + manage
            // (setup 在 WebView 加载与任何 invoke 之前运行, 命令拿到的 State 必已就绪)
            let handle = app.handle();
            let dir = data_dir(handle).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            std::fs::create_dir_all(&dir)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

            // R9 诊断: 文件日志 + panic hook。
            // release GUI 进程被 windows_subsystem="windows" 吞掉 stdout/stderr,
            // 不落文件的话 eprintln/panic 全部静默丢失。
            diag::init(&dir);
            diag::install_panic_hook();

            // 档案: v1 (裸数组) 首启动自动迁移到 v2, 旧档案无损带入
            let profile_store = store::load_profiles(&dir);
            if store::migrate_needed(&dir) {
                store::save_profiles(&dir, &profile_store)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                diag::log("info", "setup", "profiles.json 已迁移到 v2");
            }

            // 隧道列表: 恢复配置 (凭据不落盘, 不自动启动)
            let registry = Registry::persistent(dir.clone());
            // tunnels.json 落盘失败转发到文件日志 (原 eprintln 在 release 不可见)
            registry.set_diag_logger(std::sync::Arc::new(|msg: &str| {
                diag::log("error", "registry", msg);
            }));
            let restored = registry.restore();
            if !restored.is_empty() {
                diag::log(
                    "info",
                    "setup",
                    &format!("已恢复 {} 条隧道配置", restored.len()),
                );
            }

            // R9 内存自监控: 每 5 分钟 RSS 落日志 (泄漏趋势一条线看穿)
            tauri::async_runtime::spawn(async {
                let mut tick =
                    tokio::time::interval(std::time::Duration::from_secs(300));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                tick.tick().await; // interval 首拍立即到, 跳过 (启动 RSS 已记)
                loop {
                    tick.tick().await;
                    if let Some(rss) = diag::rss_bytes() {
                        diag::log("info", "mem", &format!("内存 RSS: {}", diag::fmt_mb(rss)));
                    }
                }
            });

            app.manage(AppState {
                registry,
                profile_store: Mutex::new(profile_store),
                scenario_store: Mutex::new(store::load_scenarios(&dir)),
                cmd_store: Mutex::new(cmd_recipes::load_cmd_store(&dir)),
                secret_store: Mutex::new(secrets::load_secret_store(&dir)),
            });

            setup_tray(handle)?;

            // 开机自启拉起 (--autostart): 隐藏窗口后台启动 enabled 隧道。
            // 凭据来源 = 已记住的加密落盘密码/口令 (start_by_profile 内兜底);
            // 没记住的 (首次输密码/加密私钥未记住口令) → 各自日志说明后跳过。
            if std::env::args().any(|a| a == "--autostart") {
                if let Some(w) = handle.get_webview_window("main") {
                    let _ = w.hide();
                }
                let app = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<AppState>();
                    let enabled_ids: Vec<String> = state
                        .registry
                        .list()
                        .into_iter()
                        .filter(|(s, _)| s.enabled)
                        .map(|(s, _)| s.id)
                        .collect();
                    diag::log(
                        "info",
                        "setup",
                        &format!("开机自启: {} 条 enabled 隧道", enabled_ids.len()),
                    );
                    for id in enabled_ids {
                        if let Err(e) = start_by_profile(&app, &id, None).await {
                            events_log(&app, &id, &format!("开机自启失败: {e}"));
                        }
                    }
                });
            }
            Ok(())
        })
        // 关闭按钮 = 收进托盘 (隧道常驻; 退出走托盘菜单)
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                // R8 兜底: dispatcher.hide() 走 user-message 管线, 在 CloseRequested
                // 处理期间部分路径不生效 (观测: hide ok 但窗口仍可见)。直接同步
                // ShowWindow(SW_HIDE) 绕开消息管线, 与托盘「隐藏窗口」等效。
                #[cfg(target_os = "windows")]
                if let Ok(hwnd) = window.hwnd() {
                    unsafe {
                        use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
                        ShowWindow(hwnd.0, SW_HIDE);
                    }
                }
            }
        })
        .plugin(tauri_plugin_opener::init())
        // 自启注册带 --autostart 参数: 开机拉起时据此隐藏窗口 + 后台启动隧道
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        .invoke_handler(tauri::generate_handler![
            probe_local_proxy,
            verify_remote_tunnel,
            deploy_wrapper,
            tunnels_list,
            tunnel_create,
            tunnel_start,
            tunnel_stop,
            tunnel_retry_now,
            tunnel_delete,
            tunnel_set_enabled,
            presets_list,
            tunnel_from_preset,
            scenarios_list,
            scenario_save,
            scenario_delete,
            tunnel_from_scenario,
            cmdgen_list,
            cmdgen_save,
            cmdgen_delete,
            cmdgen_set_last,
            secrets_status,
            secret_forget,
            list_profiles,
            save_profile,
            delete_profile,
            profile_defaults_get,
            profile_defaults_save,
            known_hosts_list,
            known_hosts_forget,
            autostart_get,
            autostart_set,
            open_logs_dir,
            diag_export,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
