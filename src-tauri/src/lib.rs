//! GUI 薄桥接层 (Tauri v2)
//!
//! 隧道引擎在 `proxy-tool-core` crate (零 GUI 依赖); 本层职责仅剩:
//! - Tauri 命令 (前端 invoke 入口) + AppState (注册表 + 档案)
//! - `TauriEmitter`: 把引擎事件 (TunnelEvents) 转发为 Tauri 事件给 WebView
//!
//! 命令面 (P5, 旧三页兼容命令已移除):
//! - 隧道: `tunnels_list/tunnel_create/tunnel_start/tunnel_stop/tunnel_retry_now/tunnel_delete`
//! - 预设向导: `presets_list/tunnel_from_preset`
//! - 档案: `list_profiles/save_profile/delete_profile` + 分层默认值
//!   `profile_defaults_get/profile_defaults_save`
//! - 场景动作: `verify_remote_tunnel/deploy_wrapper` (vpn_share 预设附带)
//! - 主机密钥: `known_hosts_list/known_hosts_forget` (TOFU 记忆, 服务器页)
//! - 工具: `probe_local_proxy`
//!
//! 事件: `tunnel-status {id,kind,state,message?}` / `tunnel-log {id,kind,msg}`
//! (前端按 id 键控; kind tag 保留兼容)。

use std::sync::Arc;

use proxy_tool_core::engine::{Registry, SshCreds};
use proxy_tool_core::model::{TunnelKind, TunnelSpec, TunnelState};
use proxy_tool_core::{presets, probe, profiles, ssh, store, TunnelEvents};
use serde::Serialize;
use tauri::Manager;
use tauri_plugin_autostart::ManagerExt;
use tokio::sync::Mutex;

/// 共享应用状态: 隧道注册表 + 服务器档案 (store v2)。
/// 会话槽/重连循环/内置 SOCKS 生命周期都在 core 引擎里, 这里只持有注册表。
pub struct AppState {
    /// 隧道注册表 (持久化目录 = app_data_dir)
    pub registry: Registry,
    /// 档案存储 (v2: defaults + profiles; save/delete 经此落盘)
    pub profile_store: Mutex<store::ProfileStore>,
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
    }
    fn log(&self, id: &str, kind: &str, msg: &str) {
        use tauri::Emitter;
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
/// 密码档案: 密码必填 (仅会话内存, 不落盘)。
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
            nonempty.ok_or("该服务器使用密码认证, 请输入密码")?,
        )),
    }
}

/// 按档案启动隧道 (tunnel_start 命令与开机自启动共用):
/// 查关联档案 → 解析认证方式 (密码/口令本次注入) → 注入凭据启动。
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
    let profile = {
        let store_guard = state.profile_store.lock().await;
        store_guard
            .profiles
            .iter()
            .find(|p| p.id == spec.profile_id)
            .cloned()
            .ok_or_else(|| format!("隧道关联的档案不存在 (id: {})", spec.profile_id))?
    };
    let auth = resolve_auth(&profile, password)?;
    let creds = SshCreds {
        host: profile.host,
        port: profile.port,
        username: profile.username,
        auth,
    };
    state.registry.start(&id, creds, emitter(app)).await
}

/// 命令: 启动隧道 (按 spec.profile_id 查档案; 密码/口令本次注入, 不落盘)
#[tauri::command]
async fn tunnel_start(
    app: tauri::AppHandle,
    id: String,
    password: Option<String>,
) -> Result<(), String> {
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
#[tauri::command]
fn autostart_set(app: tauri::AppHandle, enabled: bool) -> Result<(), String> {
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
    // 分层默认值: 档案层的重连策略覆盖模板内置默认 (向导表单仍可再改)
    if let Some(reconnect) = state.profile_store.lock().await.defaults.reconnect.clone() {
        spec.policy = reconnect;
    }
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
        .find(|(s, _)| &s.id == id)
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
    let mut store_guard = state.profile_store.lock().await;
    if let Some(p) = store_guard.profiles.iter_mut().find(|p| p.id == profile.id) {
        *p = profile;
    } else {
        store_guard.profiles.push(profile);
    }
    store::save_profiles(&data_dir(&app)?, &store_guard)?;
    Ok(store_guard.profiles.clone())
}

/// 命令: 删除服务器配置档案, 返回最新列表
#[tauri::command]
async fn delete_profile(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<Vec<profiles::ServerProfile>, String> {
    let mut store_guard = state.profile_store.lock().await;
    store_guard.profiles.retain(|p| p.id != id);
    store::save_profiles(&data_dir(&app)?, &store_guard)?;
    Ok(store_guard.profiles.clone())
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
    let mut store_guard = state.profile_store.lock().await;
    store_guard.defaults = defaults;
    store::save_profiles(&data_dir(&app)?, &store_guard)?;
    Ok(store_guard.defaults.clone())
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

            // 档案: v1 (裸数组) 首启动自动迁移到 v2, 旧档案无损带入
            let profile_store = store::load_profiles(&dir);
            if store::migrate_needed(&dir) {
                store::save_profiles(&dir, &profile_store)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                println!("[setup] profiles.json 已迁移到 v2");
            }

            // 隧道列表: 恢复配置 (凭据不落盘, 不自动启动)
            let registry = Registry::persistent(dir);
            let restored = registry.restore();
            if !restored.is_empty() {
                println!("[setup] 已恢复 {} 条隧道配置", restored.len());
            }

            app.manage(AppState {
                registry,
                profile_store: Mutex::new(profile_store),
            });

            setup_tray(handle)?;

            // 开机自启拉起 (--autostart): 隐藏窗口后台启动 enabled 隧道。
            // 密码档案 / 加密私钥无法免交互认证 → 各自日志说明后跳过。
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
                    println!("[setup] 开机自启: {} 条 enabled 隧道", enabled_ids.len());
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
            list_profiles,
            save_profile,
            delete_profile,
            profile_defaults_get,
            profile_defaults_save,
            known_hosts_list,
            known_hosts_forget,
            autostart_get,
            autostart_set,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
