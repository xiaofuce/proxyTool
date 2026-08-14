//! GUI 薄桥接层 (Tauri v2)
//!
//! 隧道引擎在 `proxy-tool-core` crate (零 GUI 依赖); 本层职责仅剩:
//! - Tauri 命令 (前端 invoke 入口) + AppState (注册表 + 档案)
//! - `TauriEmitter`: 把引擎事件 (TunnelEvents) 转发为 Tauri 事件给 WebView
//!
//! 两套命令面并存 (P3 迁移期):
//! - 旧三页 `connect_tunnel/connect_local/connect_dynamic`: 内部经
//!   `Registry::start_legacy` 建立固定 id (= kind tag) 的临时隧道,
//!   不落盘; 前端事件流 (kind 键控) 不变
//! - 新命令 `tunnels_list/tunnel_create/tunnel_start/tunnel_stop/tunnel_delete`:
//!   uuid id, 持久化 (tunnels.json), 供 P5 新 UI 使用
//!
//! 事件格式与旧版兼容 (新增 id 字段): `tunnel-status {id,kind,state,message?}` / `tunnel-log {id,kind,msg}`。

use std::sync::Arc;

use proxy_tool_core::engine::{Registry, SshCreds};
use proxy_tool_core::model::{Backend, ReconnectPolicy, TunnelKind, TunnelSpec, TunnelState};
use proxy_tool_core::{probe, profiles, ssh, store, TunnelEvents};
use serde::Serialize;
use tauri::Manager;
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

/// 日志便捷函数 (命令层直接发, 不经过引擎)
fn events_log(app: &tauri::AppHandle, kind: &str, msg: &str) {
    TauriEmitter(app.clone()).log(kind, kind, msg);
}

// ---------- 旧页面命令 (兼容适配, P5 移除) ----------

/// 命令: 建立反向隧道 (旧「反向隧道」页; 内部经注册表, 固定 id "remote")
#[tauri::command]
async fn connect_tunnel(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    server_host: String,
    server_port: u16,
    username: String,
    password: String,
    remote_port: u32,
    local_proxy_port: u16,
    auto_reconnect: bool,
) -> Result<(), String> {
    let port: u16 = remote_port
        .try_into()
        .map_err(|_| format!("端口 {remote_port} 超出范围 (0-65535)"))?;
    let spec = TunnelSpec {
        id: "remote".into(), // 旧页面固定 id = kind tag
        name: "反向隧道".into(),
        enabled: false,
        profile_id: "legacy".into(), // 临时隧道, 不落盘
        kind: TunnelKind::Reverse {
            bind: "127.0.0.1".into(),
            port,
        },
        backend: Backend::SocksAuto {
            fallback_port: local_proxy_port,
        },
        policy: ReconnectPolicy {
            auto: auto_reconnect,
            ..ReconnectPolicy::default()
        },
    };
    let creds = SshCreds {
        host: server_host,
        port: server_port,
        username,
        password,
    };
    state
        .registry
        .start_legacy(spec, creds, emitter(&app))
        .await
}

/// 命令: 断开反向隧道
#[tauri::command]
async fn disconnect_tunnel(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.registry.stop("remote").await
}

/// 命令: 建立本地端口转发 (旧「本地转发」页; 固定 id "local")
#[tauri::command]
async fn connect_local(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    server_host: String,
    server_port: u16,
    username: String,
    password: String,
    listen_port: u16,
    target_host: String,
    target_port: u16,
    auto_reconnect: bool,
) -> Result<(), String> {
    let spec = TunnelSpec {
        id: "local".into(),
        name: "本地转发".into(),
        enabled: false,
        profile_id: "legacy".into(),
        kind: TunnelKind::Local {
            bind: "127.0.0.1".into(),
            port: listen_port,
            target_host,
            target_port,
        },
        backend: Backend::default(),
        policy: ReconnectPolicy {
            auto: auto_reconnect,
            ..ReconnectPolicy::default()
        },
    };
    let creds = SshCreds {
        host: server_host,
        port: server_port,
        username,
        password,
    };
    state
        .registry
        .start_legacy(spec, creds, emitter(&app))
        .await
}

/// 命令: 断开本地转发
#[tauri::command]
async fn disconnect_local(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.registry.stop("local").await
}

/// 命令: 建立动态隧道 (旧「动态隧道」页; 固定 id "dynamic")
#[tauri::command]
async fn connect_dynamic(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    server_host: String,
    server_port: u16,
    username: String,
    password: String,
    listen_port: u16,
    auto_reconnect: bool,
) -> Result<(), String> {
    let spec = TunnelSpec {
        id: "dynamic".into(),
        name: "动态隧道".into(),
        enabled: false,
        profile_id: "legacy".into(),
        kind: TunnelKind::Dynamic {
            bind: "127.0.0.1".into(),
            port: listen_port,
        },
        backend: Backend::default(),
        policy: ReconnectPolicy {
            auto: auto_reconnect,
            ..ReconnectPolicy::default()
        },
    };
    let creds = SshCreds {
        host: server_host,
        port: server_port,
        username,
        password,
    };
    state
        .registry
        .start_legacy(spec, creds, emitter(&app))
        .await
}

/// 命令: 断开动态隧道
#[tauri::command]
async fn disconnect_dynamic(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.registry.stop("dynamic").await
}

// ---------- 新命令面 (P5 新 UI 使用; 与旧并存) ----------

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

/// 命令: 启动隧道 (按 spec.profile_id 查档案; 密码本次注入, 不落盘)
#[tauri::command]
async fn tunnel_start(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
    password: String,
) -> Result<(), String> {
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
    let creds = SshCreds {
        host: profile.host,
        port: profile.port,
        username: profile.username,
        password,
    };
    state.registry.start(&id, creds, emitter(&app)).await
}

/// 命令: 停止隧道
#[tauri::command]
async fn tunnel_stop(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    state.registry.stop(&id).await
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

// ---------- 既有单页命令 (保持) ----------

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
/// 在服务器上分别测试 直连 与 经隧道 (socks5h://127.0.0.1:<remote_port>) 访问 google。
#[tauri::command]
async fn verify_remote_tunnel(
    app: tauri::AppHandle,
    server_host: String,
    server_port: u16,
    username: String,
    password: String,
    remote_port: u32,
) -> Result<String, String> {
    let cmd = format!(
        "echo '--- 直连(不经隧道) ---'; curl -s -o /dev/null -m 8 -w '直连: http_code=%{{http_code}} time=%{{time_total}}s\\n' https://www.google.com || echo '直连失败(预期: 服务器网络无法访问被墙站点)'; echo '--- 经隧道 ---'; curl -s -o /dev/null -m 10 -w '隧道: http_code=%{{http_code}} time=%{{time_total}}s\\n' --socks5-hostname 127.0.0.1:{remote_port} https://www.google.com || echo '隧道访问失败'"
    );
    let out = ssh::remote_exec(
        &server_host,
        server_port,
        &username,
        &password,
        &cmd,
        std::time::Duration::from_secs(45),
    )
    .await?;
    events_log(&app, "remote", &format!("验证隧道:\n{out}"));
    Ok(out)
}

/// 命令: 部署 proxy wrapper 到服务器 (服务器可用 `proxy <命令>` 走隧道出网)。
/// 优先写 /usr/local/bin (需 root), 无权限时写 ~/.local/bin。
#[tauri::command]
async fn deploy_wrapper(
    app: tauri::AppHandle,
    server_host: String,
    server_port: u16,
    username: String,
    password: String,
    remote_port: u32,
) -> Result<String, String> {
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
        &server_host,
        server_port,
        &username,
        &password,
        &cmd,
        std::time::Duration::from_secs(30),
    )
    .await?;
    events_log(&app, "remote", &format!("部署 proxy wrapper:\n{out}"));
    Ok(out)
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // app_data_dir 需要已初始化的 app handle, 故状态在 setup 里构建 + manage
            // (setup 在 WebView 加载与任何 invoke 之前运行, 命令拿到的 State 必已就绪)
            let dir =
                data_dir(app.handle()).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
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
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            probe_local_proxy,
            connect_tunnel,
            disconnect_tunnel,
            connect_local,
            disconnect_local,
            connect_dynamic,
            disconnect_dynamic,
            verify_remote_tunnel,
            deploy_wrapper,
            tunnels_list,
            tunnel_create,
            tunnel_start,
            tunnel_stop,
            tunnel_delete,
            list_profiles,
            save_profile,
            delete_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
