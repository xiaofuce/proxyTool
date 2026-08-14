//! GUI 薄桥接层 (Tauri v2)
//!
//! 隧道引擎在 `proxy-tool-core` crate (零 GUI 依赖); 本层职责仅剩:
//! - Tauri 命令 (前端 invoke 入口) + AppState (会话槽/控制标志)
//! - `TauriEmitter`: 把引擎事件 (TunnelEvents) 转发为 Tauri 事件给 WebView
//! - 重连循环 (`run_with_reconnect`): 驱动 core 的连接函数并管理退避/终态
//!
//! 事件格式与旧版完全一致: `tunnel-status {kind,state,message?}` / `tunnel-log {kind,msg}`。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proxy_tool_core::{direct, probe, profiles, socks, ssh, tunnel, TunnelEvents};
use serde::Serialize;
use tauri::Manager;
use tokio::sync::Mutex;

/// 单条隧道的重连控制标志
pub struct TunnelControl {
    /// spawn 任务是否在运行 (true = 占用槽位, 用于防重复连接)
    pub running: AtomicBool,
    /// 用户主动请求断开 (true = 重连循环应停止, 不再重连)
    pub disconnect_intent: AtomicBool,
}

impl TunnelControl {
    pub const fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            disconnect_intent: AtomicBool::new(false),
        }
    }
}

/// 共享应用状态: 每种隧道模式一个会话槽 + 服务器配置档案。
/// 会话槽类型来自 core (引擎与 GUI 共享同一存放处)。
pub struct AppState {
    /// 反向隧道会话槽 (engine::tunnel 的 TunnelSlot)
    pub remote_session: tunnel::TunnelSlot,
    /// 本地转发会话槽
    pub local_session: Arc<Mutex<Option<Arc<direct::DirectSession>>>>,
    /// 动态隧道会话槽
    pub dynamic_session: Arc<Mutex<Option<Arc<direct::DirectSession>>>>,
    /// 反向隧道用内置 SOCKS5 服务器 (VPN 无端口时自动启动)
    pub socks_server: Mutex<Option<Arc<socks::SocksServerHandle>>>,
    /// 服务器配置档案
    pub profiles: Mutex<Vec<profiles::ServerProfile>>,
    /// 三种隧道的重连控制
    pub ctrl_remote: TunnelControl,
    pub ctrl_local: TunnelControl,
    pub ctrl_dynamic: TunnelControl,
}

/// 隧道状态事件负载: { kind, state, message? }
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct StatusPayload {
    kind: &'static str,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// 隧道日志事件负载: { kind, msg }
#[derive(Serialize, Clone)]
struct LogPayload {
    kind: &'static str,
    msg: String,
}

/// 引擎事件的 GUI 实现: 转发为 Tauri 事件 (前端 listen 的名字不变)
struct TauriEmitter(tauri::AppHandle);

impl TunnelEvents for TauriEmitter {
    fn status(&self, kind: &str, state: &str, message: Option<&str>) {
        use tauri::Emitter;
        let _ = self.0.emit(
            "tunnel-status",
            &StatusPayload {
                kind: kind_static(kind),
                state: state.to_string(),
                message: message.map(|m| m.to_string()),
            },
        );
    }
    fn log(&self, kind: &str, msg: &str) {
        use tauri::Emitter;
        let _ = self.0.emit(
            "tunnel-log",
            &LogPayload {
                kind: kind_static(kind),
                msg: msg.to_string(),
            },
        );
    }
}

/// kind 字面量收窄回 'static (core 传 &str, 前端只认 remote/local/dynamic)
fn kind_static(kind: &str) -> &'static str {
    match kind {
        "local" => "local",
        "dynamic" => "dynamic",
        _ => "remote",
    }
}

/// 应用数据目录 (档案等持久化文件的根)
fn data_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("获取应用数据目录失败: {e}"))
}

/// 指数退避: 1→2→4→8→16→30→30…s (封顶 30s)
fn next_backoff(cur: Duration) -> Duration {
    std::cmp::min(cur * 2, Duration::from_secs(30))
}

/// 退避等待 `dur`, 期间每 200ms 检查取消标志; 返回 true = 被用户取消
async fn backoff_with_cancel(flag: &AtomicBool, dur: Duration) -> bool {
    let mut waited = Duration::ZERO;
    while waited < dur {
        if flag.load(Ordering::SeqCst) {
            return true;
        }
        let step = std::cmp::min(Duration::from_millis(200), dur - waited);
        tokio::time::sleep(step).await;
        waited += step;
    }
    flag.load(Ordering::SeqCst)
}

/// 通用重连循环 (三种隧道共用): 反复执行 `attempt` —— 建立并运行一次隧道直到
/// 断开 (返回 Ok) 或建连失败 (返回 Err)。失败按指数退避重试 (1→2→…→30s 封顶)。
/// 停止条件 (三者满足其一):
/// - 用户断开意图 (`disconnect_intent`, 点「断开」按钮)
/// - `auto_reconnect` 为 false (复选框关闭)
/// - 认证被拒 (密码错误, 重连永远无法成功 —— 立即报错, 提示检查密码)
///
/// `attempt` 闭包内自行管理会话槽 (连接成功时填入, 结束时清空) 并 emit "connected";
/// 终态事件 (disconnected / error) 由本循环统一发射。
async fn run_with_reconnect<F, Fut>(
    events: Arc<dyn TunnelEvents>,
    kind: &'static str,
    intent: &AtomicBool,
    auto_reconnect: bool,
    mut attempt: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut backoff = Duration::from_secs(1);
    let mut n = 0u32;
    loop {
        // 循环顶检查: 覆盖「spawn 启动前用户已点断开」的窗口
        if intent.load(Ordering::SeqCst) {
            events.status(kind, "disconnected", None);
            return;
        }
        let result = attempt().await;
        if let Err(e) = &result {
            events.log(kind, &format!("❌ {e}"));
        }
        let auth_rejected = matches!(&result, Err(e) if ssh::is_auth_rejected(e));
        if intent.load(Ordering::SeqCst) || !auto_reconnect || auth_rejected {
            match result {
                Ok(()) => events.status(kind, "disconnected", None),
                Err(e) => {
                    let msg = if auth_rejected {
                        format!("{e} —— 已停止自动重连, 请检查用户名/密码后重新连接")
                    } else {
                        e
                    };
                    events.status(kind, "error", Some(&msg));
                }
            }
            return;
        }
        n += 1;
        events.status(
            kind,
            "reconnecting",
            Some(&format!("第 {n} 次重连, {}s 后重试", backoff.as_secs())),
        );
        if backoff_with_cancel(intent, backoff).await {
            events.status(kind, "disconnected", None);
            return;
        }
        backoff = next_backoff(backoff);
    }
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

/// 确定本地 SOCKS 代理端口 (反向隧道用):
/// 1. 优先复用 VPN 自带的端口 (探测确认是 SOCKS5)
/// 2. 探测不到则启动内置 SOCKS5 服务器
async fn resolve_local_proxy(app: &tauri::AppHandle, requested_port: u16) -> Result<u16, String> {
    let vpn = probe::probe_local_proxy().await;
    if let Some(found) = vpn.iter().find(|r| r.socks5_confirmed) {
        events_log(
            app,
            "remote",
            &format!(
                "发现 VPN 自带 SOCKS 端口 {} (SOCKS5 确认), 直接复用",
                found.port
            ),
        );
        return Ok(found.port);
    }

    // 没有 VPN 端口 -> 启动内置 SOCKS5 服务器
    let state = app.state::<AppState>();
    let mut guard = state.socks_server.lock().await;
    if let Some(server) = guard.as_ref() {
        if server.port == requested_port {
            // 已在监听同一端口, 复用
            return Ok(server.port);
        }
        // 端口变了, 停掉旧的
        server.stop();
        *guard = None;
    }
    events_log(
        app,
        "remote",
        &format!("未发现 VPN 代理端口, 启动内置 SOCKS5 服务器 (127.0.0.1:{requested_port})"),
    );
    let server = socks::start_socks_server(requested_port).await?;
    let port = server.port;
    *guard = Some(server);
    Ok(port)
}

/// 日志便捷函数 (命令层直接发, 不经过引擎)
fn events_log(app: &tauri::AppHandle, kind: &'static str, msg: &str) {
    TauriEmitter(app.clone()).log(kind, msg);
}

/// 命令: 建立反向隧道 (异步, 立即返回; 后台运行, 断开后按 auto_reconnect 自动重连)
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
    // 防重: running 标志占用槽位 (true = 已在运行/重连中)
    if state.ctrl_remote.running.swap(true, Ordering::SeqCst) {
        return Err("已有反向隧道在运行, 请先断开".into());
    }
    state
        .ctrl_remote
        .disconnect_intent
        .store(false, Ordering::SeqCst);

    // 决定本地代理端口 (VPN 端口优先, 否则内置 SOCKS)
    let local_proxy_port = resolve_local_proxy(&app, local_proxy_port).await?;

    let cfg = tunnel::TunnelConfig {
        server_host,
        server_port,
        username,
        password,
        remote_port,
        local_proxy_host: "127.0.0.1".into(),
        local_proxy_port,
    };
    let events: Arc<dyn TunnelEvents> = Arc::new(TauriEmitter(app.clone()));
    events.status("remote", "connecting", None);

    let slot = state.remote_session.clone();
    let ev = events.clone();
    let logger: ssh::Logger = Arc::new(move |msg: &str| ev.log("remote", msg));
    let ev2 = events.clone();
    let on_status: ssh::Logger = Arc::new(move |s: &str| ev2.status("remote", s, None));

    // 后台任务: 重连循环 —— 反复建立隧道直到用户断开 / 认证被拒 / 关闭自动重连
    tauri::async_runtime::spawn(async move {
        let state2 = app.state::<AppState>();
        let attempt = || {
            let slot = slot.clone();
            let cfg = cfg.clone();
            let logger = logger.clone();
            let on_status = on_status.clone();
            async move {
                // start_tunnel 内部建立会话并 emit "connected", 返回 = 会话结束
                let r = tunnel::start_tunnel(slot.clone(), cfg, logger, on_status).await;
                *slot.lock().await = None;
                r
            }
        };
        run_with_reconnect(
            events.clone(),
            "remote",
            &state2.ctrl_remote.disconnect_intent,
            auto_reconnect,
            attempt,
        )
        .await;
        *state2.remote_session.lock().await = None;
        state2.ctrl_remote.running.store(false, Ordering::SeqCst);
    });
    Ok(())
}

/// 命令: 断开反向隧道 (置停止意图 + 关闭当前会话; 重连循环检测到意图后不再重连)
#[tauri::command]
async fn disconnect_tunnel(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state
        .ctrl_remote
        .disconnect_intent
        .store(true, Ordering::SeqCst);
    let mut guard = state.remote_session.lock().await;
    if let Some(handle) = guard.take() {
        // 发送 SSH DISCONNECT 真正关闭连接 (见 core::tunnel::close_session 注释)
        tunnel::close_session(&handle).await;
    }
    Ok(())
}

/// 命令: 建立本地端口转发 (ssh -L); 断开后按 auto_reconnect 自动重连
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
    if state.ctrl_local.running.swap(true, Ordering::SeqCst) {
        return Err("本地转发已在运行, 请先断开".into());
    }
    state
        .ctrl_local
        .disconnect_intent
        .store(false, Ordering::SeqCst);

    let cfg = direct::DirectConfig {
        server_host,
        server_port,
        username,
        password,
        listen_host: "127.0.0.1".into(),
        listen_port,
    };

    let events: Arc<dyn TunnelEvents> = Arc::new(TauriEmitter(app.clone()));
    events.status("local", "connecting", None);
    let ev = events.clone();
    let logger: ssh::Logger = Arc::new(move |msg: &str| ev.log("local", msg));

    let slot = state.local_session.clone();
    tauri::async_runtime::spawn(async move {
        let state2 = app.state::<AppState>();
        let attempt = || {
            let slot = slot.clone();
            let cfg = cfg.clone();
            let target_host = target_host.clone();
            let logger = logger.clone();
            let events = events.clone();
            async move {
                match direct::run_local_forward(cfg, target_host, target_port, logger).await {
                    Ok((session, task)) => {
                        *slot.lock().await = Some(session);
                        events.status("local", "connected", None);
                        let _ = task.await; // 运行直到断开 (listener 随之 drop, 释放端口)
                        *slot.lock().await = None;
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        };
        run_with_reconnect(
            events.clone(),
            "local",
            &state2.ctrl_local.disconnect_intent,
            auto_reconnect,
            attempt,
        )
        .await;
        *state2.local_session.lock().await = None;
        state2.ctrl_local.running.store(false, Ordering::SeqCst);
    });
    Ok(())
}

/// 命令: 断开本地转发 (置停止意图 + 关闭会话)
#[tauri::command]
async fn disconnect_local(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state
        .ctrl_local
        .disconnect_intent
        .store(true, Ordering::SeqCst);
    if let Some(session) = state.local_session.lock().await.take() {
        session.disconnect().await;
    }
    Ok(())
}

/// 命令: 建立动态隧道 (ssh -D); 断开后按 auto_reconnect 自动重连
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
    if state.ctrl_dynamic.running.swap(true, Ordering::SeqCst) {
        return Err("动态隧道已在运行, 请先断开".into());
    }
    state
        .ctrl_dynamic
        .disconnect_intent
        .store(false, Ordering::SeqCst);

    let cfg = direct::DirectConfig {
        server_host,
        server_port,
        username,
        password,
        listen_host: "127.0.0.1".into(),
        listen_port,
    };

    let events: Arc<dyn TunnelEvents> = Arc::new(TauriEmitter(app.clone()));
    events.status("dynamic", "connecting", None);
    let ev = events.clone();
    let logger: ssh::Logger = Arc::new(move |msg: &str| ev.log("dynamic", msg));

    let slot = state.dynamic_session.clone();
    tauri::async_runtime::spawn(async move {
        let state2 = app.state::<AppState>();
        let attempt = || {
            let slot = slot.clone();
            let cfg = cfg.clone();
            let logger = logger.clone();
            let events = events.clone();
            async move {
                match direct::run_dynamic_forward(cfg, logger).await {
                    Ok((session, task)) => {
                        *slot.lock().await = Some(session);
                        events.status("dynamic", "connected", None);
                        let _ = task.await;
                        *slot.lock().await = None;
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        };
        run_with_reconnect(
            events.clone(),
            "dynamic",
            &state2.ctrl_dynamic.disconnect_intent,
            auto_reconnect,
            attempt,
        )
        .await;
        *state2.dynamic_session.lock().await = None;
        state2.ctrl_dynamic.running.store(false, Ordering::SeqCst);
    });
    Ok(())
}

/// 命令: 断开动态隧道 (置停止意图 + 关闭会话)
#[tauri::command]
async fn disconnect_dynamic(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state
        .ctrl_dynamic
        .disconnect_intent
        .store(true, Ordering::SeqCst);
    if let Some(session) = state.dynamic_session.lock().await.take() {
        session.disconnect().await;
    }
    Ok(())
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
        Duration::from_secs(45),
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
        Duration::from_secs(30),
    )
    .await?;
    events_log(&app, "remote", &format!("部署 proxy wrapper:\n{out}"));
    Ok(out)
}

/// 命令: 列出服务器配置档案
#[tauri::command]
async fn list_profiles(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<profiles::ServerProfile>, String> {
    Ok(state.profiles.lock().await.clone())
}

/// 命令: 保存/更新服务器配置档案 (id 相同则覆盖), 返回最新列表
#[tauri::command]
async fn save_profile(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    profile: profiles::ServerProfile,
) -> Result<Vec<profiles::ServerProfile>, String> {
    let mut list = state.profiles.lock().await;
    if let Some(p) = list.iter_mut().find(|p| p.id == profile.id) {
        *p = profile;
    } else {
        list.push(profile);
    }
    let snapshot = list.clone();
    profiles::save(&data_dir(&app)?, &snapshot)?;
    Ok(snapshot)
}

/// 命令: 删除服务器配置档案, 返回最新列表
#[tauri::command]
async fn delete_profile(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<Vec<profiles::ServerProfile>, String> {
    let mut list = state.profiles.lock().await;
    list.retain(|p| p.id != id);
    let snapshot = list.clone();
    profiles::save(&data_dir(&app)?, &snapshot)?;
    Ok(snapshot)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            remote_session: Arc::new(Mutex::new(None)),
            local_session: Arc::new(Mutex::new(None)),
            dynamic_session: Arc::new(Mutex::new(None)),
            socks_server: Mutex::new(None),
            profiles: Mutex::new(Vec::new()),
            ctrl_remote: TunnelControl::new(),
            ctrl_local: TunnelControl::new(),
            ctrl_dynamic: TunnelControl::new(),
        })
        .setup(|app| {
            // 加载服务器配置档案 (存储目录 = app_data_dir)
            let dir =
                data_dir(app.handle()).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let loaded = profiles::load(&dir);
            *app.state::<AppState>().profiles.blocking_lock() = loaded;
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
            list_profiles,
            save_profile,
            delete_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
