//! 隧道引擎 headless 测试: 注册表 + 状态机任务 + 事件序列
//!
//! 覆盖: 生命周期 (Starting→Running→Stopped)、致命错误立即停
//! (错误密码 / TOFU 指纹变更, 均不进退避, 事件流断言)、持久化往返
//! (tunnels.json 恢复)、网络掉线快试重连、retry_now 跳过退避。
//! 连接类用例打真实测试服务器 (同 e2e_direct 模式, 目标 = 服务器自身 22 端口)。

use std::sync::Arc;
use std::time::Duration;

use proxy_tool_core::engine::{Registry, SshCreds};
use proxy_tool_core::model::{Backend, ReconnectPolicy, TunnelKind, TunnelSpec, TunnelState};
use proxy_tool_core::ssh::AuthMethod;
use proxy_tool_core::TunnelEvents;
use tokio::io::AsyncReadExt;

/// 事件收集器 (设计 §3.7: CollectorEmitter, 重连逻辑 headless 可测)。
/// 内部 std::Mutex: TunnelEvents 回调是同步的 (在引擎任务的异步上下文里调用,
/// 临界区只有 push, 不阻塞)。
#[derive(Clone, Default)]
struct Collector {
    statuses: Arc<std::sync::Mutex<Vec<(String, String, String, Option<String>)>>>,
    logs: Arc<std::sync::Mutex<Vec<String>>>,
}

impl TunnelEvents for Collector {
    fn status(&self, id: &str, kind: &str, state: &str, message: Option<&str>) {
        if std::env::var("PT_TRACE").is_ok() {
            eprintln!("[trace] {id} {kind} {state} {:?}", message);
        }
        self.statuses.lock().unwrap().push((
            id.into(),
            kind.into(),
            state.into(),
            message.map(|m| m.into()),
        ));
    }
    fn log(&self, _id: &str, _kind: &str, msg: &str) {
        if std::env::var("PT_TRACE").is_ok() {
            eprintln!("[trace log] {msg}");
        }
        self.logs.lock().unwrap().push(msg.into());
    }
}

impl Collector {
    fn statuses(&self) -> Vec<(String, String, String, Option<String>)> {
        self.statuses.lock().unwrap().clone()
    }
}

fn creds() -> SshCreds {
    let c = proxy_tool_core::creds::load();
    SshCreds {
        host: c.server.clone(),
        port: c.port,
        username: c.user.clone(),
        auth: AuthMethod::Password(c.pass.clone()),
    }
}

fn local_spec(listen_port: u16) -> TunnelSpec {
    TunnelSpec {
        id: TunnelSpec::new_id(),
        name: "引擎测试-本地转发".into(),
        enabled: true,
        profile_id: "p-test".into(),
        kind: TunnelKind::Local {
            bind: "127.0.0.1".into(),
            port: listen_port,
            target_host: "127.0.0.1".into(),
            target_port: proxy_tool_core::creds::load().port, // 目标 = 服务器自身 sshd, 读 banner 验证
        },
        backend: Backend::default(),
        policy: ReconnectPolicy::default(),
    }
}

/// 挑一个临时空闲端口
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 轮询注册表直到隧道状态满足 `pred` (超时 panic 带当前状态)
async fn wait_state(registry: &Registry, id: &str, pred: impl Fn(&TunnelState) -> bool) {
    for _ in 0..100 {
        if let Some((_, state)) = registry.list().into_iter().find(|(s, _)| &s.id == id) {
            if pred(&state) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let cur = registry
        .list()
        .into_iter()
        .find(|(s, _)| &s.id == id)
        .map(|(_, st)| format!("{st:?}"))
        .unwrap_or_else(|| "不存在".into());
    panic!("等待隧道 {id} 状态超时, 当前: {cur}");
}

/// 生命周期: create → start → Running (本地端口能读到 SSH banner) → stop → Stopped
#[tokio::test]
async fn local_tunnel_lifecycle() {
    let registry = Registry::new();
    let collector = Collector::default();
    let events: Arc<dyn TunnelEvents> = Arc::new(collector.clone());
    let spec = local_spec(free_port());
    let id = spec.id.clone();
    registry.create(spec.clone()).expect("创建失败");

    registry
        .start(&id, creds(), events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &id, |s| matches!(s, TunnelState::Running)).await;

    // 通路验证: 本机监听端口 → 隧道 → 服务器 sshd (读 SSH banner)
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", listen_port_of(&spec)))
        .await
        .expect("连接本地监听端口失败");
    let mut banner = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), conn.read_to_end(&mut banner)).await;
    let banner = String::from_utf8_lossy(&banner);
    assert!(banner.contains("SSH-"), "应读到 SSH banner: {banner}");

    registry.stop(&id).await.expect("停止失败");
    wait_state(&registry, &id, |s| matches!(s, TunnelState::Stopped)).await;

    // 事件序列: connecting → connected → disconnected (id/kind 键控)
    let statuses = collector.statuses();
    let states: Vec<&str> = statuses.iter().map(|(_, _, s, _)| s.as_str()).collect();
    assert!(
        states.contains(&"connected") && states.contains(&"disconnected"),
        "事件序列应含 connected/disconnected: {states:?}"
    );
    assert!(
        statuses
            .iter()
            .all(|(eid, kind, _, _)| eid == &id && kind == "local"),
        "事件应携带隧道 id 与 kind tag: {statuses:?}"
    );
}

fn listen_port_of(spec: &TunnelSpec) -> u16 {
    match &spec.kind {
        TunnelKind::Local { port, .. } => *port,
        _ => panic!("预期 Local 形态"),
    }
}

/// 错误密码: AuthRejected = 致命 —— 立即 Failed, 恰一次 error 事件, 不进退避
#[tokio::test]
async fn wrong_password_stops_without_retry() {
    let registry = Registry::new();
    let collector = Collector::default();
    let events: Arc<dyn TunnelEvents> = Arc::new(collector.clone());
    let mut spec = local_spec(free_port());
    spec.policy.auto = true; // 即便开自动重连, 认证被拒也必须停
    let id = spec.id.clone();
    registry.create(spec).expect("创建失败");

    let bad = SshCreds {
        auth: AuthMethod::Password("definitely-wrong".into()),
        ..creds()
    };
    registry.start(&id, bad, events).await.expect("启动失败");
    wait_state(&registry, &id, |s| {
        matches!(
            s,
            TunnelState::Failed {
                retryable: false,
                ..
            }
        )
    })
    .await;

    // 等一个退避周期, 确认没有重试 (退避首拍 1s)
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let statuses = collector.statuses();
    let errors = statuses.iter().filter(|(_, _, s, _)| s == "error").count();
    let reconnects = statuses
        .iter()
        .filter(|(_, _, s, _)| s == "reconnecting")
        .count();
    assert_eq!(errors, 1, "恰一次 error 事件: {statuses:?}");
    assert_eq!(reconnects, 0, "认证被拒不得进退避: {statuses:?}");
    let msg = statuses
        .iter()
        .find(|(_, _, s, _)| s == "error")
        .and_then(|(_, _, _, m)| m.clone())
        .expect("error 事件应带消息");
    assert!(
        msg.contains("认证被拒") || msg.contains("密码"),
        "提示应指向密码问题: {msg}"
    );
}

/// TOFU 指纹校验: 记忆库中预置伪造指纹 → 连接被拒,
/// Failed{retryable:false} + 指纹变更文案, 不进退避 (防中间人场景空转重连)
#[tokio::test]
async fn host_key_mismatch_is_fatal() {
    let registry = Registry::new();
    let collector = Collector::default();
    let events: Arc<dyn TunnelEvents> = Arc::new(collector.clone());
    let spec = local_spec(free_port());
    let id = spec.id.clone();
    registry.create(spec).expect("创建失败");

    // 伪造指纹 (与真实服务器必然不符)
    let c = proxy_tool_core::creds::load();
    registry.known_hosts().remember(
        &c.server,
        c.port,
        proxy_tool_core::known_hosts::KnownHost {
            algorithm: "ssh-ed25519".into(),
            fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        },
    );

    registry
        .start(&id, creds(), events)
        .await
        .expect("启动失败");
    wait_state(&registry, &id, |s| {
        matches!(
            s,
            TunnelState::Failed {
                retryable: false,
                ..
            }
        )
    })
    .await;

    // 等一个退避周期, 确认没有重试
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let statuses = collector.statuses();
    assert_eq!(
        statuses
            .iter()
            .filter(|(_, _, s, _)| s == "reconnecting")
            .count(),
        0,
        "指纹变更不得进退避: {statuses:?}"
    );
    let msg = statuses
        .iter()
        .find(|(_, _, s, _)| s == "error")
        .and_then(|(_, _, _, m)| m.clone())
        .expect("error 事件应带消息");
    assert!(msg.contains("指纹已变更"), "提示应指向指纹变更: {msg}");
}

/// 持久化: create 落盘 → 新 Registry restore 恢复列表 (Stopped 起点)
#[tokio::test]
async fn persistence_roundtrip() {
    let dir = std::env::temp_dir().join(format!("pt-reg-{}", TunnelSpec::new_id()));
    std::fs::create_dir_all(&dir).unwrap();

    let registry = Registry::persistent(dir.clone());
    let spec = local_spec(12345);
    let id = spec.id.clone();
    registry.create(spec).expect("创建失败");

    let saved = proxy_tool_core::store::load_tunnels(&dir);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].id, id);

    // 重启恢复
    let registry2 = Registry::persistent(dir.clone());
    let restored = registry2.restore();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].id, id);
    // 恢复后可再启动 (状态 Stopped 起点正确)
    let all = registry2.list();
    assert!(all
        .iter()
        .any(|(s, st)| &s.id == &id && *st == TunnelState::Stopped));

    // set_enabled (开机自启开关): 更新内存 + 落盘, 重启后保持
    registry2
        .set_enabled(&id, false)
        .expect("更新 enabled 失败");
    assert!(!registry2.list()[0].0.enabled, "内存态应已更新");
    let registry3 = Registry::persistent(dir.clone());
    registry3.restore();
    assert!(!registry3.list()[0].0.enabled, "落盘后重启应保持 false");
    registry3.set_enabled(&id, true).expect("恢复 enabled 失败");
    assert!(registry3.list()[0].0.enabled);

    // 清理
    let _ = std::fs::remove_dir_all(&dir);
}

/// 列表与落盘顺序 = 创建顺序 (注册表 HashMap 无序, order 表保证 UI 稳定);
/// 删除后其余保持相对顺序, 重启恢复同样有序
#[tokio::test]
async fn list_and_persist_preserve_creation_order() {
    let dir = std::env::temp_dir().join(format!("pt-reg-{}", TunnelSpec::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let registry = Registry::persistent(dir.clone());

    let mut ids = Vec::new();
    for i in 0..3 {
        let mut spec = local_spec(free_port());
        spec.name = format!("顺序-{i}");
        ids.push(spec.id.clone());
        registry.create(spec).expect("创建失败");
    }
    let listed: Vec<String> = registry.list().into_iter().map(|(s, _)| s.id).collect();
    assert_eq!(listed, ids, "list 应按创建顺序");

    let saved: Vec<String> = proxy_tool_core::store::load_tunnels(&dir)
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(saved, ids, "tunnels.json 落盘顺序应稳定");

    registry.delete(&ids[1]).await.expect("删除失败");
    let after: Vec<String> = registry.list().into_iter().map(|(s, _)| s.id).collect();
    assert_eq!(
        after,
        vec![ids[0].clone(), ids[2].clone()],
        "删除后其余保持相对顺序"
    );

    // 重启恢复同样有序
    let registry2 = Registry::persistent(dir.clone());
    let restored: Vec<String> = registry2.restore().into_iter().map(|s| s.id).collect();
    assert_eq!(restored, vec![ids[0].clone(), ids[2].clone()]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// 运行中删除: 条目移出 + 状态不再可见
#[tokio::test]
async fn delete_running_tunnel() {
    let registry = Registry::new();
    let events: Arc<dyn TunnelEvents> = Arc::new(Collector::default());
    let spec = local_spec(free_port());
    let id = spec.id.clone();
    registry.create(spec).expect("创建失败");
    registry
        .start(&id, creds(), events)
        .await
        .expect("启动失败");
    wait_state(&registry, &id, |s| matches!(s, TunnelState::Running)).await;

    registry.delete(&id).await.expect("删除失败");
    assert!(
        registry.list().iter().all(|(s, _)| s.id != id),
        "删除后列表不应再有该隧道"
    );
    assert!(registry.stop(&id).await.is_err(), "删除后 stop 应报不存在");
}

/// 网络掉线 (硬断会话, 无停止意图) → Backoff 第 1 拍 1s 快试 → 自动回 Running。
/// 事件序列: connecting → connected → reconnecting(第 1 次, 1s) → connecting → connected。
#[tokio::test]
async fn network_drop_reconnects_with_fast_backoff() {
    let registry = Registry::new();
    let collector = Collector::default();
    let events: Arc<dyn TunnelEvents> = Arc::new(collector.clone());
    let spec = local_spec(free_port());
    let id = spec.id.clone();
    registry.create(spec).expect("创建失败");
    registry
        .start(&id, creds(), events)
        .await
        .expect("启动失败");
    wait_state(&registry, &id, |s| matches!(s, TunnelState::Running)).await;
    let port = listen_port(registry.list(), &id);

    // 模拟网络掉线: 硬断当前会话, 不置停止意图
    registry.drop_connection(&id).await.expect("硬断失败");

    // 第 1 拍快试: Backoff{attempt:1, wait:1s} 出现后 1s 内自动重连
    wait_state(&registry, &id, |s| {
        matches!(
            s,
            TunnelState::Backoff {
                attempt: 1,
                wait_secs: 1,
            }
        )
    })
    .await;
    wait_state(&registry, &id, |s| matches!(s, TunnelState::Running)).await;

    // 重连后同端口仍可用 (listener 重建, 端口复用)
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("重连后连接本地监听端口失败");
    let mut banner = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), conn.read_to_end(&mut banner)).await;
    assert!(String::from_utf8_lossy(&banner).contains("SSH-"));

    // 事件序列断言: 恰一次 reconnecting (第 1 次, 1s), 且连接两次 (初始 + 重连)
    let statuses = collector.statuses();
    let reconnects: Vec<_> = statuses
        .iter()
        .filter(|(_, _, s, _)| s == "reconnecting")
        .collect();
    assert_eq!(reconnects.len(), 1, "恰一次 reconnecting: {statuses:?}");
    assert!(
        reconnects[0]
            .3
            .as_deref()
            .is_some_and(|m| m.contains("第 1 次重连, 1s")),
        "首拍应为 1s 快试: {:?}",
        reconnects[0].3
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|(_, _, s, _)| s == "connected")
            .count(),
        2,
        "连接两次 (初始 + 重连): {statuses:?}"
    );

    registry.stop(&id).await.expect("停止失败");
    wait_state(&registry, &id, |s| matches!(s, TunnelState::Stopped)).await;
}

fn listen_port(list: Vec<(TunnelSpec, TunnelState)>, id: &str) -> u16 {
    match list.iter().find(|(s, _)| s.id == id) {
        Some((s, _)) => match &s.kind {
            TunnelKind::Local { port, .. } => *port,
            _ => panic!("预期 Local 形态"),
        },
        None => panic!("隧道不存在: {id}"),
    }
}

/// 立即重试: 退避等待期间置 retry_now → 跳过剩余等待马上发起新尝试
#[tokio::test]
async fn retry_now_skips_backoff_wait() {
    let registry = Registry::new();
    let collector = Collector::default();
    let events: Arc<dyn TunnelEvents> = Arc::new(collector.clone());
    // 目标不可达: 连接秒败 (Connect 可重试) → 持续退避。
    // fast_retries=0: 直接进入指数段 —— 本机拒绝连接在 Windows 上单次耗 ~2s
    // (防火墙/AV 检查), 默认快试序列会超出 wait_state 的 10s 窗口
    let mut spec = local_spec(free_port());
    spec.policy.fast_retries = 0;
    let id = spec.id.clone();
    registry.create(spec).expect("创建失败");

    let bad = SshCreds {
        host: "127.0.0.1".into(),
        port: 1,
        ..creds()
    };
    registry.start(&id, bad, events).await.expect("启动失败");

    // 等到退避拉长 (wait >= 2s, 即快试用完进入指数段)
    wait_state(
        &registry,
        &id,
        |s| matches!(s, TunnelState::Backoff { wait_secs, .. } if *wait_secs >= 2),
    )
    .await;
    let before = count_connecting(&collector);
    let t0 = std::time::Instant::now();

    registry.retry_now(&id).expect("立即重试失败");

    // 新 connecting 应在远小于剩余等待 (≥2s) 的时间内出现
    let mut appeared = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if count_connecting(&collector) > before {
            appeared = true;
            break;
        }
    }
    assert!(appeared, "retry_now 后应立即发起新尝试");
    assert!(
        t0.elapsed() < Duration::from_millis(1500),
        "新尝试应跳过剩余退避 (实际 {:?})",
        t0.elapsed()
    );

    registry.stop(&id).await.expect("停止失败");
}

fn count_connecting(collector: &Collector) -> usize {
    collector
        .statuses()
        .iter()
        .filter(|(_, _, s, _)| s == "connecting")
        .count()
}
