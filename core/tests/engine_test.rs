//! 隧道引擎 headless 测试: 注册表 + 状态机任务 + 事件序列
//!
//! 覆盖 P3 验收核心: 生命周期 (Starting→Running→Stopped)、致命错误立即停
//! (错误密码不进退避, 事件流断言)、持久化往返 (tunnels.json 恢复)、
//! 旧页面适配隧道不落盘。
//! 连接类用例打真实测试服务器 (同 e2e_direct 模式, 目标 = 服务器自身 22 端口)。

use std::sync::Arc;
use std::time::Duration;

use proxy_tool_core::engine::{Registry, SshCreds};
use proxy_tool_core::model::{Backend, ReconnectPolicy, TunnelKind, TunnelSpec, TunnelState};
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
        self.statuses.lock().unwrap().push((
            id.into(),
            kind.into(),
            state.into(),
            message.map(|m| m.into()),
        ));
    }
    fn log(&self, _id: &str, _kind: &str, msg: &str) {
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
        port: 22,
        username: c.user.clone(),
        password: c.pass.clone(),
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
            target_host: proxy_tool_core::creds::load().server.clone(),
            target_port: 22, // 目标 = 服务器自身 sshd, 读 banner 验证
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
        password: "definitely-wrong".into(),
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

/// 持久化: create 落盘 → 新 Registry restore 恢复列表; legacy 隧道不落盘
#[tokio::test]
async fn persistence_roundtrip_and_legacy_excluded() {
    let dir = std::env::temp_dir().join(format!("pt-reg-{}", TunnelSpec::new_id()));
    std::fs::create_dir_all(&dir).unwrap();

    let registry = Registry::persistent(dir.clone());
    let spec = local_spec(12345);
    let id = spec.id.clone();
    registry.create(spec).expect("创建失败");

    // legacy 隧道 (打不可达地址, 任务进退避也无妨 —— 只验证不落盘)
    let legacy = TunnelSpec {
        id: "local".into(), // 旧页面固定 id = kind tag
        name: "旧页面隧道".into(),
        enabled: false,
        profile_id: "legacy".into(),
        kind: TunnelKind::Local {
            bind: "127.0.0.1".into(),
            port: free_port(),
            target_host: "127.0.0.1".into(),
            target_port: 1,
        },
        backend: Backend::default(),
        policy: ReconnectPolicy::default(),
    };
    let events: Arc<dyn TunnelEvents> = Arc::new(Collector::default());
    registry
        .start_legacy(
            legacy,
            SshCreds {
                host: "127.0.0.1".into(),
                port: 1,
                username: "x".into(),
                password: "x".into(),
            },
            events,
        )
        .await
        .expect("legacy 启动失败");

    // 文件里只有持久化隧道
    let saved = proxy_tool_core::store::load_tunnels(&dir);
    assert_eq!(saved.len(), 1, "legacy 不落盘: {saved:?}");
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

    // 清理
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
