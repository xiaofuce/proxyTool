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
    creds_with(10)
}

/// 指定 MaxSessions 预算的凭据 (C4 准入用例)
fn creds_with(max_sessions: u32) -> SshCreds {
    let c = proxy_tool_core::creds::load();
    SshCreds {
        host: c.server.clone(),
        port: c.port,
        username: c.user.clone(),
        auth: AuthMethod::Password(c.pass.clone()),
        share: true,
        max_sessions,
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

/// 连本地端口读 SSH banner (通路验证; 读到即返回, 不等流结束)
async fn read_banner(port: u16) -> String {
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("连接 127.0.0.1:{port} 失败: {e}"));
    // sshd 的 banner 是首行写出后等客户端 —— 读到换行即返回
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut buf))
        .await
        .expect("读 banner 超时")
        .expect("读 banner 失败");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// 同档案两条 Local 隧道共享一条 SSH 连接: 池 1 条目 / 建连恰 1 次 / 2 租约;
/// 停一条共享连接不断 (兄弟隧道仍 Running 且通路可用)
#[tokio::test]
async fn shared_local_tunnels_one_connection() {
    let registry = Registry::new();
    let events: Arc<dyn TunnelEvents> = Arc::new(Collector::default());
    let mut s1 = local_spec(free_port());
    s1.profile_id = "p-share".into();
    let mut s2 = local_spec(free_port());
    s2.profile_id = "p-share".into();
    registry.create(s1.clone()).expect("创建失败");
    registry.create(s2.clone()).expect("创建失败");

    registry
        .start(&s1.id, creds(), events.clone())
        .await
        .expect("启动失败");
    registry
        .start(&s2.id, creds(), events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Running)).await;
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Running)).await;

    let stats = registry.conn_stats().await;
    assert_eq!(stats.len(), 1, "同档案应只有一个池条目: {stats:?}");
    assert_eq!(stats[0].profile_id, "p-share");
    assert_eq!(stats[0].connect_count, 1, "两条隧道只建连一次");
    assert_eq!(stats[0].leases.len(), 2, "两条租约: {stats:?}");

    // 两条隧道各自通路 (都经同一共享连接的 direct_tcpip)
    let b1 = read_banner(listen_port_of(&s1)).await;
    let b2 = read_banner(listen_port_of(&s2)).await;
    assert!(b1.contains("SSH-") && b2.contains("SSH-"), "{b1} / {b2}");

    // 停一条: 只释放本隧道租约, 共享连接保持 (兄弟不受影响)
    registry.stop(&s1.id).await.expect("停止失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Stopped)).await;
    let stats = registry.conn_stats().await;
    assert_eq!(stats[0].leases.len(), 1, "停一条后只剩一条租约: {stats:?}");
    assert!(
        matches!(
            registry.list().iter().find(|(s, _)| s.id == s2.id),
            Some((_, TunnelState::Running))
        ),
        "兄弟隧道应保持 Running"
    );
    let b2 = read_banner(listen_port_of(&s2)).await;
    assert!(b2.contains("SSH-"), "兄弟隧道通路应仍可用: {b2}");

    registry.stop(&s2.id).await.expect("停止失败");
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Stopped)).await;
}

/// 池内整连掉线: 两条成员隧道全部退避重连, single-flight 保证只重建一次
#[tokio::test]
async fn shared_pool_drop_reconnects_all() {
    let registry = Registry::new();
    let events: Arc<dyn TunnelEvents> = Arc::new(Collector::default());
    let mut s1 = local_spec(free_port());
    s1.profile_id = "p-drop".into();
    let mut s2 = local_spec(free_port());
    s2.profile_id = "p-drop".into();
    registry.create(s1.clone()).expect("创建失败");
    registry.create(s2.clone()).expect("创建失败");
    registry
        .start(&s1.id, creds(), events.clone())
        .await
        .expect("启动失败");
    registry
        .start(&s2.id, creds(), events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Running)).await;
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Running)).await;
    assert_eq!(registry.conn_stats().await[0].connect_count, 1);

    // 模拟网络掉线: 硬断一条隧道所在的 (共享) 连接 —— 两条全部进退避
    registry.drop_connection(&s1.id).await.expect("硬断失败");
    wait_state(&registry, &s1.id, |s| {
        matches!(s, TunnelState::Backoff { attempt: 1, .. })
    })
    .await;
    wait_state(&registry, &s2.id, |s| {
        matches!(s, TunnelState::Backoff { attempt: 1, .. })
    })
    .await;
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Running)).await;
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Running)).await;

    // single-flight: 两条隧道各自重试, 池只重建一次连接
    let stats = registry.conn_stats().await;
    assert_eq!(stats.len(), 1);
    assert_eq!(
        stats[0].connect_count, 2,
        "掉线重连全员只多建一次连接: {stats:?}"
    );
    assert_eq!(stats[0].leases.len(), 2, "重连后两条租约都回来: {stats:?}");

    // 通路仍可用
    let b1 = read_banner(listen_port_of(&s1)).await;
    assert!(b1.contains("SSH-"), "{b1}");

    registry.stop(&s1.id).await.expect("停止失败");
    registry.stop(&s2.id).await.expect("停止失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Stopped)).await;
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Stopped)).await;
}

/// share=false: 不入池 (stats 空), 各隧道独立连接互不影响
#[tokio::test]
async fn dedicated_when_share_off() {
    let registry = Registry::new();
    let events: Arc<dyn TunnelEvents> = Arc::new(Collector::default());
    let mut s1 = local_spec(free_port());
    s1.profile_id = "p-dedicated".into();
    let mut s2 = local_spec(free_port());
    s2.profile_id = "p-dedicated".into();
    registry.create(s1.clone()).expect("创建失败");
    registry.create(s2.clone()).expect("创建失败");

    let mut c = creds();
    c.share = false;
    registry
        .start(&s1.id, c.clone(), events.clone())
        .await
        .expect("启动失败");
    registry
        .start(&s2.id, c, events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Running)).await;
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Running)).await;

    assert!(
        registry.conn_stats().await.is_empty(),
        "不共享时池应为空 (游离连接不入表)"
    );

    // 停一条不影响另一条 (本就是独立连接)
    registry.stop(&s1.id).await.expect("停止失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Stopped)).await;
    let b2 = read_banner(listen_port_of(&s2)).await;
    assert!(b2.contains("SSH-"), "{b2}");

    registry.stop(&s2.id).await.expect("停止失败");
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Stopped)).await;
}

/// 反向隧道 spec (端口 0 动态分配; 落地指向本机不存在端口也无妨 ——
/// Running 判定只看转发建立, 不看落地数据)
fn reverse_spec(profile: &str) -> TunnelSpec {
    TunnelSpec {
        id: TunnelSpec::new_id(),
        name: "引擎测试-反向".into(),
        enabled: true,
        profile_id: profile.into(),
        kind: TunnelKind::Reverse {
            bind: "127.0.0.1".into(),
            port: 0,
        },
        backend: Backend::Tcp("127.0.0.1".into(), 59999),
        policy: ReconnectPolicy::default(),
    }
}

/// 从注册表读回填后的反向端口 (BoundPort 回填 spec)
fn reverse_port_of(registry: &Registry, id: &str) -> u16 {
    match registry.list().iter().find(|(s, _)| &s.id == id) {
        Some((s, _)) => match &s.kind {
            TunnelKind::Reverse { port, .. } => *port,
            _ => panic!("预期 Reverse 形态"),
        },
        None => panic!("隧道不存在: {id}"),
    }
}

/// 同档案两条反向隧道 (端口 0) 共享一条连接: 双 Running、动态端口互异、
/// 池 1 条目 / 建连 1 次 / 2 租约
#[tokio::test]
async fn shared_reverse_two_tunnels() {
    let registry = Registry::new();
    let events: Arc<dyn TunnelEvents> = Arc::new(Collector::default());
    let s1 = reverse_spec("p-rev-share");
    let s2 = reverse_spec("p-rev-share");
    registry.create(s1.clone()).expect("创建失败");
    registry.create(s2.clone()).expect("创建失败");

    registry
        .start(&s1.id, creds(), events.clone())
        .await
        .expect("启动失败");
    registry
        .start(&s2.id, creds(), events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Running)).await;
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Running)).await;

    // 端口 0 动态分配: 两条各自回填, 互不相同
    let (p1, p2) = (
        reverse_port_of(&registry, &s1.id),
        reverse_port_of(&registry, &s2.id),
    );
    assert!(p1 != 0 && p2 != 0, "端口应已回填: {p1} {p2}");
    assert_ne!(p1, p2, "两条隧道的动态端口应互异");

    let stats = registry.conn_stats().await;
    assert_eq!(stats.len(), 1, "同档案应只有一个池条目: {stats:?}");
    assert_eq!(stats[0].connect_count, 1, "两条反向隧道只建连一次");
    assert_eq!(stats[0].leases.len(), 2, "两条租约: {stats:?}");

    registry.stop(&s1.id).await.expect("停止失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Stopped)).await;
    let stats = registry.conn_stats().await;
    assert_eq!(stats[0].leases.len(), 1, "停一条后剩一条租约: {stats:?}");
    assert!(
        matches!(
            registry.list().iter().find(|(s, _)| s.id == s2.id),
            Some((_, TunnelState::Running))
        ),
        "兄弟反向隧道应保持 Running"
    );

    registry.stop(&s2.id).await.expect("停止失败");
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Stopped)).await;
}

/// 停止反向隧道释放服务器端口 (cancel 转发 / 助手退出), 兄弟端口不受影响
#[tokio::test]
async fn stop_reverse_releases_port() {
    let registry = Registry::new();
    let events: Arc<dyn TunnelEvents> = Arc::new(Collector::default());
    let s1 = reverse_spec("p-rev-release");
    let s2 = reverse_spec("p-rev-release");
    registry.create(s1.clone()).expect("创建失败");
    registry.create(s2.clone()).expect("创建失败");
    registry
        .start(&s1.id, creds(), events.clone())
        .await
        .expect("启动失败");
    registry
        .start(&s2.id, creds(), events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Running)).await;
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Running)).await;
    // 注入服务器 std→兼容回退会二次回填端口: 等端口稳定 (1.2s 不变) 再断言监听
    let (p1, p2) = {
        let mut last = (0u16, 0u16);
        let mut last_change = std::time::Instant::now();
        let mut got = None;
        for _ in 0..400 {
            let cur = (
                reverse_port_of(&registry, &s1.id),
                reverse_port_of(&registry, &s2.id),
            );
            if cur != last {
                last = cur;
                last_change = std::time::Instant::now();
            }
            if cur.0 != 0 && cur.1 != 0 && last_change.elapsed() >= Duration::from_millis(1200) {
                got = Some(cur);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        got.expect("等待双隧道端口回填稳定超时")
    };

    // 双端口都在监听
    assert!(
        ss_listening(registry.known_hosts(), p1).await,
        "p1 应在监听"
    );
    assert!(
        ss_listening(registry.known_hosts(), p2).await,
        "p2 应在监听"
    );

    // 停 s1: 其端口释放 (标准模式 cancel / 兼容模式助手退出), p2 保持
    registry.stop(&s1.id).await.expect("停止失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Stopped)).await;
    let mut released = false;
    for _ in 0..20 {
        if !ss_listening(registry.known_hosts(), p1).await {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(released, "停止后服务器端口 {p1} 应释放");
    assert!(
        ss_listening(registry.known_hosts(), p2).await,
        "兄弟端口 {p2} 应保持监听"
    );

    registry.stop(&s2.id).await.expect("停止失败");
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Stopped)).await;
}

/// 服务器侧检查端口是否在监听 (经 remote_exec 独立连接, TOFU 共享注册表)。
/// 注: sshd 对 localhost 双栈绑定 (127.0.0.1 + [::1]), 一条转发 = 2 行,
/// 判定用「匹配行数 ≥ 1」而非恰等于 1。
async fn ss_listening_raw(
    known_hosts: &Arc<proxy_tool_core::known_hosts::KnownHosts>,
    port: u16,
) -> usize {
    let c = proxy_tool_core::creds::load();
    let out = proxy_tool_core::ssh::remote_exec(
        &c.server,
        c.port,
        &c.user,
        &AuthMethod::Password(c.pass.clone()),
        &format!("ss -tln | grep -c ':{port} ' || true"),
        Duration::from_secs(15),
        known_hosts,
    )
    .await
    .unwrap_or_else(|e| panic!("remote_exec 失败: {e}"));
    out.trim().parse::<usize>().unwrap_or(0)
}

async fn ss_listening(
    known_hosts: &Arc<proxy_tool_core::known_hosts::KnownHosts>,
    port: u16,
) -> bool {
    ss_listening_raw(known_hosts, port).await >= 1
}

/// C4 预算准入: 两条 Local (cost 2) + max_sessions=3 —— 第一条入池,
/// 第二条准入被拒 (已承诺 2+2 > 3) 自动回退独立连接 (游离, 不入池表)。
/// 两条都应 Running 且通路可用; 池内只 1 租约 1 建连; 日志含回退告警。
#[tokio::test]
async fn budget_fallback_to_dedicated() {
    let registry = Registry::new();
    let collector = Collector::default();
    let events: Arc<dyn TunnelEvents> = Arc::new(collector.clone());
    let mut s1 = local_spec(free_port());
    s1.profile_id = "p-budget".into();
    let mut s2 = local_spec(free_port());
    s2.profile_id = "p-budget".into();
    registry.create(s1.clone()).expect("创建失败");
    registry.create(s2.clone()).expect("创建失败");

    let creds = creds_with(3);
    registry
        .start(&s1.id, creds.clone(), events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Running)).await;
    registry
        .start(&s2.id, creds, events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Running)).await;

    // 池内只有第一条 (第二条游离, 不入池表)
    let stats = registry.conn_stats().await;
    assert_eq!(stats.len(), 1, "池应只有 p-budget 条目: {stats:?}");
    assert_eq!(stats[0].connect_count, 1, "池内只建连一次");
    assert_eq!(
        stats[0].leases,
        vec![s1.id.clone()],
        "只有第一条入池: {stats:?}"
    );
    // 回退告警出现在日志
    assert!(
        collector
            .logs
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.contains("共享连接预算已满") && m.contains("自动回退为独立连接")),
        "应发出预算回退告警: {:?}",
        collector.logs.lock().unwrap()
    );
    // 两条通路都可用 (第二条走自己的独立连接)
    let b1 = read_banner(listen_port_of(&s1)).await;
    let b2 = read_banner(listen_port_of(&s2)).await;
    assert!(b1.contains("SSH-") && b2.contains("SSH-"), "{b1} / {b2}");

    registry.stop(&s1.id).await.expect("停止失败");
    registry.stop(&s2.id).await.expect("停止失败");
    wait_state(&registry, &s1.id, |s| matches!(s, TunnelState::Stopped)).await;
    wait_state(&registry, &s2.id, |s| matches!(s, TunnelState::Stopped)).await;
}

/// C4 耗尽告警: 一条 Local (cost 2) + max_sessions=2 准入放行;
/// 并发 2 条数据连接把活通道数压到预算 —— 第 2 条 direct 通道打开时告警
/// (客户端发起通道也计数, 不止服务器发起的转发)。
#[tokio::test]
async fn exhaustion_warning_emitted() {
    let registry = Registry::new();
    let collector = Collector::default();
    let events: Arc<dyn TunnelEvents> = Arc::new(collector.clone());
    let spec = local_spec(free_port());
    registry.create(spec.clone()).expect("创建失败");
    registry
        .start(&spec.id, creds_with(2), events.clone())
        .await
        .expect("启动失败");
    wait_state(&registry, &spec.id, |s| matches!(s, TunnelState::Running)).await;

    // 两条并发数据连接: 各开一条 direct_tcpip (计数 1 → 2)。
    // 不读不写保持半开 —— 通道存活期间计数不回零, sshd banner 缓冲即可。
    let port = listen_port_of(&spec);
    let mut conns = Vec::new();
    for _ in 0..2 {
        conns.push(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.expect("连接失败"));
    }
    // 等接受 + 通道打开 + 告警发出 (打开有真实网络往返, 留足窗口)
    let mut warned = false;
    for _ in 0..30 {
        if collector
            .logs
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.contains("已达预算"))
        {
            warned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    drop(conns);
    assert!(warned, "应发出通道数达预算告警: {:?}", collector.logs.lock().unwrap());

    registry.stop(&spec.id).await.expect("停止失败");
    wait_state(&registry, &spec.id, |s| matches!(s, TunnelState::Stopped)).await;
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
