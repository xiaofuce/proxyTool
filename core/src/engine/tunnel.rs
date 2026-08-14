//! 单隧道状态机任务 (设计 §3.3/§3.5)
//!
//! 每条运行中的隧道一个 tokio 任务: 反复执行「尝试建立并运行直到断开」,
//! 按 `TunnelError::retryable()` 决策 —— 致命错误立即 Failed, 可重试错误
//! 指数退避 (1→2→…→30s 封顶)。状态经 watch 通道暴露给注册表快照,
//! 事件经 `TunnelEvents` 发出 (id + kind tag, 迁移期与旧前端事件一一对应)。
//!
//! 语义与旧 src-tauri 的 `run_with_reconnect` 逐行为等价 (P3 搬家);
//! FastBackoff / alive_reset / keepalive 显式化在 P4 落地。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::backend::BackendPool;
use crate::direct;
use crate::model::{TunnelError, TunnelKind, TunnelSpec, TunnelState};
use crate::ssh::Logger;
use crate::tunnel;
use crate::TunnelEvents;

use super::{SessionSlot, SshCreds};

/// 指数退避: 1→2→4→8→16→30→30…s (封顶 30s)
fn next_backoff(cur: Duration) -> Duration {
    std::cmp::min(cur * 2, Duration::from_secs(30))
}

/// 退避等待 `dur`, 期间每 200ms 检查停止标志; 返回 true = 用户请求停止
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

/// 单隧道运行任务 (由 Registry 启动)。
/// 退出时置终态 (Stopped/Failed) 并清空会话槽。
pub(super) async fn run_task(
    spec: TunnelSpec,
    creds: SshCreds,
    slot: SessionSlot,
    stop: Arc<AtomicBool>,
    state_tx: watch::Sender<TunnelState>,
    backend: Arc<BackendPool>,
    events: Arc<dyn TunnelEvents>,
) {
    let id = spec.id.clone();
    let tag = spec.kind.tag();
    let logger: Logger = {
        let events = events.clone();
        let id = id.clone();
        let tag = tag.to_string();
        Arc::new(move |msg: &str| events.log(&id, &tag, msg))
    };

    // 反向隧道: 本地落地 (VPN 探测/内置 SOCKS) 只解析一次,
    // 内置 SOCKS 服务器常驻 (BackendPool 缓存), 重连沿用同一端口 —— 与旧
    // resolve_local_proxy 在重连循环外只调一次的语义一致。
    let reverse_local: Option<(String, u16)> = match &spec.kind {
        TunnelKind::Reverse { .. } => match backend.resolve_reverse(&spec.backend, &logger).await {
            Ok(x) => Some(x),
            Err(e) => {
                // 落地不可用 (如内置 SOCKS 端口被占) = 致命, 不进重试
                events.log(&id, tag, &format!("❌ {e}"));
                let _ = state_tx.send(TunnelState::Failed {
                    message: e.to_string(),
                    retryable: false,
                });
                events.status(&id, tag, "error", Some(&e.to_string()));
                return;
            }
        },
        _ => None,
    };

    let policy_auto = spec.policy.auto;
    let mut backoff = Duration::from_secs(1);
    let mut n = 0u32;
    loop {
        // 循环顶检查: 覆盖「任务启动前用户已请求停止」的窗口
        if stop.load(Ordering::SeqCst) {
            finish(&state_tx, &events, &id, tag, &Ok(()), &slot).await;
            return;
        }
        let _ = state_tx.send(TunnelState::Starting);
        events.status(&id, tag, "connecting", None);

        let result = attempt(
            &spec,
            &creds,
            &slot,
            &state_tx,
            &events,
            &logger,
            &reverse_local,
        )
        .await;
        if let Err(e) = &result {
            events.log(&id, tag, &format!("❌ {e}"));
        }
        let fatal = matches!(&result, Err(e) if !e.retryable());
        if stop.load(Ordering::SeqCst) || !policy_auto || fatal {
            finish(&state_tx, &events, &id, tag, &result, &slot).await;
            return;
        }
        n += 1;
        let _ = state_tx.send(TunnelState::Backoff {
            attempt: n,
            wait_secs: backoff.as_secs(),
        });
        events.status(
            &id,
            tag,
            "reconnecting",
            Some(&format!("第 {n} 次重连, {}s 后重试", backoff.as_secs())),
        );
        if backoff_with_cancel(&stop, backoff).await {
            finish(&state_tx, &events, &id, tag, &Ok(()), &slot).await;
            return;
        }
        backoff = next_backoff(backoff);
    }
}

/// 一次尝试: 建立并运行隧道直到断开 (Ok) 或建连失败 (Err)。
/// 会话句柄填入共享槽 (注册表据此硬断开), 结束时清槽。
async fn attempt(
    spec: &TunnelSpec,
    creds: &SshCreds,
    slot: &SessionSlot,
    state_tx: &watch::Sender<TunnelState>,
    events: &Arc<dyn TunnelEvents>,
    logger: &Logger,
    reverse_local: &Option<(String, u16)>,
) -> Result<(), TunnelError> {
    let id = &spec.id;
    let tag = spec.kind.tag();
    match &spec.kind {
        TunnelKind::Reverse { port, .. } => {
            let (local_host, local_port) = reverse_local
                .clone()
                .expect("反向隧道的本地落地在任务启动前已解析");
            let cfg = tunnel::TunnelConfig {
                server_host: creds.host.clone(),
                server_port: creds.port,
                username: creds.username.clone(),
                password: creds.password.clone(),
                remote_port: *port as u32,
                local_proxy_host: local_host,
                local_proxy_port: local_port,
            };
            // start_tunnel 内部建立会话并回调 "connected", 返回 = 会话结束
            let st = state_tx.clone();
            let ev = events.clone();
            let id2 = id.clone();
            let on_status: crate::ssh::Logger = Arc::new(move |s: &str| {
                if s == "connected" {
                    let _ = st.send(TunnelState::Running);
                    ev.status(&id2, tag, "connected", None);
                }
            });
            let SessionSlot::Reverse(rslot) = slot else {
                unreachable!("反向隧道配反向会话槽");
            };
            let r = tunnel::start_tunnel(rslot.clone(), cfg, logger.clone(), on_status).await;
            *rslot.lock().await = None;
            r
        }
        TunnelKind::Local {
            port,
            target_host,
            target_port,
            bind,
        } => {
            let cfg = direct::DirectConfig {
                server_host: creds.host.clone(),
                server_port: creds.port,
                username: creds.username.clone(),
                password: creds.password.clone(),
                listen_host: bind.clone(),
                listen_port: *port,
            };
            match direct::run_local_forward(cfg, target_host.clone(), *target_port, logger.clone())
                .await
            {
                Ok((session, task)) => {
                    run_direct_session(slot, session, task, state_tx, events, id, tag).await
                }
                Err(e) => Err(e),
            }
        }
        TunnelKind::Dynamic { port, bind } => {
            let cfg = direct::DirectConfig {
                server_host: creds.host.clone(),
                server_port: creds.port,
                username: creds.username.clone(),
                password: creds.password.clone(),
                listen_host: bind.clone(),
                listen_port: *port,
            };
            match direct::run_dynamic_forward(cfg, logger.clone()).await {
                Ok((session, task)) => {
                    run_direct_session(slot, session, task, state_tx, events, id, tag).await
                }
                Err(e) => Err(e),
            }
        }
    }
}

/// 本地/动态隧道: 会话入槽 → Running → 运行任务直到断开 → 清槽
async fn run_direct_session(
    slot: &SessionSlot,
    session: Arc<direct::DirectSession>,
    task: tokio::task::JoinHandle<()>,
    state_tx: &watch::Sender<TunnelState>,
    events: &Arc<dyn TunnelEvents>,
    id: &str,
    tag: &str,
) -> Result<(), TunnelError> {
    let SessionSlot::Direct(dslot) = slot else {
        unreachable!("本地/动态隧道配直连会话槽");
    };
    *dslot.lock().await = Some(session);
    let _ = state_tx.send(TunnelState::Running);
    events.status(id, tag, "connected", None);
    let _ = task.await; // 运行直到断开 (listener 随之 drop, 释放端口)
    *dslot.lock().await = None;
    Ok(())
}

/// 终态收尾: 清槽 + 置 Stopped/Failed + 发终态事件
/// (事件语义与旧 run_with_reconnect 完全一致: Ok → disconnected, Err → error)
async fn finish(
    state_tx: &watch::Sender<TunnelState>,
    events: &Arc<dyn TunnelEvents>,
    id: &str,
    tag: &str,
    result: &Result<(), TunnelError>,
    slot: &SessionSlot,
) {
    slot.clear().await;
    match result {
        Ok(()) => {
            let _ = state_tx.send(TunnelState::Stopped);
            events.status(id, tag, "disconnected", None);
        }
        Err(e) => {
            // 认证被拒: 补充用户可操作的提示 (旧文案保持)
            let msg = if matches!(e, TunnelError::AuthRejected) {
                format!("{e} —— 已停止自动重连, 请检查用户名/密码后重新连接")
            } else {
                e.to_string()
            };
            let _ = state_tx.send(TunnelState::Failed {
                message: e.to_string(),
                retryable: e.retryable(),
            });
            events.status(id, tag, "error", Some(&msg));
        }
    }
}
