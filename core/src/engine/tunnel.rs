//! 单隧道状态机任务 (设计 §3.3/§3.5)
//!
//! 每条运行中的隧道一个 tokio 任务: 反反复复执行「尝试建立并运行直到断开」,
//! 按 `TunnelError::retryable()` 决策 —— 致命错误立即 Failed, 可重试错误进入
//! FastBackoff 退避。状态经 watch 通道暴露给注册表快照, 事件经 `TunnelEvents`
//! 发出 (id + kind tag, 迁移期与旧前端事件一一对应)。
//!
//! P4 重连语义 (融合 frp / rathole / autossh, 设计 §3.5):
//! - **FastBackoff** (frp): 断线先 `fast_retries` × 1s 快试 (闪断秒恢复),
//!   之后指数 2→4→…→`max_backoff` 封顶;
//! - **存活重置** (rathole): 连接存活 ≥ `alive_reset` (默认 3s) 后断线,
//!   退避计数归零——长稳连接偶发掉线不受 30s 惩罚, 掉线频繁才递增;
//! - **立即重试** (autossh SIGHUP): Backoff 等待期间 `retry_now` 置位即
//!   跳过剩余等待马上重连;
//! - **保活显式化** (OpenSSH): policy → `Keepalive` (判死时延 = interval × max)。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::backend::BackendPool;
use crate::direct;
use crate::known_hosts::KnownHosts;
use crate::model::{ReconnectPolicy, TunnelError, TunnelKind, TunnelSpec, TunnelState};
use crate::ssh::Logger;
use crate::tunnel::{self, TunnelEvent};
use crate::TunnelEvents;

use super::pool::{self, ConnPool};
use super::{SessionSlot, SshCreds};

/// 第 n 次重连前的等待时长 (n 从 1 起)。
/// FastBackoff (frp) + 现状指数序列 (1→2→4→…→封顶) 的复合:
/// 先 `fast_retries` × 1s 快试, 之后指数序列从 1s 重新起步。
/// fast_retries=3: 1,1,1, 1,2,4,8,16,30,30…; fast_retries=0: 1,2,4,8,16,30…
fn wait_before(policy: &ReconnectPolicy, n: u32) -> Duration {
    let exp = if n <= policy.fast_retries {
        return Duration::from_secs(1);
    } else {
        n - policy.fast_retries - 1 // 快试之后的指数序号: 0,1,2,…
    };
    // 2^exp 秒, 封顶 max_backoff (指数溢出按饱和处理)
    let secs = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
    Duration::min(Duration::from_secs(secs), policy.max_backoff)
}

/// 退避等待的结果
enum BackoffOutcome {
    /// 等满, 正常进入下一次尝试
    Completed,
    /// 用户请求停止
    Stopped,
    /// UI 请求立即重试 (跳过剩余等待)
    RetryNow,
}

/// 退避等待 `dur`: 每 200ms 检查停止/立即重试标志。
async fn backoff_wait(stop: &AtomicBool, retry_now: &AtomicBool, dur: Duration) -> BackoffOutcome {
    let mut waited = Duration::ZERO;
    loop {
        if stop.load(Ordering::SeqCst) {
            return BackoffOutcome::Stopped;
        }
        if retry_now.swap(false, Ordering::SeqCst) {
            return BackoffOutcome::RetryNow;
        }
        if waited >= dur {
            return BackoffOutcome::Completed;
        }
        let step = std::cmp::min(Duration::from_millis(200), dur - waited);
        tokio::time::sleep(step).await;
        waited += step;
    }
}

/// 单隧道运行任务 (由 Registry 启动)。
/// `on_bound_port`: 反向隧道端口 0 动态分配时, 服务器实际监听端口回填回调。
/// 退出时置终态 (Stopped/Failed) 并清空会话槽。
pub(super) async fn run_task(
    spec: TunnelSpec,
    creds: SshCreds,
    slot: SessionSlot,
    stop: Arc<AtomicBool>,
    retry_now: Arc<AtomicBool>,
    state_tx: watch::Sender<TunnelState>,
    backend: Arc<BackendPool>,
    known_hosts: Arc<KnownHosts>,
    pool: Arc<ConnPool>,
    events: Arc<dyn TunnelEvents>,
    on_bound_port: Arc<dyn Fn(u16) + Send + Sync>,
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
    // 进入 Running 的时刻 (alive_reset 判据: 存活多久)
    let connected_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let mut n = 0u32;
    loop {
        // 循环顶检查: 覆盖「任务启动前用户已请求停止」的窗口
        if stop.load(Ordering::SeqCst) {
            finish(&state_tx, &events, &id, tag, &Ok(()), &slot).await;
            return;
        }
        *connected_at.lock().unwrap() = None;
        let _ = state_tx.send(TunnelState::Starting);
        events.status(&id, tag, "connecting", None);

        let result = attempt(
            &spec,
            &creds,
            &slot,
            &stop,
            &state_tx,
            &events,
            &logger,
            &reverse_local,
            &on_bound_port,
            &connected_at,
            &known_hosts,
            &pool,
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
        // rathole 存活重置: 长稳连接 (存活 ≥ alive_reset) 断线后从头快试
        let alive_long = connected_at
            .lock()
            .unwrap()
            .is_some_and(|t0| t0.elapsed() >= spec.policy.alive_reset);
        if alive_long {
            if n != 0 {
                events.log(&id, tag, "连接存活超过重置阈值, 退避计数归零");
            }
            n = 0;
        }
        n += 1;
        let wait = wait_before(&spec.policy, n);
        let _ = state_tx.send(TunnelState::Backoff {
            attempt: n,
            wait_secs: wait.as_secs(),
        });
        events.status(
            &id,
            tag,
            "reconnecting",
            Some(&format!("第 {n} 次重连, {}s 后重试", wait.as_secs())),
        );
        match backoff_wait(&stop, &retry_now, wait).await {
            BackoffOutcome::Stopped => {
                finish(&state_tx, &events, &id, tag, &Ok(()), &slot).await;
                return;
            }
            BackoffOutcome::RetryNow => {
                events.log(&id, tag, "跳过剩余等待, 立即重试");
            }
            BackoffOutcome::Completed => {}
        }
    }
}

/// 一次尝试: 建立并运行隧道直到断开 (Ok) 或建连失败 (Err)。
/// 会话句柄填入共享槽 (注册表据此硬断开), 结束时清槽。
/// `connected_at`: 进入 Running 时写入 (alive_reset 判据)。
///
/// 三种形态统一经 ConnPool 取租约 (share=true 复用同档案连接, false 游离),
/// attempt 结束显式 `lease.close()` (共享 = 末位才断连; 游离 = 立即断连)。
#[allow(clippy::too_many_arguments)]
async fn attempt(
    spec: &TunnelSpec,
    creds: &SshCreds,
    slot: &SessionSlot,
    stop: &Arc<AtomicBool>,
    state_tx: &watch::Sender<TunnelState>,
    events: &Arc<dyn TunnelEvents>,
    logger: &Logger,
    reverse_local: &Option<(String, u16)>,
    on_bound_port: &Arc<dyn Fn(u16) + Send + Sync>,
    connected_at: &Arc<Mutex<Option<Instant>>>,
    known_hosts: &Arc<KnownHosts>,
    pool: &Arc<ConnPool>,
) -> Result<(), TunnelError> {
    let id = spec.id.clone();
    let tag = spec.kind.tag();
    // 保活来自隧道策略 (显式化: 判死时延 = interval × max, 默认 10s×3 ≈ 30s)
    let keepalive = crate::ssh::Keepalive {
        interval: spec.policy.keepalive,
        max: spec.policy.keepalive_max,
    };
    match &spec.kind {
        TunnelKind::Reverse { port, .. } => {
            let (local_host, local_port) = reverse_local
                .clone()
                .expect("反向隧道的本地落地在任务启动前已解析");
            let cfg = tunnel::TunnelConfig {
                server_host: creds.host.clone(),
                server_port: creds.port,
                username: creds.username.clone(),
                auth: creds.auth.clone(),
                remote_port: *port as u32,
                local_proxy_host: local_host,
                local_proxy_port: local_port,
                keepalive,
                known_hosts: known_hosts.clone(),
            };
            // start_tunnel_on 回调: Connected → Running; BoundPort → 注册表回填
            let st = state_tx.clone();
            let ev = events.clone();
            let id2 = id.clone();
            let t0 = connected_at.clone();
            let bound = on_bound_port.clone();
            let on_event: tunnel::OnTunnelEvent = Arc::new(move |e: TunnelEvent| match e {
                TunnelEvent::Connected => {
                    *t0.lock().unwrap() = Some(Instant::now());
                    let _ = st.send(TunnelState::Running);
                    ev.status(&id2, tag, "connected", None);
                }
                TunnelEvent::BoundPort(p) => bound(p),
            });
            let SessionSlot::Reverse(rslot) = slot else {
                unreachable!("反向隧道配反向会话槽");
            };
            let lease = pool
                .acquire(
                    &spec.profile_id,
                    &id,
                    creds,
                    keepalive,
                    known_hosts,
                    logger,
                    // 形态建连期未定 (std/compat), 按最重形态估
                    pool::COST_STD_REVERSE,
                )
                .await?;
            let r = tunnel::start_tunnel_on(
                rslot.clone(),
                lease.state(),
                cfg,
                logger.clone(),
                on_event,
                stop,
            )
            .await;
            // 会话收尾: 槽内还有会话 = 本任务自己退出 (断线) → 拆除;
            // 注册表已取走 (用户停止) 则无操作
            if let Some(sess) = rslot.lock().await.take() {
                sess.teardown(false).await;
            }
            lease.close().await;
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
                auth: creds.auth.clone(),
                listen_host: bind.clone(),
                listen_port: *port,
                keepalive,
                known_hosts: known_hosts.clone(),
            };
            let lease = pool
                .acquire(
                    &spec.profile_id,
                    &id,
                    creds,
                    keepalive,
                    known_hosts,
                    logger,
                    pool::COST_DIRECT,
                )
                .await?;
            let r = direct::run_local_forward_on(
                lease.state(),
                &cfg,
                target_host.clone(),
                *target_port,
                logger.clone(),
                lease.is_shared(),
            )
            .await;
            match r {
                Ok((session, task)) => {
                    let out = run_direct_session(
                        slot,
                        session,
                        task,
                        state_tx,
                        events,
                        &id,
                        tag,
                        connected_at,
                    )
                    .await;
                    lease.close().await;
                    out
                }
                Err(e) => {
                    lease.close().await;
                    Err(e)
                }
            }
        }
        TunnelKind::Dynamic { port, bind } => {
            let cfg = direct::DirectConfig {
                server_host: creds.host.clone(),
                server_port: creds.port,
                username: creds.username.clone(),
                auth: creds.auth.clone(),
                listen_host: bind.clone(),
                listen_port: *port,
                keepalive,
                known_hosts: known_hosts.clone(),
            };
            let lease = pool
                .acquire(
                    &spec.profile_id,
                    &id,
                    creds,
                    keepalive,
                    known_hosts,
                    logger,
                    pool::COST_DIRECT,
                )
                .await?;
            let r = direct::run_dynamic_forward_on(lease.state(), &cfg, logger.clone(), lease.is_shared())
                .await;
            match r {
                Ok((session, task)) => {
                    let out = run_direct_session(
                        slot,
                        session,
                        task,
                        state_tx,
                        events,
                        &id,
                        tag,
                        connected_at,
                    )
                    .await;
                    lease.close().await;
                    out
                }
                Err(e) => {
                    lease.close().await;
                    Err(e)
                }
            }
        }
    }
}

/// 本地/动态隧道: 会话入槽 → Running → 运行任务直到断开 → 清槽
#[allow(clippy::too_many_arguments)]
async fn run_direct_session(
    slot: &SessionSlot,
    session: Arc<direct::DirectSession>,
    task: tokio::task::JoinHandle<()>,
    state_tx: &watch::Sender<TunnelState>,
    events: &Arc<dyn TunnelEvents>,
    id: &str,
    tag: &str,
    connected_at: &Arc<Mutex<Option<Instant>>>,
) -> Result<(), TunnelError> {
    let SessionSlot::Direct(dslot) = slot else {
        unreachable!("本地/动态隧道配直连会话槽");
    };
    *dslot.lock().await = Some(session);
    *connected_at.lock().unwrap() = Some(Instant::now());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ReconnectPolicy;

    fn policy(fast_retries: u32) -> ReconnectPolicy {
        ReconnectPolicy {
            auto: true,
            fast_retries,
            ..ReconnectPolicy::default()
        }
    }

    /// FastBackoff 序列: 3×1s 快试 → 指数 1,2,4,8,16 → 30 封顶
    #[test]
    fn fast_backoff_sequence() {
        let p = policy(3);
        let seq: Vec<u64> = (1..=8).map(|n| wait_before(&p, n).as_secs()).collect();
        assert_eq!(seq, vec![1, 1, 1, 1, 2, 4, 8, 16]);
        // 封顶之后稳定 30s
        assert_eq!(wait_before(&p, 9).as_secs(), 30);
        assert_eq!(wait_before(&p, 99).as_secs(), 30);
    }

    /// fast_retries = 0: 直接指数退避 (1,2,4,…) —— 与旧版行为一致的形态
    #[test]
    fn no_fast_retries_is_pure_exponential() {
        let p = policy(0);
        let seq: Vec<u64> = (1..=5).map(|n| wait_before(&p, n).as_secs()).collect();
        assert_eq!(seq, vec![1, 2, 4, 8, 16]);
    }

    /// max_backoff 可配置
    #[test]
    fn max_backoff_respected() {
        let p = ReconnectPolicy {
            max_backoff: Duration::from_secs(5),
            ..policy(0)
        };
        assert_eq!(wait_before(&p, 1).as_secs(), 1);
        assert_eq!(wait_before(&p, 3).as_secs(), 4);
        assert_eq!(wait_before(&p, 4).as_secs(), 5);
        assert_eq!(wait_before(&p, 10).as_secs(), 5);
    }
}
