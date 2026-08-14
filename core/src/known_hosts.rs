//! 服务器主机密钥记忆库 (TOFU, OpenSSH StrictHostKeyChecking=accept-new 语义)
//!
//! P6: 所有出站 SSH 连接 (反向/本地/动态/remote_exec) 统一走本模块校验:
//! - 首次连接: 记住指纹 (known_hosts.json, 与 profiles/tunnels 同目录), 放行;
//! - 再次连接: 指纹一致放行;
//! - 指纹变更: 拒绝 + **致命错误** (`TunnelError::HostKeyChanged`, 不进重连 ——
//!   重连无意义, 且可能是中间人攻击)。服务器确已重装时, 用户在 UI 清除记录
//!   后重连即重新 TOFU。
//!
//! russh 的 `check_server_key` 只能返回 bool (false → `russh::Error::UnknownKey`),
//! 类型化错误经 `HostKeyCheck` 共享状态带回: 连接失败后调用方 `take_error()`
//! 把 UnknownKey 转换为 `TunnelError::HostKeyChanged` (与 transport 的
//! corrupted 标志同一手法)。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::model::TunnelError;
use crate::ssh::Logger;

/// 已记住的一条服务器密钥 (指纹为 OpenSSH 格式 `SHA256:<base64>`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownHost {
    pub algorithm: String,
    pub fingerprint: String,
}

/// 记忆库: `"host:port" -> KnownHost`, 内存为主, 变更时原子落盘。
/// Arc 共享 (Registry 持有一份, 全部隧道/全部重连共用)。
#[derive(Debug)]
pub struct KnownHosts {
    entries: Mutex<BTreeMap<String, KnownHost>>,
    /// None = 不落盘 (测试)
    dir: Option<PathBuf>,
}

fn key_of(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// 原子写 (tmp + rename, 与 store.rs 同模式)
fn persist(path: &Path, entries: &BTreeMap<String, KnownHost>) {
    let text = match serde_json::to_string_pretty(entries) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[known_hosts] 序列化失败: {e}");
            return;
        }
    };
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, path)) {
        // 持久化失败不阻断运行, 但必须可见 (下次启动回到未记住状态)
        eprintln!("[known_hosts] known_hosts.json 保存失败: {e}");
    }
}

impl KnownHosts {
    /// 不落盘的记忆库 (测试)
    pub fn in_memory() -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(BTreeMap::new()),
            dir: None,
        })
    }

    /// 从 `<dir>/known_hosts.json` 装载 (不存在/损坏 = 空库, 不阻断启动)
    pub fn load(dir: &Path) -> Arc<Self> {
        let entries = std::fs::read_to_string(dir.join("known_hosts.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Arc::new(Self {
            entries: Mutex::new(entries),
            dir: Some(dir.to_path_buf()),
        })
    }

    /// 查询
    pub fn known(&self, host: &str, port: u16) -> Option<KnownHost> {
        self.entries
            .lock()
            .unwrap()
            .get(&key_of(host, port))
            .cloned()
    }

    /// 全量列表 (UI 展示)
    pub fn list(&self) -> Vec<(String, u16, KnownHost)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(k, v)| {
                let (h, p) = k.rsplit_once(':')?;
                Some((h.to_string(), p.parse().ok()?, v.clone()))
            })
            .collect()
    }

    /// 写入一条记忆 (TOFU 首次 / UI 信任新指纹) + 落盘
    pub fn remember(&self, host: &str, port: u16, entry: KnownHost) {
        self.entries
            .lock()
            .unwrap()
            .insert(key_of(host, port), entry);
        if let Some(dir) = &self.dir {
            persist(&dir.join("known_hosts.json"), &self.entries.lock().unwrap());
        }
    }

    /// 清除一条记忆 (服务器重装/换机后用户确认) + 落盘。返回是否确有删除。
    pub fn forget(&self, host: &str, port: u16) -> bool {
        let removed = self
            .entries
            .lock()
            .unwrap()
            .remove(&key_of(host, port))
            .is_some();
        if removed {
            if let Some(dir) = &self.dir {
                persist(&dir.join("known_hosts.json"), &self.entries.lock().unwrap());
            }
        }
        removed
    }
}

/// 单次连接的校验器: `check_server_key` 回调持有, TOFU 决策 + mismatch 详情
/// 暂存 (russh 只回 bool, 调用方在 connect 失败后 `take_error` 取类型化错误)。
pub struct HostKeyCheck {
    known: Arc<KnownHosts>,
    host: String,
    port: u16,
    logger: Logger,
    /// 指纹变更详情 (verify 时记录)
    mismatch: Mutex<Option<(String, String)>>,
}

impl HostKeyCheck {
    pub fn new(known: Arc<KnownHosts>, host: &str, port: u16, logger: Logger) -> Arc<Self> {
        Arc::new(Self {
            known,
            host: host.to_string(),
            port,
            logger,
            mismatch: Mutex::new(None),
        })
    }

    /// TOFU 校验 (check_server_key 回调): 首次记住, 一致放行, 变更拒绝。
    /// 返回给 russh 的 bool; mismatch 详情在 `take_error` 里取。
    pub fn verify(&self, key: &ssh_key::PublicKey) -> bool {
        let algorithm = key.algorithm().to_string();
        let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        match self.known.known(&self.host, self.port) {
            None => {
                self.known.remember(
                    &self.host,
                    self.port,
                    KnownHost {
                        algorithm,
                        fingerprint: fingerprint.clone(),
                    },
                );
                (self.logger)(&format!(
                    "首次连接 {}:{}, 已记住服务器指纹 {fingerprint} (TOFU)",
                    self.host, self.port
                ));
                true
            }
            Some(entry) if entry.fingerprint == fingerprint => true,
            Some(entry) => {
                (self.logger)(&format!(
                    "❌ 服务器 {}:{} 主机密钥指纹已变更 (预期 {}, 实际 {})",
                    self.host, self.port, entry.fingerprint, fingerprint
                ));
                *self.mismatch.lock().unwrap() = Some((entry.fingerprint, fingerprint));
                false
            }
        }
    }

    /// connect 失败后调用: 若失败源于指纹校验拒绝, 返回致命错误
    /// (替代原始的 `russh::Error::UnknownKey` → `Connect` 可重试误分类)。
    pub fn take_error(&self) -> Option<TunnelError> {
        self.mismatch
            .lock()
            .unwrap()
            .take()
            .map(|(expected, actual)| TunnelError::HostKeyChanged {
                host: format!("{}:{}", self.host, self.port),
                expected,
                actual,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两条不同的 ed25519 公钥 (OpenSSH 单行格式)
    const KEY_A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJl1AV4vB6DFTGXYUd0dl9nUsZbRl+3zUtnzGfTeUbL alice@example";
    const KEY_B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBAm5LhPTLMQnKaaPyvL3c1PnRfL1T4nS8smWFCeeJsb bob@example";

    fn silent() -> Logger {
        Arc::new(|_| {})
    }

    fn key(openssh: &str) -> ssh_key::PublicKey {
        ssh_key::PublicKey::from_openssh(openssh).unwrap()
    }

    /// TOFU 全生命周期: 首次记住 → 一致放行 → 变更拒绝 + 致命错误
    #[test]
    fn tofu_trust_match_reject() {
        let known = KnownHosts::in_memory();
        let check = HostKeyCheck::new(known.clone(), "srv", 22, silent());

        // 首次: 放行 + 记住
        assert!(check.verify(&key(KEY_A)));
        let remembered = known.known("srv", 22).expect("首次连接应记住指纹");
        assert_eq!(remembered.algorithm, "ssh-ed25519");
        assert!(remembered.fingerprint.starts_with("SHA256:"));
        assert!(check.take_error().is_none());

        // 一致: 放行, 无错误
        let check2 = HostKeyCheck::new(known.clone(), "srv", 22, silent());
        assert!(check2.verify(&key(KEY_A)));
        assert!(check2.take_error().is_none());

        // 变更: 拒绝 + take_error 给出 HostKeyChanged (致命)
        let check3 = HostKeyCheck::new(known.clone(), "srv", 22, silent());
        assert!(!check3.verify(&key(KEY_B)));
        let err = check3.take_error().expect("指纹变更应给出类型化错误");
        assert!(!err.retryable(), "指纹变更应为致命 (不进重连)");
        let msg = err.to_string();
        assert!(msg.contains("指纹已变更"), "信息应指向指纹变更: {msg}");
        assert!(msg.contains("SHA256:"), "信息应含指纹: {msg}");
        // take 只取一次
        assert!(check3.take_error().is_none());
    }

    /// 不同端口 = 不同条目; forget 后重新 TOFU
    #[test]
    fn port_scoped_and_forget() {
        let known = KnownHosts::in_memory();
        let c22 = HostKeyCheck::new(known.clone(), "srv", 22, silent());
        let c2222 = HostKeyCheck::new(known.clone(), "srv", 2222, silent());
        assert!(c22.verify(&key(KEY_A)));
        // 2222 未记住, 首次同样放行 (互不干扰)
        assert!(c2222.verify(&key(KEY_B)));

        assert!(known.forget("srv", 22));
        assert!(!known.forget("srv", 22), "重复 forget 返回 false");
        assert!(known.known("srv", 22).is_none());
        assert!(known.known("srv", 2222).is_some(), "2222 不受影响");

        // forget 后新指纹可重新 TOFU (服务器重装场景)
        let c = HostKeyCheck::new(known.clone(), "srv", 22, silent());
        assert!(c.verify(&key(KEY_B)));
    }

    /// 落盘往返: load 恢复记忆; list 展示全部条目
    #[test]
    fn persistence_roundtrip() {
        let dir = std::env::temp_dir().join(format!("pt-kh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let known = KnownHosts::load(&dir);
        let c = HostKeyCheck::new(known.clone(), "h1", 22, silent());
        c.verify(&key(KEY_A));

        // 新实例从盘上恢复
        let known2 = KnownHosts::load(&dir);
        assert!(known2.known("h1", 22).is_some());
        let c2 = HostKeyCheck::new(known2.clone(), "h1", 22, silent());
        assert!(!c2.verify(&key(KEY_B)), "重启后仍应拒绝变更指纹");

        // list
        let l = known2.list();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].0, "h1");
        assert_eq!(l[0].1, 22);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
