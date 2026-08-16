//! 服务器凭据 (SSH 密码 / 私钥口令) —— 按用户要求加密落盘
//!
//! 跨平台统一方案: AES-256-GCM (原语在 `crypto.rs`), 密文是 app data 目录
//! 下一个文件, mac/win/linux 同一代码路径, 不依赖任何平台密钥库。
//! 键 = 档案 id (服务器档案级, 同档案多条隧道共享一条 SSH 连接共用一份凭据)。
//!
//! 文件布局 (与 profiles.json 同目录):
//! - `secrets.key`: 32 字节随机密钥, 首次写入后不再变动
//! - `secrets.enc`: `PTSR1` magic + 12 字节 nonce + 密文 (JSON map), 原子替换
//!
//! 安全定位 (诚实分级, 见 crypto.rs): 密钥与密文同机存放 = 防顺手查看级。
//! 红线相应改写: 凭据**仅以本模块密文形式**落盘, 任何明文路径 (日志/
//! profiles.json/其他 store) 仍然禁止。
//!
//! 文件缺失/密钥丢失/解密失败 → 空 store 不 panic (重输即恢复)。

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto;

/// secrets.enc 文件标识 (前缀不符 = 不可读, 静默当空)
const MAGIC: &[u8; 5] = b"PTSR1";
const ENC_FILE: &str = "secrets.enc";
const KEY_FILE: &str = "secrets.key";

/// 档案 id → 凭据 (密码或私钥口令)。BTreeMap: 落盘字段序稳定。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretStore {
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
}

impl SecretStore {
    pub fn set(&mut self, profile_id: &str, secret: &str) {
        self.secrets.insert(profile_id.to_string(), secret.to_string());
    }

    pub fn get(&self, profile_id: &str) -> Option<&str> {
        self.secrets.get(profile_id).map(|s| s.as_str())
    }

    /// 删除一条 (不存在 = 无操作)
    pub fn remove(&mut self, profile_id: &str) {
        self.secrets.remove(profile_id);
    }

    pub fn contains(&self, profile_id: &str) -> bool {
        self.secrets.contains_key(profile_id)
    }
}

/// 读取 (文件不存在/密钥丢失/解密失败/解析失败 → 空 store, 不阻断启动)
pub fn load_secret_store(dir: &Path) -> SecretStore {
    crypto::open(dir, ENC_FILE, KEY_FILE, MAGIC)
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// 写入 (整体覆盖, 每次新 nonce, 原子替换)
pub fn save_secret_store(dir: &Path, store: &SecretStore) -> Result<(), String> {
    let text = serde_json::to_string(store).map_err(|e| format!("序列化失败: {e}"))?;
    crypto::seal(dir, ENC_FILE, KEY_FILE, MAGIC, &text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_recipes;

    fn dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pt-secrets-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 往返无损 + 落盘内容确为密文 (密码明文不出现)
    #[test]
    fn roundtrip_and_ciphertext_is_opaque() {
        let d = dir();
        assert!(!load_secret_store(&d).contains("p1"), "无文件应返回空");

        let mut s = SecretStore::default();
        s.set("p1", "S3cret!密码");
        s.set("p2", "");
        save_secret_store(&d, &s).unwrap();
        let back = load_secret_store(&d);
        assert_eq!(back.get("p1"), Some("S3cret!密码"));
        assert_eq!(back.get("p2"), Some(""));

        let bytes = std::fs::read(d.join(ENC_FILE)).unwrap();
        assert!(bytes.starts_with(MAGIC));
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("S3cret"), "密码明文不应出现在密文文件: {text}");
        assert_eq!(std::fs::read(d.join(KEY_FILE)).unwrap().len(), crypto::KEY_LEN);
    }

    /// 删除条目 + 覆盖更新 (改密码场景)
    #[test]
    fn remove_and_overwrite() {
        let d = dir();
        let mut s = SecretStore::default();
        s.set("p1", "old");
        s.set("p1", "new");
        s.remove("p2"); // 不存在的键 = 无操作
        s.remove("p1");
        s.set("p1", "kept");
        save_secret_store(&d, &s).unwrap();
        let back = load_secret_store(&d);
        assert_eq!(back.get("p1"), Some("kept"));
        assert!(!back.contains("p2"));
    }

    /// 密文损坏 / 密钥丢失 → 空 store 不 panic (重输即恢复)
    #[test]
    fn corrupt_or_keyless_is_empty() {
        let d = dir();
        let mut s = SecretStore::default();
        s.set("p1", "x");
        save_secret_store(&d, &s).unwrap();

        let mut bytes = std::fs::read(d.join(ENC_FILE)).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(d.join(ENC_FILE), bytes).unwrap();
        assert!(!load_secret_store(&d).contains("p1"));

        save_secret_store(&d, &s).unwrap();
        std::fs::remove_file(d.join(KEY_FILE)).unwrap();
        assert!(!load_secret_store(&d).contains("p1"));
    }

    /// 与 cmd_recipes 的密文互不通用 (magic 隔离, 各自密钥独立)
    #[test]
    fn magic_isolates_stores() {
        let d = dir();
        let mut s = SecretStore::default();
        s.set("p1", "x");
        save_secret_store(&d, &s).unwrap();
        // cmd_recipes 读 secrets.enc → magic 不符 → 空, 不串数据
        assert!(cmd_recipes::load_cmd_store(&d).recipes.is_empty());
    }
}
