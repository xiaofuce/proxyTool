//! 命令生成页的用户数据 (「我的命令」+ 最近输入) —— 加密落盘
//!
//! 生成的命令不含密码, 但带服务器地址/用户名等半敏感信息, 按用户要求
//! 落盘即加密。加密 = AES-256-GCM, 密钥是同目录下首次生成的随机文件
//! —— 属于「防顺手查看/防 grep」级别, 不是对抗性安全 (密钥与密文同机
//! 存放); 凭据类数据仍遵循「永不落盘」红线, 与本模块无关。
//!
//! 文件布局 (目录由调用方注入, 与 profiles.json 同目录):
//! - `cmd_recipes.key`: 32 字节随机密钥, 首次写入后不再变动
//! - `cmd_recipes.enc`: `PTCR1` magic + 12 字节 nonce + 密文, 原子替换

use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};

/// cmd_recipes.enc 文件标识 (前缀不符 = 不可读, 静默当空)
const MAGIC: &[u8; 5] = b"PTCR1";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// 命令生成表单的一组参数 (与前端字段一一对应)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CmdParams {
    /// 形态: local | reverse | dynamic (前端 radio 值, 字符串透传)
    pub kind: String,
    /// 目标服务器 B
    pub host: String,
    pub port: u16,
    pub user: String,
    /// 监听端口
    pub listen: u16,
    /// 目标地址 (动态形态下无意义, 仍保留)
    pub target_host: String,
    pub target_port: u16,
    /// 监听 0.0.0.0
    #[serde(default)]
    pub bind_all: bool,
}

/// 用户保存的一条「我的命令」(命名参数组)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CmdRecipe {
    /// uuid (空 = 新建, 由保存方补)
    pub id: String,
    /// 命令名
    pub name: String,
    /// 参数 (serde flatten → JSON 与表单字段同层)
    #[serde(flatten)]
    pub params: CmdParams,
}

/// 落盘结构: 我的命令列表 + 最近一次输入 (打开页面时恢复)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CmdRecipeStore {
    #[serde(default)]
    pub recipes: Vec<CmdRecipe>,
    #[serde(default)]
    pub last: Option<CmdParams>,
}

fn create_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败: {e}"))
}

fn data_path(dir: &Path) -> Result<PathBuf, String> {
    create_dir(dir)?;
    Ok(dir.join("cmd_recipes.enc"))
}

fn key_path(dir: &Path) -> Result<PathBuf, String> {
    create_dir(dir)?;
    Ok(dir.join("cmd_recipes.key"))
}

/// 读取或首次生成密钥 (固定 32 字节; 损坏/超短 → 重新生成,
/// 旧密文随之作废, load 侧静默返回空)
fn load_or_create_key(dir: &Path) -> Result<[u8; KEY_LEN], String> {
    let path = key_path(dir)?;
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == KEY_LEN {
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
    }
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).map_err(|e| format!("生成密钥失败: {e}"))?;
    // 原子写, 避免写一半崩溃后密钥/密文错位
    let tmp = path.with_extension("key.tmp");
    std::fs::write(&tmp, key).map_err(|e| format!("写入密钥失败: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("替换密钥失败: {e}"))?;
    Ok(key)
}

/// 读取 (文件不存在/密钥丢失/解密失败/解析失败 → 空 store, 不阻断启动)
pub fn load_cmd_store(dir: &Path) -> CmdRecipeStore {
    let (Ok(data), Ok(key)) = (data_path(dir), load_or_create_key(dir)) else {
        return CmdRecipeStore::default();
    };
    let Ok(bytes) = std::fs::read(&data) else {
        return CmdRecipeStore::default();
    };
    if bytes.len() < MAGIC.len() + NONCE_LEN || &bytes[..MAGIC.len()] != MAGIC {
        return CmdRecipeStore::default();
    }
    let nonce = &bytes[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let cipher_text = &bytes[MAGIC.len() + NONCE_LEN..];
    let cipher = Aes256Gcm::new((&key).into());
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload { msg: cipher_text, aad: MAGIC },
        )
        .map_err(|e| format!("解密失败: {e}"))
        .and_then(|b| String::from_utf8(b).map_err(|e| format!("解码失败: {e}")));
    match plain {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => CmdRecipeStore::default(),
    }
}

/// 写入 (整体覆盖, 每次新 nonce, 原子替换)
pub fn save_cmd_store(dir: &Path, store: &CmdRecipeStore) -> Result<(), String> {
    let path = data_path(dir)?;
    let key = load_or_create_key(dir)?;
    let text = serde_json::to_string(store).map_err(|e| format!("序列化失败: {e}"))?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| format!("生成 nonce 失败: {e}"))?;
    let cipher = Aes256Gcm::new((&key).into());
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: text.as_bytes(), aad: MAGIC },
        )
        .map_err(|e| format!("加密失败: {e}"))?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    let tmp = path.with_extension("enc.tmp");
    std::fs::write(&tmp, out).map_err(|e| format!("写入配置失败: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("替换配置失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pt-cmdrec-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sample() -> CmdRecipeStore {
        let params = CmdParams {
            kind: "local".into(),
            host: "10.0.0.8".into(),
            port: 22,
            user: "root".into(),
            listen: 3307,
            target_host: "10.0.0.5".into(),
            target_port: 3306,
            bind_all: false,
        };
        CmdRecipeStore {
            recipes: vec![CmdRecipe { id: "r1".into(), name: "A 连 B 的数据库".into(), params: params.clone() }],
            last: Some(CmdParams { listen: 1080, kind: "dynamic".into(), ..params.clone() }),
        }
    }

    /// 往返无损 + 落盘内容确为密文 (明文字串不出现)
    #[test]
    fn roundtrip_and_ciphertext_is_opaque() {
        let d = dir();
        assert!(load_cmd_store(&d).recipes.is_empty(), "无文件应返回空");

        let store = sample();
        save_cmd_store(&d, &store).unwrap();
        let back = load_cmd_store(&d);
        assert_eq!(back.recipes, store.recipes);
        assert_eq!(back.last, store.last);

        let bytes = std::fs::read(data_path(&d).unwrap()).unwrap();
        assert!(bytes.starts_with(MAGIC));
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("10.0.0.8"), "内网地址不应明文出现: {text}");
        assert!(!text.contains("root"), "用户名不应明文出现");
        // 密钥文件同样不含明文痕迹, 长度 = 32
        let key = std::fs::read(key_path(&d).unwrap()).unwrap();
        assert_eq!(key.len(), KEY_LEN);
    }

    /// 二次保存 (换 nonce) 仍可读; 密钥稳定不漂移
    #[test]
    fn resave_keeps_key_stable() {
        let d = dir();
        save_cmd_store(&d, &sample()).unwrap();
        let key1 = std::fs::read(key_path(&d).unwrap()).unwrap();
        let mut s = sample();
        s.recipes.clear();
        save_cmd_store(&d, &s).unwrap();
        let key2 = std::fs::read(key_path(&d).unwrap()).unwrap();
        assert_eq!(key1, key2, "密钥不应随保存变动");
        assert!(load_cmd_store(&d).recipes.is_empty());
        assert!(load_cmd_store(&d).last.is_some());
    }

    /// 密文损坏 / magic 不符 → 空 store 不 panic; 密钥丢失 (删除) → 同样静默为空
    #[test]
    fn corrupt_or_keyless_is_empty() {
        let d = dir();
        save_cmd_store(&d, &sample()).unwrap();
        let data = data_path(&d).unwrap();

        // 篡改一个密文字节 → GCM 校验失败 → 空
        let mut bytes = std::fs::read(&data).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&data, &bytes).unwrap();
        assert!(load_cmd_store(&d).recipes.is_empty());

        // 密钥丢了 → 解不开 → 空 (且会生成新密钥, 不 panic)
        save_cmd_store(&d, &sample()).unwrap();
        std::fs::remove_file(key_path(&d).unwrap()).unwrap();
        assert!(load_cmd_store(&d).recipes.is_empty());

        // magic 不符 → 空
        std::fs::write(&data, b"XXXXrest-of-file").unwrap();
        assert!(load_cmd_store(&d).recipes.is_empty());
    }

    /// CmdRecipe JSON 契约: flatten 后 id/name 与参数同层 (前端直接消费)
    #[test]
    fn recipe_json_flattens_params() {
        let r = sample().recipes.into_iter().next().unwrap();
        let json = serde_json::to_string(&r).unwrap();
        for needle in ["\"id\":\"r1\"", "\"name\":\"A 连 B 的数据库\"", "\"kind\":\"local\"", "\"targetHost\":\"10.0.0.5\"", "\"bindAll\":false"] {
            assert!(json.contains(needle), "缺少 {needle}: {json}");
        }
        let back: CmdRecipe = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
