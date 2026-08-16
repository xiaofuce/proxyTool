//! 落盘加密原语 —— AES-256-GCM (cmd_recipes 与 secrets 共用)
//!
//! 统一文件格式: `<MAGIC> + 12B nonce + 密文`, AAD = MAGIC (magic 不符/
//! 篡改 → GCM 校验失败 → 调用方静默当空)。密钥 = 数据目录下首次生成的
//! 32 字节随机文件, 跨保存稳定; 损坏/超短 → 重新生成 (旧密文作废)。
//!
//! 安全定位 (诚实分级): 密钥与密文同机存放, 属「防顺手查看/防 grep」
//! 级别, 不是对抗性安全。凭据类数据由用户明确要求加密落盘 (secrets),
//! 红线从「密码永不落盘」改为「密码仅以本模块密文形式落盘」。

use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

fn create_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败: {e}"))
}

fn join(dir: &Path, name: &str) -> Result<PathBuf, String> {
    create_dir(dir)?;
    Ok(dir.join(name))
}

/// 读取或首次生成密钥 (固定 32 字节; 损坏/超短 → 重新生成,
/// 旧密文随之作废, open 侧静默返回空)
pub fn load_or_create_key(dir: &Path, key_file: &str) -> Result<[u8; KEY_LEN], String> {
    let path = join(dir, key_file)?;
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

/// 解密 (文件不存在/密钥丢失/解密失败/解析失败 → None, 调用方给默认值)
pub fn open(dir: &Path, enc_file: &str, key_file: &str, magic: &[u8]) -> Option<String> {
    let (data, key) = (join(dir, enc_file).ok()?, load_or_create_key(dir, key_file).ok()?);
    let bytes = std::fs::read(data).ok()?;
    if bytes.len() < magic.len() + NONCE_LEN || &bytes[..magic.len()] != magic {
        return None;
    }
    let nonce = &bytes[magic.len()..magic.len() + NONCE_LEN];
    let cipher_text = &bytes[magic.len() + NONCE_LEN..];
    let plain = Aes256Gcm::new((&key).into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload { msg: cipher_text, aad: magic },
        )
        .ok()?;
    String::from_utf8(plain).ok()
}

/// 加密写入 (整体覆盖, 每次新 nonce, 原子替换)
pub fn seal(dir: &Path, enc_file: &str, key_file: &str, magic: &[u8], plain: &str) -> Result<(), String> {
    let path = join(dir, enc_file)?;
    let key = load_or_create_key(dir, key_file)?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| format!("生成 nonce 失败: {e}"))?;
    let sealed = Aes256Gcm::new((&key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plain.as_bytes(), aad: magic },
        )
        .map_err(|e| format!("加密失败: {e}"))?;

    let mut out = Vec::with_capacity(magic.len() + NONCE_LEN + sealed.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    let tmp = path.with_extension("enc.tmp");
    std::fs::write(&tmp, out).map_err(|e| format!("写入配置失败: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("替换配置失败: {e}"))
}
