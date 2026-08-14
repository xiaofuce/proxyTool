//! 兼容模式帧协议: 编码/解码/解析状态机 (从 tunnel.rs 抽出, 独立可单测)
//!
//! # 协议 (通道两侧对称)
//!
//! 帧格式: `[u32 BE 长度][u32 BE CRC32][数据]`; 每个写单元 = `[标记帧][帧]`。
//! - **标记帧**: 12 字节常量 `[00 00 00 08][DE AD BE EF DE AD BE EF]`。
//!   幂等同步点: 任何状态都吸收 (丢弃)。注入会复制前次写入的标记帧
//!   (产生 `[M][M][f1][M][f2]` 布局), 同步后绝不回头扫描, 标记之间的真实
//!   数据帧才不会误丢。
//! - **结束帧**: `[00 00 00 04][crc32(DEADBEEF)][DE AD BE EF]` (12 字节),
//!   非零编码 —— libonion 空审计记录就是 `[00000000]`, 与零长度结束帧字节
//!   完全相同无法区分, 故结束帧不用零长度编码, 空记录按残留丢弃。
//!
//! # 注入防护 (标记帧协议)
//!
//! 云主机安全组件 (libonion) 注入 sshd 的通道 socket 写路径, 每次写入前
//! 前置审计转储 (前次写入的流量副本, 与真实帧无法区分)。双方以「跳过注入」
//! 状态开始: 丢弃一切字节直到标记帧; 标记帧前的一切只可能是注入。解析器
//! 状态机 (见 `FrameParser`):
//! - 有未完成帧 (partial): 直接补齐 —— 帧尾残余是真实数据, 不可能是注入;
//! - 无未完成帧: 扫描标记帧, 丢弃其前的一切。
//!
//! # 截断防护
//!
//! libonion 注入大写入时 sshd 的通道写被截断 (~16KB 内部缓冲), 帧尾丢失:
//! - helper 的 stdout 写入按 4KB 分块 (转储+帧恒 <16KB, 从根源避免);
//! - CRC 校验检测残留损坏帧 → 丢弃该连接 (发 End, SOCKS 客户端自动重试)
//!   并重置同步;
//! - partial 长期不补齐 → 超时重置 (调用方计时, 见 `on_partial_timeout`)。
//!
//! 服务器侧 (python3 helper) 的对称实现见 tunnel.rs 的 HELPER_PY。

/// 标记帧 (幂等同步点, 任何状态都吸收; 亦作首写触发/吸收注入)
pub const MARKER: [u8; 12] = [
    0x00, 0x00, 0x00, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
];

/// 结束帧载荷 (非零, 与 libonion 空审计记录 [00000000] 区分)
const END_PAYLOAD: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// 解出的帧: 数据帧 / 连接结束帧
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// 数据帧载荷
    Payload(Vec<u8>),
    /// 连接结束 (对端 EOF); 上层丢弃当前连接, 等待下一连接的首帧
    End,
}

/// 标准 CRC32 (与 python zlib.crc32 一致), 帧校验用
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// 校验 buf 头部是否构成完整合法帧: [长度][CRC32][数据] 且 CRC 匹配
fn frame_crc_ok(buf: &[u8], len: usize) -> bool {
    if buf.len() < 8 + len {
        return false;
    }
    let crc = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    crc32(&buf[8..8 + len]) == crc
}

/// 在 buf 中查找标记帧位置 (未同步时跳过注入用)
fn find_marker(buf: &[u8]) -> Option<usize> {
    buf.windows(MARKER.len()).position(|w| w == MARKER)
}

/// 编码一个写单元: [标记帧][数据帧]。
/// 注入转储前置在每次写入的数据前, 对端解析器丢弃标记帧前的一切。
pub fn encode_payload(data: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(MARKER.len() + 8 + data.len());
    f.extend_from_slice(&MARKER);
    f.extend_from_slice(&(data.len() as u32).to_be_bytes());
    f.extend_from_slice(&crc32(data).to_be_bytes());
    f.extend_from_slice(data);
    f
}

/// 编码一个写单元: [标记帧][结束帧]。
pub fn encode_end() -> Vec<u8> {
    let mut f = Vec::with_capacity(MARKER.len() + 12);
    f.extend_from_slice(&MARKER);
    f.extend_from_slice(&4u32.to_be_bytes());
    f.extend_from_slice(&crc32(&END_PAYLOAD).to_be_bytes());
    f.extend_from_slice(&END_PAYLOAD);
    f
}

/// 帧解析状态机 (从通道字节流解出帧; 语义与旧版 tunnel.rs 内联实现逐行等价)
///
/// 状态:
/// - `partial`: 有未完成帧 (已读到长度头, 帧体未到齐) —— 到齐后直接补齐;
/// - `synced`: 刚消费标记帧, 头部必然是帧 (结束帧/连续标记帧/数据帧),
///   绝不在此扫描标记帧 —— 标记之间是真实数据, 扫描会把它当注入丢弃。
pub struct FrameParser {
    buf: Vec<u8>,
    partial: Option<usize>,
    synced: bool,
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameParser {
    /// 新解析器: 未同步 (跳过注入模式, 等待对端标记帧)
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            partial: None,
            synced: false,
        }
    }

    /// 是否有未完成帧 (调用方据此做 partial 超时计时)
    pub fn partial_pending(&self) -> bool {
        self.partial.is_some()
    }

    /// partial 超时 (帧尾丢失/注入截断): 丢弃缓冲与当前连接 (返回 End),
    /// 等待重同步。synced 保持 —— 后续标记帧自身是合法帧 (len=8), 同步态
    /// 可直接吸收, 无需扫描。
    pub fn on_partial_timeout(&mut self, note: impl Fn(&str)) -> Frame {
        if let Some(plen) = self.partial {
            note(&format!(
                "帧 {plen} 字节不完整超时 (注入截断), 丢弃连接并重置同步"
            ));
        }
        self.partial = None;
        self.buf.clear();
        Frame::End
    }

    /// 喂入通道字节, 返回解出的帧 (可能为空)。注入转储/空审计记录/标记帧被静默吸收。
    pub fn feed(&mut self, data: &[u8]) -> Vec<Frame> {
        self.feed_with(data, |_| {})
    }

    /// 同 [`feed`], 额外经 `note` 报告丢弃事件 (CRC 失败等, 供日志)
    pub fn feed_with(&mut self, data: &[u8], note: impl Fn(&str)) -> Vec<Frame> {
        let mut out = Vec::new();
        self.buf.extend_from_slice(data);
        loop {
            // --- 部分帧: 直接补齐 (帧尾残余是真实数据, 不可能是注入) ---
            if let Some(plen) = self.partial {
                if self.buf.len() < 8 + plen {
                    break;
                }
                if plen == 8 && self.buf[4..12] == MARKER[4..] {
                    // 标记帧残片补齐后判定为同步点, 丢弃 (保持同步态)
                    self.buf.drain(..12);
                    self.partial = None;
                    continue;
                }
                if plen == 4 && self.buf[8..12] == END_PAYLOAD {
                    // 结束帧残片补齐 (拆批到达的 [00000004][crc][DEADBEEF])
                    self.buf.drain(..12);
                    self.partial = None;
                    self.synced = false;
                    out.push(Frame::End);
                    continue;
                }
                if !frame_crc_ok(&self.buf, plen) {
                    // 注入截断导致数据损坏: 丢连接 + 清缓冲重同步
                    note("CRC 校验失败 (注入截断), 丢弃连接并重置同步");
                    self.partial = None;
                    self.buf.clear();
                    self.synced = false;
                    out.push(Frame::End);
                    break;
                }
                let payload = self.buf[8..8 + plen].to_vec();
                self.buf.drain(..8 + plen);
                self.partial = None;
                self.synced = false;
                out.push(Frame::Payload(payload));
                continue;
            }
            // --- 完整结束帧 (12 字节) ---
            // 必须先于标记帧扫描处理: 若滞后, 下一次扫描找到后续标记帧后
            // drain 其前的一切, 会把滞留在缓冲中的结束帧误当注入丢弃,
            // 当前连接收不到 End, 后续连接的帧全部串入前一连接。
            if self.buf.len() >= 12
                && u32::from_be_bytes(self.buf[..4].try_into().unwrap()) == 4
                && self.buf[8..12] == END_PAYLOAD
            {
                self.buf.drain(..12);
                out.push(Frame::End);
                continue;
            }
            // --- 已同步: 头部必然是帧 ---
            if self.synced {
                if self.buf.len() < 8 {
                    break;
                }
                let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
                if len == 0 {
                    // 空审计记录残留: 丢弃 (结束帧不再是零长度编码)
                    self.buf.drain(..4);
                    continue;
                }
                if len == 8 && self.buf.len() >= 12 && self.buf[4..12] == MARKER[4..] {
                    // 连续标记帧 (注入副本 + 真实标记): 丢弃, 保持同步
                    self.buf.drain(..12);
                    continue;
                }
                if self.buf.len() < 8 + len {
                    self.partial = Some(len);
                    break;
                }
                if !frame_crc_ok(&self.buf, len) {
                    // 注入截断导致数据损坏: 丢本帧 + 发 End, 后续帧继续解
                    note(&format!(
                        "CRC 校验失败 (注入截断, 帧 {len} 字节), 丢弃连接并重置同步"
                    ));
                    self.buf.drain(..8 + len);
                    out.push(Frame::End);
                    self.synced = false;
                    continue;
                }
                let payload = self.buf[8..8 + len].to_vec();
                self.buf.drain(..8 + len);
                out.push(Frame::Payload(payload));
                self.synced = false;
                continue;
            }
            // --- 未同步: 扫描标记帧, 丢弃其前的一切 (注入) ---
            match find_marker(&self.buf) {
                None => {
                    // 只保留可能跨批的标记帧尾部
                    let keep = MARKER.len() - 1;
                    if self.buf.len() > keep {
                        self.buf.drain(..self.buf.len() - keep);
                    }
                    break;
                }
                Some(pos) => {
                    self.buf.drain(..pos + MARKER.len());
                    self.synced = true;
                    // 回到循环顶部: 标记帧后可能是结束帧 (顶部检查),
                    // 也可能是数据帧 (synced 分支)
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 模拟对端写单元序列: 首标记 + 若干帧
    fn stream(units: &[Vec<u8>]) -> Vec<u8> {
        let mut s = MARKER.to_vec();
        for u in units {
            s.extend_from_slice(u);
        }
        s
    }

    fn payload(data: &[u8]) -> Frame {
        Frame::Payload(data.to_vec())
    }

    /// 基本往返: 单个数据帧
    #[test]
    fn roundtrip_single_payload() {
        let mut p = FrameParser::new();
        let frames = p.feed(&stream(&[encode_payload(b"hello")]));
        assert_eq!(frames, vec![payload(b"hello")]);
    }

    /// 往返: 结束帧 (独立于标记前缀也能解出)
    #[test]
    fn roundtrip_end_frame() {
        let mut p = FrameParser::new();
        let frames = p.feed(&stream(&[encode_end()]));
        assert_eq!(frames, vec![Frame::End]);
    }

    /// 分块到达: 逐字节喂入, 帧仍完整解出 (跨批 partial 补齐)
    #[test]
    fn chunked_byte_by_byte() {
        let bytes = stream(&[encode_payload(b"0123456789"), encode_end()]);
        let mut p = FrameParser::new();
        let mut frames = Vec::new();
        for b in &bytes {
            frames.extend(p.feed(std::slice::from_ref(b)));
        }
        assert_eq!(frames, vec![payload(b"0123456789"), Frame::End]);
    }

    /// 多帧一次到达: 单次 feed 解出全部
    #[test]
    fn multiple_frames_one_feed() {
        let mut p = FrameParser::new();
        let bytes = stream(&[encode_payload(b"a"), encode_end(), encode_payload(b"bb")]);
        let frames = p.feed(&bytes);
        assert_eq!(frames, vec![payload(b"a"), Frame::End, payload(b"bb")]);
    }

    /// 注入转储: 标记帧前的垃圾被丢弃, 帧不受污染
    #[test]
    fn injection_dump_before_marker_discarded() {
        let mut p = FrameParser::new();
        let mut bytes = b"\x17\xff audit dump \x00\x01garbage".to_vec();
        bytes.extend_from_slice(&stream(&[encode_payload(b"clean")]));
        assert_eq!(p.feed(&bytes), vec![payload(b"clean")]);
    }

    /// 空审计记录 [00000000]: 与零长度结束帧同字节, 应被丢弃而非当作结束
    #[test]
    fn empty_audit_record_dropped() {
        let mut p = FrameParser::new();
        let mut bytes = vec![0, 0, 0, 0]; // libonion 空审计记录
        bytes.extend_from_slice(&stream(&[encode_payload(b"data")]));
        assert_eq!(p.feed(&bytes), vec![payload(b"data")]);
    }

    /// 连续标记帧 [M][M][f1][M][f2] (注入复制标记): f1/f2 都要解出。
    /// 旧 bug: 同步后仍按扫描处理, 会把标记之间的 f1 当注入丢弃
    #[test]
    fn consecutive_markers_keep_real_frames() {
        let mut p = FrameParser::new();
        let mut bytes = MARKER.to_vec(); // 首标记 (同步)
        bytes.extend_from_slice(&MARKER); // 注入副本的标记
        bytes.extend_from_slice(&encode_payload(b"f1"));
        bytes.extend_from_slice(&MARKER); // 下一写单元的标记
        bytes.extend_from_slice(&encode_payload(b"f2"));
        assert_eq!(p.feed(&bytes), vec![payload(b"f1"), payload(b"f2")]);
    }

    /// 结束帧滞留缓冲时, 后续标记先到: 结束帧必须先于扫描解出,
    /// 否则当前连接收不到 End, 下一连接的帧串入前一连接
    #[test]
    fn end_frame_parsed_before_marker_scan() {
        let mut p = FrameParser::new();
        // 同步并解一帧后, 缓冲里依次是: 结束帧 + 下一连接的标记与首帧
        let mut bytes = stream(&[encode_payload(b"first")]);
        bytes.extend_from_slice(&encode_end()[MARKER.len()..]); // 结束帧 (无标记前缀)
        bytes.extend_from_slice(&encode_payload(b"next")); // 下一单元 [M][帧]
        assert_eq!(
            p.feed(&bytes),
            vec![payload(b"first"), Frame::End, payload(b"next")]
        );
    }

    /// 标记帧跨批: 以 partial(len=8) 状态补齐, 静默吸收不产帧
    #[test]
    fn marker_completed_via_partial() {
        let mut p = FrameParser::new();
        // 首标记同步后, 下一标记只到前 8 字节 (长度头 + 半个标记) → partial=8
        let mut head = MARKER.to_vec();
        head.extend_from_slice(&MARKER[..8]);
        assert!(p.feed(&head).is_empty());
        assert!(p.partial_pending());
        // 标记剩余 4 字节到齐: partial 补齐判定为标记帧 (静默吸收),
        // 随后的数据帧 (去掉自身标记前缀) 正常解出
        let mut tail = MARKER[8..].to_vec();
        tail.extend_from_slice(&encode_payload(b"x")[MARKER.len()..]);
        assert_eq!(p.feed(&tail), vec![payload(b"x")]);
    }

    /// CRC 损坏 (注入截断): 发 End 丢连接, 后续帧继续正常解出
    #[test]
    fn crc_corruption_recovers() {
        let mut p = FrameParser::new();
        let mut bytes = stream(&[encode_payload(b"good-before")]);
        let mut bad = encode_payload(b"corrupted-payload");
        let last = bad.len() - 1;
        bad[last] ^= 0xFF; // 破坏数据位 → CRC 失配
        bytes.extend_from_slice(&bad);
        bytes.extend_from_slice(&encode_payload(b"after"));
        assert_eq!(
            p.feed(&bytes),
            vec![
                payload(b"good-before"),
                Frame::End,        // 坏帧 → 丢连接
                payload(b"after")  // 重同步后恢复
            ]
        );
    }

    /// partial 超时: 帧尾丢失, 返回 End 丢连接; 之后的新连接正常解出
    #[test]
    fn partial_timeout_resets() {
        let mut p = FrameParser::new();
        let mut bytes = stream(&[encode_payload(b"12345678")]);
        bytes.truncate(bytes.len() - 3); // 帧尾丢失 → partial
        assert!(p.feed(&bytes).is_empty());
        assert!(p.partial_pending());
        assert_eq!(p.on_partial_timeout(|_| {}), Frame::End);
        assert!(!p.partial_pending());
        // 新连接的写单元照常解析
        assert_eq!(p.feed(&encode_payload(b"fresh")), vec![payload(b"fresh")]);
    }

    /// 超时后 synced 态吸收下一标记帧: 标记自身是合法帧 (len=8),
    /// 无需扫描即可重同步 —— [timeout 残留同步态] + [M][帧] 的恢复路径
    #[test]
    fn after_timeout_marker_absorbed_in_synced_state() {
        let mut p = FrameParser::new();
        let mut bytes = stream(&[encode_payload(b"12345678")]);
        bytes.truncate(bytes.len() - 3); // partial
        p.feed(&bytes);
        p.on_partial_timeout(|_| {}); // synced 保持 true, buf 清空
                                      // 到达的是完整写单元 [M][帧]: synced 态把 M 当 len=8 的标记帧吸收
        assert_eq!(
            p.feed(&encode_payload(b"next-conn")),
            vec![payload(b"next-conn")]
        );
    }
}
