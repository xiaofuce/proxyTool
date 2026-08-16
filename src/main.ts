import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { icon, type IconName } from "./icons";
import { initAppearance } from "./theme";
import {
  toast,
  toastRich,
  dialog,
  withLoading,
  openMenu,
  closeMenus,
  menuTag,
  type MenuItem,
} from "./ui";

// ---------- 类型 (与 core serde camelCase 对应) ----------
interface Profile {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  /** 私钥路径 (选填): 设置后走密钥认证, 密码框改充当密钥口令 */
  identityFile?: string | null;
  /** 共享 SSH 连接 (null = 跟随全局默认; 服务器级覆盖) */
  shareConnection?: boolean | null;
}

// serde externally-tagged enum: { reverse: {...} } | { local: {...} } | { dynamic: {...} }
type Kind =
  | { reverse: { bind: string; port: number } }
  | { local: { bind: string; port: number; targetHost: string; targetPort: number } }
  | { dynamic: { bind: string; port: number } };

type Backend = { tcp: [string, number] } | { socksAuto: { fallbackPort: number } };

interface Policy {
  auto: boolean;
  fastRetries: number;
  maxBackoff: number;
  aliveReset: number;
  keepalive: number;
  keepaliveMax: number;
}

interface TunnelSpec {
  id: string;
  name: string;
  enabled: boolean;
  profileId: string;
  kind: Kind;
  backend: Backend;
  policy: Policy;
}

interface TunnelDto extends TunnelSpec {
  state: string;
  message?: string;
}

interface Preset {
  id: string;
  name: string;
  description: string;
  actions: string[];
}

/** 我的场景 (用户保存的隧道模板) */
interface Scenario {
  id: string;
  name: string;
  description: string;
  kind: Kind;
  backend: Backend;
}

interface Defaults {
  connectTimeoutSecs?: number | null;
  reconnect?: Policy | null;
  /** 共享连接全局默认 (null = 引擎默认开) */
  shareConnection?: boolean | null;
  /** MaxSessions 预算 (null = sshd 默认 10) */
  maxSessions?: number | null;
}

const DEFAULT_POLICY: Policy = {
  auto: true,
  fastRetries: 3,
  maxBackoff: 30,
  aliveReset: 3,
  keepalive: 10,
  keepaliveMax: 3,
};

// ---------- 工具 ----------
function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!;
  });
}

/** serde 变体名 (reverse/local/dynamic) —— 注意与后端事件里的形态 tag "remote" 不同源 */
type KindTag = "reverse" | "local" | "dynamic";

function kindTag(k: Kind): KindTag {
  return Object.keys(k)[0] as KindTag;
}

function kindLabel(k: Kind): string {
  return { reverse: "反向", local: "本地", dynamic: "动态" }[kindTag(k)];
}

/** 隧道表单里的形态值 ↔ serde tag */
type FormKind = "reverse" | "local" | "dynamic";

function formKindOf(k: Kind): FormKind {
  return kindTag(k) as FormKind;
}

/** 五态五语义: 未启动(中性)/连接中(蓝)/已连接(绿)/重连中(琥珀)/连接失败(红) */
const STATUS_TEXT: Record<string, string> = {
  connecting: "连接中",
  connected: "已连接",
  reconnecting: "重连中",
  disconnected: "未启动",
  error: "连接失败",
};

const ACTIVE_STATES = ["connected", "connecting", "reconnecting"];

// ---------- 全局状态 ----------
let tunnels: TunnelDto[] = [];
let profiles: Profile[] = [];
let scenarios: Scenario[] = [];
/** profileId -> 本次会话凭据 (密码 / 密钥口令; null = 密钥档案无口令。仅内存, 重启即失) */
const passwords = new Map<string, string | null>();
/** 结构化日志行 (时间戳 + 级别 + 文本; textContent 渲染天然转义) */
interface LogLine {
  ts: string;
  level: "info" | "warn" | "error";
  msg: string;
}
/** tunnelId -> 日志行 (行内展开时渲染; 上限防膨胀) */
const logs = new Map<string, LogLine[]>();
/** tunnelId -> 展开状态 (重渲染保持) */
const expanded = new Set<string>();
/** tunnelId -> 连接建立时刻 (uptime 计时; 进/出 connected 维护, 初始加载从加载时刻起算) */
const connectedSince = new Map<string, number>();
/** tunnelId -> 行内密码输入草稿 (整表重绘回填, 防正在输入的密码丢失) */
const pwDrafts = new Map<string, string>();
/** tunnelId -> 行内 DOM 引用 (事件增量更新, 不整表重绘) */
interface RowRefs {
  status: HTMLSpanElement;
  portChip: HTMLSpanElement;
  uptime: HTMLSpanElement;
  msg: HTMLSpanElement;
  msgIcon: HTMLSpanElement;
  msgRow: HTMLDivElement;
  log: HTMLDivElement;
  pwBar: HTMLDivElement;
  pwInput: HTMLInputElement;
  btnStart: HTMLButtonElement;
  btnStop: HTMLButtonElement;
  moreBtn: HTMLButtonElement;
}
const rowRefs = new Map<string, RowRefs>();

/** 当前选中服务器 (服务器页) */
let selectedProfileId: string | null = null;
/** 右面板视图状态 */
type DetailView = "empty" | "detail" | "server-form" | "scenario-pick" | "tunnel-form";
let detailView: DetailView = "empty";
/** 一键启动等待密码时暂存的目标隧道 */
let pdPwTargets: TunnelDto[] = [];
/** 隧道表单上下文 (来自预设/我的场景/自定义的模板) */
let wzSpec: TunnelSpec | null = null;

const LOG_CAP = 500; // 行数上限, 超出丢弃头部

/** 级别推断: ❌/失败/错误 → error; 警告/WARN/回退 → warn */
function logLevel(msg: string): LogLine["level"] {
  if (msg.startsWith("❌") || msg.includes("失败") || msg.includes("错误")) return "error";
  if (msg.includes("警告") || /WARN/i.test(msg) || msg.includes("回退")) return "warn";
  return "info";
}

/** 日志全文 (复制用; 与行渲染同口径) */
function logText(id: string): string {
  return (logs.get(id) ?? []).map((l) => `[${l.ts}] ${l.msg}`).join("\n");
}

function makeLogLine(l: LogLine): HTMLDivElement {
  const row = document.createElement("div");
  row.className = `log-line ${l.level}`;
  const ts = document.createElement("span");
  ts.className = "log-ts";
  ts.textContent = l.ts;
  const msg = document.createElement("span");
  msg.className = "log-msg";
  msg.textContent = l.msg;
  row.append(ts, msg);
  return row;
}

/** 智能滚动: 仅当用户接近底部 (<24px) 时跟随新行, 上翻浏览不强拉 */
function appendLogLine(logEl: HTMLElement, line: LogLine) {
  const follow = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 24;
  logEl.append(makeLogLine(line));
  while (logEl.childElementCount > LOG_CAP) logEl.firstElementChild?.remove();
  if (follow) logEl.scrollTop = logEl.scrollHeight;
}

function appendLog(id: string, msg: string) {
  const arr = logs.get(id) ?? [];
  arr.push({ ts: new Date().toLocaleTimeString(), level: logLevel(msg), msg });
  if (arr.length > LOG_CAP) arr.splice(0, arr.length - LOG_CAP);
  logs.set(id, arr);
  const refs = rowRefs.get(id);
  if (refs) appendLogLine(refs.log, arr[arr.length - 1]);
}

function selectedProfile(): Profile | undefined {
  return profiles.find((p) => p.id === selectedProfileId);
}

// ---------- 页面路由 ----------
const navItems = document.querySelectorAll<HTMLButtonElement>(".nav-item");
const pages = document.querySelectorAll<HTMLElement>(".page");

function showPage(name: string) {
  navItems.forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  pages.forEach((p) => p.classList.toggle("active", p.dataset.page === name));
}

navItems.forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page!)));

// ---------- 隧道行渲染 (服务器详情页) ----------
function summary(t: TunnelDto): string {
  const k = t.kind;
  if ("reverse" in k) {
    const port = k.reverse.port;
    const remote = port === 0 ? "服务器动态端口" : `服务器 127.0.0.1:${port}`;
    const local =
      "socksAuto" in t.backend
        ? "本机 VPN SOCKS (自动探测)"
        : `本机 ${t.backend.tcp[0]}:${t.backend.tcp[1]}`;
    return `${remote} ← ${local}`;
  }
  if ("local" in k) {
    return `本机 ${k.local.bind}:${k.local.port} → ${k.local.targetHost}:${k.local.targetPort}`;
  }
  return `本机 SOCKS5 ${k.dynamic.bind}:${k.dynamic.port} → 服务器代连内网`;
}

/** 摘要行文案: summary · host (host 比别名有增量) */
function subLine(t: TunnelDto): string {
  const profile = profiles.find((p) => p.id === t.profileId);
  if (!profile) return `档案缺失 — ${summary(t)}`;
  return `${summary(t)} · ${profile.host}`;
}

/** vpn_share 形态 (反向 + SOCKS 落地): 显示「验证外网 / 部署 proxy」动作 */
function isVpnShare(t: TunnelDto): boolean {
  return kindTag(t.kind) === "reverse" && "socksAuto" in t.backend;
}

/** 该隧道是否还需要输入凭据 (本会话未输入过; 密钥档案无口令也算已输入) */
function needPassword(t: TunnelDto): boolean {
  return !passwords.has(t.profileId);
}

/** 运行时长: <60 秒 / N分N秒 / N时N分 / N天N时 */
function fmtUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}秒`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}分${s % 60}秒`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}时${m % 60}分`;
  return `${Math.floor(h / 24)}天${h % 24}时`;
}

/** 端口 chip: 反向 = 服务器端口 (0=动态分配弱 chip, 回填后 :port 绿点);
 * 本地/动态 = 本机监听 bind:port。updateRow 与重绘共用 */
function refreshPortChip(chip: HTMLSpanElement, t: TunnelDto): void {
  const k = t.kind;
  if ("reverse" in k) {
    if (k.reverse.port > 0) {
      chip.className = "port-chip bound";
      chip.textContent = `:${k.reverse.port}`;
      chip.title = "服务器监听端口 (127.0.0.1)";
    } else {
      chip.className = "port-chip dyn";
      chip.textContent = "动态分配";
      chip.title = "服务器端口 0 = 连接后由服务器分配, 回填显示";
    }
  } else if ("local" in k) {
    chip.className = "port-chip";
    chip.textContent = `${k.local.bind}:${k.local.port}`;
    chip.title = "本机监听端口";
  } else {
    chip.className = "port-chip";
    chip.textContent = `${k.dynamic.bind}:${k.dynamic.port}`;
    chip.title = "本机 SOCKS5 监听端口";
  }
}

/** connectedSince 维护: 进 connected 记时刻 (已记不重置), 离 connected 清除。
 * 状态事件与整表重绘两条路径都过这里, 保证口径一致 */
function noteConnected(t: TunnelDto): void {
  if (t.state === "connected") {
    if (!connectedSince.has(t.id)) connectedSince.set(t.id, Date.now());
  } else {
    connectedSince.delete(t.id);
  }
}

/** 按当前状态更新一行 (增量, 不重建 DOM; 行不在当前容器则跳过)。
 * 其余动作钮 (重试/信任/验证/部署/场景/删除) 走 ⋯ 菜单, 打开时惰性求值 */
function updateRow(t: TunnelDto) {
  const refs = rowRefs.get(t.id);
  if (!refs) return;
  refs.status.className = `status-badge ${t.state}`;
  refs.status.textContent = STATUS_TEXT[t.state] ?? t.state;
  const isErr = t.state === "error";
  refs.msg.textContent = t.message ?? "";
  refs.msgRow.classList.toggle("hidden", !t.message);
  refs.msgRow.classList.toggle("error", isErr);
  refs.msgIcon.hidden = !isErr;
  refreshPortChip(refs.portChip, t);

  const active = ACTIVE_STATES.includes(t.state);
  refs.btnStart.disabled = active;
  refs.btnStop.disabled = !active;

  const since = connectedSince.get(t.id);
  if (t.state === "connected" && since) {
    refs.uptime.hidden = false;
    refs.uptime.textContent = fmtUptime(Date.now() - since);
  } else {
    refs.uptime.hidden = true;
  }

  if (t.state === "connecting" || t.state === "connected") {
    refs.pwBar.classList.add("hidden"); // 已受理, 收起密码条
  }
}

/** 把一批隧道行渲染进容器 (服务器详情页; rowRefs 单容器假设: 同一时刻只显示一页)。
 * U4 行结构: head(展开|名称+形态+端口chip|状态徽章|时长|启动/停止+⋯) + 摘要行 + 消息行 + 详情 */
function renderTunnelRows(container: HTMLElement, list: TunnelDto[]) {
  closeMenus(); // 行将整表重建, 悬挂的菜单锚点一并收掉
  container.innerHTML = "";
  for (const t of list) {
    const profile = profiles.find((p) => p.id === t.profileId);
    noteConnected(t); // 非事件路径进 connected (初始加载/拉取) 从本时刻起算
    const card = document.createElement("div");
    card.className = "card tunnel-card";

    // --- 头部: 展开钮 + 名称/形态/端口chip + 状态徽章 + 运行时长 + 主操作/⋯ ---
    const head = document.createElement("div");
    head.className = "tunnel-head";

    const expand = document.createElement("button");
    expand.type = "button";
    expand.className = "icon-btn tunnel-expand";
    expand.innerHTML = icon("chevron-right", 14);
    expand.setAttribute("aria-label", "展开日志");

    const title = document.createElement("div");
    title.className = "tunnel-title";
    title.innerHTML =
      `<strong>${escapeHtml(t.name)}</strong>` +
      `<span class="tunnel-kind">${kindLabel(t.kind)}</span>`;
    const portChip = document.createElement("span");
    title.append(portChip);

    const status = document.createElement("span");
    status.className = `status-badge ${t.state}`;

    const uptime = document.createElement("span");
    uptime.className = "tunnel-uptime";
    uptime.hidden = true;

    const actions = document.createElement("div");
    actions.className = "tunnel-actions";
    const btnStart = document.createElement("button");
    btnStart.type = "button";
    btnStart.innerHTML = `${icon("play", 13)}<span class="btn-label">启动</span>`;
    const btnStop = document.createElement("button");
    btnStop.type = "button";
    btnStop.innerHTML = `${icon("square", 13)}<span class="btn-label">停止</span>`;
    const moreBtn = document.createElement("button");
    moreBtn.type = "button";
    moreBtn.className = "icon-btn more-btn";
    moreBtn.innerHTML = icon("ellipsis", 16);
    moreBtn.setAttribute("aria-label", "更多操作");
    moreBtn.title = "更多操作";
    actions.append(btnStart, btnStop, moreBtn);

    head.append(expand, title, status, uptime, actions);
    card.append(head);

    // --- 摘要行 (参数 · host; ellipsis + title 全文) ---
    const sub = document.createElement("div");
    sub.className = "tunnel-sub";
    sub.textContent = subLine(t);
    sub.title = sub.textContent;
    card.append(sub);

    // --- 状态消息行 (重连进度 / 错误信息; error 态警示图标红字) ---
    const msgRow = document.createElement("div");
    msgRow.className = "tunnel-msg hidden";
    const msgIcon = document.createElement("span");
    msgIcon.className = "tunnel-msg-ic";
    msgIcon.innerHTML = icon("triangle-alert", 13);
    msgIcon.hidden = true;
    const msg = document.createElement("span");
    msg.className = "tunnel-msg-text";
    msgRow.append(msgIcon, msg);
    card.append(msgRow);

    // --- 详情: 密码条 + 日志工具条 + 日志 (grid 0fr→1fr 展开动画, 见 .tunnel-detail) ---
    const detail = document.createElement("div");
    detail.className = "tunnel-detail collapsed";

    const detailIn = document.createElement("div");
    detailIn.className = "tunnel-detail-in";

    const pwBar = document.createElement("div");
    pwBar.className = "pw-bar hidden";
    const pwInput = document.createElement("input");
    pwInput.type = "password";
    // 密钥档案: 密码框充当密钥口令 (未加密私钥可留空)
    pwInput.placeholder = profile?.identityFile
      ? `密钥口令 (${profile.username}@${profile.host}, 未加密私钥可留空)`
      : `SSH 密码 (${profile ? profile.username + "@" + profile.host : "服务器"})`;
    pwInput.autocomplete = "off";
    const pwBtn = document.createElement("button");
    pwBtn.type = "button";
    pwBtn.className = "primary";
    pwBtn.textContent = "连接";
    pwBar.append(pwInput, pwBtn);

    // 日志工具条: 复制 / 清空
    const logBar = document.createElement("div");
    logBar.className = "log-bar";
    const logCopy = document.createElement("button");
    logCopy.type = "button";
    logCopy.className = "log-copy";
    logCopy.title = "复制日志";
    logCopy.innerHTML = `${icon("copy", 13)}<span class="btn-label">复制</span>`;
    const logClear = document.createElement("button");
    logClear.type = "button";
    logClear.className = "log-clear";
    logClear.title = "清空日志";
    logClear.innerHTML = `${icon("eraser", 13)}<span class="btn-label">清空</span>`;
    logBar.append(logCopy, logClear);

    const logEl = document.createElement("div");
    logEl.className = "log";
    for (const line of logs.get(t.id) ?? []) logEl.append(makeLogLine(line));
    logEl.scrollTop = logEl.scrollHeight; // 初始渲染贴底 (最新在下)
    detailIn.append(pwBar, logBar, logEl);
    detail.append(detailIn);
    card.append(detail);
    container.append(card);

    const refs: RowRefs = {
      status,
      portChip,
      uptime,
      msg,
      msgIcon,
      msgRow,
      log: logEl,
      pwBar,
      pwInput,
      btnStart,
      btnStop,
      moreBtn,
    };
    rowRefs.set(t.id, refs);
    const open0 = expanded.has(t.id);
    detail.classList.toggle("collapsed", !open0);
    detail.toggleAttribute("inert", !open0); // 收起时移出 Tab 序, 免焦点钻进不可见区
    expand.classList.toggle("open", open0);
    updateRow(t);

    // 密码草稿保护: 正在输入的密码经整表重绘回填并恢复焦点
    const draft = pwDrafts.get(t.id);
    if (draft && t.state !== "connecting" && t.state !== "connected") {
      pwInput.value = draft;
      pwBar.classList.remove("hidden");
      pwInput.focus();
    }

    // --- 接线 ---
    expand.addEventListener("click", () => {
      const open = expanded.has(t.id);
      if (open) expanded.delete(t.id);
      else expanded.add(t.id);
      detail.classList.toggle("collapsed", open);
      detail.toggleAttribute("inert", open);
      expand.classList.toggle("open", !open);
      if (!open) logEl.scrollTop = logEl.scrollHeight;
    });
    head.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).closest("button")) return;
      expand.click();
    });

    /** password: null = 密钥档案无口令 (后端 KeyFile passphrase=None) */
    const doStart = async (password: string | null) => {
      try {
        await invoke("tunnel_start", { id: t.id, password: password || null });
        passwords.set(t.profileId, password);
        pwDrafts.delete(t.id);
        pwBar.classList.add("hidden");
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      }
    };
    btnStart.addEventListener("click", async () => {
      if (passwords.has(t.profileId)) {
        await doStart(passwords.get(t.profileId) ?? null);
        return;
      }
      expanded.add(t.id);
      detail.classList.remove("collapsed");
      detail.removeAttribute("inert");
      expand.classList.add("open");
      pwBar.classList.remove("hidden");
      pwInput.focus();
    });
    pwBtn.addEventListener("click", async () => {
      // 密码档案必须非空; 密钥档案口令可空 (passphrase: None)
      if (!pwInput.value && !profile?.identityFile) {
        pwInput.focus();
        return;
      }
      await withLoading(pwBtn, () => doStart(pwInput.value || null), "连接中...");
    });
    pwInput.addEventListener("input", () => pwDrafts.set(t.id, pwInput.value));
    pwInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") pwBtn.click();
    });
    logCopy.addEventListener("click", async () => {
      const text = logText(t.id);
      if (!text) {
        toast("日志为空", "info");
        return;
      }
      try {
        await navigator.clipboard.writeText(text);
        toast("日志已复制", "success");
      } catch {
        toast("复制失败", "error");
      }
    });
    logClear.addEventListener("click", () => {
      logs.delete(t.id);
      logEl.innerHTML = "";
    });
    btnStop.addEventListener("click", async () => {
      try {
        await invoke("tunnel_stop", { id: t.id });
        appendLog(t.id, "请求断开...");
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      }
    });

    // --- ⋯ 菜单条目动作 (打开时惰性求值, 这里只定义) ---
    const trustNewFingerprint = async () => {
      const prof = profiles.find((p) => p.id === t.profileId);
      if (!prof) {
        appendLog(t.id, "❌ 隧道关联的档案缺失, 无法定位指纹记录");
        return;
      }
      const ok = await dialog({
        title: "信任新指纹并重连?",
        body: `将清除 ${prof.host}:${prof.port} 的旧指纹记录, 重连后重新记忆当前指纹。\n仅当服务器确已重装/更换时继续 —— 否则可能是中间人攻击。`,
        confirmText: "信任并重连",
        danger: true,
      });
      if (!ok) return;
      try {
        await invoke("known_hosts_forget", { host: prof.host, port: prof.port });
        appendLog(t.id, `已清除 ${prof.host}:${prof.port} 的指纹记录, 重连后将重新记忆当前指纹`);
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
        return;
      }
      // 复用启动路径: 有缓存密码直接重启, 否则展开密码条
      btnStart.click();
    };
    const runAction = async (cmd: "verify_remote_tunnel" | "deploy_wrapper") => {
      if (!passwords.has(t.profileId)) {
        appendLog(t.id, "需要凭据: 请先启动隧道 (或重新输入密码/口令)");
        btnStart.click();
        return;
      }
      const pass = passwords.get(t.profileId) ?? null;
      // busy 挂在行内 ⋯ 钮上 (菜单即点即关, 反馈落在持久元素)
      await withLoading(moreBtn, async () => {
        try {
          await invoke<string>(cmd, { id: t.id, password: pass || null });
          // 输出经 tunnel-log 事件回流行内日志, 此处不重复
        } catch (err) {
          appendLog(t.id, `❌ ${err}`);
        }
      });
    };
    const saveScenario = async () => {
      const r = await dialog({
        title: "存为我的场景",
        body: "以当前隧道的形态与参数保存, 新建隧道时直接复用。",
        input: { value: t.name, placeholder: "场景名称" },
        confirmText: "保存",
      });
      // 确认但空名视为取消
      if (typeof r !== "string" || !r.trim()) return;
      const name = r.trim();
      try {
        scenarios = await invoke<Scenario[]>("scenario_save", {
          scenario: {
            id: crypto.randomUUID(),
            name,
            description: "",
            kind: t.kind,
            backend: t.backend,
          },
        });
        appendLog(t.id, `已保存场景「${name}」`);
      } catch (err) {
        appendLog(t.id, `❌ 保存场景失败: ${err}`);
      }
    };
    const deleteTunnel = async () => {
      const ok = await dialog({
        title: `删除隧道「${t.name}」?`,
        body: "运行中的隧道会先停止。",
        confirmText: "删除",
        danger: true,
      });
      if (!ok) return;
      try {
        tunnels = await invoke<TunnelDto[]>("tunnel_delete", { id: t.id });
        connectedSince.delete(t.id);
        pwDrafts.delete(t.id);
        renderHosts();
        if (detailView === "detail") renderServerDetail();
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      }
    };

    /** 打开瞬间取最新状态计算条目 (hidden/disabled 按当时 state 出没, 与重绘解耦) */
    const menuItems = (): MenuItem[] => {
      const cur = currentTunnel(t.id) ?? t;
      const prof = profiles.find((p) => p.id === cur.profileId);
      const items: MenuItem[] = [];
      if (cur.state === "reconnecting") {
        items.push({
          label: "立即重试",
          icon: "rotate-ccw",
          action: async () => {
            try {
              await invoke("tunnel_retry_now", { id: cur.id });
            } catch (err) {
              appendLog(cur.id, `❌ ${err}`);
            }
          },
        });
      }
      if (cur.state === "error" && (cur.message ?? "").includes("指纹已变更")) {
        items.push({
          label: "信任新指纹",
          icon: "shield-check",
          title: "服务器指纹变更被拒后, 清除记录并重连 (仅服务器确已重装/更换时使用)",
          action: trustNewFingerprint,
        });
      }
      if (isVpnShare(cur)) {
        const vpnEnabled = cur.state === "connected" && !needPassword(cur);
        items.push(
          {
            label: "验证外网",
            icon: "globe",
            title: "在服务器上经隧道测试访问外网 (google)",
            disabled: !vpnEnabled,
            action: () => runAction("verify_remote_tunnel"),
          },
          {
            label: "部署 proxy",
            icon: "terminal",
            title: "部署 proxy 命令, 服务器上可 'proxy curl ...' 走隧道",
            disabled: !vpnEnabled,
            action: () => runAction("deploy_wrapper"),
          },
        );
      }
      if (items.length) items.push({ separator: true });
      items.push({
        label: "存为场景",
        icon: "bookmark",
        title: "把这条隧道的形态/参数存为「我的场景」, 新建隧道时复用",
        action: saveScenario,
      });
      items.push({
        label: "开机自启",
        icon: "power",
        checked: cur.enabled,
        title: "系统启动时后台拉起此隧道 (需私钥认证档案; 密码/加密私钥无法免交互启动)",
        action: async () => {
          try {
            tunnels = await invoke<TunnelDto[]>("tunnel_set_enabled", {
              id: cur.id,
              enabled: !cur.enabled,
            });
            if (!cur.enabled && prof && !prof.identityFile) {
              appendLog(
                cur.id,
                "提示: 该档案为密码认证, 开机自启时无法免交互启动; 建议为服务器配置私钥路径"
              );
            }
            renderHosts();
          } catch (err) {
            appendLog(cur.id, `❌ ${err}`);
          }
        },
      });
      items.push({ separator: true });
      items.push({ label: "删除", icon: "trash-2", danger: true, title: "删除隧道配置", action: deleteTunnel });
      return items;
    };

    moreBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (menuTag() === t.id) {
        closeMenus(); // 再点同一 ⋯ = 关闭
        return;
      }
      openMenu(moreBtn, menuItems, t.id);
    });
  }
}

function currentTunnel(id: string): TunnelDto | undefined {
  return tunnels.find((t) => t.id === id);
}

/** 双拉隧道 + 档案 (档案列表曾只 init 拉一次导致陈旧); 托盘常驻场景由 window focus 兜底刷新 */
async function refreshTunnels() {
  const [ts, ps] = await Promise.all([
    invoke<TunnelDto[]>("tunnels_list"),
    invoke<Profile[]>("list_profiles"),
  ]);
  tunnels = ts;
  profiles = ps;
  renderHosts();
  if (detailView === "detail") renderServerDetail();
}

/** 托盘常驻/他窗口操作后回窗: 防抖刷新一次 (focus 事件连发) */
let focusRefreshTimer: number | undefined;
window.addEventListener("focus", () => {
  clearTimeout(focusRefreshTimer);
  focusRefreshTimer = window.setTimeout(() => refreshTunnels().catch(() => {}), 600);
});

// ---------- 后端事件 (按 id 键控) ----------
interface StatusPayload {
  id: string;
  kind: string;
  state: string;
  message?: string;
}

listen("tunnel-status", (e) => {
  const p = e.payload as StatusPayload;
  const t = currentTunnel(p.id);
  if (t) {
    t.state = p.state;
    t.message = p.message;
    // 凭据失效即逐出缓存 (tunnel_start 受理即返回, 缓存是乐观的):
    // 认证被拒 / 私钥加载失败(口令不对) → 清掉, 下次启动重新询问, 不静默复用坏凭据
    const msg = p.message ?? "";
    if (p.state === "error" && (msg.includes("认证被拒") || msg.includes("加载私钥"))) {
      passwords.delete(t.profileId);
    }
    noteConnected(t); // 进/出 connected 维护 uptime 起算点
    updateRow(t);
    if (p.message && p.state !== "connected")
      appendLog(p.id, p.state === "error" ? `❌ ${p.message}` : p.message);
    // 块状态点/计数随事件刷新 (总在)
    renderHosts();
    if (p.state === "connected") {
      // 端口 0 动态分配回填会改 spec, 连接成功时拉一次最新列表
      refreshTunnels().catch(() => {});
    }
  }
});

/** TOFU 首连记住指纹 → 可点击复制的 toast (替代裸日志行, 美化提示) */
function fpRememberedToast(fingerprint: string): void {
  toastRich({
    html: `已记住服务器指纹（首次连接）<code>${escapeHtml(fingerprint)}</code>`,
    kind: "success",
    icon: "shield-check",
    ms: 8000,
    title: "点击复制指纹",
    onClick: async () => {
      try {
        await navigator.clipboard.writeText(fingerprint);
        toast("指纹已复制", "success");
      } catch {
        toast("复制失败", "error");
      }
    },
  });
}

listen("tunnel-log", (e) => {
  const p = e.payload as { id: string; kind: string; msg: string };
  appendLog(p.id, p.msg);
  const m = p.msg.match(/已记住服务器指纹 (SHA256:\S+)/);
  if (m) fpRememberedToast(m[1]);
});

/** uptime 走字: 30s 只改已显示行的 uptime.textContent, 绝不重绘 */
setInterval(() => {
  for (const [id, refs] of rowRefs) {
    if (refs.uptime.hidden) continue;
    const since = connectedSince.get(id);
    refs.uptime.textContent = since ? fmtUptime(Date.now() - since) : "";
  }
}, 30_000);

// ---------- 服务器块 (中列, Termius 式) ----------
function profileAggregate(p: Profile): { total: number; running: number; state: string } {
  const mine = tunnels.filter((t) => t.profileId === p.id);
  const states = mine.map((t) => t.state);
  const state = states.includes("error")
    ? "error"
    : states.includes("connecting") || states.includes("reconnecting")
      ? "connecting"
      : states.includes("connected")
        ? "connected"
        : "";
  return { total: mine.length, running: states.filter((s) => s === "connected").length, state };
}

function renderHosts() {
  const grid = el<HTMLDivElement>("host-grid");
  grid.innerHTML = "";

  for (const p of profiles) {
    const agg = profileAggregate(p);
    const block = document.createElement("div");
    block.className = "host-block";
    if (p.id === selectedProfileId) block.classList.add("active");

    // 行 1: 状态点 + 名称 (右留白给 ▶ 钮)
    const name = document.createElement("div");
    name.className = "hb-name";
    const dot = document.createElement("span");
    dot.className = `hb-status ${agg.state}`;
    dot.title = agg.state || "无隧道运行";
    const nameText = document.createElement("span");
    nameText.textContent = p.name;
    name.append(dot, nameText);

    // 行 2: 地址 + 右槽 (运行 pill ⇄ hover 换出 编辑/删除 图标钮, 同位交叉淡换)
    const meta = document.createElement("div");
    meta.className = "hb-meta";
    const addr = document.createElement("div");
    addr.className = "hb-addr";
    addr.innerHTML =
      `${escapeHtml(`${p.host}:${p.port} · ${p.username}`)}` +
      (p.identityFile ? ` <span class="hb-key" title="密钥认证">${icon("key", 12)}</span>` : "");
    const pill = document.createElement("span");
    pill.className = "hb-pill" + (agg.running > 0 ? " running" : "");
    pill.textContent =
      agg.total === 0 ? "无隧道" : `${agg.running}/${agg.total} 运行`;
    pill.title =
      agg.total === 0 ? "还没有隧道" : `${agg.running} 条运行 / 共 ${agg.total} 条`;
    const side = document.createElement("div");
    side.className = "hb-side";
    const acts = document.createElement("div");
    acts.className = "hb-acts";
    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "hb-act";
    editBtn.title = "编辑服务器";
    editBtn.setAttribute("aria-label", `编辑服务器 ${p.name}`);
    editBtn.innerHTML = icon("pencil", 13);
    editBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      selectProfile(p.id);
      openServerForm(p);
    });
    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "hb-act danger";
    delBtn.title = "删除服务器";
    delBtn.setAttribute("aria-label", `删除服务器 ${p.name}`);
    delBtn.innerHTML = icon("trash-2", 13);
    delBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      selectProfile(p.id);
      void deleteProfileFlow(p);
    });
    acts.append(editBtn, delBtn);
    side.append(pill, acts);
    meta.append(addr, side);

    // ▶ 一键启动 enabled 隧道 / ■ 全部停止 (右上角圆形钮)
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "hb-toggle";
    const anyActive = tunnels.some(
      (t) => t.profileId === p.id && ACTIVE_STATES.includes(t.state)
    );
    if (anyActive) toggle.classList.add("stop");
    toggle.innerHTML = anyActive ? icon("square", 13) : icon("play", 13);
    toggle.setAttribute("aria-label", anyActive ? "全部停止" : "一键启动");
    toggle.title = anyActive
      ? "停止该服务器的全部隧道"
      : "一键启动该服务器全部 enabled 隧道 (密码认证首次会要求输入密码)";
    toggle.addEventListener("click", (e) => {
      e.stopPropagation();
      selectProfile(p.id);
      // busy 期间防双击重复启停 (状态点即时反馈, 图标钮不显 spinner —— CSS 抑制)
      withLoading(toggle, () => (anyActive ? stopAllForProfile(p) : startAllForProfile(p)));
    });

    block.append(name, meta, toggle);
    block.addEventListener("click", () => selectProfile(p.id));
    grid.append(block);
  }

  // + 新建块
  const newBlock = document.createElement("button");
  newBlock.type = "button";
  newBlock.className = "host-block new-block";
  newBlock.innerHTML = `${icon("plus", 14)}<span class="btn-label">新建</span>`;
  newBlock.addEventListener("click", () => openServerForm(null));
  grid.append(newBlock);
}

function selectProfile(id: string | null) {
  selectedProfileId = id;
  renderHosts();
  setDetailView(id ? "detail" : "empty");
}

/** ▶: 启动该服务器全部 enabled 且未在运行的隧道 (密码档案首次弹右面板密码条) */
async function startAllForProfile(p: Profile) {
  const targets = tunnels.filter(
    (t) => t.profileId === p.id && t.enabled && !ACTIVE_STATES.includes(t.state)
  );
  if (targets.length === 0) {
    renderServerDetail();
    return;
  }
  // 密码档案且本会话未输入过 → 右面板密码条收集一次, 再批量启动
  if (!p.identityFile && !passwords.has(p.id)) {
    pdPwTargets = targets;
    renderServerDetail(true);
    el<HTMLInputElement>("pd-pw-input")?.focus();
    return;
  }
  const pass = passwords.get(p.id) ?? null;
  for (const t of targets) {
    try {
      await invoke("tunnel_start", { id: t.id, password: pass });
    } catch (err) {
      appendLog(t.id, `❌ ${err}`);
    }
  }
}

/** ■: 停止该服务器全部运行中隧道 */
async function stopAllForProfile(p: Profile) {
  const targets = tunnels.filter(
    (t) => t.profileId === p.id && ACTIVE_STATES.includes(t.state)
  );
  for (const t of targets) {
    try {
      await invoke("tunnel_stop", { id: t.id });
      appendLog(t.id, "请求断开...");
    } catch (err) {
      appendLog(t.id, `❌ ${err}`);
    }
  }
}

// ---------- 右面板 (多态视图) ----------
const DP_VIEWS: Record<DetailView, string> = {
  empty: "detail-empty",
  detail: "server-detail",
  "server-form": "server-form",
  "scenario-pick": "scenario-pick",
  "tunnel-form": "tunnel-form",
};

function setDetailView(view: DetailView) {
  detailView = view;
  for (const id of Object.values(DP_VIEWS)) el(id).classList.add("hidden");
  el(DP_VIEWS[view]).classList.remove("hidden");
  if (view === "detail") renderServerDetail();
}

// ---------- 服务器详情 ----------
/** 服务器删除 (块上删除图标钮): 确认对话框 → delete_profile → 回空态 */
async function deleteProfileFlow(p: Profile) {
  const used = tunnels.filter((t) => t.profileId === p.id);
  const body = used.length
    ? `有 ${used.length} 条隧道关联此服务器 (${used.map((t) => t.name).join(", ")}), 删除后这些隧道将无法启动。`
    : undefined;
  const ok = await dialog({
    title: `删除服务器「${p.name}」?`,
    body,
    confirmText: "删除",
    danger: true,
  });
  if (!ok) return;
  try {
    profiles = await invoke<Profile[]>("delete_profile", { id: p.id });
    passwords.delete(p.id);
    selectedProfileId = null;
    renderHosts();
    setDetailView("empty");
  } catch (err) {
    toast(`删除失败: ${err}`, "error");
  }
}

/** renderServerDetail(showPwBar): 一键启动的密码条显隐 */
function renderServerDetail(showPwBar = false) {
  const p = selectedProfile();
  if (!p) {
    setDetailView("empty");
    return;
  }
  const head = el<HTMLDivElement>("pd-head");
  head.innerHTML = "";

  const title = document.createElement("div");
  title.className = "pd-title";
  title.innerHTML =
    `<strong>${escapeHtml(p.name)}</strong>` +
    `<span>${escapeHtml(p.host)}:${p.port} · ${escapeHtml(p.username)} · ${p.identityFile ? icon("key", 12) + " 密钥认证" : "密码认证"}</span>`;
  head.append(title);

  // 一键启动密码条 (密码档案首次 ▶ 时出现)
  const pwbar = el<HTMLDivElement>("pd-pwbar");
  pwbar.innerHTML = "";
  pwbar.classList.toggle("hidden", !showPwBar);
  if (showPwBar) {
    const input = document.createElement("input");
    input.id = "pd-pw-input";
    input.type = "password";
    input.autocomplete = "off";
    input.placeholder = `SSH 密码 (${p.username}@${p.host}, 启动 ${pdPwTargets.length} 条隧道)`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "primary";
    btn.textContent = `连接 ${pdPwTargets.length} 条隧道`;
    btn.addEventListener("click", async () => {
      if (!input.value) {
        input.focus();
        return;
      }
      passwords.set(p.id, input.value);
      pwbar.classList.add("hidden");
      const targets = pdPwTargets;
      pdPwTargets = [];
      for (const t of targets) {
        try {
          await invoke("tunnel_start", { id: t.id, password: input.value });
        } catch (err) {
          appendLog(t.id, `❌ ${err}`);
        }
      }
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") btn.click();
    });
    pwbar.append(input, btn);
  }

  // 该服务器的隧道行
  rowRefs.clear();
  const mine = tunnels.filter((t) => t.profileId === p.id);
  const listEl = el<HTMLDivElement>("pd-tunnels");
  if (mine.length === 0) {
    listEl.innerHTML = '<div class="hint tight">还没有隧道 —— 点右上「＋ 新建隧道」从场景开始</div>';
  } else {
    renderTunnelRows(listEl, mine);
  }

  fillFingerprint(p);
}

// ---------- 服务器详情尾: 指纹卡片 (TOFU 记忆) ----------

/** 上次渲染的指纹内容键 (host:port:fingerprint)。
 * refreshTunnels 每次连接成功都会重进详情, 内容没变就跳过重渲染 (防闪烁/防 hover 态被打断) */
let lastFpKey = "";

async function fillFingerprint(p: Profile) {
  const box = el<HTMLDivElement>("pd-fingerprint");
  const key = (fp: string | null) => `${p.host}:${p.port}:${fp ?? "-"}`;
  try {
    const list = await invoke<Array<{ host: string; port: number; algorithm: string; fingerprint: string }>>(
      "known_hosts_list"
    );
    const hit = list.find((h) => h.host === p.host && h.port === p.port);
    if (key(hit?.fingerprint ?? null) === lastFpKey) return;
    lastFpKey = key(hit?.fingerprint ?? null);
    box.innerHTML = "";
    if (!hit) {
      const none = document.createElement("div");
      none.className = "fp-none";
      none.textContent = "指纹: 首次连接后自动记住 (TOFU); 变更即拒绝连接";
      box.append(none);
      return;
    }
    const row = document.createElement("div");
    row.className = "fp-row";
    row.innerHTML =
      `<span class="fp-ic">${icon("shield-check", 16)}</span>` +
      `<div class="fp-main"><div class="fp-head">已记住服务器指纹<span class="fp-algo"></span></div>` +
      `<code class="fp-code">${escapeHtml(hit.fingerprint)}</code></div>`;
    row.querySelector(".fp-algo")!.textContent = hit.algorithm;

    const actions = document.createElement("div");
    actions.className = "fp-actions";
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.title = "复制指纹";
    copyBtn.innerHTML = `${icon("copy", 12)}<span class="btn-label">复制</span>`;
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(hit.fingerprint);
        toast("指纹已复制", "success");
      } catch {
        toast("复制失败", "error");
      }
    });
    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "danger";
    clearBtn.textContent = "清除";
    clearBtn.addEventListener("click", async () => {
      const ok = await dialog({
        title: `清除 ${p.host}:${p.port} 的指纹记录?`,
        body: "下次连接将重新记住当前指纹 (仅服务器确已变更时操作)。",
        confirmText: "清除",
        danger: true,
      });
      if (!ok) return;
      try {
        await invoke("known_hosts_forget", { host: p.host, port: p.port });
        lastFpKey = ""; // 强制重渲染 (清后回到占位态)
        fillFingerprint(p);
      } catch (err) {
        toast(`清除失败: ${err}`, "error");
      }
    });
    actions.append(copyBtn, clearBtn);
    row.append(actions);
    box.append(row);
  } catch (err) {
    box.textContent = `指纹信息读取失败: ${err}`;
  }
}

// ---------- 服务器表单 (新建/编辑) ----------
function openServerForm(p: Profile | null) {
  el<HTMLSpanElement>("sf-title").textContent = p ? "编辑服务器" : "新建服务器";
  el<HTMLInputElement>("profile-id").value = p?.id ?? "";
  el<HTMLInputElement>("profile-name").value = p?.name ?? "";
  el<HTMLInputElement>("profile-host").value = p?.host ?? "";
  el<HTMLInputElement>("profile-port").value = String(p?.port ?? 22);
  el<HTMLInputElement>("profile-user").value = p?.username ?? "";
  el<HTMLInputElement>("profile-key").value = p?.identityFile ?? "";
  el<HTMLSelectElement>("profile-share").value =
    p?.shareConnection == null ? "" : p.shareConnection ? "on" : "off";
  setDetailView("server-form");
  el<HTMLInputElement>("profile-name").focus();
}

el<HTMLFormElement>("server-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = el<HTMLInputElement>("profile-name").value.trim();
  const host = el<HTMLInputElement>("profile-host").value.trim();
  const port = Number(el<HTMLInputElement>("profile-port").value);
  const username = el<HTMLInputElement>("profile-user").value.trim();
  const keyPath = el<HTMLInputElement>("profile-key").value.trim();
  const shareSel = el<HTMLSelectElement>("profile-share").value;
  const shareConnection = shareSel === "" ? null : shareSel === "on";
  if (!name || !host || !username) {
    toast("请填写名称、地址和用户名", "info");
    return;
  }
  const btn =
    (e.submitter as HTMLButtonElement | null) ??
    el<HTMLFormElement>("server-form").querySelector<HTMLButtonElement>('button[type="submit"]');
  await withLoading(
    btn,
    async () => {
      try {
        const id = el<HTMLInputElement>("profile-id").value || crypto.randomUUID();
        profiles = await invoke<Profile[]>("save_profile", {
          profile: { id, name, host, port, username, identityFile: keyPath || null, shareConnection },
        });
        selectProfile(id); // 保存后选中并进入详情
      } catch (err) {
        toast(`保存失败: ${err}`, "error");
      }
    },
    "保存中..."
  );
});

el<HTMLButtonElement>("sf-back").addEventListener("click", () =>
  setDetailView(selectedProfileId ? "detail" : "empty")
);
el<HTMLButtonElement>("sf-cancel").addEventListener("click", () =>
  setDetailView(selectedProfileId ? "detail" : "empty")
);

// ---------- 新建隧道: 选场景 (预设 + 自定义 + 我的场景) ----------
async function loadScenarios() {
  scenarios = await invoke<Scenario[]>("scenarios_list");
}

async function openScenarioPick() {
  if (!selectedProfileId) {
    toast("请先选择服务器", "info");
    return;
  }
  setDetailView("scenario-pick");
  el<HTMLSpanElement>("sp-title").textContent = `新建隧道 — ${selectedProfile()?.name ?? ""}`;

  // 预设 (含「自定义」)
  const presetEl = el<HTMLDivElement>("preset-cards");
  presetEl.innerHTML = "";
  const presets = await invoke<Preset[]>("presets_list");
  for (const preset of presets) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "preset-card" + (preset.id === "custom" ? " custom" : "");
    card.innerHTML = `<strong>${escapeHtml(preset.name)}</strong><span>${escapeHtml(preset.description)}</span>`;
    card.addEventListener("click", async () => {
      try {
        wzSpec = await invoke<TunnelSpec>("tunnel_from_preset", {
          presetId: preset.id,
          name: preset.id === "custom" ? "新隧道" : preset.name,
          profileId: selectedProfileId!,
        });
        openTunnelForm({
          title: preset.name,
          hint: WZ_HINTS[preset.id] ?? "",
          defaultName: preset.id === "custom" ? "" : preset.name,
        });
      } catch (err) {
        toast(String(err), "error");
      }
    });
    presetEl.append(card);
  }

  // 我的场景
  await loadScenarios();
  const scEl = el<HTMLDivElement>("scenario-cards");
  scEl.innerHTML = "";
  el<HTMLDivElement>("scenario-empty-hint").classList.toggle("hidden", scenarios.length > 0);
  for (const s of scenarios) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "preset-card scenario-card";
    card.innerHTML = `<strong>${escapeHtml(s.name)}</strong><span>${escapeHtml(s.description || s.name)}</span>`;
    // ✕ 删除 (不触发选择)
    const del = document.createElement("span");
    del.className = "sc-del";
    del.innerHTML = icon("x", 13);
    del.title = "删除此场景";
    del.addEventListener("click", async (e) => {
      e.stopPropagation();
      const ok = await dialog({
        title: `删除场景「${s.name}」?`,
        confirmText: "删除",
        danger: true,
      });
      if (!ok) return;
      try {
        scenarios = await invoke<Scenario[]>("scenario_delete", { id: s.id });
        openScenarioPick(); // 重渲染卡片
      } catch (err) {
        toast(`删除失败: ${err}`, "error");
      }
    });
    card.append(del);
    card.addEventListener("click", async () => {
      try {
        wzSpec = await invoke<TunnelSpec>("tunnel_from_scenario", {
          scenarioId: s.id,
          name: s.name,
          profileId: selectedProfileId!,
        });
        openTunnelForm({
          title: s.name,
          hint: s.description || `来自我的场景「${s.name}」`,
          defaultName: s.name,
        });
      } catch (err) {
        toast(String(err), "error");
      }
    });
    scEl.append(card);
  }
}

el<HTMLButtonElement>("pd-new-tunnel").addEventListener("click", openScenarioPick);
el<HTMLButtonElement>("sp-back").addEventListener("click", () => setDetailView("detail"));

const WZ_HINTS: Record<string, string> = {
  vpn_share: "服务器经本机 VPN 出外网: 服务器上用 socks5h://127.0.0.1:<端口>",
  expose_local: "服务器直接访问本机运行的服务 (如本地 dev web)",
  reach_service: "本机访问服务器侧服务 (如服务器上的数据库/Web)",
  reach_lan: "应用/浏览器配 SOCKS5 代理即可访问服务器内网任意主机",
  custom: "自选形态与参数; 反向隧道服务器端口 0 = 动态分配 (连接后回填显示)",
};

// ---------- 新建隧道: 表单 (kind/backend 驱动) ----------
function defaultKind(kind: FormKind): Kind {
  switch (kind) {
    case "reverse":
      return { reverse: { bind: "127.0.0.1", port: 0 } };
    case "local":
      return {
        local: { bind: "127.0.0.1", port: 8080, targetHost: "127.0.0.1", targetPort: 80 },
      };
    case "dynamic":
      return { dynamic: { bind: "127.0.0.1", port: 1080 } };
  }
}

function defaultBackend(tag: "socksAuto" | "tcp"): Backend {
  return tag === "socksAuto"
    ? { socksAuto: { fallbackPort: 1080 } }
    : { tcp: ["127.0.0.1", 3000] };
}

function currentFormKind(): FormKind {
  const checked = document.querySelector<HTMLInputElement>('input[name="tf-kind"]:checked');
  return (checked?.value as FormKind) ?? "reverse";
}

function currentFormBackend(): "socksAuto" | "tcp" {
  const checked = document.querySelector<HTMLInputElement>('input[name="tf-backend"]:checked');
  return (checked?.value as "socksAuto" | "tcp") ?? "socksAuto";
}

interface WzField {
  id: string;
  label: string;
  value: string | number;
  hint?: string;
}

/** 字段生成统一 kind/backend 驱动: 预设/自定义/我的场景共用 */
function wzFieldsForSpec(spec: TunnelSpec): WzField[] {
  const k = spec.kind;
  const b = spec.backend;
  if ("reverse" in k) {
    const fields: WzField[] = [
      {
        id: "port",
        label: "服务器监听端口 (0 = 动态分配)",
        value: k.reverse.port,
        hint: "0 由服务器分配实际端口, 连接后显示在摘要里",
      },
    ];
    if ("socksAuto" in b) {
      fields.push({
        id: "fallback",
        label: "本机 VPN SOCKS 端口 (探测不到时内置)",
        value: b.socksAuto.fallbackPort,
      });
    } else {
      fields.push(
        { id: "host", label: "本地服务地址", value: b.tcp[0] },
        { id: "lport", label: "本地服务端口", value: b.tcp[1] }
      );
    }
    return fields;
  }
  if ("local" in k) {
    return [
      { id: "port", label: "本机监听端口", value: k.local.port },
      { id: "thost", label: "目标主机 (服务器视角)", value: k.local.targetHost },
      { id: "tport", label: "目标端口", value: k.local.targetPort },
    ];
  }
  return [{ id: "port", label: "本机 SOCKS5 端口", value: k.dynamic.port }];
}

function renderTunnelFields() {
  if (!wzSpec) return;
  // 形态/落地 radio 对齐 wzSpec
  const kindRadio = document.querySelector<HTMLInputElement>(
    `input[name="tf-kind"][value="${formKindOf(wzSpec.kind)}"]`
  );
  if (kindRadio) kindRadio.checked = true;
  el<HTMLDivElement>("tf-backend-wrap").classList.toggle(
    "hidden",
    formKindOf(wzSpec.kind) !== "reverse"
  );
  if (formKindOf(wzSpec.kind) === "reverse") {
    const backendTag = "socksAuto" in wzSpec.backend ? "socksAuto" : "tcp";
    const backendRadio = document.querySelector<HTMLInputElement>(
      `input[name="tf-backend"][value="${backendTag}"]`
    );
    if (backendRadio) backendRadio.checked = true;
  }

  // 动态字段
  const fields = el<HTMLDivElement>("wz-fields");
  fields.innerHTML = "";
  for (const f of wzFieldsForSpec(wzSpec)) {
    const label = document.createElement("label");
    label.innerHTML = `<span>${escapeHtml(f.label)}</span>`;
    const input = document.createElement("input");
    input.id = `wz-f-${f.id}`;
    input.value = String(f.value);
    label.append(input);
    if (f.hint) {
      const hint = document.createElement("div");
      hint.className = "hint";
      hint.textContent = f.hint;
      label.append(hint);
    }
    fields.append(label);
  }
  // 反向 + SOCKS 落地: 「探测并填入」本机 VPN 端口 (原 vpn_share 专属, 结构判定泛化)
  if (formKindOf(wzSpec.kind) === "reverse" && "socksAuto" in wzSpec.backend) {
    const label = document.createElement("label");
    label.innerHTML = "<span>探测本机 VPN 端口</span>";
    const probeBtn = document.createElement("button");
    probeBtn.type = "button";
    probeBtn.textContent = "探测并填入";
    label.append(probeBtn);
    fields.append(label);
    probeBtn.addEventListener("click", async () => {
      probeBtn.disabled = true;
      probeBtn.textContent = "探测中...";
      try {
        const results = await invoke<Array<{ port: number; socks5_confirmed: boolean }>>(
          "probe_local_proxy"
        );
        const socks = results.find((r) => r.socks5_confirmed);
        if (socks) {
          el<HTMLInputElement>("wz-f-fallback").value = String(socks.port);
          probeBtn.textContent = `已填入 ${socks.port}`;
        } else {
          probeBtn.textContent = results.length
            ? `发现端口但非 SOCKS5: ${results.map((r) => r.port).join(", ")}`
            : "未发现 (VPN 未开? 将用内置 SOCKS)";
        }
      } catch (e) {
        probeBtn.textContent = `探测失败: ${e}`;
      } finally {
        probeBtn.disabled = false;
      }
    });
  }
}

function openTunnelForm(ctx: { title: string; hint: string; defaultName: string }) {
  if (!wzSpec) return;
  setDetailView("tunnel-form");
  el<HTMLSpanElement>("tf-title").textContent = `新建隧道 — ${ctx.title}`;
  el<HTMLDivElement>("wz-hint").textContent = ctx.hint;
  el<HTMLInputElement>("wz-name").value = ctx.defaultName;
  el<HTMLInputElement>("wz-password").value = "";
  el<HTMLInputElement>("wz-auto").checked = wzSpec.policy.auto;
  el<HTMLInputElement>("wz-save-scenario").checked = false;
  el<HTMLInputElement>("wz-scenario-name").value = "";
  el<HTMLInputElement>("wz-scenario-name").classList.add("hidden");
  el<HTMLDivElement>("wz-error").textContent = "";
  syncWzPasswordLabel();
  renderTunnelFields();
}

/** 密码栏文案随选中服务器认证方式 (密钥档案: 口令可空) */
function syncWzPasswordLabel() {
  el("wz-password-label").textContent = selectedProfile()?.identityFile
    ? "密钥口令 (私钥未加密可留空, 仅本次会话)"
    : "密码 (仅本次会话内存, 不保存)";
}

/** 形态切换: 重置为该形态的默认参数 (切换即弃当前未保存的参数) */
document.querySelectorAll<HTMLInputElement>('input[name="tf-kind"]').forEach((radio) => {
  radio.addEventListener("change", () => {
    if (!wzSpec || !radio.checked) return;
    wzSpec.kind = defaultKind(currentFormKind());
    if (currentFormKind() === "reverse" && !("socksAuto" in wzSpec.backend) && !("tcp" in wzSpec.backend)) {
      wzSpec.backend = defaultBackend("socksAuto");
    }
    renderTunnelFields();
  });
});

/** 落地后端切换 (仅反向) */
document.querySelectorAll<HTMLInputElement>('input[name="tf-backend"]').forEach((radio) => {
  radio.addEventListener("change", () => {
    if (!wzSpec || !radio.checked) return;
    wzSpec.backend = defaultBackend(currentFormBackend());
    renderTunnelFields();
  });
});

el<HTMLInputElement>("wz-save-scenario").addEventListener("change", (e) => {
  const cb = e.target as HTMLInputElement;
  el<HTMLInputElement>("wz-scenario-name").classList.toggle("hidden", !cb.checked);
});

function num(s: string): number {
  return Number(s);
}

/** 表单值 → 覆盖模板的 kind/backend (读当前形态/落地 radio + 对应字段) */
function wzApplyToSpec(spec: TunnelSpec): string | null {
  const v = (id: string) => el<HTMLInputElement>(`wz-f-${id}`).value.trim();
  const n = (id: string) => num(v(id));
  switch (currentFormKind()) {
    case "reverse": {
      const port = n("port");
      if (!Number.isInteger(port) || port < 0 || port > 65535) return "服务器监听端口无效";
      spec.kind = { reverse: { bind: "127.0.0.1", port } };
      if (currentFormBackend() === "socksAuto") {
        const fallback = n("fallback");
        if (!Number.isInteger(fallback) || fallback <= 0 || fallback > 65535)
          return "SOCKS 端口无效";
        spec.backend = { socksAuto: { fallbackPort: fallback } };
      } else {
        const host = v("host");
        const lport = n("lport");
        if (!host) return "本地服务地址不能为空";
        if (!Number.isInteger(lport) || lport <= 0 || lport > 65535) return "本地服务端口无效";
        spec.backend = { tcp: [host, lport] };
      }
      break;
    }
    case "local": {
      const port = n("port");
      const thost = v("thost");
      const tport = n("tport");
      if (!Number.isInteger(port) || port <= 0 || port > 65535) return "本机监听端口无效";
      if (!thost) return "目标主机不能为空";
      if (!Number.isInteger(tport) || tport <= 0 || tport > 65535) return "目标端口无效";
      spec.kind = {
        local: { bind: "127.0.0.1", port, targetHost: thost, targetPort: tport },
      };
      break;
    }
    case "dynamic": {
      const port = n("port");
      if (!Number.isInteger(port) || port <= 0 || port > 65535) return "本机 SOCKS5 端口无效";
      spec.kind = { dynamic: { bind: "127.0.0.1", port } };
      break;
    }
  }
  return null;
}

el<HTMLButtonElement>("tf-back").addEventListener("click", () => openScenarioPick());

async function submitTunnelForm(start: boolean, btn?: HTMLButtonElement | null) {
  if (!wzSpec || !selectedProfileId) return;
  const errEl = el<HTMLDivElement>("wz-error");
  errEl.textContent = "";
  const name = el<HTMLInputElement>("wz-name").value.trim();
  if (!name) {
    errEl.textContent = "请填写名称";
    return;
  }
  const profileId = selectedProfileId;
  const cached = passwords.get(profileId);
  const password = el<HTMLInputElement>("wz-password").value;
  // 密钥档案口令可空 (passphrase: None); 密码档案须本次输入或会话已缓存
  if (start && !password && !selectedProfile()?.identityFile && cached === undefined) {
    errEl.textContent = "启动需要密码 (仅本次会话内存)";
    return;
  }
  const spec: TunnelSpec = { ...wzSpec, name, profileId };
  const invalid = wzApplyToSpec(spec);
  if (invalid) {
    errEl.textContent = invalid;
    return;
  }
  spec.policy = { ...spec.policy, auto: el<HTMLInputElement>("wz-auto").checked };
  await withLoading(
    btn,
    async () => {
      try {
        tunnels = await invoke<TunnelDto[]>("tunnel_create", { spec }); // 校验失败会抛错
      } catch (err) {
        errEl.textContent = String(err);
        return;
      }
      // 存为我的场景 (可选)
      if (el<HTMLInputElement>("wz-save-scenario").checked) {
        const scenarioName =
          el<HTMLInputElement>("wz-scenario-name").value.trim() || name;
        try {
          scenarios = await invoke<Scenario[]>("scenario_save", {
            scenario: {
              id: crypto.randomUUID(),
              name: scenarioName,
              description: "",
              kind: spec.kind,
              backend: spec.backend,
            },
          });
          toast(`已保存场景「${scenarioName}」`, "success");
        } catch (err) {
          appendLog(spec.id, `❌ 保存场景失败: ${err}`);
        }
      }
      if (start) {
        const pass = password || cached || null;
        if (password) passwords.set(profileId, password);
        try {
          await invoke("tunnel_start", { id: spec.id, password: pass });
        } catch (err) {
          appendLog(spec.id, `❌ ${err}`);
        }
      }
      await refreshTunnels();
      setDetailView("detail");
    },
    start ? "启动中..." : "保存中..."
  );
}

el<HTMLFormElement>("tunnel-form").addEventListener("submit", (e) => {
  e.preventDefault();
  submitTunnelForm(true, e.submitter as HTMLButtonElement | null);
});
el<HTMLButtonElement>("wz-save").addEventListener("click", (e) =>
  submitTunnelForm(false, e.currentTarget as HTMLButtonElement)
);

// ---------- 分层默认值 (档案层) ----------
async function loadDefaults() {
  try {
    const d = await invoke<Defaults>("profile_defaults_get");
    const p = d.reconnect ?? DEFAULT_POLICY;
    el<HTMLInputElement>("def-auto").checked = p.auto;
    el<HTMLInputElement>("def-fast").value = String(p.fastRetries);
    el<HTMLInputElement>("def-max").value = String(p.maxBackoff);
    el<HTMLInputElement>("def-share").checked = d.shareConnection ?? true;
    el<HTMLInputElement>("def-maxsessions").value = String(d.maxSessions ?? 10);
  } catch (err) {
    console.error("读取默认值失败", err);
  }
}

el<HTMLButtonElement>("def-save").addEventListener("click", (e) =>
  withLoading(
    e.currentTarget as HTMLButtonElement,
    async () => {
      try {
        const d = await invoke<Defaults>("profile_defaults_get");
        const base = d.reconnect ?? DEFAULT_POLICY;
        const policy: Policy = {
          ...base,
          auto: el<HTMLInputElement>("def-auto").checked,
          fastRetries: Number(el<HTMLInputElement>("def-fast").value),
          maxBackoff: Number(el<HTMLInputElement>("def-max").value),
        };
        const maxSessions = Number(el<HTMLInputElement>("def-maxsessions").value);
        await invoke("profile_defaults_save", {
          defaults: {
            connectTimeoutSecs: d.connectTimeoutSecs ?? null,
            reconnect: policy,
            shareConnection: el<HTMLInputElement>("def-share").checked,
            maxSessions: Number.isFinite(maxSessions) && maxSessions > 0 ? maxSessions : null,
          },
        });
        toast("默认值已保存", "success");
      } catch (err) {
        toast(`保存失败: ${err}`, "error");
      }
    },
    "保存中..."
  )
);

// ---------- 开机自启 (经后端命令包装 tauri-plugin-autostart) ----------
el<HTMLInputElement>("autostart").addEventListener("change", async () => {
  const cb = el<HTMLInputElement>("autostart");
  try {
    await invoke("autostart_set", { enabled: cb.checked });
  } catch (err) {
    toast(`设置失败: ${err}`, "error");
    cb.checked = !cb.checked;
  }
});

async function loadAutostart() {
  try {
    el<HTMLInputElement>("autostart").checked = await invoke<boolean>("autostart_get");
  } catch (err) {
    console.error("读取开机自启状态失败", err);
  }
}

// ---------- 初始化 ----------
/** 静态位图标填充 (nav / 返回钮 / 新建隧道钮) —— HTML 留空, 图标统一走 icons.ts */
function applyStaticIcons() {
  const NAV_ICONS: Record<string, IconName> = {
    servers: "server",
    settings: "settings",
  };
  for (const b of document.querySelectorAll<HTMLElement>(".nav-item")) {
    const slot = b.querySelector(".nav-icon");
    const name = NAV_ICONS[b.dataset.page ?? ""];
    if (slot && name) slot.innerHTML = icon(name);
  }
  for (const id of ["sf-back", "sp-back", "tf-back"]) {
    el<HTMLButtonElement>(id).innerHTML = icon("arrow-left");
  }
  el<HTMLButtonElement>("pd-new-tunnel").innerHTML =
    `${icon("plus", 15)}<span class="btn-label">新建隧道</span>`;
  // 空态配线性图标
  document.querySelector("#detail-empty .dp-empty")?.insertAdjacentHTML(
    "afterbegin",
    `<div class="empty-ic">${icon("server", 28)}</div>`,
  );
}

applyStaticIcons();
initAppearance();
(async () => {
  profiles = await invoke<Profile[]>("list_profiles");
  tunnels = await invoke<TunnelDto[]>("tunnels_list");
  await loadDefaults();
  await loadAutostart();
  renderHosts();
  showPage("servers");
})().catch((e) => console.error("初始化失败", e));
