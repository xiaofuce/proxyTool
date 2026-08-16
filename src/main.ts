import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { icon, type IconName } from "./icons";
import { initAppearance } from "./theme";
import { t, getLang, setLang, onLangChange, applyI18nStatic, hasKey, type I18nKey, type Lang } from "./i18n";
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
  // 结构判定而非 Object.keys 序 (serde externally-tagged 键唯一, 但序不可依赖)
  if ("reverse" in k) return "reverse";
  if ("local" in k) return "local";
  return "dynamic";
}

function kindLabel(k: Kind): string {
  const map: Record<KindTag, I18nKey> = {
    reverse: "kind.reverse",
    local: "kind.local",
    dynamic: "kind.dynamic",
  };
  return t(map[kindTag(k)]);
}

/** 隧道表单里的形态值 ↔ serde tag */
type FormKind = "reverse" | "local" | "dynamic";

function formKindOf(k: Kind): FormKind {
  return kindTag(k) as FormKind;
}

/** 五态五语义: 未启动(中性)/连接中(蓝)/已连接(绿)/重连中(琥珀)/连接失败(红) */
function statusText(state: string): string {
  const map: Record<string, I18nKey> = {
    connecting: "st.connecting",
    connected: "st.connected",
    reconnecting: "st.reconnecting",
    disconnected: "st.disconnected",
    error: "st.error",
  };
  return map[state] ? t(map[state]) : state;
}

const ACTIVE_STATES = ["connected", "connecting", "reconnecting"];

// ---------- 全局状态 ----------
let tunnels: TunnelDto[] = [];
let profiles: Profile[] = [];
let scenarios: Scenario[] = [];
/** profileId -> 本次会话凭据 (密码 / 密钥口令; null = 密钥档案无口令。
 * 会话内存优先; 未命中时后端兜底用已记住的加密落盘凭据) */
const passwords = new Map<string, string | null>();
/** 已记住凭据 (加密落盘 secrets.enc) 的档案 id —— 免输启动/开机自启的数据源 */
let rememberedIds = new Set<string>();
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
/** 密码输入焦点归属 (R8): 视图切换销毁行后重建时只恢复原活动行的焦点, 不抢新行焦点 */
let lastPwFocusedId: string | null = null;
/** tunnelId -> 行内 DOM 引用 (事件增量更新, 不整表重绘) */
interface RowRefs {
  card: HTMLElement; // 行根元素 (增量移除用)
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
/** 一键启动密码条 (R8 #2): 重绘不销毁输入 —— draft/focused 持态, 启动完成才清 */
interface PdPwState {
  profileId: string;
  targets: TunnelDto[];
  draft: string;
  focused: boolean;
}
let pdPwState: PdPwState | null = null;
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
  // content 是多个页面共享的滚动容器, 不重置则新页带着上一页的滚动位置出现
  document.querySelector(".content")?.scrollTo({ top: 0 });
}

navItems.forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page!)));

// ---------- 隧道行渲染 (服务器详情页) ----------
function summary(dt: TunnelDto): string {
  const k = dt.kind;
  if ("reverse" in k) {
    const port = k.reverse.port;
    const remote =
      port === 0 ? t("sm.remoteDyn") : t("sm.remotePort", { port });
    const local =
      "socksAuto" in dt.backend
        ? t("sm.localSocks")
        : t("sm.localTcp", { host: dt.backend.tcp[0], port: dt.backend.tcp[1] });
    return `${remote} ← ${local}`;
  }
  if ("local" in k) {
    return t("sm.localFwd", {
      bind: k.local.bind,
      port: k.local.port,
      host: k.local.targetHost,
      tport: k.local.targetPort,
    });
  }
  return t("sm.dynFwd", { bind: k.dynamic.bind, port: k.dynamic.port });
}

/** 摘要行文案: summary · host (host 比别名有增量) */
function subLine(dt: TunnelDto): string {
  const profile = profiles.find((p) => p.id === dt.profileId);
  if (!profile) return t("sm.noProfile", { s: summary(dt) });
  return `${summary(dt)} · ${profile.host}`;
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
  if (s < 60) return t("up.s", { s });
  const m = Math.floor(s / 60);
  if (m < 60) return t("up.ms", { m, s: s % 60 });
  const h = Math.floor(m / 60);
  if (h < 24) return t("up.hm", { h, m: m % 60 });
  return t("up.dh", { d: Math.floor(h / 24), h: h % 24 });
}

/** 端口 chip: 反向 = 服务器端口 (0=动态分配弱 chip, 回填后 :port 绿点);
 * 本地/动态 = 本机监听 bind:port。updateRow 与重绘共用 */
function refreshPortChip(chip: HTMLSpanElement, dt: TunnelDto): void {
  const k = dt.kind;
  if ("reverse" in k) {
    if (k.reverse.port > 0) {
      chip.className = "port-chip bound";
      chip.textContent = `:${k.reverse.port}`;
      chip.title = t("chip.remote");
    } else {
      chip.className = "port-chip dyn";
      chip.textContent = t("chip.dyn");
      chip.title = t("chip.dynTitle");
    }
  } else if ("local" in k) {
    chip.className = "port-chip";
    chip.textContent = `${k.local.bind}:${k.local.port}`;
    chip.title = t("chip.local");
  } else {
    chip.className = "port-chip";
    chip.textContent = `${k.dynamic.bind}:${k.dynamic.port}`;
    chip.title = t("chip.socks");
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
  refs.status.textContent = statusText(t.state);
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

/** 单行构建 (U4 行结构: head(展开|名称+形态+端口chip|状态徽章|时长|启动/停止+⋯) + 摘要行 + 消息行 + 详情)。
 * 增量渲染 (R8): 只有新隧道才走这里; 已有行走 updateRow —— 见 syncTunnelRows */
function buildTunnelRow(container: HTMLElement, dt: TunnelDto) {
  const profile = profiles.find((p) => p.id === dt.profileId);
  noteConnected(dt); // 非事件路径进 connected (初始加载/拉取) 从本时刻起算
  const card = document.createElement("div");
  card.className = "card tunnel-card";
  card.dataset.tid = dt.id; // 增量定位锚点 (syncTunnelRows 移除用)

    // --- 头部: 展开钮 + 名称/形态/端口chip + 状态徽章 + 运行时长 + 主操作/⋯ ---
    const head = document.createElement("div");
    head.className = "tunnel-head";

    const expand = document.createElement("button");
    expand.type = "button";
    expand.className = "icon-btn tunnel-expand";
    expand.innerHTML = icon("chevron-right", 14);
    expand.setAttribute("aria-label", t("row.expandLogs"));

    const title = document.createElement("div");
    title.className = "tunnel-title";
    title.innerHTML =
      `<strong>${escapeHtml(dt.name)}</strong>` +
      `<span class="tunnel-kind">${kindLabel(dt.kind)}</span>`;
    const portChip = document.createElement("span");
    title.append(portChip);

    const status = document.createElement("span");
    status.className = `status-badge ${dt.state}`;

    const uptime = document.createElement("span");
    uptime.className = "tunnel-uptime";
    uptime.hidden = true;

    const actions = document.createElement("div");
    actions.className = "tunnel-actions";
    const btnStart = document.createElement("button");
    btnStart.type = "button";
    btnStart.innerHTML = `${icon("play", 13)}<span class="btn-label">${t("row.start")}</span>`;
    const btnStop = document.createElement("button");
    btnStop.type = "button";
    btnStop.innerHTML = `${icon("square", 13)}<span class="btn-label">${t("row.stop")}</span>`;
    const moreBtn = document.createElement("button");
    moreBtn.type = "button";
    moreBtn.className = "icon-btn more-btn";
    moreBtn.innerHTML = icon("ellipsis", 16);
    moreBtn.setAttribute("aria-label", t("row.more"));
    moreBtn.title = t("row.more");
    actions.append(btnStart, btnStop, moreBtn);

    head.append(expand, title, status, uptime, actions);
    card.append(head);

    // --- 摘要行 (参数 · host; ellipsis + title 全文) ---
    const sub = document.createElement("div");
    sub.className = "tunnel-sub";
    sub.textContent = subLine(dt);
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
      ? t("row.pwKeyPh", { user: profile.username, host: profile.host })
      : t("row.pwPh", {
          user: profile ? profile.username : "",
          host: profile ? profile.host : "",
        });
    pwInput.autocomplete = "off";
    const pwBtn = document.createElement("button");
    pwBtn.type = "button";
    pwBtn.className = "primary";
    pwBtn.textContent = t("row.connect");
    pwBar.append(pwInput, pwBtn);

    // 日志工具条: 复制 / 清空
    const logBar = document.createElement("div");
    logBar.className = "log-bar";
    const logCopy = document.createElement("button");
    logCopy.type = "button";
    logCopy.className = "log-copy";
    logCopy.title = t("row.copyLog");
    logCopy.innerHTML = `${icon("copy", 13)}<span class="btn-label">${t("common.copy")}</span>`;
    const logClear = document.createElement("button");
    logClear.type = "button";
    logClear.className = "log-clear";
    logClear.title = t("row.clearLog");
    logClear.innerHTML = `${icon("eraser", 13)}<span class="btn-label">${t("row.clear")}</span>`;
    logBar.append(logCopy, logClear);

    const logEl = document.createElement("div");
    logEl.className = "log";
    for (const line of logs.get(dt.id) ?? []) logEl.append(makeLogLine(line));
    logEl.scrollTop = logEl.scrollHeight; // 初始渲染贴底 (最新在下)
    detailIn.append(pwBar, logBar, logEl);
    detail.append(detailIn);
    card.append(detail);
    container.append(card);

    const refs: RowRefs = {
      card,
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
    rowRefs.set(dt.id, refs);
    const open0 = expanded.has(dt.id);
    detail.classList.toggle("collapsed", !open0);
    detail.toggleAttribute("inert", !open0); // 收起时移出 Tab 序, 免焦点钻进不可见区
    expand.classList.toggle("open", open0);
    updateRow(dt);

    // 密码草稿保护: 正在输入的密码经整表重绘回填; 仅当销毁前焦点就在本行才恢复焦点
    const draft = pwDrafts.get(dt.id);
    if (draft && dt.state !== "connecting" && dt.state !== "connected") {
      pwInput.value = draft;
      pwBar.classList.remove("hidden");
      if (lastPwFocusedId === dt.id) pwInput.focus();
    }

    // --- 接线 ---
    expand.addEventListener("click", () => {
      const open = expanded.has(dt.id);
      if (open) expanded.delete(dt.id);
      else expanded.add(dt.id);
      detail.classList.toggle("collapsed", open);
      detail.toggleAttribute("inert", open);
      expand.classList.toggle("open", !open);
      if (!open) logEl.scrollTop = logEl.scrollHeight;
    });
    head.addEventListener("click", (e) => {
      if ((e.target as HTMLElement).closest("button")) return;
      expand.click();
    });

    /** password: null = 密钥档案无口令 (后端 KeyFile passphrase=None)。
     * remember: 有密码即记住 (AES-256-GCM 加密落盘, 重启/自启免输) */
    const doStart = async (password: string | null) => {
      try {
        await invoke("tunnel_start", {
          id: dt.id,
          password: password || null,
          remember: password ? true : null,
        });
        passwords.set(dt.profileId, password);
        if (password) rememberedIds.add(dt.profileId);
        pwDrafts.delete(dt.id);
        pwBar.classList.add("hidden");
      } catch (err) {
        appendLog(dt.id, `❌ ${err}`);
      }
    };
    btnStart.addEventListener("click", async () => {
      // 优先级: 本次会话输入 > 已记住的加密凭据 (后端兜底, 免输) > 弹条询问
      if (passwords.has(dt.profileId) || rememberedIds.has(dt.profileId)) {
        await doStart(passwords.get(dt.profileId) ?? null);
        return;
      }
      expanded.add(dt.id);
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
      await withLoading(pwBtn, () => doStart(pwInput.value || null), t("row.connecting"));
    });
    pwInput.addEventListener("input", () => pwDrafts.set(dt.id, pwInput.value));
    pwInput.addEventListener("focus", () => {
      lastPwFocusedId = dt.id;
    });
    pwInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") pwBtn.click();
    });
    logCopy.addEventListener("click", async () => {
      const text = logText(dt.id);
      if (!text) {
        toast(t("row.logEmpty"), "info");
        return;
      }
      try {
        await navigator.clipboard.writeText(text);
        toast(t("row.logCopied"), "success");
      } catch {
        toast(t("common.copyFail"), "error");
      }
    });
    logClear.addEventListener("click", () => {
      logs.delete(dt.id);
      logEl.innerHTML = "";
    });
    btnStop.addEventListener("click", async () => {
      try {
        await invoke("tunnel_stop", { id: dt.id });
        appendLog(dt.id, t("row.stopping"));
      } catch (err) {
        appendLog(dt.id, `❌ ${err}`);
      }
    });

    // --- ⋯ 菜单条目动作 (打开时惰性求值, 这里只定义) ---
    const trustNewFingerprint = async () => {
      const prof = profiles.find((p) => p.id === dt.profileId);
      if (!prof) {
        appendLog(dt.id, t("row.noProfileErr"));
        return;
      }
      const ok = await dialog({
        title: t("fp.trustTitle"),
        body: t("fp.trustBody", { host: prof.host, port: prof.port }),
        confirmText: t("fp.trustConfirm"),
        danger: true,
      });
      if (!ok) return;
      try {
        await invoke("known_hosts_forget", { host: prof.host, port: prof.port });
        appendLog(dt.id, t("fp.forgotLog", { host: prof.host, port: prof.port }));
      } catch (err) {
        appendLog(dt.id, `❌ ${err}`);
        return;
      }
      // 复用启动路径: 有缓存密码直接重启, 否则展开密码条
      btnStart.click();
    };
    const runAction = async (cmd: "verify_remote_tunnel" | "deploy_wrapper") => {
      if (!passwords.has(dt.profileId) && !rememberedIds.has(dt.profileId)) {
        appendLog(dt.id, t("row.needCreds"));
        btnStart.click();
        return;
      }
      const pass = passwords.get(dt.profileId) ?? null; // null → 后端兜底用记住的凭据
      // busy 挂在行内 ⋯ 钮上 (菜单即点即关, 反馈落在持久元素)
      await withLoading(moreBtn, async () => {
        try {
          await invoke<string>(cmd, { id: dt.id, password: pass || null });
          // 输出经 tunnel-log 事件回流行内日志, 此处不重复
        } catch (err) {
          appendLog(dt.id, `❌ ${err}`);
        }
      });
    };
    const saveScenario = async () => {
      const r = await dialog({
        title: t("sc.saveTitle"),
        body: t("sc.saveBody"),
        input: { value: dt.name, placeholder: t("sc.namePh") },
        confirmText: t("common.save"),
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
            kind: dt.kind,
            backend: dt.backend,
          },
        });
        appendLog(dt.id, t("sc.saved", { name }));
      } catch (err) {
        appendLog(dt.id, t("sc.saveFailLog", { err: String(err) }));
      }
    };
    const deleteTunnel = async () => {
      const ok = await dialog({
        title: t("tun.delTitle", { name: dt.name }),
        body: t("tun.delBody"),
        confirmText: t("common.delete"),
        danger: true,
      });
      if (!ok) return;
      try {
        tunnels = await invoke<TunnelDto[]>("tunnel_delete", { id: dt.id });
        connectedSince.delete(dt.id);
        pwDrafts.delete(dt.id);
        renderHosts();
        if (detailView === "detail") renderServerDetail();
      } catch (err) {
        appendLog(dt.id, `❌ ${err}`);
      }
    };

    /** 打开瞬间取最新状态计算条目 (hidden/disabled 按当时 state 出没, 与重绘解耦) */
    const menuItems = (): MenuItem[] => {
      const cur = currentTunnel(dt.id) ?? dt;
      const prof = profiles.find((p) => p.id === cur.profileId);
      const items: MenuItem[] = [];
      if (cur.state === "reconnecting") {
        items.push({
          label: t("menu.retryNow"),
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
          label: t("menu.trustFp"),
          icon: "shield-check",
          title: t("menu.trustFpTitle"),
          action: trustNewFingerprint,
        });
      }
      if (isVpnShare(cur)) {
        const vpnEnabled = cur.state === "connected" && !needPassword(cur);
        items.push(
          {
            label: t("menu.verify"),
            icon: "globe",
            title: t("menu.verifyTitle"),
            disabled: !vpnEnabled,
            action: () => runAction("verify_remote_tunnel"),
          },
          {
            label: t("menu.deploy"),
            icon: "terminal",
            title: t("menu.deployTitle"),
            disabled: !vpnEnabled,
            action: () => runAction("deploy_wrapper"),
          },
        );
      }
      if (items.length) items.push({ separator: true });
      items.push({
        label: t("menu.saveScenario"),
        icon: "bookmark",
        title: t("menu.saveScenarioTitle"),
        action: saveScenario,
      });
      items.push({
        label: t("menu.autostart"),
        icon: "power",
        checked: cur.enabled,
        title: t("menu.autostartTitle"),
        action: async () => {
          try {
            tunnels = await invoke<TunnelDto[]>("tunnel_set_enabled", {
              id: cur.id,
              enabled: !cur.enabled,
            });
            if (!cur.enabled && prof && !rememberedIds.has(prof.id)) {
              appendLog(cur.id, t("menu.autostartHintLog"));
            }
            renderHosts();
          } catch (err) {
            appendLog(cur.id, `❌ ${err}`);
          }
        },
      });
      items.push({ separator: true });
      items.push({ label: t("menu.delete"), icon: "trash-2", danger: true, title: t("menu.deleteTitle"), action: deleteTunnel });
      return items;
    };

    moreBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (menuTag() === dt.id) {
        closeMenus(); // 再点同一 ⋯ = 关闭
        return;
      }
      openMenu(moreBtn, menuItems, dt.id);
    });
}

/** 增量渲染 (R8 #1 重绘风暴): 已有行 updateRow, 新行 buildTunnelRow, 消失行移除。
 * 重连风暴/事件流下不再整表 innerHTML 重建 —— 只改文本节点, hover/焦点不重置 */
function syncTunnelRows(container: HTMLElement, list: TunnelDto[]) {
  const ids = new Set(list.map((t) => t.id));
  let removed = false;
  for (const [id, refs] of rowRefs) {
    if (!ids.has(id)) {
      refs.card.remove();
      rowRefs.delete(id);
      removed = true;
    }
  }
  if (removed) closeMenus(); // 行被移除时收起悬挂菜单 (锚点已脱离 DOM)
  for (const t of list) {
    if (rowRefs.has(t.id)) updateRow(t);
    else buildTunnelRow(container, t);
  }
}

function currentTunnel(id: string): TunnelDto | undefined {
  return tunnels.find((t) => t.id === id);
}

/** 请求序号: focus 防抖与 connected 事件两条路径并发, 过期响应 (last-write-wins) 丢弃 */
let refreshSeq = 0;

/** 三拉隧道 + 档案 + 已记住凭据 (档案列表曾只 init 拉一次导致陈旧); 托盘常驻场景由 window focus 兜底刷新 */
async function refreshTunnels() {
  const my = ++refreshSeq;
  const [ts, ps, secs] = await Promise.all([
    invoke<TunnelDto[]>("tunnels_list"),
    invoke<Profile[]>("list_profiles"),
    invoke<string[]>("secrets_status").catch(() => [] as string[]),
  ]);
  if (my !== refreshSeq) return; // 已有更新的请求落盘, 本响应作废
  tunnels = ts;
  profiles = ps;
  rememberedIds = new Set(secs);
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
    // 认证被拒 / 私钥加载失败(口令不对) → 会话缓存 + 记住的加密凭据一并
    // 作废 (后端事件桥已删 secrets.enc 里的那份), 下次启动重新询问
    const msg = p.message ?? "";
    if (p.state === "error" && (msg.includes("认证被拒") || msg.includes("加载私钥"))) {
      passwords.delete(t.profileId);
      rememberedIds.delete(t.profileId);
    }
    noteConnected(t); // 进/出 connected 维护 uptime 起算点
    updateRow(t);
    if (p.message && p.state !== "connected")
      appendLog(p.id, p.state === "error" ? `❌ ${p.message}` : p.message);
    // 中列块状态点/pill/▶ 随事件增量更新 (R8: 不再全量重建 host-grid)
    updateHostBlock(t.profileId);
    if (p.state === "connected") {
      // 端口 0 动态分配回填会改 spec, 连接成功时拉一次最新列表
      refreshTunnels().catch(() => {});
    }
  }
});

/** TOFU 首连记住指纹 → 可点击复制的 toast (替代裸日志行, 美化提示) */
function fpRememberedToast(fingerprint: string): void {
  toastRich({
    html: `${escapeHtml(t("fp.toast"))}<code>${escapeHtml(fingerprint)}</code>`,
    kind: "success",
    icon: "shield-check",
    ms: 8000,
    title: t("fp.clickCopy"),
    onClick: async () => {
      try {
        await navigator.clipboard.writeText(fingerprint);
        toast(t("fp.copied"), "success");
      } catch {
        toast(t("common.copyFail"), "error");
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

/** 服务器块引用表: 事件级增量补丁 (R8: 重连风暴/事件刷屏不再整表重建) */
interface HostBlockRefs {
  blk: HTMLDivElement;
  nameText: HTMLElement;
  addr: HTMLElement;
  dot: HTMLElement;
  pill: HTMLElement;
  toggle: HTMLButtonElement;
}
const hostBlocks = new Map<string, HostBlockRefs>();
let newBlockBtn: HTMLButtonElement | undefined;

function buildHostBlock(p: Profile): HTMLDivElement {
  const block = document.createElement("div");
  block.className = "host-block";
  if (p.id === selectedProfileId) block.classList.add("active");

  // 行 1: 状态点 + 名称 (右留白给 ▶ 钮; 状态类/文本由 updateHostBlock 补丁)
  const name = document.createElement("div");
  name.className = "hb-name";
  const dot = document.createElement("span");
  dot.className = "hb-status";
  const nameText = document.createElement("span");
  nameText.textContent = p.name;
  name.append(dot, nameText);

  // 行 2: 地址 + 右槽 (运行 pill ⇄ hover 换出 编辑/删除 图标钮, 同位交叉淡换)
  const meta = document.createElement("div");
  meta.className = "hb-meta";
  const addr = document.createElement("div");
  addr.className = "hb-addr";
  const side = document.createElement("div");
  side.className = "hb-side";
  const acts = document.createElement("div");
  acts.className = "hb-acts";
  const editBtn = document.createElement("button");
  editBtn.type = "button";
  editBtn.className = "hb-act";
  editBtn.title = t("host.edit");
  editBtn.setAttribute("aria-label", t("host.editAria", { name: p.name }));
  editBtn.innerHTML = icon("pencil", 13);
  editBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    selectProfile(p.id);
    openServerForm(p);
  });
  const delBtn = document.createElement("button");
  delBtn.type = "button";
  delBtn.className = "hb-act danger";
  delBtn.title = t("host.del");
  delBtn.setAttribute("aria-label", t("host.delAria", { name: p.name }));
  delBtn.innerHTML = icon("trash-2", 13);
  delBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    selectProfile(p.id);
    void deleteProfileFlow(p);
  });
  acts.append(editBtn, delBtn);
  const pill = document.createElement("span");
  pill.className = "hb-pill";
  side.append(pill, acts);
  meta.append(addr, side);

  // ▶ 一键启动 enabled 隧道 / ■ 全部停止 (右上角圆形钮; 点击时读图标态, 不用构建时快照)
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "hb-toggle";
  toggle.addEventListener("click", (e) => {
    e.stopPropagation();
    selectProfile(p.id);
    const stopping = toggle.classList.contains("stop");
    // busy 期间防双击重复启停 (状态点即时反馈, 图标钮不显 spinner —— CSS 抑制)
    withLoading(toggle, () => (stopping ? stopAllForProfile(p) : startAllForProfile(p)));
  });

  block.append(name, meta, toggle);
  block.addEventListener("click", () => selectProfile(p.id));
  // a11y: 块是可聚焦的"选中"卡片; 内层按钮保留自己的 Tab 位, 键事件不冒泡处理
  block.tabIndex = 0;
  block.setAttribute("role", "button");
  block.setAttribute("aria-label", t("host.aria", { name: p.name }));
  block.addEventListener("keydown", (e) => {
    if (e.target !== block) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      selectProfile(p.id);
    }
  });
  hostBlocks.set(p.id, { blk: block, nameText, addr, dot, pill, toggle });
  return block;
}

/** 事件级局部补丁: 只改状态点/pill/▶/名称/地址, 不重建块 (重连风暴下每次事件只动几个节点) */
function updateHostBlock(profileId: string) {
  const refs = hostBlocks.get(profileId);
  const p = refs ? profiles.find((x) => x.id === profileId) : undefined;
  if (!refs || !p) return;
  const agg = profileAggregate(p);
  refs.nameText.textContent = p.name;
  refs.addr.innerHTML =
    `${escapeHtml(`${p.host}:${p.port} · ${p.username}`)}` +
    (p.identityFile ? ` <span class="hb-key" title="${escapeHtml(t("auth.key"))}">${icon("key", 12)}</span>` : "");
  refs.dot.className = `hb-status ${agg.state}`;
  refs.dot.title = agg.state || t("host.idleTitle");
  refs.pill.classList.toggle("running", agg.running > 0);
  refs.pill.textContent =
    agg.total === 0 ? t("host.noTunnels") : t("host.running", { r: agg.running, t: agg.total });
  refs.pill.title =
    agg.total === 0
      ? t("host.noTunnelsTitle")
      : t("host.runningTitle", { r: agg.running, t: agg.total });
  const anyActive = tunnels.some(
    (t) => t.profileId === profileId && ACTIVE_STATES.includes(t.state)
  );
  refs.toggle.classList.toggle("stop", anyActive);
  refs.toggle.innerHTML = anyActive ? icon("square", 13) : icon("play", 13);
  refs.toggle.setAttribute("aria-label", anyActive ? t("host.stopAll") : t("host.startAll"));
  refs.toggle.title = anyActive ? t("host.stopAllTitle") : t("host.startAllTitle");
}

/** 选中高亮类 (selectProfile 走这里, 不再重建) */
function updateHostActive() {
  for (const [id, refs] of hostBlocks) refs.blk.classList.toggle("active", id === selectedProfileId);
}

function renderHosts() {
  const grid = el<HTMLDivElement>("host-grid");
  const alive = new Set(profiles.map((p) => p.id));
  // 集合 diff: 档案删了摘块, 新增建块, 已存在走局部补丁
  for (const [id, refs] of hostBlocks) {
    if (!alive.has(id)) {
      refs.blk.remove();
      hostBlocks.delete(id);
    }
  }
  for (const p of profiles) {
    if (!hostBlocks.has(p.id)) grid.append(buildHostBlock(p));
    updateHostBlock(p.id); // 新建块也走同一补丁初始化 (初始态/名称/地址)
  }
  // + 新建块 (持久元素, 不随刷新重建)
  if (!newBlockBtn || !newBlockBtn.isConnected) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "host-block new-block";
    b.innerHTML = `${icon("plus", 14)}<span class="btn-label">${t("host.newBtn")}</span>`;
    b.addEventListener("click", () => openServerForm(null));
    grid.append(b);
    newBlockBtn = b;
  }
  updateHostActive();
  cmdGenRefreshProfiles();
}

function selectProfile(id: string | null) {
  if (id !== selectedProfileId) pdPwState = null; // 换档案, 挂起的批量密码条作废 (草稿只属于原档案)
  selectedProfileId = id;
  updateHostActive();
  setDetailView(id ? "detail" : "empty");
}

/** ▶: 启动该服务器全部 enabled 且未在运行的隧道 (无凭据可用时弹右面板密码条) */
async function startAllForProfile(p: Profile) {
  const targets = tunnels.filter(
    (t) => t.profileId === p.id && t.enabled && !ACTIVE_STATES.includes(t.state)
  );
  if (targets.length === 0) {
    renderServerDetail();
    return;
  }
  // 密码档案且既没本次输入也没记住 → 右面板密码条收集一次, 再批量启动
  if (!p.identityFile && !passwords.has(p.id) && !rememberedIds.has(p.id)) {
    pdPwState = { profileId: p.id, targets, draft: "", focused: true };
    renderServerDetail();
    el<HTMLInputElement>("pd-pw-input")?.focus();
    return;
  }
  const pass = passwords.get(p.id) ?? null; // null → 后端兜底用记住的凭据
  for (const t of targets) {
    try {
      await invoke("tunnel_start", { id: t.id, password: pass, remember: pass ? true : null });
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
  for (const tn of targets) {
    try {
      await invoke("tunnel_stop", { id: tn.id });
      appendLog(tn.id, t("row.stopping"));
    } catch (err) {
      appendLog(tn.id, `❌ ${err}`);
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
  if (view === "detail") {
    renderServerDetail();
  } else {
    // 离开详情: 摘掉隧道行 DOM + 清引用 —— 防旧行被后续事件幽灵更新/泄漏
    // 记录销毁前焦点所在行, 重建时只恢复它的密码输入焦点
    const ae = document.activeElement;
    lastPwFocusedId =
      ae instanceof HTMLElement ? ae.closest(".tunnel-card")?.getAttribute("data-tid") ?? null : null;
    for (const [, refs] of rowRefs) refs.card.remove();
    if (rowRefs.size > 0) closeMenus();
    rowRefs.clear();
  }
}

// ---------- 命令生成页: 隧道命令生成器 (命令在服务器 A 上执行, 经 SSH 到目标 B) ----------

/** 按当前表单状态生成 ssh / autossh 命令 (纯字符串, 不碰引擎) */
function cmdGenBuild(): { ssh: string; autossh: string; hint: string } {
  const host = el<HTMLInputElement>("cg-host").value.trim();
  const port = el<HTMLInputElement>("cg-port").value.trim() || "22";
  const user = el<HTMLInputElement>("cg-user").value.trim();
  const listen = el<HTMLInputElement>("cg-listen").value.trim() || "1080";
  const thost = el<HTMLInputElement>("cg-thost").value.trim() || "127.0.0.1";
  const tport = el<HTMLInputElement>("cg-tport").value.trim() || "8080";
  const bind = el<HTMLInputElement>("cg-bind").checked;
  const kind = (document.querySelector<HTMLInputElement>("input[name=cg-kind]:checked")?.value ?? "local") as
    | "local" | "reverse" | "dynamic";

  const bindPrefix = bind ? "0.0.0.0:" : "";
  const fwd =
    kind === "dynamic"
      ? `-D ${bindPrefix}${listen}`
      : kind === "local"
        ? `-L ${bindPrefix}${listen}:${thost}:${tport}`
        : `-R ${bindPrefix}${listen}:${thost}:${tport}`;
  const opts = "-o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3";
  const dest = `${user ? `${user}@` : ""}${host} -p ${port}`;
  const ssh = `ssh -N ${fwd} ${opts} ${dest}`;
  const autossh = `AUTOSSH_GATETIME=0 autossh -M 0 -N ${fwd} ${opts} ${dest}`;

  let hint: string;
  if (kind === "local") hint = t("cg.hintL", { bind: bind ? "0.0.0.0" : "127.0.0.1", listen, thost, tport });
  else if (kind === "reverse") hint = t("cg.hintR", { bind: bind ? "0.0.0.0" : "127.0.0.1", listen, thost, tport });
  else hint = t("cg.hintD", { listen });
  if (kind === "reverse" && bind) hint += t("cg.hintGateway");
  const sel = profiles.find((p) => p.id === el<HTMLSelectElement>("cg-profile").value);
  if (sel?.identityFile) hint += t("cg.hintKeyFile");
  return { ssh, autossh, hint };
}

function cmdGenRegen() {
  const { ssh, autossh, hint } = cmdGenBuild();
  el<HTMLPreElement>("cg-ssh").textContent = ssh;
  el<HTMLPreElement>("cg-autossh").textContent = autossh;
  el<HTMLDivElement>("cg-hint").textContent = hint;
  const kind = (document.querySelector<HTMLInputElement>("input[name=cg-kind]:checked")?.value ?? "local") as
    "local" | "reverse" | "dynamic";
  el<HTMLElement>("cg-target-wrap").classList.toggle("hidden", kind === "dynamic");
  renderCmdFlow(kind, {
    host: el<HTMLInputElement>("cg-host").value.trim(),
    listen: el<HTMLInputElement>("cg-listen").value.trim() || "1080",
    thost: el<HTMLInputElement>("cg-thost").value.trim() || "127.0.0.1",
    tport: el<HTMLInputElement>("cg-tport").value.trim() || "8080",
  });
  scheduleCmdLastSave();
}

/** 流程图示: 三节点 (在哪开端口 → SSH → 流量最后到哪), 按形态换序换文案 */
function renderCmdFlow(
  kind: "local" | "reverse" | "dynamic",
  v: { host: string; listen: string; thost: string; tport: string },
) {
  const node = (ic: IconName, title: string, sub: string) =>
    `<div class="flow-node"><span class="flow-ic">${icon(ic, 18)}</span><div class="flow-tx"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(sub)}</span></div></div>`;
  const arrow = (lab: string) =>
    `<div class="flow-arrow">${icon("arrow-right", 14)}<span>${escapeHtml(lab)}</span></div>`;
  const bTxt = escapeHtml(v.host || t("cg.bAddr"));
  const target = `${v.thost}:${v.tport}`;
  let html: string;
  if (kind === "local") {
    html =
      node("monitor", t("cg.flowA"), t("cg.flowAOpen", { p: v.listen })) + arrow("SSH") +
      node("server", t("cg.flowB"), bTxt) + arrow(t("cg.arrowB")) +
      node("globe", target, t("cg.fromB"));
  } else if (kind === "reverse") {
    html =
      node("server", t("cg.flowB"), t("cg.flowBOpen", { addr: bTxt, p: v.listen })) + arrow("SSH") +
      node("monitor", t("cg.flowA"), t("cg.flowARun")) + arrow(t("cg.arrowA")) +
      node("globe", target, t("cg.fromA"));
  } else {
    html =
      node("monitor", t("cg.flowA"), t("cg.flowSocks", { p: v.listen })) + arrow("SSH") +
      node("server", t("cg.flowB"), bTxt) + arrow(t("cg.arrowB")) +
      node("globe", t("cg.anyAddr"), t("cg.anyFromB"));
  }
  el<HTMLElement>("cg-flow").innerHTML = html;
}

// ---------- 命令生成页落盘 (我的命令 + 最近输入; 后端 AES-GCM 加密文件) ----------

type CmdParamsT = {
  kind: string; host: string; port: number; user: string;
  listen: number; targetHost: string; targetPort: number; bindAll: boolean;
};
type CmdRecipeT = { id: string; name: string } & CmdParamsT;

let cmdRecipes: CmdRecipeT[] = [];
/** 最近输入落盘就绪标志 (初始恢复完成前不回写, 避免载入即覆盖) */
let cmdLastReady = false;
let cmdLastTimer: number | undefined;

function collectCmdParams(): CmdParamsT {
  return {
    kind: document.querySelector<HTMLInputElement>("input[name=cg-kind]:checked")?.value ?? "local",
    host: el<HTMLInputElement>("cg-host").value.trim(),
    port: Number(el<HTMLInputElement>("cg-port").value.trim() || "22") || 22,
    user: el<HTMLInputElement>("cg-user").value.trim(),
    listen: Number(el<HTMLInputElement>("cg-listen").value.trim() || "1080") || 1080,
    targetHost: el<HTMLInputElement>("cg-thost").value.trim() || "127.0.0.1",
    targetPort: Number(el<HTMLInputElement>("cg-tport").value.trim() || "8080") || 8080,
    bindAll: el<HTMLInputElement>("cg-bind").checked,
  };
}

/** 参数回填表单 (载入我的命令 / 恢复最近输入) */
function applyCmdParams(p: CmdParamsT) {
  const radio =
    document.querySelector<HTMLInputElement>(`input[name=cg-kind][value="${p.kind}"]`) ??
    document.querySelector<HTMLInputElement>('input[name=cg-kind][value="local"]');
  if (radio) radio.checked = true;
  el<HTMLInputElement>("cg-host").value = p.host;
  el<HTMLInputElement>("cg-port").value = String(p.port);
  el<HTMLInputElement>("cg-user").value = p.user;
  el<HTMLInputElement>("cg-listen").value = String(p.listen);
  el<HTMLInputElement>("cg-thost").value = p.targetHost;
  el<HTMLInputElement>("cg-tport").value = String(p.targetPort);
  el<HTMLInputElement>("cg-bind").checked = !!p.bindAll;
  // 档案下拉: 同 host+port+user 的档案选中, 否则手动输入
  const match = profiles.find((x) => x.host === p.host && x.port === p.port && x.username === p.user);
  el<HTMLSelectElement>("cg-profile").value = match?.id ?? "";
}

function refreshCmdRecipes() {
  const sel = el<HTMLSelectElement>("cg-recipes");
  const prev = sel.value;
  sel.innerHTML = "";
  const ph = document.createElement("option");
  ph.value = "";
  ph.textContent = cmdRecipes.length ? t("cg.loadPh") : t("cg.nonePh");
  sel.append(ph);
  for (const r of cmdRecipes) {
    const o = document.createElement("option");
    o.value = r.id;
    o.textContent = r.name;
    sel.append(o);
  }
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
}

function suggestCmdName(p: CmdParamsT): string {
  return p.kind === "dynamic"
    ? t("cg.suggestD", { host: p.host, listen: p.listen })
    : t("cg.suggestLR", { host: p.host, thost: p.targetHost, tport: p.targetPort });
}

/** 存为命令 (选中已有条目 = 更新它; dialog 输入名) */
async function saveCmdRecipe() {
  const params = collectCmdParams();
  const selId = el<HTMLSelectElement>("cg-recipes").value;
  const cur = cmdRecipes.find((r) => r.id === selId);
  const name = await dialog({
    title: t("cg.saveTitle"),
    body: t("cg.saveBody"),
    input: { value: cur?.name ?? suggestCmdName(params) },
  });
  if (typeof name !== "string") return;
  if (!name.trim()) {
    toast(t("cg.nameEmpty"), "error");
    return;
  }
  try {
    const list = await invoke<CmdRecipeT[]>("cmdgen_save", {
      recipe: { id: cur?.id ?? "", name: name.trim(), ...params },
    });
    cmdRecipes = list;
    refreshCmdRecipes();
    el<HTMLSelectElement>("cg-recipes").value = cur?.id ?? list[list.length - 1]?.id ?? "";
    toast(t("cg.saved"), "success");
  } catch (err) {
    toast(String(err), "error");
  }
}

async function deleteCmdRecipe() {
  const id = el<HTMLSelectElement>("cg-recipes").value;
  if (!id) {
    toast(t("cg.pickFirst"), "info");
    return;
  }
  const r = cmdRecipes.find((x) => x.id === id);
  if (
    !(await dialog({
      title: t("cg.delTitle"),
      body: t("cg.delBody", { name: r?.name ?? "" }),
      danger: true,
      confirmText: t("common.delete"),
    }))
  ) {
    return;
  }
  try {
    cmdRecipes = await invoke<CmdRecipeT[]>("cmdgen_delete", { id });
    refreshCmdRecipes();
    toast(t("cg.deleted"), "success");
  } catch (err) {
    toast(String(err), "error");
  }
}

/** 最近输入防抖落盘 (1.2s 静默后写一次; 失败静默——只影响下次恢复) */
function scheduleCmdLastSave() {
  if (!cmdLastReady) return;
  window.clearTimeout(cmdLastTimer);
  cmdLastTimer = window.setTimeout(() => {
    void invoke("cmdgen_set_last", { params: collectCmdParams() }).catch(() => {});
  }, 1200);
}

/** 档案集合指纹: 下拉只在实际变化时重建 (R8: renderHosts 每次刷新都调, 事件风暴下省掉无谓 DOM 重建) */
let lastProfilesKey: string | null = null;

/** 档案下拉选项刷新 (renderHosts 后调用 —— profiles 变化的汇聚点) */
function cmdGenRefreshProfiles() {
  const key = profiles.map((p) => `${p.id}:${p.name}:${p.host}:${p.port}:${p.username}`).join("|");
  if (key === lastProfilesKey) return;
  lastProfilesKey = key;
  const sel = el<HTMLSelectElement>("cg-profile");
  const prev = sel.value;
  sel.innerHTML = "";
  const manual = document.createElement("option");
  manual.value = "";
  manual.textContent = t("cg.manual");
  sel.append(manual);
  for (const p of profiles) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = `${p.name} (${p.host})`;
    sel.append(o);
  }
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
}

/** 服务器详情「生成命令」入口: 跳工具页并预填该服务器为目标 */
function jumpToCmdGen(p: Profile) {
  showPage("tools");
  cmdGenRefreshProfiles();
  el<HTMLSelectElement>("cg-profile").value = p.id;
  el<HTMLInputElement>("cg-host").value = p.host;
  el<HTMLInputElement>("cg-port").value = String(p.port);
  el<HTMLInputElement>("cg-user").value = p.username;
  cmdGenRegen();
}

function initCmdGen() {
  el<HTMLSelectElement>("cg-profile").addEventListener("change", () => {
    const p = profiles.find((x) => x.id === el<HTMLSelectElement>("cg-profile").value);
    if (p) {
      el<HTMLInputElement>("cg-host").value = p.host;
      el<HTMLInputElement>("cg-port").value = String(p.port);
      el<HTMLInputElement>("cg-user").value = p.username;
    }
    cmdGenRegen();
  });
  for (const id of ["cg-host", "cg-port", "cg-user", "cg-listen", "cg-thost", "cg-tport"]) {
    el<HTMLInputElement>(id).addEventListener("input", cmdGenRegen);
  }
  el<HTMLInputElement>("cg-bind").addEventListener("change", cmdGenRegen);
  for (const r of document.querySelectorAll<HTMLInputElement>("input[name=cg-kind]")) {
    r.addEventListener("change", cmdGenRegen);
  }
  for (const b of document.querySelectorAll<HTMLButtonElement>(".cmd-copy")) {
    b.innerHTML = `${icon("copy", 12)}<span class="btn-label">${t("common.copy")}</span>`;
    b.addEventListener("click", async () => {
      const { ssh, autossh } = cmdGenBuild();
      try {
        await navigator.clipboard.writeText(b.dataset.cmd === "autossh" ? autossh : ssh);
        toast(t("cg.copied"), "success");
      } catch {
        toast(t("common.copyFail"), "error");
      }
    });
  }
  // 我的命令: 载入已存条目 + 恢复最近输入 (后端加密落盘; 失败不阻断页面)
  el<HTMLSelectElement>("cg-recipes").addEventListener("change", () => {
    const r = cmdRecipes.find((x) => x.id === el<HTMLSelectElement>("cg-recipes").value);
    if (r) {
      applyCmdParams(r);
      cmdGenRegen();
    }
  });
  el<HTMLButtonElement>("cg-save").addEventListener("click", () => void saveCmdRecipe());
  el<HTMLButtonElement>("cg-del").addEventListener("click", () => void deleteCmdRecipe());
  void (async () => {
    try {
      const st = await invoke<{ recipes?: CmdRecipeT[]; last?: CmdParamsT | null }>("cmdgen_list");
      cmdRecipes = st.recipes ?? [];
      if (st.last) applyCmdParams(st.last);
    } catch {
      /* 落盘不可用 → 空列表照常用 */
    }
    refreshCmdRecipes();
    cmdGenRegen();
    cmdLastReady = true;
  })();

  cmdGenRefreshProfiles();
  cmdGenRegen();
}

/** 帮助页: CTA 直达「新建服务器」表单 */
function initHelp() {
  el<HTMLButtonElement>("help-new-server").addEventListener("click", () => {
    showPage("servers");
    selectProfile(null);
    openServerForm(null);
  });
}


// ---------- 服务器详情 ----------
/** 服务器删除 (块上删除图标钮): 确认对话框 → delete_profile → 回空态 */
async function deleteProfileFlow(p: Profile) {
  const used = tunnels.filter((t) => t.profileId === p.id);
  const body = used.length
    ? t("pf.delBody", {
        n: used.length,
        names: used.map((t) => t.name).join(", "),
      })
    : undefined;
  const ok = await dialog({
    title: t("pf.delTitle", { name: p.name }),
    body,
    confirmText: t("common.delete"),
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
    toast(t("common.delFail", { err: String(err) }), "error");
  }
}

/** 隧道空态提示 (持久元素, 跟 syncTunnelRows 的摘挂走, 避免重建) */
const listHint = document.createElement("div");
listHint.className = "hint tight";
listHint.textContent = t("detail.noTunnels");

/** 服务器详情渲染 (R8: 行走 syncTunnelRows diff; 密码条 pdPwState 驱动, 重绘回填草稿不丢输入) */
function renderServerDetail() {
  const p = selectedProfile();
  if (!p) {
    pdPwState = null;
    setDetailView("empty");
    return;
  }
  const head = el<HTMLDivElement>("pd-head");
  head.innerHTML = "";

  const title = document.createElement("div");
  title.className = "pd-title";
  title.innerHTML =
    `<strong>${escapeHtml(p.name)}</strong>` +
    `<span>${escapeHtml(p.host)}:${p.port} · ${escapeHtml(p.username)} · ${p.identityFile ? icon("key", 12) + " " + escapeHtml(t("auth.key")) : escapeHtml(t("auth.password"))}</span>`;
  const genBtn = document.createElement("button");
  genBtn.type = "button";
  genBtn.className = "pd-gen";
  genBtn.title = t("pd.genTitle");
  genBtn.innerHTML = `${icon("terminal", 14)}<span class="btn-label">${t("pd.gen")}</span>`;
  genBtn.addEventListener("click", () => jumpToCmdGen(p));
  head.append(title, genBtn);

  // 一键启动密码条 (状态驱动: pdPwState 匹配当前档案才显示; 换档案即作废)
  const pwbar = el<HTMLDivElement>("pd-pwbar");
  pwbar.innerHTML = "";
  const st = pdPwState !== null && pdPwState.profileId === p.id ? pdPwState : null;
  pwbar.classList.toggle("hidden", st === null);
  if (st) {
    const input = document.createElement("input");
    input.id = "pd-pw-input";
    input.type = "password";
    input.autocomplete = "off";
    input.placeholder = t("pd.batchPwPh", {
      user: p.username,
      host: p.host,
      n: st.targets.length,
    });
    input.value = st.draft; // 重绘回填, 批量启动期间刷新不丢输入
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "primary";
    btn.textContent = t("pd.batchConnect", { n: st.targets.length });
    btn.addEventListener("click", async () => {
      if (!input.value) {
        input.focus();
        return;
      }
      passwords.set(p.id, input.value);
      rememberedIds.add(p.id);
      pdPwState = null;
      pwbar.classList.add("hidden");
      for (const t of st.targets) {
        try {
          await invoke("tunnel_start", { id: t.id, password: input.value, remember: true });
        } catch (err) {
          appendLog(t.id, `❌ ${err}`);
        }
      }
    });
    input.addEventListener("input", () => {
      if (pdPwState) pdPwState.draft = input.value;
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") btn.click();
    });
    pwbar.append(input, btn);
    if (st.focused) input.focus(); // 重建后恢复焦点
  }

  // 该服务器的隧道行 (diff: 跨档案切换时旧档案的行随 refs 一并摘除)
  const mine = tunnels.filter((t) => t.profileId === p.id);
  const listEl = el<HTMLDivElement>("pd-tunnels");
  listHint.remove();
  syncTunnelRows(listEl, mine);
  if (mine.length === 0) listEl.append(listHint);

  fillSecretCard(p);
  fillFingerprint(p);
}

// ---------- 服务器详情尾: 凭据卡片 (记住的密码, 加密落盘) ----------

/** 凭据卡 (排印复用指纹卡 .fp-* 类): 已记住 → 状态 + 清除; 未记住 → 占位说明 */
function fillSecretCard(p: Profile) {
  const box = el<HTMLDivElement>("pd-secret");
  const remembered = rememberedIds.has(p.id);
  box.innerHTML = "";
  const row = document.createElement("div");
  row.className = "fp-row";
  if (!remembered) {
    const none = document.createElement("div");
    none.className = "fp-none";
    none.textContent = p.identityFile ? t("sec.noneKey") : t("sec.none");
    box.append(none);
    return;
  }
  row.innerHTML =
    `<span class="fp-ic">${icon("key", 16)}</span>` +
    `<div class="fp-main"><div class="fp-head">${escapeHtml(p.identityFile ? t("sec.headKey") : t("sec.head"))}</div>` +
    `<span class="sec-note">${escapeHtml(t("sec.note"))}</span></div>`;
  const actions = document.createElement("div");
  actions.className = "fp-actions";
  const clearBtn = document.createElement("button");
  clearBtn.type = "button";
  clearBtn.className = "danger";
  clearBtn.textContent = t("common.clear");
  clearBtn.addEventListener("click", async () => {
    const ok = await dialog({
      title: p.identityFile
        ? t("sec.clearTitleKey", { name: p.name })
        : t("sec.clearTitle", { name: p.name }),
      body: t("sec.clearBody"),
      confirmText: t("common.clear"),
      danger: true,
    });
    if (!ok) return;
    try {
      await invoke("secret_forget", { profileId: p.id });
      rememberedIds.delete(p.id);
      passwords.delete(p.id);
      toast(t("sec.cleared"), "success");
      fillSecretCard(p);
    } catch (err) {
      toast(t("common.clearFail", { err: String(err) }), "error");
    }
  });
  actions.append(clearBtn);
  row.append(actions);
  box.append(row);
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
      none.textContent = t("fp.none");
      box.append(none);
      return;
    }
    const row = document.createElement("div");
    row.className = "fp-row";
    row.innerHTML =
      `<span class="fp-ic">${icon("shield-check", 16)}</span>` +
      `<div class="fp-main"><div class="fp-head">${escapeHtml(t("fp.head"))}<span class="fp-algo"></span></div>` +
      `<code class="fp-code">${escapeHtml(hit.fingerprint)}</code></div>`;
    row.querySelector(".fp-algo")!.textContent = hit.algorithm;

    const actions = document.createElement("div");
    actions.className = "fp-actions";
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.title = t("fp.copyTitle");
    copyBtn.innerHTML = `${icon("copy", 12)}<span class="btn-label">${t("common.copy")}</span>`;
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(hit.fingerprint);
        toast(t("fp.copied"), "success");
      } catch {
        toast(t("common.copyFail"), "error");
      }
    });
    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "danger";
    clearBtn.textContent = t("common.clear");
    clearBtn.addEventListener("click", async () => {
      const ok = await dialog({
        title: t("fp.clearTitle", { host: p.host, port: p.port }),
        body: t("fp.clearBody"),
        confirmText: t("common.clear"),
        danger: true,
      });
      if (!ok) return;
      try {
        await invoke("known_hosts_forget", { host: p.host, port: p.port });
        lastFpKey = ""; // 强制重渲染 (清后回到占位态)
        fillFingerprint(p);
      } catch (err) {
        toast(t("common.clearFail", { err: String(err) }), "error");
      }
    });
    actions.append(copyBtn, clearBtn);
    row.append(actions);
    box.append(row);
  } catch (err) {
    box.textContent = t("fp.loadFail", { err: String(err) });
  }
}

// ---------- 服务器表单 (新建/编辑) ----------
function openServerForm(p: Profile | null) {
  el<HTMLSpanElement>("sf-title").textContent = p ? t("sf.titleEdit") : t("sf.titleNew");
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
    toast(t("sf.needFields"), "info");
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
        toast(t("common.saveFail", { err: String(err) }), "error");
      }
    },
    t("common.saving")
  );
});

el<HTMLButtonElement>("sf-back").addEventListener("click", () =>
  setDetailView(selectedProfileId ? "detail" : "empty")
);
el<HTMLButtonElement>("sf-cancel").addEventListener("click", () =>
  setDetailView(selectedProfileId ? "detail" : "empty")
);

// ---------- 新建隧道: 选场景 (预设 + 自定义 + 我的场景) ----------
/** 预设名/描述本地化: 后端 presets_list 返回中文, 前端按 id 覆盖 (未知 id 回退后端串) */
function presetName(p: Preset): string {
  const key = `preset.${p.id}.name` as I18nKey;
  return hasKey(key) ? t(key) : p.name;
}
function presetDesc(p: Preset): string {
  const key = `preset.${p.id}.desc` as I18nKey;
  return hasKey(key) ? t(key) : p.description;
}

async function loadScenarios() {
  scenarios = await invoke<Scenario[]>("scenarios_list");
}

async function openScenarioPick() {
  if (!selectedProfileId) {
    toast(t("sp.needProfile"), "info");
    return;
  }
  setDetailView("scenario-pick");
  el<HTMLSpanElement>("sp-title").textContent = t("sp.titleWith", {
    name: selectedProfile()?.name ?? "",
  });

  // 预设 (含「自定义」)
  const presetEl = el<HTMLDivElement>("preset-cards");
  presetEl.innerHTML = "";
  const presets = await invoke<Preset[]>("presets_list");
  for (const preset of presets) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "preset-card" + (preset.id === "custom" ? " custom" : "");
    card.innerHTML = `<strong>${escapeHtml(presetName(preset))}</strong><span>${escapeHtml(presetDesc(preset))}</span>`;
    card.addEventListener("click", async () => {
      try {
        wzSpec = await invoke<TunnelSpec>("tunnel_from_preset", {
          presetId: preset.id,
          name: preset.id === "custom" ? t("sp.defaultName") : presetName(preset),
          profileId: selectedProfileId!,
        });
        openTunnelForm({
          title: presetName(preset),
          hint: WZ_HINTS[preset.id]?.() ?? "",
          defaultName: preset.id === "custom" ? "" : presetName(preset),
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
    del.title = t("sc.delThis");
    del.addEventListener("click", async (e) => {
      e.stopPropagation();
      const ok = await dialog({
        title: t("sc.delTitle", { name: s.name }),
        confirmText: t("common.delete"),
        danger: true,
      });
      if (!ok) return;
      try {
        scenarios = await invoke<Scenario[]>("scenario_delete", { id: s.id });
        openScenarioPick(); // 重渲染卡片
      } catch (err) {
        toast(t("common.delFail", { err: String(err) }), "error");
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
          hint: s.description || t("sc.fromHint", { name: s.name }),
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

const WZ_HINTS: Record<string, () => string> = {
  vpn_share: () => t("wz.hintVpn"),
  expose_local: () => t("wz.hintExpose"),
  reach_service: () => t("wz.hintReach"),
  reach_lan: () => t("wz.hintLan"),
  custom: () => t("wz.hintCustom"),
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
        label: t("wz.rPort"),
        value: k.reverse.port,
        hint: t("wz.rPortHint"),
      },
    ];
    if ("socksAuto" in b) {
      fields.push({
        id: "fallback",
        label: t("wz.fallback"),
        value: b.socksAuto.fallbackPort,
      });
    } else {
      fields.push(
        { id: "host", label: t("wz.tcpHost"), value: b.tcp[0] },
        { id: "lport", label: t("wz.tcpPort"), value: b.tcp[1] }
      );
    }
    return fields;
  }
  if ("local" in k) {
    return [
      { id: "port", label: t("wz.lPort"), value: k.local.port },
      { id: "thost", label: t("wz.tHost"), value: k.local.targetHost },
      { id: "tport", label: t("wz.tPort"), value: k.local.targetPort },
    ];
  }
  return [{ id: "port", label: t("wz.dPort"), value: k.dynamic.port }];
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
    label.innerHTML = `<span>${escapeHtml(t("wz.probeLabel"))}</span>`;
    const probeBtn = document.createElement("button");
    probeBtn.type = "button";
    probeBtn.textContent = t("wz.probe");
    label.append(probeBtn);
    fields.append(label);
    probeBtn.addEventListener("click", async () => {
      probeBtn.disabled = true;
      probeBtn.textContent = t("wz.probing");
      try {
        const results = await invoke<Array<{ port: number; socks5_confirmed: boolean }>>(
          "probe_local_proxy"
        );
        const socks = results.find((r) => r.socks5_confirmed);
        if (socks) {
          el<HTMLInputElement>("wz-f-fallback").value = String(socks.port);
          probeBtn.textContent = t("wz.probed", { port: socks.port });
        } else {
          probeBtn.textContent = results.length
            ? t("wz.probeNoSocks", { ports: results.map((r) => r.port).join(", ") })
            : t("wz.probeNone");
        }
      } catch (e) {
        probeBtn.textContent = t("wz.probeFail", { err: String(e) });
      } finally {
        probeBtn.disabled = false;
      }
    });
  }
}

function openTunnelForm(ctx: { title: string; hint: string; defaultName: string }) {
  if (!wzSpec) return;
  setDetailView("tunnel-form");
  el<HTMLSpanElement>("tf-title").textContent = t("tf.titleWith", { title: ctx.title });
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
    ? t("tf.passphraseLabel")
    : t("tf.password");
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
      if (!Number.isInteger(port) || port < 0 || port > 65535) return t("err.rPort");
      spec.kind = { reverse: { bind: "127.0.0.1", port } };
      if (currentFormBackend() === "socksAuto") {
        const fallback = n("fallback");
        if (!Number.isInteger(fallback) || fallback <= 0 || fallback > 65535)
          return t("err.fallback");
        spec.backend = { socksAuto: { fallbackPort: fallback } };
      } else {
        const host = v("host");
        const lport = n("lport");
        if (!host) return t("err.tcpHost");
        if (!Number.isInteger(lport) || lport <= 0 || lport > 65535) return t("err.tcpPort");
        spec.backend = { tcp: [host, lport] };
      }
      break;
    }
    case "local": {
      const port = n("port");
      const thost = v("thost");
      const tport = n("tport");
      if (!Number.isInteger(port) || port <= 0 || port > 65535) return t("err.lPort");
      if (!thost) return t("err.tHost");
      if (!Number.isInteger(tport) || tport <= 0 || tport > 65535) return t("err.tPort");
      spec.kind = {
        local: { bind: "127.0.0.1", port, targetHost: thost, targetPort: tport },
      };
      break;
    }
    case "dynamic": {
      const port = n("port");
      if (!Number.isInteger(port) || port <= 0 || port > 65535) return t("err.dPort");
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
    errEl.textContent = t("err.name");
    return;
  }
  const profileId = selectedProfileId;
  const cached = passwords.get(profileId);
  const password = el<HTMLInputElement>("wz-password").value;
  // 密钥档案口令可空 (passphrase: None); 密码档案须本次输入/会话缓存/已记住其一
  if (start && !password && !selectedProfile()?.identityFile && cached === undefined && !rememberedIds.has(profileId)) {
    errEl.textContent = t("err.needPassword");
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
          toast(t("sc.saved", { name: scenarioName }), "success");
        } catch (err) {
          appendLog(spec.id, t("sc.saveFailLog", { err: String(err) }));
        }
      }
      if (start) {
        const pass = password || cached || null; // null → 后端兜底用记住的凭据
        if (password) {
          passwords.set(profileId, password);
          rememberedIds.add(profileId);
        }
        try {
          await invoke("tunnel_start", { id: spec.id, password: pass, remember: pass ? true : null });
        } catch (err) {
          appendLog(spec.id, `❌ ${err}`);
        }
      }
      await refreshTunnels();
      setDetailView("detail");
    },
    start ? t("common.starting") : t("common.saving")
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
        toast(t("set.defaultsSaved"), "success");
      } catch (err) {
        toast(t("common.saveFail", { err: String(err) }), "error");
      }
    },
    t("common.saving")
  )
);

// ---------- 开机自启 (经后端命令包装 tauri-plugin-autostart) ----------
el<HTMLInputElement>("autostart").addEventListener("change", async () => {
  const cb = el<HTMLInputElement>("autostart");
  try {
    await invoke("autostart_set", { enabled: cb.checked });
  } catch (err) {
    toast(t("common.setFail", { err: String(err) }), "error");
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

// ---------- 语言切换 (设置页「外观」卡; zh/en 双语) ----------
/** 语言分段控件: 初态高亮 + 点击切换 (偏好落 pt-lang, 与主题/字号同机制) */
function initLang() {
  const seg = document.getElementById("set-lang");
  if (!seg) return;
  const sync = () => {
    for (const b of seg.querySelectorAll("button")) {
      const on = b.dataset.lang === getLang();
      b.classList.toggle("active", on);
      b.setAttribute("aria-pressed", String(on));
    }
  };
  seg.addEventListener("click", (e) => {
    const b = (e.target as HTMLElement).closest("button");
    if (b?.dataset.lang) setLang(b.dataset.lang as Lang);
  });
  sync();
  onLangChange(sync);
}

/** 切语言后的动态内容重渲染: 静态文案由 setLang→applyI18nStatic 处理,
 * 这里重建 JS 生成的部分 (服务器块/隧道行/命令生成输出)。表单视图不打断 ——
 * 静态 label 走 data-i18n 即时换, 动态字段 (标题/预设卡) 下次进入时重建 */
function rerenderOnLangChange() {
  closeMenus();
  hostBlocks.clear();
  rowRefs.clear();
  const grid = el<HTMLDivElement>("host-grid");
  grid.innerHTML = "";
  newBlockBtn = undefined;
  lastProfilesKey = null; // 档案下拉「手动输入」选项强制重建
  lastFpKey = ""; // 详情指纹卡强制重渲染
  listHint.textContent = t("detail.noTunnels");
  renderHosts();
  if (detailView === "detail") renderServerDetail();
  refreshCmdRecipes();
  cmdGenRegen();
  for (const b of document.querySelectorAll<HTMLButtonElement>(".cmd-copy")) {
    b.innerHTML = `${icon("copy", 12)}<span class="btn-label">${t("common.copy")}</span>`;
  }
}

// ---------- 初始化 ----------
/** 静态位图标填充 (nav / 返回钮 / 新建隧道钮) —— HTML 留空, 图标统一走 icons.ts */
function applyStaticIcons() {
  const NAV_ICONS: Record<string, IconName> = {
    servers: "server",
    tools: "terminal",
    settings: "settings",
    help: "circle-help",
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
    `${icon("plus", 15)}<span class="btn-label">${t("detail.newTunnel")}</span>`;
  // 空态配线性图标
  document.querySelector("#detail-empty .dp-empty")?.insertAdjacentHTML(
    "afterbegin",
    `<div class="empty-ic">${icon("server", 28)}</div>`,
  );
}

// ---------- 初始化 ----------
applyStaticIcons();
applyI18nStatic(); // 静态文案 (data-i18n) 初次应用 + document.title
initLang();
initAppearance();
initCmdGen();
initHelp();
onLangChange(rerenderOnLangChange);
(async () => {
  // 三拉: 隧道 + 档案 + 已记住凭据 (rememberedIds —— 凭据卡/免输启动/自启判定,
  // 漏拉则新会话 (重启/reload) 恒空, 记住了密码 UI 仍会询问)
  await refreshTunnels();
  await loadDefaults();
  await loadAutostart();
  // 首次使用软引导: 一台服务器都没有 → 落在帮助页
  showPage(profiles.length === 0 ? "help" : "servers");
})().catch((e) => console.error("初始化失败", e));
