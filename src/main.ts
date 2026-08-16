import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { icon, type IconName } from "./icons";
import { initTheme } from "./theme";

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

const STATUS_TEXT: Record<string, string> = {
  connecting: "连接中...",
  connected: "已连接",
  reconnecting: "重连中...",
  disconnected: "未连接",
  error: "错误",
};

const ACTIVE_STATES = ["connected", "connecting", "reconnecting"];

// ---------- 全局状态 ----------
let tunnels: TunnelDto[] = [];
let profiles: Profile[] = [];
let scenarios: Scenario[] = [];
/** profileId -> 本次会话凭据 (密码 / 密钥口令; null = 密钥档案无口令。仅内存, 重启即失) */
const passwords = new Map<string, string | null>();
/** tunnelId -> 日志文本 (行内展开时渲染; 上限防膨胀) */
const logs = new Map<string, string>();
/** tunnelId -> 展开状态 (重渲染保持) */
const expanded = new Set<string>();
/** tunnelId -> 行内 DOM 引用 (事件增量更新, 不整表重绘) */
interface RowRefs {
  badge: HTMLSpanElement;
  msg: HTMLSpanElement;
  msgRow: HTMLDivElement;
  pre: HTMLPreElement;
  pwBar: HTMLDivElement;
  pwInput: HTMLInputElement;
  btnStart: HTMLButtonElement;
  btnStop: HTMLButtonElement;
  btnRetry: HTMLButtonElement;
  btnTrust: HTMLButtonElement;
  btnVerify: HTMLButtonElement;
  btnDeploy: HTMLButtonElement;
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

const LOG_CAP = 60_000; // 字符上限, 超出丢弃头部

function appendLog(id: string, msg: string) {
  const ts = new Date().toLocaleTimeString();
  let text = (logs.get(id) ?? "") + `[${ts}] ${msg}\n`;
  if (text.length > LOG_CAP) text = text.slice(-LOG_CAP);
  logs.set(id, text);
  const refs = rowRefs.get(id);
  if (refs) {
    refs.pre.textContent = text;
    refs.pre.scrollTop = refs.pre.scrollHeight;
  }
}

function selectedProfile(): Profile | undefined {
  return profiles.find((p) => p.id === selectedProfileId);
}

// ---------- 页面路由 ----------
const navItems = document.querySelectorAll<HTMLButtonElement>(".nav-item");
const pages = document.querySelectorAll<HTMLElement>(".page");

function activePage(): string {
  return document.querySelector<HTMLElement>(".nav-item.active")?.dataset.page ?? "servers";
}

function showPage(name: string) {
  navItems.forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  pages.forEach((p) => p.classList.toggle("active", p.dataset.page === name));
  renderCurrentPage();
}

navItems.forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page!)));

/** 按当前页面渲染隧道列表 (总览 = 全部; 服务器页 = 右面板详情里的该档案隧道) */
function renderCurrentPage() {
  if (activePage() === "tunnels") renderOverview();
}

// ---------- 隧道行渲染 (总览页与服务器详情页共用) ----------
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

/** vpn_share 形态 (反向 + SOCKS 落地): 显示「验证外网 / 部署 proxy」动作 */
function isVpnShare(t: TunnelDto): boolean {
  return kindTag(t.kind) === "reverse" && "socksAuto" in t.backend;
}

/** 该隧道是否还需要输入凭据 (本会话未输入过; 密钥档案无口令也算已输入) */
function needPassword(t: TunnelDto): boolean {
  return !passwords.has(t.profileId);
}

function refreshNavDot() {
  const dot = el<HTMLSpanElement>("dot-tunnels");
  const states = tunnels.map((t) => t.state);
  if (states.includes("error")) dot.className = "nav-dot error";
  else if (states.includes("connecting") || states.includes("reconnecting"))
    dot.className = "nav-dot connecting";
  else if (states.includes("connected")) dot.className = "nav-dot connected";
  else dot.className = "nav-dot";
}

/** 按当前状态更新一行的徽章与按钮 (增量, 不重建 DOM; 行不在当前容器则跳过) */
function updateRow(t: TunnelDto) {
  const refs = rowRefs.get(t.id);
  if (!refs) return;
  refs.badge.className = `badge ${t.state}`;
  refs.badge.textContent = STATUS_TEXT[t.state] ?? t.state;
  refs.msg.textContent = t.message ?? "";
  refs.msgRow.classList.toggle("hidden", !t.message);

  const active = ACTIVE_STATES.includes(t.state);
  refs.btnStart.disabled = active;
  refs.btnStop.disabled = !active;
  refs.btnRetry.hidden = t.state !== "reconnecting";
  // 指纹变更错误 (TOFU 拒绝): 给一条「信任新指纹」的恢复路径
  refs.btnTrust.hidden = !(
    t.state === "error" && (t.message ?? "").includes("指纹已变更")
  );

  const vpn = isVpnShare(t);
  refs.btnVerify.hidden = !vpn;
  refs.btnDeploy.hidden = !vpn;
  const vpnEnabled = vpn && t.state === "connected" && !needPassword(t);
  refs.btnVerify.disabled = !vpnEnabled;
  refs.btnDeploy.disabled = !vpnEnabled;

  if (t.state === "connecting" || t.state === "connected") {
    refs.pwBar.classList.add("hidden"); // 已受理, 收起密码条
  }
  refreshNavDot();
}

/** 把一批隧道行渲染进容器 (总览页/服务器详情页共用; rowRefs 单容器假设: 同一时刻只显示一页) */
function renderTunnelRows(container: HTMLElement, list: TunnelDto[]) {
  container.innerHTML = "";
  for (const t of list) {
    const profile = profiles.find((p) => p.id === t.profileId);
    const card = document.createElement("div");
    card.className = "card tunnel-card";

    // --- 头部: 展开钮 + 名称/形态/摘要 + 状态徽章 + 操作 ---
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
      `<span class="tunnel-kind">${kindLabel(t.kind)}</span>` +
      `<span class="tunnel-sub">${escapeHtml(profile ? `${profile.name} · ${profile.host}` : "档案缺失")} — ${escapeHtml(summary(t))}</span>`;

    const badge = document.createElement("span");
    badge.className = `badge ${t.state}`;
    badge.textContent = STATUS_TEXT[t.state] ?? t.state;

    const actions = document.createElement("div");
    actions.className = "tunnel-actions";
    // 开机自启开关 (enabled 字段; 系统启动时后台拉起)
    const autoWrap = document.createElement("label");
    autoWrap.className = "check-inline";
    autoWrap.title =
      "开机自启: 系统启动时后台拉起此隧道 (需私钥认证档案; 密码/加密私钥无法免交互启动)";
    const autoChk = document.createElement("input");
    autoChk.type = "checkbox";
    autoChk.checked = t.enabled;
    const autoText = document.createElement("span");
    autoText.textContent = "自启";
    autoWrap.append(autoChk, autoText);
    autoChk.addEventListener("change", async () => {
      try {
        tunnels = await invoke<TunnelDto[]>("tunnel_set_enabled", {
          id: t.id,
          enabled: autoChk.checked,
        });
        if (autoChk.checked && profile && !profile.identityFile) {
          appendLog(
            t.id,
            "提示: 该档案为密码认证, 开机自启时无法免交互启动; 建议为服务器配置私钥路径"
          );
        }
        renderHosts();
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      }
    });
    const mkBtn = (text: string, cls = "") => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = text;
      if (cls) b.className = cls;
      actions.append(b);
      return b;
    };
    const btnStart = mkBtn("启动");
    const btnStop = mkBtn("停止");
    const btnRetry = mkBtn("立即重试");
    const btnTrust = mkBtn("信任新指纹");
    btnTrust.title = "服务器指纹变更被拒后, 清除记录并重连 (仅服务器确已重装/更换时使用)";
    const btnVerify = mkBtn("验证外网");
    btnVerify.title = "在服务器上经隧道测试访问外网 (google)";
    const btnDeploy = mkBtn("部署 proxy");
    btnDeploy.title = "部署 proxy 命令, 服务器上可 'proxy curl ...' 走隧道";
    const btnScenario = mkBtn("存为场景");
    btnScenario.title = "把这条隧道的形态/参数存为「我的场景」, 新建隧道时复用";
    const btnDelete = mkBtn("删除", "danger");
    btnDelete.title = "删除隧道配置";

    head.append(expand, title, badge, autoWrap, actions);
    card.append(head);

    // --- 状态消息行 (重连进度 / 错误信息) ---
    const msgRow = document.createElement("div");
    msgRow.className = "tunnel-msg hidden";
    const msg = document.createElement("span");
    msg.className = "tunnel-msg-text";
    msgRow.append(msg);
    card.append(msgRow);

    // --- 详情: 密码条 + 日志 ---
    const detail = document.createElement("div");
    detail.className = "tunnel-detail hidden";

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

    const pre = document.createElement("pre");
    pre.className = "log";
    pre.textContent = logs.get(t.id) ?? "";
    detail.append(pwBar, pre);
    card.append(detail);
    container.append(card);

    const refs: RowRefs = {
      badge,
      msg,
      msgRow,
      pre,
      pwBar,
      pwInput,
      btnStart,
      btnStop,
      btnRetry,
      btnTrust,
      btnVerify,
      btnDeploy,
    };
    rowRefs.set(t.id, refs);
    detail.classList.toggle("hidden", !expanded.has(t.id));
    expand.classList.toggle("open", expanded.has(t.id));
    updateRow(t);

    // --- 接线 ---
    expand.addEventListener("click", () => {
      const open = expanded.has(t.id);
      if (open) expanded.delete(t.id);
      else expanded.add(t.id);
      detail.classList.toggle("hidden", open);
      expand.classList.toggle("open", !open);
      if (!open) pre.scrollTop = pre.scrollHeight;
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
      detail.classList.remove("hidden");
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
      await doStart(pwInput.value || null);
    });
    pwInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") pwBtn.click();
    });
    btnStop.addEventListener("click", async () => {
      try {
        await invoke("tunnel_stop", { id: t.id });
        appendLog(t.id, "请求断开...");
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      }
    });
    btnRetry.addEventListener("click", async () => {
      try {
        await invoke("tunnel_retry_now", { id: t.id });
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      }
    });
    btnTrust.addEventListener("click", async () => {
      const profile = profiles.find((p) => p.id === t.profileId);
      if (!profile) {
        appendLog(t.id, "❌ 隧道关联的档案缺失, 无法定位指纹记录");
        return;
      }
      if (
        !confirm(
          `清除 ${profile.host}:${profile.port} 的旧指纹并重连?\n仅当服务器确已重装/更换时继续 —— 否则可能是中间人攻击。`
        )
      )
        return;
      try {
        await invoke("known_hosts_forget", { host: profile.host, port: profile.port });
        appendLog(t.id, `已清除 ${profile.host}:${profile.port} 的指纹记录, 重连后将重新记忆当前指纹`);
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
        return;
      }
      // 复用启动路径: 有缓存密码直接重启, 否则展开密码条
      btnStart.click();
    });
    const runAction = async (cmd: "verify_remote_tunnel" | "deploy_wrapper") => {
      if (!passwords.has(t.profileId)) {
        appendLog(t.id, "需要凭据: 请先启动隧道 (或重新输入密码/口令)");
        btnStart.click();
        return;
      }
      const pass = passwords.get(t.profileId) ?? null;
      const btn = cmd === "verify_remote_tunnel" ? btnVerify : btnDeploy;
      btn.disabled = true;
      const label = btn.textContent;
      btn.textContent = "执行中...";
      try {
        await invoke<string>(cmd, { id: t.id, password: pass || null });
        // 输出经 tunnel-log 事件回流行内日志, 此处不重复
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      } finally {
        btn.textContent = label!;
        const cur = currentTunnel(t.id);
        if (cur) updateRow(cur);
      }
    };
    btnVerify.addEventListener("click", () => runAction("verify_remote_tunnel"));
    btnDeploy.addEventListener("click", () => runAction("deploy_wrapper"));
    btnScenario.addEventListener("click", async () => {
      const name = prompt("保存为我的场景, 名称:", t.name)?.trim();
      if (!name) return;
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
    });
    btnDelete.addEventListener("click", async () => {
      if (!confirm(`删除隧道「${t.name}」? (运行中会先停止)`)) return;
      try {
        tunnels = await invoke<TunnelDto[]>("tunnel_delete", { id: t.id });
        renderHosts();
        renderCurrentPage();
        if (detailView === "detail") renderServerDetail();
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      }
    });
  }
  refreshNavDot();
}

function currentTunnel(id: string): TunnelDto | undefined {
  return tunnels.find((t) => t.id === id);
}

/** 总览页: 全部隧道 */
function renderOverview() {
  rowRefs.clear();
  const listEl = el<HTMLDivElement>("tunnel-list");
  el<HTMLDivElement>("tunnel-empty").classList.toggle("hidden", tunnels.length > 0);
  el<HTMLSpanElement>("tunnel-count").textContent = tunnels.length
    ? `${tunnels.length} 条隧道`
    : "";
  renderTunnelRows(listEl, tunnels);
}

async function refreshTunnels() {
  tunnels = await invoke<TunnelDto[]>("tunnels_list");
  renderHosts();
  renderCurrentPage();
  if (detailView === "detail") renderServerDetail();
}

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

listen("tunnel-log", (e) => {
  const p = e.payload as { id: string; kind: string; msg: string };
  appendLog(p.id, p.msg);
});

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

    const name = document.createElement("div");
    name.className = "hb-name";
    const dot = document.createElement("span");
    dot.className = `hb-status ${agg.state}`;
    dot.title = agg.state || "无隧道运行";
    const nameText = document.createElement("span");
    nameText.textContent = p.name;
    name.append(dot, nameText);

    const addr = document.createElement("div");
    addr.className = "hb-addr";
    addr.innerHTML =
      `${escapeHtml(`${p.host}:${p.port} · ${p.username}`)}` +
      (p.identityFile ? ` <span class="hb-key" title="密钥认证">${icon("key", 12)}</span>` : "");

    const count = document.createElement("div");
    count.className = "hb-count";
    count.textContent =
      agg.total === 0
        ? "无隧道"
        : agg.total === agg.running
          ? `${agg.total} 条隧道 · 全部运行`
          : `${agg.total} 条隧道 · ${agg.running} 运行`;

    // ▶ 一键启动 enabled 隧道 / ■ 全部停止
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "hb-toggle";
    const anyActive = tunnels.some(
      (t) => t.profileId === p.id && ACTIVE_STATES.includes(t.state)
    );
    toggle.innerHTML = anyActive ? icon("square", 14) : icon("play", 14);
    toggle.setAttribute("aria-label", anyActive ? "全部停止" : "一键启动");
    toggle.title = anyActive
      ? "停止该服务器的全部隧道"
      : "一键启动该服务器全部 enabled 隧道 (密码认证首次会要求输入密码)";
    toggle.addEventListener("click", (e) => {
      e.stopPropagation();
      selectProfile(p.id);
      if (anyActive) stopAllForProfile(p);
      else startAllForProfile(p);
    });

    block.append(name, addr, count, toggle);
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
    `<span>${escapeHtml(p.host)}:${p.port} · ${escapeHtml(p.username)} · ${p.identityFile ? "🔑 密钥认证" : "密码认证"}</span>`;

  const btns = document.createElement("div");
  btns.className = "actions";
  const editBtn = document.createElement("button");
  editBtn.type = "button";
  editBtn.textContent = "编辑";
  editBtn.addEventListener("click", () => openServerForm(p));
  const delBtn = document.createElement("button");
  delBtn.type = "button";
  delBtn.textContent = "删除";
  delBtn.className = "danger";
  delBtn.addEventListener("click", async () => {
    const used = tunnels.filter((t) => t.profileId === p.id);
    const warn = used.length
      ? `\n注意: 有 ${used.length} 条隧道关联此服务器 (${used.map((t) => t.name).join(", ")}), 删除后这些隧道将无法启动`
      : "";
    if (!confirm(`删除服务器「${p.name}」?${warn}`)) return;
    try {
      profiles = await invoke<Profile[]>("delete_profile", { id: p.id });
      passwords.delete(p.id);
      selectedProfileId = null;
      renderHosts();
      setDetailView("empty");
    } catch (err) {
      alert(`删除失败: ${err}`);
    }
  });
  btns.append(editBtn, delBtn);
  head.append(title, btns);

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
    listEl.innerHTML =
      '<div class="hint" style="min-height:0;margin:4px 0">还没有隧道 —— 点右上「＋ 新建隧道」从场景开始</div>';
  } else {
    renderTunnelRows(listEl, mine);
  }

  fillFingerprint(p);
}

/** 服务器详情尾: 指纹卡片 (TOFU 记忆, 异步填充) */
async function fillFingerprint(p: Profile) {
  const box = el<HTMLDivElement>("pd-fingerprint");
  try {
    const list = await invoke<Array<{ host: string; port: number; algorithm: string; fingerprint: string }>>(
      "known_hosts_list"
    );
    const hit = list.find((h) => h.host === p.host && h.port === p.port);
    if (!hit) {
      box.innerHTML =
        '<span class="fp-text">指纹: 首次连接后自动记住 (TOFU); 变更即拒绝连接</span>';
      return;
    }
    box.innerHTML = `<span class="fp-text">指纹已记住 (${escapeHtml(hit.algorithm)}) <code>${escapeHtml(hit.fingerprint)}</code></span>`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "清除";
    btn.className = "danger";
    btn.addEventListener("click", async () => {
      if (
        !confirm(
          `清除 ${p.host}:${p.port} 的指纹记录?\n下次连接将重新记住当前指纹 (仅服务器确已变更时操作)。`
        )
      )
        return;
      try {
        await invoke("known_hosts_forget", { host: p.host, port: p.port });
        fillFingerprint(p);
      } catch (err) {
        alert(`清除失败: ${err}`);
      }
    });
    box.append(btn);
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
    alert("请填写名称、地址和用户名");
    return;
  }
  try {
    const id = el<HTMLInputElement>("profile-id").value || crypto.randomUUID();
    profiles = await invoke<Profile[]>("save_profile", {
      profile: { id, name, host, port, username, identityFile: keyPath || null, shareConnection },
    });
    selectProfile(id); // 保存后选中并进入详情
    renderCurrentPage(); // 已有隧道摘要里的档案名同步
  } catch (err) {
    alert(`保存失败: ${err}`);
  }
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
    alert("请先选择服务器");
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
        alert(String(err));
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
      if (!confirm(`删除场景「${s.name}」?`)) return;
      try {
        scenarios = await invoke<Scenario[]>("scenario_delete", { id: s.id });
        openScenarioPick(); // 重渲染卡片
      } catch (err) {
        alert(`删除失败: ${err}`);
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
        alert(String(err));
      }
    });
    scEl.append(card);
  }
}

el<HTMLButtonElement>("pd-new-tunnel").addEventListener("click", openScenarioPick);
el<HTMLButtonElement>("sp-back").addEventListener("click", () => setDetailView("detail"));
el<HTMLButtonElement>("goto-servers").addEventListener("click", () => showPage("servers"));

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

async function submitTunnelForm(start: boolean) {
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
}

el<HTMLFormElement>("tunnel-form").addEventListener("submit", (e) => {
  e.preventDefault();
  submitTunnelForm(true);
});
el<HTMLButtonElement>("wz-save").addEventListener("click", () => submitTunnelForm(false));

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

el<HTMLButtonElement>("def-save").addEventListener("click", async () => {
  const btn = el<HTMLButtonElement>("def-save");
  btn.disabled = true;
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
    btn.textContent = "已保存 ✓";
    setTimeout(() => (btn.textContent = "保存默认值"), 1500);
  } catch (err) {
    alert(`保存失败: ${err}`);
  } finally {
    btn.disabled = false;
  }
});

// ---------- 开机自启 (经后端命令包装 tauri-plugin-autostart) ----------
el<HTMLInputElement>("autostart").addEventListener("change", async () => {
  const cb = el<HTMLInputElement>("autostart");
  try {
    await invoke("autostart_set", { enabled: cb.checked });
  } catch (err) {
    alert(`设置失败: ${err}`);
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
    tunnels: "arrow-right-left",
    defaults: "settings",
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
}

applyStaticIcons();
initTheme();
(async () => {
  profiles = await invoke<Profile[]>("list_profiles");
  tunnels = await invoke<TunnelDto[]>("tunnels_list");
  await loadDefaults();
  await loadAutostart();
  renderHosts();
  showPage("servers");
})().catch((e) => console.error("初始化失败", e));
