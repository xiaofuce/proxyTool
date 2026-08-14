import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// ---------- 类型 (与 core serde camelCase 对应) ----------
interface Profile {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
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

interface Defaults {
  connectTimeoutSecs?: number | null;
  reconnect?: Policy | null;
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

function kindTag(k: Kind): "remote" | "local" | "dynamic" {
  return Object.keys(k)[0] as "remote" | "local" | "dynamic";
}

function kindLabel(k: Kind): string {
  return { remote: "反向", local: "本地", dynamic: "动态" }[kindTag(k)];
}

const STATUS_TEXT: Record<string, string> = {
  connecting: "连接中...",
  connected: "已连接",
  reconnecting: "重连中...",
  disconnected: "未连接",
  error: "错误",
};

// ---------- 状态 ----------
let tunnels: TunnelDto[] = [];
let profiles: Profile[] = [];
/** profileId -> 密码 (仅本会话内存; 启动/验证/部署复用, 重启即失) */
const passwords = new Map<string, string>();
/** tunnelId -> 日志文本 (行内展开时渲染; 上限防膨胀) */
const logs = new Map<string, string>();
/** tunnelId -> 展开状态 (重渲染保持) */
const expanded = new Set<string>();
/** tunnelId -> 行内 DOM 引用 (事件增量更新, 不整表重绘) */
interface RowRefs {
  badge: HTMLSpanElement;
  msg: HTMLSpanElement;
  pre: HTMLPreElement;
  pwBar: HTMLDivElement;
  pwInput: HTMLInputElement;
  btnStart: HTMLButtonElement;
  btnStop: HTMLButtonElement;
  btnRetry: HTMLButtonElement;
  btnVerify: HTMLButtonElement;
  btnDeploy: HTMLButtonElement;
}
const rowRefs = new Map<string, RowRefs>();

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

// ---------- 页面路由 ----------
const navItems = document.querySelectorAll<HTMLButtonElement>(".nav-item");
const pages = document.querySelectorAll<HTMLElement>(".page");

function showPage(name: string) {
  navItems.forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  pages.forEach((p) => p.classList.toggle("active", p.dataset.page === name));
}
navItems.forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page!)));

// ---------- 隧道列表 ----------
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
  return kindTag(t.kind) === "remote" && "socksAuto" in t.backend;
}

/** 该隧道是否需要密码才能操作 (本会话未输入过) */
function needPassword(t: TunnelDto): boolean {
  return !passwords.get(t.profileId);
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

/** 按当前状态更新一行的徽章与按钮 (增量, 不重建 DOM) */
function updateRow(t: TunnelDto) {
  const refs = rowRefs.get(t.id);
  if (!refs) return;
  refs.badge.className = `badge ${t.state}`;
  refs.badge.textContent = STATUS_TEXT[t.state] ?? t.state;
  refs.msg.textContent = t.message ?? "";

  const active = ["connected", "connecting", "reconnecting"].includes(t.state);
  refs.btnStart.disabled = active;
  refs.btnStop.disabled = !active;
  refs.btnRetry.hidden = t.state !== "reconnecting";

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

function renderTunnels() {
  const listEl = el<HTMLDivElement>("tunnel-list");
  const countEl = el<HTMLSpanElement>("tunnel-count");
  listEl.innerHTML = "";
  rowRefs.clear();

  el<HTMLDivElement>("tunnel-empty").classList.toggle("hidden", tunnels.length > 0);
  countEl.textContent = tunnels.length ? `${tunnels.length} 条隧道` : "";

  for (const t of tunnels) {
    const profile = profiles.find((p) => p.id === t.profileId);
    const card = document.createElement("div");
    card.className = "card tunnel-card";

    // --- 头部: 展开钮 + 名称/形态/摘要 + 状态徽章 + 操作 ---
    const head = document.createElement("div");
    head.className = "tunnel-head";

    const expand = document.createElement("button");
    expand.type = "button";
    expand.className = "icon-btn tunnel-expand";
    expand.textContent = "▸";
    expand.title = "展开日志";

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
    const btnVerify = mkBtn("验证外网");
    btnVerify.title = "在服务器上经隧道测试访问外网 (google)";
    const btnDeploy = mkBtn("部署 proxy");
    btnDeploy.title = "部署 proxy 命令, 服务器上可 'proxy curl ...' 走隧道";
    const btnDelete = mkBtn("删除", "danger");
    btnDelete.title = "删除隧道配置";

    head.append(expand, title, badge, actions);
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
    pwInput.placeholder = `SSH 密码 (${profile ? profile.username + "@" + profile.host : "服务器"})`;
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
    listEl.append(card);

    const refs: RowRefs = {
      badge,
      msg,
      pre,
      pwBar,
      pwInput,
      btnStart,
      btnStop,
      btnRetry,
      btnVerify,
      btnDeploy,
    };
    rowRefs.set(t.id, refs);
    // 消息行显隐跟随内容
    msgRow.classList.toggle("hidden", !t.message);
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

    const doStart = async (password: string) => {
      try {
        await invoke("tunnel_start", { id: t.id, password });
        passwords.set(t.profileId, password);
        pwBar.classList.add("hidden");
      } catch (err) {
        appendLog(t.id, `❌ ${err}`);
      }
    };
    btnStart.addEventListener("click", async () => {
      const cached = passwords.get(t.profileId);
      if (cached) {
        await doStart(cached);
        return;
      }
      expanded.add(t.id);
      detail.classList.remove("hidden");
      expand.classList.add("open");
      pwBar.classList.remove("hidden");
      pwInput.focus();
    });
    pwBtn.addEventListener("click", async () => {
      if (!pwInput.value) {
        pwInput.focus();
        return;
      }
      await doStart(pwInput.value);
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
    const runAction = async (cmd: "verify_remote_tunnel" | "deploy_wrapper") => {
      const pass = passwords.get(t.profileId);
      if (!pass) {
        appendLog(t.id, "需要密码: 请先启动隧道 (或重新输入密码)");
        btnStart.click();
        return;
      }
      const btn = cmd === "verify_remote_tunnel" ? btnVerify : btnDeploy;
      btn.disabled = true;
      const label = btn.textContent;
      btn.textContent = "执行中...";
      try {
        await invoke<string>(cmd, { id: t.id, password: pass });
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
    btnDelete.addEventListener("click", async () => {
      if (!confirm(`删除隧道「${t.name}」? (运行中会先停止)`)) return;
      try {
        tunnels = await invoke<TunnelDto[]>("tunnel_delete", { id: t.id });
        renderTunnels();
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

async function refreshTunnels() {
  tunnels = await invoke<TunnelDto[]>("tunnels_list");
  renderTunnels();
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
    // 消息行跟随 (updateRow 只更新文本, 不动显隐)
    const refs = rowRefs.get(p.id);
    if (refs) {
      const row = refs.msg.closest(".tunnel-msg")!;
      row.classList.toggle("hidden", !p.message);
    }
    if (p.message && p.state !== "connected") appendLog(p.id, p.state === "error" ? `❌ ${p.message}` : p.message);
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

// ---------- 新建隧道向导 ----------
let wzPreset: Preset | null = null;
let wzSpec: TunnelSpec | null = null;

function openWizard() {
  wzPreset = null;
  wzSpec = null;
  el("wizard-title").textContent = "新建隧道 — 选择场景";
  el("wizard-step1").classList.remove("hidden");
  el("wizard-form").classList.add("hidden");
  el<HTMLDivElement>("wz-error").textContent = "";
  loadPresetCards();
  el<HTMLDivElement>("wizard").classList.remove("hidden");
}

function closeWizard() {
  el<HTMLDivElement>("wizard").classList.add("hidden");
}

el<HTMLButtonElement>("new-tunnel").addEventListener("click", openWizard);
el<HTMLButtonElement>("wizard-close").addEventListener("click", closeWizard);
el<HTMLDivElement>("wizard").addEventListener("click", (e) => {
  if (e.target === e.currentTarget) closeWizard(); // 点遮罩关闭
});

async function loadPresetCards() {
  const container = el<HTMLDivElement>("preset-cards");
  container.innerHTML = "";
  const list = await invoke<Preset[]>("presets_list");
  for (const p of list) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "preset-card";
    card.innerHTML = `<strong>${escapeHtml(p.name)}</strong><span>${escapeHtml(p.description)}</span>`;
    card.addEventListener("click", () => selectPreset(p));
    container.append(card);
  }
}

/** 预设专属表单字段: 从后端模板预填 (含档案层默认策略)。
 * 模板形态与预设一一匹配 (后端 presets.rs 保证), 故非空断言安全。 */
interface WzField {
  id: string;
  label: string;
  value: string | number;
  hint?: string;
}

function wzFieldsFor(presetId: string, spec: TunnelSpec): WzField[] {
  const k = spec.kind;
  const b = spec.backend;
  const rev = "reverse" in k ? k.reverse : null;
  const loc = "local" in k ? k.local : null;
  const dyn = "dynamic" in k ? k.dynamic : null;
  const tcp = "tcp" in b ? b.tcp : null;
  const socks = "socksAuto" in b ? b.socksAuto : null;
  switch (presetId) {
    case "vpn_share":
      return [
        { id: "port", label: "服务器监听端口", value: rev!.port },
        {
          id: "fallback",
          label: "本机 VPN SOCKS 端口 (探测不到时内置)",
          value: socks!.fallbackPort,
        },
      ];
    case "expose_local":
      return [
        { id: "port", label: "服务器监听端口 (0 = 动态分配)", value: rev!.port, hint: "0 由服务器分配实际端口, 连接后显示在摘要里" },
        { id: "host", label: "本地服务地址", value: tcp![0] },
        { id: "lport", label: "本地服务端口", value: tcp![1] },
      ];
    case "reach_service":
      return [
        { id: "port", label: "本机监听端口", value: loc!.port },
        { id: "thost", label: "目标主机 (服务器视角)", value: loc!.targetHost },
        { id: "tport", label: "目标端口", value: loc!.targetPort },
      ];
    case "reach_lan":
      return [{ id: "port", label: "本机 SOCKS5 端口", value: dyn!.port }];
    default:
      return [];
  }
}

const WZ_HINTS: Record<string, string> = {
  vpn_share: "服务器经本机 VPN 出外网: 服务器上用 socks5h://127.0.0.1:<端口>",
  expose_local: "服务器直接访问本机运行的服务 (如本地 dev web)",
  reach_service: "本机访问服务器侧服务 (如服务器上的数据库/Web)",
  reach_lan: "应用/浏览器配 SOCKS5 代理即可访问服务器内网任意主机",
};

async function selectPreset(p: Preset) {
  if (profiles.length === 0) {
    alert("还没有服务器档案。请先到「服务器」页添加, 再新建隧道。");
    showPage("servers");
    closeWizard();
    return;
  }
  try {
    wzSpec = await invoke<TunnelSpec>("tunnel_from_preset", {
      presetId: p.id,
      name: p.name,
      profileId: profiles[0].id,
    });
  } catch (err) {
    el<HTMLDivElement>("wz-error").textContent = String(err);
    return;
  }
  wzPreset = p;
  el("wizard-title").textContent = `新建隧道 — ${p.name}`;
  el("wizard-step1").classList.add("hidden");
  el("wizard-form").classList.remove("hidden");
  el<HTMLDivElement>("wz-error").textContent = "";
  el<HTMLDivElement>("wz-hint").textContent = WZ_HINTS[p.id] ?? "";

  // 名称默认 = 预设名; 档案下拉
  const nameInput = el<HTMLInputElement>("wz-name");
  nameInput.value = p.name;
  const profileSelect = el<HTMLSelectElement>("wz-profile");
  profileSelect.innerHTML = profiles
    .map((pr) => `<option value="${pr.id}">${escapeHtml(pr.name)} (${pr.host})</option>`)
    .join("");
  // 自动重连默认 = 档案层默认 (已由后端合入模板 policy)
  el<HTMLInputElement>("wz-auto").checked = wzSpec.policy.auto;
  el<HTMLInputElement>("wz-password").value = "";

  // 预设专属字段
  const fields = el<HTMLDivElement>("wz-fields");
  fields.innerHTML = "";
  for (const f of wzFieldsFor(p.id, wzSpec)) {
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
  // vpn_share: SOCKS 端口旁加「探测」按钮
  if (p.id === "vpn_share") {
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

function num(s: string): number {
  return Number(s);
}

/** 表单值 → 覆盖模板的 kind/backend */
function wzApplyFields(spec: TunnelSpec): string | null {
  const v = (id: string) => el<HTMLInputElement>(`wz-f-${id}`).value.trim();
  const n = (id: string) => num(v(id));
  switch (wzPreset!.id) {
    case "vpn_share":
      spec.kind = { reverse: { bind: "127.0.0.1", port: n("port") } };
      spec.backend = { socksAuto: { fallbackPort: n("fallback") } };
      break;
    case "expose_local":
      spec.kind = { reverse: { bind: "127.0.0.1", port: n("port") } };
      spec.backend = { tcp: [v("host"), n("lport")] };
      break;
    case "reach_service":
      spec.kind = {
        local: {
          bind: "127.0.0.1",
          port: n("port"),
          targetHost: v("thost"),
          targetPort: n("tport"),
        },
      };
      break;
    case "reach_lan":
      spec.kind = { dynamic: { bind: "127.0.0.1", port: n("port") } };
      break;
  }
  return null;
}

async function submitWizard(start: boolean) {
  if (!wzPreset || !wzSpec) return;
  const errEl = el<HTMLDivElement>("wz-error");
  errEl.textContent = "";
  const name = el<HTMLInputElement>("wz-name").value.trim();
  const profileId = el<HTMLSelectElement>("wz-profile").value;
  if (!name) {
    errEl.textContent = "请填写名称";
    return;
  }
  const password = el<HTMLInputElement>("wz-password").value;
  if (start && !password) {
    errEl.textContent = "启动需要密码 (仅本次会话内存)";
    return;
  }
  const spec: TunnelSpec = { ...wzSpec!, name, profileId };
  wzApplyFields(spec);
  spec.policy = { ...spec.policy, auto: el<HTMLInputElement>("wz-auto").checked };
  try {
    await invoke("tunnel_create", { spec }); // 校验失败会抛错 (端口范围/空主机等)
  } catch (err) {
    errEl.textContent = String(err);
    return;
  }
  if (start) {
    passwords.set(profileId, password);
    try {
      await invoke("tunnel_start", { id: spec.id, password });
    } catch (err) {
      appendLog(spec.id, `❌ ${err}`);
    }
  }
  closeWizard();
  await refreshTunnels();
}

el<HTMLFormElement>("wizard-form").addEventListener("submit", (e) => {
  e.preventDefault();
  submitWizard(true);
});
el<HTMLButtonElement>("wz-save").addEventListener("click", () => submitWizard(false));
el<HTMLButtonElement>("wz-back").addEventListener("click", () => {
  el("wizard-step1").classList.remove("hidden");
  el("wizard-form").classList.add("hidden");
  el("wizard-title").textContent = "新建隧道 — 选择场景";
});

// ---------- 服务器档案 ----------
async function refreshProfiles() {
  profiles = await invoke<Profile[]>("list_profiles");
  const container = el<HTMLDivElement>("profile-list");
  container.innerHTML = "";
  if (profiles.length === 0) {
    container.innerHTML = '<div class="hint" style="min-height:0;margin:4px 0">还没有保存的服务器，用上方表单添加</div>';
    return;
  }
  for (const p of profiles) {
    const row = document.createElement("div");
    row.className = "profile-row";

    const info = document.createElement("div");
    info.className = "profile-info";
    info.innerHTML = `<strong>${escapeHtml(p.name)}</strong><span>${escapeHtml(p.host)}:${p.port} (${escapeHtml(p.username)})</span>`;

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.textContent = "编辑";
    editBtn.addEventListener("click", () => {
      el<HTMLInputElement>("profile-id").value = p.id;
      el<HTMLInputElement>("profile-name").value = p.name;
      el<HTMLInputElement>("profile-host").value = p.host;
      el<HTMLInputElement>("profile-port").value = String(p.port);
      el<HTMLInputElement>("profile-user").value = p.username;
      el<HTMLInputElement>("profile-name").focus();
    });

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.textContent = "删除";
    delBtn.className = "danger";
    delBtn.addEventListener("click", async () => {
      const used = tunnels.filter((t) => t.profileId === p.id);
      const warn = used.length
        ? `\n注意: 有 ${used.length} 条隧道关联此档案 (${used.map((t) => t.name).join(", ")}), 删除后这些隧道将无法启动`
        : "";
      if (!confirm(`删除服务器「${p.name}」?${warn}`)) return;
      try {
        profiles = await invoke<Profile[]>("delete_profile", { id: p.id });
        passwords.delete(p.id);
        await refreshProfiles();
        renderTunnels(); // 摘要里的档案名同步
      } catch (err) {
        alert(`删除失败: ${err}`);
      }
    });

    row.append(info, editBtn, delBtn);
    container.append(row);
  }
}

function clearProfileForm() {
  el<HTMLInputElement>("profile-id").value = "";
  el<HTMLInputElement>("profile-name").value = "";
  el<HTMLInputElement>("profile-host").value = "";
  el<HTMLInputElement>("profile-port").value = "22";
  el<HTMLInputElement>("profile-user").value = "";
}

el<HTMLFormElement>("profile-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = el<HTMLInputElement>("profile-name").value.trim();
  const host = el<HTMLInputElement>("profile-host").value.trim();
  const port = Number(el<HTMLInputElement>("profile-port").value);
  const username = el<HTMLInputElement>("profile-user").value.trim();
  if (!name || !host || !username) {
    alert("请填写名称、地址和用户名");
    return;
  }
  try {
    const id = el<HTMLInputElement>("profile-id").value || crypto.randomUUID();
    profiles = await invoke<Profile[]>("save_profile", {
      profile: { id, name, host, port, username },
    });
    clearProfileForm();
    await refreshProfiles();
    renderTunnels(); // 已有隧道摘要里的档案名同步
  } catch (err) {
    alert(`保存失败: ${err}`);
  }
});

el<HTMLButtonElement>("profile-clear").addEventListener("click", clearProfileForm);

// ---------- 分层默认值 (档案层) ----------
async function loadDefaults() {
  try {
    const d = await invoke<Defaults>("profile_defaults_get");
    const p = d.reconnect ?? DEFAULT_POLICY;
    el<HTMLInputElement>("def-auto").checked = p.auto;
    el<HTMLInputElement>("def-fast").value = String(p.fastRetries);
    el<HTMLInputElement>("def-max").value = String(p.maxBackoff);
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
    await invoke("profile_defaults_save", {
      defaults: { connectTimeoutSecs: d.connectTimeoutSecs ?? null, reconnect: policy },
    });
    btn.textContent = "已保存 ✓";
    setTimeout(() => (btn.textContent = "保存默认值"), 1500);
  } catch (err) {
    alert(`保存失败: ${err}`);
  } finally {
    btn.disabled = false;
  }
});

// ---------- 初始化 ----------
(async () => {
  await refreshProfiles();
  await refreshTunnels();
  await loadDefaults();
})().catch((e) => console.error("初始化失败", e));
