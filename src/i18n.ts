// 极简 i18n: zh/en 双语。词典以 zh 为 key 源, en 用映射类型强制齐全 (tsc 拦漏译)。
// 静态文案走 data-i18n (innerHTML —— 词典含受控 <b> 标记; 词典非用户输入, 无注入面),
// 动态字符串走 t()。偏好存 localStorage "pt-lang" (默认 zh), 仿 pt-theme/pt-font。
export type Lang = "zh" | "en";

const zh = {
  // ---- 全局 ----
  "app.title": "proxyTool — 本机↔远程 SSH 隧道",
  "brand.sub": "本机 ↔ 远程 · SSH 隧道",
  "nav.servers": "服务器",
  "nav.tools": "命令生成",
  "nav.settings": "设置",
  "nav.help": "帮助",

  // ---- 服务器页 ----
  "servers.head": "服务器",
  "servers.lead":
    '管理你的<b>本机 ↔ 远程服务器</b> SSH 隧道 —— 点选服务器查看详情，块上的播放键一键启动',

  // ---- 设置页 ----
  "set.head": "设置",
  "set.lead": "外观立即生效并记住；默认值仅影响之后新建的隧道",
  "set.appearance": "外观",
  "set.theme": "主题",
  "set.fontsize": "字体大小",
  "set.language": "语言",
  "set.fontSm": "小",
  "set.fontMd": "标准",
  "set.fontLg": "大",
  "set.appearHint": "「跟随系统」主题在系统切换明暗时实时跟随；字号整体缩放界面文字。",
  "set.defaults": "新隧道默认值",
  "set.defaultsSub": "重连策略在新建隧道时继承",
  "set.defAuto": "新隧道自动重连",
  "set.defFast": "快试次数 (断线先 N×1s 快试)",
  "set.defMax": "退避封顶 (秒)",
  "set.defShare": "共享 SSH 连接 (同服务器隧道复用一条连接)",
  "set.defMaxSessions": "MaxSessions 预算",
  "set.defaultsHint":
    "共享连接与 MaxSessions 对全部隧道在<b>启动时</b>生效（服务器表单可按服务器覆盖共享开关）；服务器 sshd 的 MaxSessions（默认 10）计入转发通道，预算将满时新隧道自动改用独立连接并在日志告警。",
  "set.saveDefaults": "保存默认值",
  "set.autostart": "开机自启",
  "set.autostartSub": "随系统启动 · 后台运行",
  "set.autostartLabel": "系统启动时自动运行 proxyTool",
  "set.autostartHint":
    "启动后隐藏到托盘（点击托盘图标显示主窗口，关闭按钮也是收进托盘）。需同时勾选隧道行的「自启」，且档案为<b>未加密私钥</b>认证，隧道才会免交互自动连接；密码认证的隧道需打开窗口手动启动。",

  // ---- 命令生成页 ----
  "cmdgen.head": "命令生成",
  "cmdgen.lead":
    "填好参数，拼出一条 ssh 命令。把命令拿到<b>服务器 A</b> 上一运行，A 就和目标服务器 <b>B</b> 打通了 —— 你的电脑只负责生成命令，不经手流量。",
  "cmdgen.params": "选参数",
  "cmdgen.mine": "我的命令",
  "cmdgen.saveAs": "存为命令",
  "cmdgen.del": "删除",
  "cmdgen.targetB": "SSH 连到哪台服务器 (B)",
  "cmdgen.hostB": "B 的地址",
  "cmdgen.portB": "B 的 SSH 端口",
  "cmdgen.userB": "登录 B 的用户名",
  "cmdgen.kind": "隧道形态",
  "cmdgen.kindL": "-L · A 访问 B 那边",
  "cmdgen.kindR": "-R · B 访问 A 这边",
  "cmdgen.kindD": "-D · A 借 B 当代理",
  "cmdgen.listen": "监听端口",
  "cmdgen.targetHost": "目标地址",
  "cmdgen.targetPort": "目标端口",
  "cmdgen.bindAll": "监听 0.0.0.0（同一网络里的其他机器也能连）",
  "cmdgen.output": "生成的命令",
  "cmdgen.sshTitle": "ssh · 临时（前台运行，断开即停）",
  "cmdgen.copy": "复制",
  "cmdgen.noteN": "只做端口转发，不在远端开终端",
  "cmdgen.noteLRD": "三种转发方向，区别看上面的图",
  "cmdgen.noteExit": "端口没建成功就让 ssh 退出，免得看着连上了、实际用不了",
  "cmdgen.noteAlive": "每 30 秒发一次心跳，连续 3 次没回应就认定断线",
  "cmdgen.autosshTitle": "autossh · 常驻（断线自动重连）",
  "cmdgen.noteAutossh": "ssh 的自动重连版，断了会自己接上（服务器上需先安装）",
  "cmdgen.noteM0": "关掉 autossh 自带的探测，改用上面的心跳（推荐）",
  "cmdgen.noteGatetime": "第一次就连不上也不退出，接着重试，适合开机自启",
  "cmdgen.trailingHint":
    "第一次连接会提示输密码；想让它长期挂着，先用 <b>ssh-copy-id</b> 配好免密登录更省心。",

  // ---- 帮助页 ----
  "help.head": "帮助",
  "help.lead": "proxyTool 是什么、怎么用",
  "help.what": "proxyTool 是什么",
  "help.whatLead":
    "在你的<b>电脑</b>和<b>远程服务器</b>之间一键建立 SSH 隧道 —— 免命令行、断线自动重连、密码加密保存。",
  "help.step1": "<strong>新建服务器</strong><span>填地址和账号，像 SSH 客户端一样</span>",
  "help.step2": "<strong>新建隧道</strong><span>选一个场景预设（如 VPN 共享），参数自动填好</span>",
  "help.step3": "<strong>点 ▶ 启动</strong><span>服务器块上的播放键一次启动全部隧道</span>",
  "help.cta": "新建第一台服务器",
  "help.kinds": "三种隧道形态",
  "help.ktagR": "反向 -R",
  "help.ktagL": "本地 -L",
  "help.ktagD": "动态 -D",
  "help.kindRHead":
    '<span class="ktag">反向 -R</span><strong>服务器 → 你的电脑</strong>',
  "help.kindLHead":
    '<span class="ktag">本地 -L</span><strong>你的电脑 → 服务器</strong>',
  "help.kindDHead":
    '<span class="ktag">动态 -D</span><strong>你的电脑 → 服务器（SOCKS5）</strong>',
  "help.kindRp":
    "在服务器上开端口，流量回到你电脑。典型：<b>让服务器借你 PC 的 VPN 出网</b>（服务器 127.0.0.1:1080 → 你电脑的 SOCKS 代理），或让服务器访问你电脑上的服务。",
  "help.kindLp":
    "在你电脑上开端口，访问<b>服务器侧或其内网</b>的服务。典型：本机 3307 → 服务器内网的 MySQL。",
  "help.kindDp":
    "在你电脑上开一个 SOCKS5 代理，任意流量<b>经服务器代连</b> —— 浏览器挂上就能访问服务器内网。",
  "help.kindsHint": "「命令生成」页是第四种场景：服务器 ↔ 服务器，命令拷到服务器上执行，不经过本机。",
  "help.cases": "什么情况用哪种？",
  "help.casesSub": "三个常见例子",
  "help.case1T": "服务器上不了外网，你的电脑可以",
  "help.case1P":
    "服务器要装软件、拉代码，却只有你的电脑能上外网。把你电脑上的代理「借」给服务器用——本软件的「VPN 共享」预设干的就是这件事。",
  "help.case2T": "人在外面，想访问公司内网的服务",
  "help.case2P": "数据库、管理后台只对公司内网开放，你的电脑连不进去。在本机开个小端口，流量经服务器带你进内网。",
  "help.case3T": "内网服务一大把，一个个开隧道太麻烦",
  "help.case3P": "一条命令把服务器变成你电脑的出口：浏览器或终端挂上 SOCKS5 代理，就像人坐在服务器跟前。",
  "help.faq": "常见问题",
  "faq1Q": "密码会被保存吗？",
  "faq1A":
    "会。首次启动输入后自动记住：以 <b>AES-256-GCM 密文</b>保存在本机（secrets.enc），重启与开机自启都不用再输；密码错误会自动作废，服务器详情页也能随时清除。",
  "faq2Q": "首次连接弹出的「指纹」是什么？",
  "faq2A":
    "首次连接会记住服务器公钥指纹（TOFU），之后指纹一旦变化就拒绝连接并提示 —— 防中间人攻击。服务器详情页可查看 / 复制 / 清除。",
  "faq3Q": "服务器块上的 ▶ 一键启动做了什么？",
  "faq3A": "启动该服务器全部勾了「自启」的隧道；密码认证首次会要一次密码，之后会话内免输。",
  "faq4Q": "共享 SSH 连接是什么？",
  "faq4A": "同一服务器的多条隧道复用一条 SSH 连接（N 条隧道只认证一次）；受服务器 MaxSessions 限制，将满时自动改用独立连接。",
  "faq5Q": "点关闭按钮软件退出了吗？",
  "faq5A": "没有 —— 收进系统托盘继续运行，隧道不断；托盘图标右键菜单里才是真正退出。",
  "faq6Q": "隧道断了会自动重连吗？",
  "faq6A": "会。快试 3 次后指数退避（最长 30 秒），连接保持 3 秒以上退避清零；行菜单里有「立即重试」。",

  // ---- 右面板骨架 ----
  "detail.empty1": "选择左侧服务器查看详情",
  "detail.empty2":
    "每台服务器可建多条<b>本机 ↔ 该服务器</b>的隧道；块上的<b>播放键</b>一键全部启动，没有服务器就先「＋ 新建」。",
  "detail.tunnels": "隧道",
  "detail.newTunnel": "新建隧道",
  "sf.back": "返回",
  "sf.titleNew": "新建服务器",
  "sf.name": "名称",
  "sf.namePh": "腾讯云-测试机",
  "sf.host": "服务器地址",
  "sf.port": "SSH 端口",
  "sf.user": "用户名",
  "sf.key": "私钥路径 (选填)",
  "sf.keyHint":
    "填写私钥路径则用密钥认证 (公钥需已加入服务器 authorized_keys)，密码框此时充当密钥口令；留空用密码认证。",
  "sf.share": "共享 SSH 连接",
  "sf.shareFollow": "跟随默认值",
  "sf.shareOn": "共享 — 同服务器隧道复用一条连接",
  "sf.shareOff": "独立 — 每条隧道单独连接",
  "common.save": "保存",
  "common.cancel": "取消",
  "common.ok": "确定",
  "theme.light": "浅色",
  "theme.system": "跟随系统",
  "theme.dark": "深色",
  "sp.back": "返回",
  "sp.title": "新建隧道 — 选择场景",
  "sp.presets": "场景预设",
  "sp.mine": "我的场景",
  "sp.mineHint": "还没有保存的场景 —— 建隧道时勾选「存为我的场景」，或隧道行点「存为场景」。",
  "tf.back": "重选场景",
  "tf.title": "新建隧道",
  "tf.name": "名称",
  "tf.namePh": "隧道名称",
  "tf.kind": "隧道形态",
  "tf.kindR": "反向 -R",
  "tf.kindL": "本地 -L",
  "tf.kindD": "动态 -D",
  "tf.backend": "本机落地 (反向隧道的流量去向)",
  "tf.backendSocks": "本机 SOCKS (VPN)",
  "tf.backendTcp": "固定地址",
  "tf.password": "密码 (连接成功后加密保存到本机)",
  "tf.auto": "自动重连",
  "tf.saveScenario": "存为我的场景 (下次新建直接复用)",
  "tf.scenarioPh": "场景名称 (默认同隧道名)",
  "tf.saveOnly": "仅保存",
  "tf.saveStart": "保存并启动",

  // ---- 形态 / 状态 / uptime ----
  "kind.reverse": "反向",
  "kind.local": "本地",
  "kind.dynamic": "动态",
  "st.connecting": "连接中",
  "st.connected": "已连接",
  "st.reconnecting": "重连中",
  "st.disconnected": "未启动",
  "st.error": "连接失败",
  "up.s": "{s}秒",
  "up.ms": "{m}分{s}秒",
  "up.hm": "{h}时{m}分",
  "up.dh": "{d}天{h}时",
  "auth.key": "密钥认证",
  "auth.password": "密码认证",

  // ---- 摘要行 / 端口 chip ----
  "sm.remoteDyn": "服务器动态端口",
  "sm.remotePort": "服务器 127.0.0.1:{port}",
  "sm.localSocks": "本机 VPN SOCKS (自动探测)",
  "sm.localTcp": "本机 {host}:{port}",
  "sm.localFwd": "本机 {bind}:{port} → {host}:{tport}",
  "sm.dynFwd": "本机 SOCKS5 {bind}:{port} → 服务器代连内网",
  "sm.noProfile": "档案缺失 — {s}",
  "chip.remote": "服务器监听端口 (127.0.0.1)",
  "chip.dyn": "动态分配",
  "chip.dynTitle": "服务器端口 0 = 连接后由服务器分配, 回填显示",
  "chip.local": "本机监听端口",
  "chip.socks": "本机 SOCKS5 监听端口",

  // ---- 隧道行 ----
  "row.expandLogs": "展开日志",
  "row.start": "启动",
  "row.stop": "停止",
  "row.more": "更多操作",
  "row.pwPh": "SSH 密码 ({user}@{host})",
  "row.pwKeyPh": "密钥口令 ({user}@{host}, 未加密私钥可留空)",
  "row.connect": "连接",
  "row.connecting": "连接中...",
  "row.copyLog": "复制日志",
  "row.clearLog": "清空日志",
  "row.clear": "清空",
  "row.logEmpty": "日志为空",
  "row.logCopied": "日志已复制",
  "row.stopping": "请求断开...",
  "row.needCreds": "需要凭据: 请先启动隧道 (或重新输入密码/口令)",
  "row.noProfileErr": "❌ 隧道关联的档案缺失, 无法定位指纹记录",

  // ---- ⋯ 菜单 ----
  "menu.retryNow": "立即重试",
  "menu.trustFp": "信任新指纹",
  "menu.trustFpTitle": "服务器指纹变更被拒后, 清除记录并重连 (仅服务器确已重装/更换时使用)",
  "menu.verify": "验证外网",
  "menu.verifyTitle": "在服务器上经隧道测试访问外网 (google)",
  "menu.deploy": "部署 proxy",
  "menu.deployTitle": "部署 proxy 命令, 服务器上可 'proxy curl ...' 走隧道",
  "menu.saveScenario": "存为场景",
  "menu.saveScenarioTitle": "把这条隧道的形态/参数存为「我的场景」, 新建隧道时复用",
  "menu.autostart": "开机自启",
  "menu.autostartTitle": "系统启动时后台拉起此隧道 (密码/口令已记住或私钥免口令即可免交互)",
  "menu.autostartHintLog":
    "提示: 该服务器尚未记住密码, 开机自启时无法免交互启动; 启动一次并记住密码即可覆盖",
  "menu.delete": "删除",
  "menu.deleteTitle": "删除隧道配置",

  // ---- 通用动作/反馈 ----
  "common.copy": "复制",
  "common.delete": "删除",
  "common.clear": "清除",
  "common.copyFail": "复制失败",
  "common.saveFail": "保存失败: {err}",
  "common.delFail": "删除失败: {err}",
  "common.clearFail": "清除失败: {err}",
  "common.setFail": "设置失败: {err}",
  "common.saving": "保存中...",
  "common.starting": "启动中...",

  // ---- 服务器块 ----
  "host.idleTitle": "无隧道运行",
  "host.noTunnels": "无隧道",
  "host.running": "{r}/{t} 运行",
  "host.noTunnelsTitle": "还没有隧道",
  "host.runningTitle": "{r} 条运行 / 共 {t} 条",
  "host.startAll": "一键启动",
  "host.stopAll": "全部停止",
  "host.startAllTitle": "一键启动该服务器全部 enabled 隧道 (首次需输密码, 之后记住免输)",
  "host.stopAllTitle": "停止该服务器的全部隧道",
  "host.edit": "编辑服务器",
  "host.editAria": "编辑服务器 {name}",
  "host.del": "删除服务器",
  "host.delAria": "删除服务器 {name}",
  "host.aria": "服务器 {name}",
  "host.newBtn": "新建",

  // ---- 命令生成 (动态部分) ----
  "cg.hintL": "这条命令在 A 上运行：A 开出端口 {bind}:{listen}，连它的流量经 SSH 送到 B，再由 B 去连 {thost}:{tport}",
  "cg.hintR": "这条命令在 A 上运行，但端口开在 B 上（{bind}:{listen}）；B 上这个端口的流量经 SSH 回到 A，由 A 去连 {thost}:{tport}",
  "cg.hintD": "这条命令在 A 上运行：A 会多出一个 SOCKS5 代理（127.0.0.1:{listen}），程序把代理指向它，流量就从 B 出去了",
  "cg.hintGateway": "。注意：想让 B 同一网络的其他机器也能连，B 的 sshd 要设 GatewayPorts yes，默认只有 B 自己连得上",
  "cg.hintKeyFile": "。这个档案平时用密钥登录——但命令要在 A 上跑，A 上也得有私钥（可加参数 -i ~/.ssh/id_ed25519）",
  "cg.bAddr": "B 的地址",
  "cg.flowA": "A · 跑命令的机器",
  "cg.flowB": "B · 目标服务器",
  "cg.flowAOpen": "A 上开端口 :{p}",
  "cg.flowBOpen": "{addr} · 开端口 :{p}",
  "cg.flowARun": "命令在这台机器上运行",
  "cg.flowSocks": "SOCKS5 代理 :{p}",
  "cg.arrowB": "B 帮忙连",
  "cg.arrowA": "A 帮忙连",
  "cg.fromB": "这个地址从 B 那边连",
  "cg.fromA": "这个地址从 A 那边连",
  "cg.anyAddr": "任意地址",
  "cg.anyFromB": "从 B 那边连出去",
  "cg.loadPh": "载入已保存的命令…",
  "cg.nonePh": "还没有保存的命令",
  "cg.manual": "手动输入",
  "cg.suggestD": "{host} 的代理 :{listen}",
  "cg.suggestLR": "{host} → {thost}:{tport}",
  "cg.saveTitle": "保存命令",
  "cg.saveBody": "给这组参数起个名字，下次直接从「我的命令」里载入。",
  "cg.nameEmpty": "命令名称不能为空",
  "cg.saved": "命令已保存",
  "cg.pickFirst": "先在下拉框里选中一条命令",
  "cg.delTitle": "删除命令",
  "cg.delBody": "确定删除「{name}」吗？",
  "cg.deleted": "已删除",
  "cg.copied": "命令已复制",

  // ---- 档案 / 服务器详情 ----
  "pf.delTitle": "删除服务器「{name}」?",
  "pf.delBody": "有 {n} 条隧道关联此服务器 ({names}), 删除后这些隧道将无法启动。",
  "detail.noTunnels": "还没有隧道 —— 点右上「＋ 新建隧道」从场景开始",
  "pd.genTitle": "为此服务器生成隧道命令 (命令生成页)",
  "pd.gen": "生成命令",
  "pd.batchPwPh": "SSH 密码 ({user}@{host}, 启动 {n} 条隧道)",
  "pd.batchConnect": "连接 {n} 条隧道",

  // ---- 凭据卡 ----
  "sec.noneKey": "密码: 私钥口令输入一次即记住 (加密保存); 未加密私钥无需输入",
  "sec.none": "密码: 首次启动输入后自动记住 (AES-256-GCM 加密保存到本机)",
  "sec.headKey": "已记住私钥口令",
  "sec.head": "已记住密码",
  "sec.note": "加密保存于本机 (secrets.enc) · 重启与开机自启免输入",
  "sec.clearTitleKey": "清除 {name} 记住的私钥口令?",
  "sec.clearTitle": "清除 {name} 记住的密码?",
  "sec.clearBody": "下次启动会重新询问; 服务器上的任何配置不受影响。",
  "sec.cleared": "已清除记住的密码",

  // ---- 指纹 ----
  "fp.none": "指纹: 首次连接后自动记住 (TOFU); 变更即拒绝连接",
  "fp.head": "已记住服务器指纹",
  "fp.copyTitle": "复制指纹",
  "fp.copied": "指纹已复制",
  "fp.clearTitle": "清除 {host}:{port} 的指纹记录?",
  "fp.clearBody": "下次连接将重新记住当前指纹 (仅服务器确已变更时操作)。",
  "fp.loadFail": "指纹信息读取失败: {err}",
  "fp.toast": "已记住服务器指纹（首次连接）",
  "fp.clickCopy": "点击复制指纹",
  "fp.trustTitle": "信任新指纹并重连?",
  "fp.trustBody":
    "将清除 {host}:{port} 的旧指纹记录, 重连后重新记忆当前指纹。\n仅当服务器确已重装/更换时继续 —— 否则可能是中间人攻击。",
  "fp.trustConfirm": "信任并重连",
  "fp.forgotLog": "已清除 {host}:{port} 的指纹记录, 重连后将重新记忆当前指纹",

  // ---- 表单 / 校验 ----
  "sf.titleEdit": "编辑服务器",
  "sf.needFields": "请填写名称、地址和用户名",
  "sp.needProfile": "请先选择服务器",
  "sp.titleWith": "新建隧道 — {name}",
  "sp.defaultName": "新隧道",
  "sc.saveTitle": "存为我的场景",
  "sc.saveBody": "以当前隧道的形态与参数保存, 新建隧道时直接复用。",
  "sc.namePh": "场景名称",
  "sc.delThis": "删除此场景",
  "sc.delTitle": "删除场景「{name}」?",
  "sc.fromHint": "来自我的场景「{name}」",
  "sc.saved": "已保存场景「{name}」",
  "sc.saveFailLog": "❌ 保存场景失败: {err}",
  "tun.delTitle": "删除隧道「{name}」?",
  "tun.delBody": "运行中的隧道会先停止。",
  "tf.titleWith": "新建隧道 — {title}",
  "tf.passphraseLabel": "密钥口令 (私钥未加密可留空)",
  "wz.hintVpn": "服务器经本机 VPN 出外网: 服务器上用 socks5h://127.0.0.1:<端口>",
  "wz.hintExpose": "服务器直接访问本机运行的服务 (如本地 dev web)",
  "wz.hintReach": "本机访问服务器侧服务 (如服务器上的数据库/Web)",
  "wz.hintLan": "应用/浏览器配 SOCKS5 代理即可访问服务器内网任意主机",
  "wz.hintCustom": "自选形态与参数; 反向隧道服务器端口 0 = 动态分配 (连接后回填显示)",
  "wz.rPort": "服务器监听端口 (0 = 动态分配)",
  "wz.rPortHint": "0 由服务器分配实际端口, 连接后显示在摘要里",
  "wz.fallback": "本机 VPN SOCKS 端口 (探测不到时内置)",
  "wz.tcpHost": "本地服务地址",
  "wz.tcpPort": "本地服务端口",
  "wz.lPort": "本机监听端口",
  "wz.tHost": "目标主机 (服务器视角)",
  "wz.tPort": "目标端口",
  "wz.dPort": "本机 SOCKS5 端口",
  "wz.probeLabel": "探测本机 VPN 端口",
  "wz.probe": "探测并填入",
  "wz.probing": "探测中...",
  "wz.probed": "已填入 {port}",
  "wz.probeNoSocks": "发现端口但非 SOCKS5: {ports}",
  "wz.probeNone": "未发现 (VPN 未开? 将用内置 SOCKS)",
  "wz.probeFail": "探测失败: {err}",
  "err.name": "请填写名称",
  "err.needPassword": "启动需要密码",
  "err.rPort": "服务器监听端口无效",
  "err.fallback": "SOCKS 端口无效",
  "err.tcpHost": "本地服务地址不能为空",
  "err.tcpPort": "本地服务端口无效",
  "err.lPort": "本机监听端口无效",
  "err.tHost": "目标主机不能为空",
  "err.tPort": "目标端口无效",
  "err.dPort": "本机 SOCKS5 端口无效",

  // ---- 设置页动态反馈 ----
  "set.defaultsSaved": "默认值已保存",

  // ---- 预设本地化 (后端返回中文, 前端按 id 覆盖) ----
  "preset.vpn_share.name": "服务器借 VPN 出网",
  "preset.vpn_share.desc": "反向隧道 + SOCKS: 服务器经本机 VPN 访问外网",
  "preset.expose_local.name": "暴露本地服务到服务器",
  "preset.expose_local.desc": "反向隧道 + 固定地址: 服务器上直接访问本机运行的服务",
  "preset.reach_service.name": "访问服务器侧服务",
  "preset.reach_service.desc": "本地转发: 本机端口 → 服务器侧目标 (如服务器的数据库)",
  "preset.reach_lan.name": "访问服务器内网",
  "preset.reach_lan.desc": "动态隧道: 本机 SOCKS5, 服务器代连其内网任意地址",
  "preset.custom.name": "自定义",
  "preset.custom.desc": "从空白配置: 自选隧道形态 (反向/本地/动态) 与落地后端",
} as const;

export type I18nKey = keyof typeof zh;

const en: { [K in I18nKey]: string } = {
  // ---- global ----
  "app.title": "proxyTool — Local↔Remote SSH Tunnels",
  "brand.sub": "Local ↔ Remote · SSH Tunnel",
  "nav.servers": "Servers",
  "nav.tools": "Command Builder",
  "nav.settings": "Settings",
  "nav.help": "Help",

  // ---- servers page ----
  "servers.head": "Servers",
  "servers.lead":
    "Manage <b>local ↔ remote server</b> SSH tunnels — click a server for details, or hit the play button on its card to start everything at once",

  // ---- settings page ----
  "set.head": "Settings",
  "set.lead":
    "Appearance applies instantly and is remembered; defaults only affect tunnels created afterwards",
  "set.appearance": "Appearance",
  "set.theme": "Theme",
  "set.fontsize": "Font size",
  "set.language": "Language",
  "set.fontSm": "Small",
  "set.fontMd": "Standard",
  "set.fontLg": "Large",
  "set.appearHint":
    "\"Follow system\" theme tracks OS light/dark changes live; font size scales all UI text.",
  "set.defaults": "New-tunnel defaults",
  "set.defaultsSub": "Reconnect policy is inherited when creating a tunnel",
  "set.defAuto": "Auto-reconnect new tunnels",
  "set.defFast": "Fast retries (N×1s right after a drop)",
  "set.defMax": "Backoff cap (seconds)",
  "set.defShare": "Shared SSH connection (tunnels to one server reuse a single connection)",
  "set.defMaxSessions": "MaxSessions budget",
  "set.defaultsHint":
    "Connection sharing and the MaxSessions budget apply to all tunnels <b>when they start</b> (the server form can override sharing per server). The server's sshd MaxSessions (default 10) counts forwarded channels; when the budget is nearly full, new tunnels automatically fall back to dedicated connections and log a warning.",
  "set.saveDefaults": "Save defaults",
  "set.autostart": "Start with system",
  "set.autostartSub": "Launch at login · run in background",
  "set.autostartLabel": "Run proxyTool automatically when the system starts",
  "set.autostartHint":
    "Starts hidden in the tray (click the tray icon to show the window; the close button also minimizes to tray). Tunnels connect non-interactively only if their row's \"Auto-start\" is checked and the profile authenticates with an <b>unencrypted private key</b>; password tunnels need the window opened to start manually.",

  // ---- command builder page ----
  "cmdgen.head": "Command Builder",
  "cmdgen.lead":
    "Fill in the parameters and get a ready-to-run ssh command. Run it on <b>server A</b> and A is instantly connected to target server <b>B</b> — your PC only generates the command, it never sees the traffic.",
  "cmdgen.params": "Parameters",
  "cmdgen.mine": "My commands",
  "cmdgen.saveAs": "Save as command",
  "cmdgen.del": "Delete",
  "cmdgen.targetB": "Which server to SSH into (B)",
  "cmdgen.hostB": "B's address",
  "cmdgen.portB": "B's SSH port",
  "cmdgen.userB": "Username for B",
  "cmdgen.kind": "Tunnel type",
  "cmdgen.kindL": "-L · A reaches B's side",
  "cmdgen.kindR": "-R · B reaches A's side",
  "cmdgen.kindD": "-D · A uses B as proxy",
  "cmdgen.listen": "Listen port",
  "cmdgen.targetHost": "Target address",
  "cmdgen.targetPort": "Target port",
  "cmdgen.bindAll": "Listen on 0.0.0.0 (other machines on the same network can connect)",
  "cmdgen.output": "Generated command",
  "cmdgen.sshTitle": "ssh · one-off (foreground, stops when disconnected)",
  "cmdgen.copy": "Copy",
  "cmdgen.noteN": "Port forwarding only, no remote shell",
  "cmdgen.noteLRD": "The three forwarding directions — see the diagram above",
  "cmdgen.noteExit": "Exit ssh if any forwarding fails, so a \"connected\" tunnel is always usable",
  "cmdgen.noteAlive": "Send a keepalive every 30s; 3 missed replies means the link is down",
  "cmdgen.autosshTitle": "autossh · persistent (auto-reconnects)",
  "cmdgen.noteAutossh": "Auto-reconnecting ssh (install it on the server first)",
  "cmdgen.noteM0": "Disable autossh's own probe and use the keepalive above (recommended)",
  "cmdgen.noteGatetime": "Keep retrying even if the first connect fails — good for boot-time startup",
  "cmdgen.trailingHint":
    "The first connection asks for a password; to keep it running long-term, set up <b>ssh-copy-id</b> passwordless login first.",

  // ---- help page ----
  "help.head": "Help",
  "help.lead": "What proxyTool is and how to use it",
  "help.what": "What is proxyTool",
  "help.whatLead":
    "One-click SSH tunnels between your <b>PC</b> and <b>remote servers</b> — no command line, automatic reconnection, passwords stored encrypted.",
  "help.step1": "<strong>Add a server</strong><span>Enter its address and account, like any SSH client</span>",
  "help.step2": "<strong>Add a tunnel</strong><span>Pick a scenario preset (e.g. VPN share) — parameters are pre-filled</span>",
  "help.step3": "<strong>Press ▶ to start</strong><span>The play button on a server card starts all its tunnels at once</span>",
  "help.cta": "Create your first server",
  "help.kinds": "Three tunnel types",
  "help.ktagR": "Reverse -R",
  "help.ktagL": "Local -L",
  "help.ktagD": "Dynamic -D",
  "help.kindRHead":
    '<span class="ktag">Reverse -R</span><strong>Server → your PC</strong>',
  "help.kindLHead":
    '<span class="ktag">Local -L</span><strong>Your PC → server</strong>',
  "help.kindDHead":
    '<span class="ktag">Dynamic -D</span><strong>Your PC → server (SOCKS5)</strong>',
  "help.kindRp":
    "Opens a port on the server; traffic comes back to your PC. Typical: <b>let the server use your PC's VPN</b> (server 127.0.0.1:1080 → your PC's SOCKS proxy), or give the server access to services on your PC.",
  "help.kindLp":
    "Opens a port on your PC to reach services <b>on the server or its intranet</b>. Typical: local 3307 → an intranet MySQL behind the server.",
  "help.kindDp":
    "Opens a SOCKS5 proxy on your PC; any traffic is <b>relayed through the server</b> — point your browser at it to browse the server's intranet.",
  "help.kindsHint":
    "The Command Builder page covers a fourth case: server ↔ server. The command is copied to the server and run there; your PC is not involved.",
  "help.cases": "Which one should I use?",
  "help.casesSub": "Three common examples",
  "help.case1T": "The server can't reach the internet, but your PC can",
  "help.case1P":
    "The server needs to install packages or pull code, but only your PC has internet access. \"Lend\" your PC's proxy to the server — that's exactly what the \"VPN share\" preset does.",
  "help.case2T": "You're away and need a service on the company intranet",
  "help.case2P":
    "Databases and admin panels are only open to the intranet, which your PC can't reach. Open a local port and let the server relay you in.",
  "help.case3T": "Too many intranet services to tunnel one by one",
  "help.case3P":
    "Turn the server into your PC's exit with one command: point your browser or terminal at the SOCKS5 proxy, as if you were sitting at the server.",
  "help.faq": "FAQ",
  "faq1Q": "Are passwords saved?",
  "faq1A":
    "Yes. After the first successful start it's remembered automatically: stored locally as <b>AES-256-GCM ciphertext</b> (secrets.enc), so restarts and autostart never ask again; a wrong password invalidates itself, and you can clear it anytime on the server detail page.",
  "faq2Q": "What is the \"fingerprint\" prompt on first connect?",
  "faq2A":
    "The first connection remembers the server's public key fingerprint (TOFU). If it ever changes, the connection is refused with a warning — protection against man-in-the-middle attacks. View / copy / clear it on the server detail page.",
  "faq3Q": "What does the ▶ one-click start on a server card do?",
  "faq3A":
    "Starts all of that server's tunnels that have \"Auto-start\" checked; password profiles ask once, then stay password-free for the session.",
  "faq4Q": "What is a shared SSH connection?",
  "faq4A":
    "Multiple tunnels to the same server reuse one SSH connection (N tunnels, one authentication); limited by the server's MaxSessions — when nearly full, tunnels automatically fall back to dedicated connections.",
  "faq5Q": "Does clicking close quit the app?",
  "faq5A":
    "No — it hides into the system tray and keeps running with tunnels alive; the tray icon's right-click menu is where you actually quit.",
  "faq6Q": "Do tunnels reconnect automatically?",
  "faq6A":
    "Yes. 3 fast retries, then exponential backoff (up to 30s); staying connected for 3s+ resets the backoff. There's also \"Retry now\" in the row menu.",

  // ---- detail pane skeleton ----
  "detail.empty1": "Select a server on the left to see details",
  "detail.empty2":
    "Each server can have multiple <b>local ↔ server</b> tunnels; the <b>play button</b> on its card starts them all. No servers yet? Hit \"＋ New\".",
  "detail.tunnels": "Tunnels",
  "detail.newTunnel": "New tunnel",
  "sf.back": "Back",
  "sf.titleNew": "New server",
  "sf.name": "Name",
  "sf.namePh": "tencent-test",
  "sf.host": "Server address",
  "sf.port": "SSH port",
  "sf.user": "Username",
  "sf.key": "Private key path (optional)",
  "sf.keyHint":
    "With a key path set, key authentication is used (the public key must already be in the server's authorized_keys) and the password box becomes the key passphrase; leave empty for password authentication.",
  "sf.share": "Shared SSH connection",
  "sf.shareFollow": "Follow defaults",
  "sf.shareOn": "Shared — tunnels to one server reuse a single connection",
  "sf.shareOff": "Dedicated — each tunnel gets its own connection",
  "common.save": "Save",
  "common.cancel": "Cancel",
  "common.ok": "OK",
  "theme.light": "Light",
  "theme.system": "System",
  "theme.dark": "Dark",
  "sp.back": "Back",
  "sp.title": "New tunnel — pick a scenario",
  "sp.presets": "Scenario presets",
  "sp.mine": "My scenarios",
  "sp.mineHint":
    "No saved scenarios yet — check \"Save as my scenario\" when creating a tunnel, or use \"Save as scenario\" in a tunnel row menu.",
  "tf.back": "Pick another scenario",
  "tf.title": "New tunnel",
  "tf.name": "Name",
  "tf.namePh": "Tunnel name",
  "tf.kind": "Tunnel type",
  "tf.kindR": "Reverse -R",
  "tf.kindL": "Local -L",
  "tf.kindD": "Dynamic -D",
  "tf.backend": "Local landing (where reverse-tunnel traffic goes)",
  "tf.backendSocks": "Local SOCKS (VPN)",
  "tf.backendTcp": "Fixed address",
  "tf.password": "Password (stored encrypted locally after a successful connect)",
  "tf.auto": "Auto-reconnect",
  "tf.saveScenario": "Save as my scenario (reusable next time)",
  "tf.scenarioPh": "Scenario name (defaults to the tunnel name)",
  "tf.saveOnly": "Save only",
  "tf.saveStart": "Save & start",

  // ---- kind / status / uptime ----
  "kind.reverse": "Reverse",
  "kind.local": "Local",
  "kind.dynamic": "Dynamic",
  "st.connecting": "Connecting",
  "st.connected": "Connected",
  "st.reconnecting": "Reconnecting",
  "st.disconnected": "Stopped",
  "st.error": "Failed",
  "up.s": "{s}s",
  "up.ms": "{m}m {s}s",
  "up.hm": "{h}h {m}m",
  "up.dh": "{d}d {h}h",
  "auth.key": "Key auth",
  "auth.password": "Password auth",

  // ---- summary / port chip ----
  "sm.remoteDyn": "server dynamic port",
  "sm.remotePort": "server 127.0.0.1:{port}",
  "sm.localSocks": "local VPN SOCKS (auto-detected)",
  "sm.localTcp": "local {host}:{port}",
  "sm.localFwd": "local {bind}:{port} → {host}:{tport}",
  "sm.dynFwd": "local SOCKS5 {bind}:{port} → server relays intranet",
  "sm.noProfile": "profile missing — {s}",
  "chip.remote": "Server listen port (127.0.0.1)",
  "chip.dyn": "dynamic",
  "chip.dynTitle": "Server port 0 = assigned by the server on connect, shown here after bind",
  "chip.local": "Local listen port",
  "chip.socks": "Local SOCKS5 listen port",

  // ---- tunnel row ----
  "row.expandLogs": "Expand logs",
  "row.start": "Start",
  "row.stop": "Stop",
  "row.more": "More actions",
  "row.pwPh": "SSH password ({user}@{host})",
  "row.pwKeyPh": "Key passphrase ({user}@{host}, empty for unencrypted keys)",
  "row.connect": "Connect",
  "row.connecting": "Connecting…",
  "row.copyLog": "Copy logs",
  "row.clearLog": "Clear logs",
  "row.clear": "Clear",
  "row.logEmpty": "No logs yet",
  "row.logCopied": "Logs copied",
  "row.stopping": "Disconnecting…",
  "row.needCreds": "Credentials needed: start the tunnel first (or re-enter the password/passphrase)",
  "row.noProfileErr": "❌ The tunnel's profile is missing; cannot locate its fingerprint record",

  // ---- ⋯ menu ----
  "menu.retryNow": "Retry now",
  "menu.trustFp": "Trust new fingerprint",
  "menu.trustFpTitle": "After a fingerprint change was rejected: clear the record and reconnect (only if the server really was reinstalled)",
  "menu.verify": "Verify internet",
  "menu.verifyTitle": "Test internet access through the tunnel from the server (google)",
  "menu.deploy": "Deploy proxy",
  "menu.deployTitle": "Deploy the proxy command; use 'proxy curl …' on the server to go through the tunnel",
  "menu.saveScenario": "Save as scenario",
  "menu.saveScenarioTitle": "Save this tunnel's type/parameters as a reusable scenario",
  "menu.autostart": "Auto-start",
  "menu.autostartTitle": "Start this tunnel in the background at system startup (non-interactive if credentials are remembered or the key needs no passphrase)",
  "menu.autostartHintLog":
    "Note: no password remembered for this server yet, so auto-start can't connect non-interactively; start it once with the password remembered to fix that",
  "menu.delete": "Delete",
  "menu.deleteTitle": "Delete the tunnel config",

  // ---- common actions/feedback ----
  "common.copy": "Copy",
  "common.delete": "Delete",
  "common.clear": "Clear",
  "common.copyFail": "Copy failed",
  "common.saveFail": "Save failed: {err}",
  "common.delFail": "Delete failed: {err}",
  "common.clearFail": "Clear failed: {err}",
  "common.setFail": "Setting failed: {err}",
  "common.saving": "Saving…",
  "common.starting": "Starting…",

  // ---- server blocks ----
  "host.idleTitle": "No tunnels running",
  "host.noTunnels": "No tunnels",
  "host.running": "{r}/{t} running",
  "host.noTunnelsTitle": "No tunnels yet",
  "host.runningTitle": "{r} running / {t} total",
  "host.startAll": "Start all",
  "host.stopAll": "Stop all",
  "host.startAllTitle": "Start all enabled tunnels of this server (password asked once, then remembered)",
  "host.stopAllTitle": "Stop all tunnels of this server",
  "host.edit": "Edit server",
  "host.editAria": "Edit server {name}",
  "host.del": "Delete server",
  "host.delAria": "Delete server {name}",
  "host.aria": "Server {name}",
  "host.newBtn": "New",

  // ---- command builder (dynamic parts) ----
  "cg.hintL": "Run this command on A: A opens port {bind}:{listen}; traffic to it travels over SSH to B, which then connects to {thost}:{tport}",
  "cg.hintR": "Run this command on A, but the port opens on B ({bind}:{listen}); traffic to that port on B comes back over SSH to A, which connects to {thost}:{tport}",
  "cg.hintD": "Run this command on A: A gains a SOCKS5 proxy (127.0.0.1:{listen}); point apps at it and traffic exits from B",
  "cg.hintGateway": ". Note: for other machines on B's network to connect, B's sshd needs GatewayPorts yes — by default only B itself can",
  "cg.hintKeyFile": ". This profile normally logs in with a key — but the command runs on A, so A needs the private key too (add -i ~/.ssh/id_ed25519)",
  "cg.bAddr": "B's address",
  "cg.flowA": "A · runs the command",
  "cg.flowB": "B · target server",
  "cg.flowAOpen": "opens port :{p} on A",
  "cg.flowBOpen": "{addr} · opens port :{p}",
  "cg.flowARun": "the command runs on this machine",
  "cg.flowSocks": "SOCKS5 proxy :{p}",
  "cg.arrowB": "B connects",
  "cg.arrowA": "A connects",
  "cg.fromB": "this address is reached from B",
  "cg.fromA": "this address is reached from A",
  "cg.anyAddr": "any address",
  "cg.anyFromB": "reached from B",
  "cg.loadPh": "Load a saved command…",
  "cg.nonePh": "No saved commands yet",
  "cg.manual": "Manual input",
  "cg.suggestD": "proxy via {host} :{listen}",
  "cg.suggestLR": "{host} → {thost}:{tport}",
  "cg.saveTitle": "Save command",
  "cg.saveBody": "Name this set of parameters to load it from \"My commands\" next time.",
  "cg.nameEmpty": "Command name cannot be empty",
  "cg.saved": "Command saved",
  "cg.pickFirst": "Select a command in the dropdown first",
  "cg.delTitle": "Delete command",
  "cg.delBody": "Delete \"{name}\"?",
  "cg.deleted": "Deleted",
  "cg.copied": "Command copied",

  // ---- profiles / server detail ----
  "pf.delTitle": "Delete server \"{name}\"?",
  "pf.delBody": "{n} tunnels belong to this server ({names}); they will no longer start after deletion.",
  "detail.noTunnels": "No tunnels yet — hit \"＋ New tunnel\" above to start from a scenario",
  "pd.genTitle": "Generate tunnel commands for this server (Command Builder)",
  "pd.gen": "Build command",
  "pd.batchPwPh": "SSH password ({user}@{host}, starting {n} tunnels)",
  "pd.batchConnect": "Connect {n} tunnels",

  // ---- credentials card ----
  "sec.noneKey": "Password: the key passphrase is remembered after one entry (stored encrypted); unencrypted keys need nothing",
  "sec.none": "Password: remembered automatically after the first start (AES-256-GCM encrypted locally)",
  "sec.headKey": "Passphrase remembered",
  "sec.head": "Password remembered",
  "sec.note": "Encrypted on this machine (secrets.enc) · no re-entry on restart or autostart",
  "sec.clearTitleKey": "Clear the remembered passphrase for {name}?",
  "sec.clearTitle": "Clear the remembered password for {name}?",
  "sec.clearBody": "It will be asked again on the next start; nothing on the server is affected.",
  "sec.cleared": "Remembered password cleared",

  // ---- fingerprint ----
  "fp.none": "Fingerprint: remembered on first connect (TOFU); any change refuses the connection",
  "fp.head": "Server fingerprint remembered",
  "fp.copyTitle": "Copy fingerprint",
  "fp.copied": "Fingerprint copied",
  "fp.clearTitle": "Clear the fingerprint record for {host}:{port}?",
  "fp.clearBody": "The current fingerprint will be remembered again on next connect (only do this if the server really changed).",
  "fp.loadFail": "Failed to read fingerprint info: {err}",
  "fp.toast": "Server fingerprint remembered (first connection)",
  "fp.clickCopy": "Click to copy the fingerprint",
  "fp.trustTitle": "Trust the new fingerprint and reconnect?",
  "fp.trustBody":
    "This clears the old fingerprint record for {host}:{port}; the current one is remembered again after reconnecting.\nContinue only if the server was really reinstalled/replaced — otherwise this could be a man-in-the-middle attack.",
  "fp.trustConfirm": "Trust & reconnect",
  "fp.forgotLog": "Fingerprint record for {host}:{port} cleared; the current fingerprint will be remembered on reconnect",

  // ---- forms / validation ----
  "sf.titleEdit": "Edit server",
  "sf.needFields": "Please fill in name, address and username",
  "sp.needProfile": "Select a server first",
  "sp.titleWith": "New tunnel — {name}",
  "sp.defaultName": "New tunnel",
  "sc.saveTitle": "Save as my scenario",
  "sc.saveBody": "Save the current tunnel's type and parameters for reuse when creating tunnels.",
  "sc.namePh": "Scenario name",
  "sc.delThis": "Delete this scenario",
  "sc.delTitle": "Delete scenario \"{name}\"?",
  "sc.fromHint": "From my scenario \"{name}\"",
  "sc.saved": "Scenario \"{name}\" saved",
  "sc.saveFailLog": "❌ Failed to save scenario: {err}",
  "tun.delTitle": "Delete tunnel \"{name}\"?",
  "tun.delBody": "Running tunnels are stopped first.",
  "tf.titleWith": "New tunnel — {title}",
  "tf.passphraseLabel": "Key passphrase (empty for unencrypted keys)",
  "wz.hintVpn": "Server reaches the internet via your local VPN: use socks5h://127.0.0.1:<port> on the server",
  "wz.hintExpose": "Server accesses a service running on your machine (e.g. a local dev web server)",
  "wz.hintReach": "Your machine reaches a service on the server side (e.g. a database/web on the server)",
  "wz.hintLan": "Point apps/browser at the SOCKS5 proxy to reach any host on the server's intranet",
  "wz.hintCustom": "Pick the type and parameters; reverse tunnel server port 0 = dynamic (filled in after connect)",
  "wz.rPort": "Server listen port (0 = dynamic)",
  "wz.rPortHint": "0 lets the server assign the actual port; it shows in the summary after connecting",
  "wz.fallback": "Local VPN SOCKS port (built-in if detection fails)",
  "wz.tcpHost": "Local service address",
  "wz.tcpPort": "Local service port",
  "wz.lPort": "Local listen port",
  "wz.tHost": "Target host (as seen by the server)",
  "wz.tPort": "Target port",
  "wz.dPort": "Local SOCKS5 port",
  "wz.probeLabel": "Detect local VPN port",
  "wz.probe": "Detect & fill",
  "wz.probing": "Detecting…",
  "wz.probed": "Filled in {port}",
  "wz.probeNoSocks": "Ports found but not SOCKS5: {ports}",
  "wz.probeNone": "None found (VPN off? the built-in SOCKS will be used)",
  "wz.probeFail": "Detection failed: {err}",
  "err.name": "Please fill in a name",
  "err.needPassword": "Password required to start",
  "err.rPort": "Invalid server listen port",
  "err.fallback": "Invalid SOCKS port",
  "err.tcpHost": "Local service address cannot be empty",
  "err.tcpPort": "Invalid local service port",
  "err.lPort": "Invalid local listen port",
  "err.tHost": "Target host cannot be empty",
  "err.tPort": "Invalid target port",
  "err.dPort": "Invalid local SOCKS5 port",

  // ---- settings dynamic feedback ----
  "set.defaultsSaved": "Defaults saved",

  // ---- preset localization (backend sends zh; frontend overrides by id) ----
  "preset.vpn_share.name": "Server uses VPN",
  "preset.vpn_share.desc": "Reverse tunnel + SOCKS: server reaches the internet via your local VPN",
  "preset.expose_local.name": "Expose local service",
  "preset.expose_local.desc": "Reverse tunnel + fixed address: the server accesses a service on your machine",
  "preset.reach_service.name": "Reach server-side service",
  "preset.reach_service.desc": "Local forward: local port → target on the server (e.g. its database)",
  "preset.reach_lan.name": "Reach server intranet",
  "preset.reach_lan.desc": "Dynamic tunnel: local SOCKS5, the server relays any intranet address",
  "preset.custom.name": "Custom",
  "preset.custom.desc": "Blank slate: pick the tunnel type (reverse/local/dynamic) and landing backend",
};

const dict: Record<Lang, { [K in I18nKey]: string }> = { zh, en };

let lang: Lang = "zh";

/** 读偏好 (无值/坏值回退 zh)。模块加载即初始化, 供 t() 在任何渲染前可用。 */
function loadPref(): Lang {
  try {
    const v = localStorage.getItem("pt-lang");
    return v === "en" ? "en" : "zh";
  } catch {
    return "zh";
  }
}
lang = loadPref();

export function getLang(): Lang {
  return lang;
}

/** key 是否存在于词典 (动态拼 key 时的存在性检查, 如 preset.{id}.name) */
export function hasKey(k: string): k is I18nKey {
  return k in zh;
}

/** 查词条; {var} 插值。key 不存在由 tsc 保证 (I18nKey 类型)。 */
export function t(key: I18nKey, vars?: Record<string, string | number>): string {
  let s = dict[lang][key] ?? dict.zh[key];
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      // split/join 代替 replaceAll (tsconfig lib < es2021)
      s = s.split(`{${k}}`).join(String(v));
    }
  }
  return s;
}

const listeners = new Set<() => void>();

/** 语言变化订阅 (main.ts 注册重渲染入口), 返回退订函数 */
export function onLangChange(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function setLang(l: Lang): void {
  if (l === lang) return;
  lang = l;
  try {
    localStorage.setItem("pt-lang", l);
  } catch {
    /* 隐私模式等: 仅会话内生效 */
  }
  document.documentElement.lang = l === "zh" ? "zh-CN" : "en";
  applyI18nStatic();
  for (const cb of listeners) cb();
}

/** 把 [data-i18n] / [data-i18n-ph] / [data-i18n-title] 应用到静态 DOM。
 *  innerHTML: 词典值含受控标记 (<b>/<strong>...), 词典非用户输入。 */
export function applyI18nStatic(root: ParentNode = document): void {
  document.title = t("app.title");
  document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
  root.querySelectorAll<HTMLElement>("[data-i18n]").forEach((n) => {
    n.innerHTML = t(n.dataset.i18n as I18nKey);
  });
  root.querySelectorAll<HTMLInputElement>("[data-i18n-ph]").forEach((n) => {
    n.placeholder = t(n.dataset.i18nPh as I18nKey);
  });
  root.querySelectorAll<HTMLElement>("[data-i18n-title]").forEach((n) => {
    n.title = t(n.dataset.i18nTitle as I18nKey);
  });
  root.querySelectorAll<HTMLElement>("[data-i18n-aria]").forEach((n) => {
    n.setAttribute("aria-label", t(n.dataset.i18nAria as I18nKey));
  });
}
