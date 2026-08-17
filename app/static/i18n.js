"use strict";
// Lightweight i18n for SAST Studio. No framework: a dictionary + a t() helper,
// plus data-i18n attributes for static markup. Default language is 中文.

const DICT = {
  zh: {
    "tagline": "一頁搞定六個免費資安掃描器。",
    "lang.toggle": "EN",

    "sec.newScan": "新增掃描",
    "sec.tools": "工具",
    "sec.results": "結果",

    "tab.upload": "上傳 zip",
    "tab.git": "Git 網址",
    "tab.path": "本機路徑",

    "field.upload": "原始碼壓縮檔（.zip）",
    "field.git": "儲存庫網址（http/https）",
    "field.path": "伺服器本機目錄路徑",
    "ph.filter": "依檔名篩選…",
    "pathNote": "本機路徑掃描已被設定停用。",

    "btn.inspect": "檢查專案",
    "btn.selectAll": "全選可用工具",
    "btn.start": "開始掃描",
    "btn.run": "執行掃描",
    "btn.cancel": "取消",

    "filter.allSev": "全部嚴重度",
    "filter.allTools": "全部工具",

    "needs": "需要：",
    "notInstalled": "（未安裝）",

    // job status pills
    "status.queued": "排隊中",
    "status.running": "執行中",
    "status.awaiting_confirmation": "等待確認",
    "status.done": "完成",
    "status.error": "錯誤",
    "status.cancelled": "已取消",

    // tool phases / final statuses
    "phase.queued": "排隊中",
    "phase.running": "執行中",
    "tstat.unavailable": "未安裝",
    "tstat.not_applicable": "不適用",
    "tstat.ok": "完成",
    "tstat.notApplicableFallback": "此工具在這個專案沒有可掃描的內容",
    "findings.count": "{n} 個發現",

    // severities
    "sev.critical": "嚴重", "sev.high": "高", "sev.medium": "中",
    "sev.low": "低", "sev.info": "資訊", "sev.unknown": "未知",
    "stat.total": "總計",

    // progress
    "progress.preparing": "準備中…",
    "progress.scanning": "掃描中… {n} 個執行中",
    "progress.count": "{f}/{t} 個工具 · {p}%",
    "progress.complete": "掃描完成",

    // confirmation step
    "confirm.title": "來源已就緒 — 掃描前請確認",
    "confirm.wontApply": "以下已選工具在此專案不會有結果：",
    "confirm.run": "執行掃描",
    "confirm.cancel": "取消",

    // inspect panel
    "inspect.inspecting": "檢查中 {path} …",
    "inspect.failed": "無法檢查：{msg}",
    "inspect.wontApply": "以下工具不適用此專案：",
    "toolwarn.title": "⚠ 已選但不適用此專案的工具：",

    // meta
    "meta.files": "· {n} 個檔案{langs}",
    "files.unit": "{n} 個檔案",

    // findings list
    "findings.emptyFiltered": "沒有符合目前篩選的結果。",
    "findings.scanning": "掃描中…工具完成後會顯示結果。",
    "chip.available": "可用",

    // tool descriptions (what each tool does)
    "tool.semgrep.desc": "基於規則的靜態程式碼分析（30+ 語言）",
    "tool.bearer.desc": "語意／資料流 SAST，找安全與隱私風險",
    "tool.trivy.desc": "相依弱點 ＋ 密鑰 ＋ IaC 設定錯誤",
    "tool.npm_audit.desc": "Node 相依套件弱點（npm 資料庫）",
    "tool.osv_scanner.desc": "多生態系相依套件弱點（OSV.dev）",
    "tool.gitleaks.desc": "掃描硬編碼的密鑰／憑證",

    // tool requirements (localized; overrides backend English)
    "tool.semgrep.req": "原始碼（30+ 語言）",
    "tool.bearer.req": "Ruby/JS/TS/Java/PHP/Python/Go 原始碼",
    "tool.trivy.req": "任何專案（相依／密鑰／IaC）",
    "tool.npm_audit.req": "package.json（Node/npm 專案）",
    "tool.osv_scanner.req": "相依鎖定檔（npm、pip、go、cargo…）",
    "tool.gitleaks.req": "任何檔案（密鑰掃描）",

    // localized inapplicability reasons (keyed by tool)
    "reason.bearer": "找不到支援的原始碼（Bearer 分析 Ruby/JS/TS/Java/PHP/Python/Go）",
    "reason.npm_audit": "找不到 package.json（非 Node/npm 專案）",
    "reason.osv_scanner": "找不到支援的相依鎖定檔（package-lock.json、requirements.txt、go.mod…）",

    // severity meaning (shown as a small note on findings)
    "sevnote.critical": "嚴重：應立即修補",
    "sevnote.high": "高：儘快修補",
    "sevnote.medium": "中：排入修補",
    "sevnote.low": "低：可評估後處理",
    "sevnote.info": "資訊：參考用",
    "sevnote.unknown": "未知：需人工判斷",

    "err.noTool": "請至少選一個可用的工具。",
    "err.noZip": "請選擇要掃描的 .zip 檔。",
    "err.noUrl": "請輸入儲存庫網址。",
    "err.noPath": "請輸入伺服器本機路徑。",
    "err.allInapplicable": "所選工具都不適用此專案（{tools}）。請改選符合其語言／鎖定檔的工具。",

    "nav.scan": "掃描",
    "nav.monitor": "監控",
    "mon.tools": "掃描工具版本",
    "mon.containers": "Docker 容器效能",
    "mon.refresh": "重新整理",
    "mon.installed": "已安裝",
    "mon.updateHint": "提示：工具的弱點資料庫（Trivy／OSV／npm）會在掃描時自動更新；工具本身可用 ./setup.sh --update 更新。",
    "mon.dockerOff": "Docker 監控未啟用。",
    "mon.enableHint": "要啟用：設定 SAST_ENABLE_DOCKER_STATS=true 並把 docker.sock 掛進容器（見 docker-compose.yml 的註解）。注意：掛載 docker socket 屬高權限，僅在信任的環境開啟。",
    "mon.dockerErr": "無法讀取 Docker：{msg}",
    "mon.noContainers": "沒有容器。",
    "col.name": "容器", "col.image": "映像", "col.state": "狀態",
    "col.cpu": "CPU", "col.mem": "記憶體", "col.net": "網路 RX/TX",
  },

  en: {
    "tagline": "One page, six free security scanners.",
    "lang.toggle": "中",

    "sec.newScan": "New scan",
    "sec.tools": "Tools",
    "sec.results": "Results",

    "tab.upload": "Upload zip",
    "tab.git": "Git URL",
    "tab.path": "Local path",

    "field.upload": "Source archive (.zip)",
    "field.git": "Repository URL (http/https)",
    "field.path": "Server-local directory path",
    "ph.filter": "filter by file…",
    "pathNote": "Local path scanning is disabled by config.",

    "btn.inspect": "inspect project",
    "btn.selectAll": "select all available",
    "btn.start": "Start scan",
    "btn.run": "Run scan",
    "btn.cancel": "Cancel",

    "filter.allSev": "All severities",
    "filter.allTools": "All tools",

    "needs": "needs: ",
    "notInstalled": " (not installed)",

    "status.queued": "queued",
    "status.running": "running",
    "status.awaiting_confirmation": "awaiting confirmation",
    "status.done": "done",
    "status.error": "error",
    "status.cancelled": "cancelled",

    "phase.queued": "queued",
    "phase.running": "running",
    "tstat.unavailable": "unavailable",
    "tstat.not_applicable": "not applicable",
    "tstat.ok": "ok",
    "tstat.notApplicableFallback": "nothing to scan for this tool",
    "findings.count": "{n} findings",

    "sev.critical": "critical", "sev.high": "high", "sev.medium": "medium",
    "sev.low": "low", "sev.info": "info", "sev.unknown": "unknown",
    "stat.total": "total",

    "progress.preparing": "Preparing…",
    "progress.scanning": "Scanning… {n} running",
    "progress.count": "{f}/{t} tools · {p}%",
    "progress.complete": "Scan complete",

    "confirm.title": "Source ready — review before scanning",
    "confirm.wontApply": "These selected tools won’t find anything here:",
    "confirm.run": "Run scan",
    "confirm.cancel": "Cancel",

    "inspect.inspecting": "Inspecting {path} …",
    "inspect.failed": "Could not inspect: {msg}",
    "inspect.wontApply": "Won’t apply to this project:",
    "toolwarn.title": "⚠ Selected tools that won’t find anything here:",

    "meta.files": "· {n} files{langs}",
    "files.unit": "{n} files",

    "findings.emptyFiltered": "No findings match the current filters.",
    "findings.scanning": "Scanning… findings will appear as tools finish.",
    "chip.available": "available",

    "tool.semgrep.desc": "Pattern-based static analysis (30+ languages)",
    "tool.bearer.desc": "Semantic/dataflow SAST for security & privacy",
    "tool.trivy.desc": "Dependency vulns + secrets + IaC misconfig",
    "tool.npm_audit.desc": "Node dependency advisories (npm database)",
    "tool.osv_scanner.desc": "Multi-ecosystem dependency vulns (OSV.dev)",
    "tool.gitleaks.desc": "Detects hardcoded secrets / credentials",

    "tool.semgrep.req": "source code (30+ languages)",
    "tool.bearer.req": "Ruby/JS/TS/Java/PHP/Python/Go source",
    "tool.trivy.req": "any project (deps, secrets, IaC)",
    "tool.npm_audit.req": "package.json (Node/npm project)",
    "tool.osv_scanner.req": "a dependency lockfile (npm, pip, go, cargo…)",
    "tool.gitleaks.req": "any files (secret scan)",

    "reason.bearer": "no supported source files (Bearer analyses Ruby/JS/TS/Java/PHP/Python/Go)",
    "reason.npm_audit": "no package.json found — not a Node/npm project",
    "reason.osv_scanner": "no supported lockfile found (package-lock.json, requirements.txt, go.mod…)",

    "sevnote.critical": "Critical: fix immediately",
    "sevnote.high": "High: fix soon",
    "sevnote.medium": "Medium: schedule a fix",
    "sevnote.low": "Low: address when convenient",
    "sevnote.info": "Info: for reference",
    "sevnote.unknown": "Unknown: needs manual review",

    "err.noTool": "Pick at least one available tool.",
    "err.noZip": "Choose a .zip archive to scan.",
    "err.noUrl": "Enter a repository URL.",
    "err.noPath": "Enter a server-local path.",
    "err.allInapplicable": "None of the selected tools apply to this project ({tools}). Pick tools that match its languages/lockfiles.",

    "nav.scan": "Scan",
    "nav.monitor": "Monitor",
    "mon.tools": "Scanner versions",
    "mon.containers": "Docker container performance",
    "mon.refresh": "refresh",
    "mon.installed": "installed",
    "mon.updateHint": "Note: tool vulnerability databases (Trivy/OSV/npm) refresh automatically at scan time; update the tool binaries with ./setup.sh --update.",
    "mon.dockerOff": "Docker monitoring is not enabled.",
    "mon.enableHint": "To enable: set SAST_ENABLE_DOCKER_STATS=true and mount docker.sock into the container (see the comments in docker-compose.yml). Note: mounting the docker socket is a privileged capability — only on a trusted deployment.",
    "mon.dockerErr": "Cannot read Docker: {msg}",
    "mon.noContainers": "No containers.",
    "col.name": "Container", "col.image": "Image", "col.state": "State",
    "col.cpu": "CPU", "col.mem": "Memory", "col.net": "Net RX/TX",
  },
};

let lang = localStorage.getItem("sast_lang") || "zh";

function t(key, params) {
  let s = (DICT[lang] && DICT[lang][key]);
  if (s == null) s = DICT.en[key];
  if (s == null) return key;
  if (!params) return s;
  return s.replace(/\{(\w+)\}/g, (_, k) => (params[k] != null ? params[k] : ""));
}

function getLang() { return lang; }

function setLang(l) {
  lang = l;
  localStorage.setItem("sast_lang", l);
  document.documentElement.lang = (l === "zh" ? "zh-Hant" : "en");
  applyStaticI18n();
  const tog = document.getElementById("lang-toggle");
  if (tog) tog.textContent = t("lang.toggle");
  if (window.onLangChange) window.onLangChange();
}

function applyStaticI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPh);
  });
}

window.t = t;
window.getLang = getLang;
window.setLang = setLang;
window.applyStaticI18n = applyStaticI18n;
