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
    "status.policy_review": "需人工審查",
    "status.blocked": "政策阻擋",
    "status.error": "錯誤",
    "status.cancelled": "已取消",

    // scan policy (掃描政策)
    "verdict.rule": "判定規則（固定）：任一工具發現「高」以上風險或外洩密鑰 → 不可上線；「中」風險 → 需人員審查；僅「低」或無發現 → 通過。判定是這次掃描的結論標記，不會中止掃描或阻擋部署。",
    "policy.gate": "判定：{decision}",
    "policy.decision.passed": "通過",
    "policy.decision.manual_review": "需人工審查",
    "policy.decision.blocked": "阻擋",

    // 說明政策的作用範圍（使用者最常誤解的一點）

    // 每條規則的情境式說明：發生什麼 → 判定為什麼
    "policy.blocking.title": "阻擋中的發現",

    // policy template names / descriptions (keyed by backend template id)

    // tool phases / final statuses
    "phase.queued": "排隊中",
    "phase.running": "執行中",
    "tstat.unavailable": "未安裝",
    "tstat.not_applicable": "不適用",
    "tstat.ok": "完成",
    "tstat.notApplicableFallback": "此工具在這個專案沒有可掃描的內容",
    "findings.count": "{n} 個發現",

    // finding detail: where the problem is
    "admin.outcome.upgraded": "已安裝新版本",
    "admin.outcome.data_updated": "資料庫已更新（下次掃描自動生效，不需重啟）",
    "admin.outcome.already_current": "已是最新版本",
    "admin.outcome.unknown": "已執行",
    "admin.outcome.failed": "失敗",
    "admin.needRestart": "有套件更新了版本 —— 請按「重啟服務」讓新版本生效。",
    "findings.showMore": "顯示更多（已顯示 {shown} / 共 {total} 筆）",
    "ruleset.why.default": "通用預設，涵蓋面最廣",
    "ruleset.why.owasp-top-ten": "對照 OWASP Top 10",
    "ruleset.why.security-audit": "較嚴格的稽核規則，誤報較多",
    "ruleset.why.python": "Python 專用",
    "ruleset.why.javascript": "JavaScript / TypeScript 專用",
    "ruleset.why.java": "Java 專用",
    "ruleset.why.golang": "Go 專用",
    "ruleset.why.secrets": "硬編碼密鑰樣式",
    "stage.probing": "檢查工具版本…",
    "stage.checking": "判斷是否適用…",
    "stage.rules": "取得並編譯規則集…",
    "stage.vulndb": "更新弱點資料庫…",
    "stage.advisories": "查詢漏洞情資…",
    "stage.secrets": "比對密鑰樣式…",
    "stage.dataflow": "分析資料流…",
    "stage.scanning": "掃描中…",
    "triage.hint": "掃描器回報的是「樣式」，它判斷不了在你的情境下是否真的有問題。先看卡片上的程式碼再判斷；標記會印進 PDF。",
    "triage.unset": "未判定",
    "triage.real": "確認為問題",
    "triage.falsePositive": "誤報",
    "triage.accepted": "已知並接受",
    "triage.marked.real": "已確認為問題",
    "triage.marked.false_positive": "已標記為誤報",
    "triage.marked.accepted": "已知風險，接受",
    "rules.title": "自訂規則",
    "rules.hint": "用 Semgrep（YAML）或 Trivy（Rego）寫自己的檢查規則。先從內建範本改起最快；儲存前會實際請掃描器檢查規則能不能編譯。",
    "rules.new": "新增規則",
    "rules.pick": "編輯中",
    "rules.name": "名稱",
    "rules.builtin": "內建範本",
    "rules.readonly": "這是內建範本，不能覆蓋。改好後填一個名稱另存為你自己的規則。",
    "rules.validate": "檢查規則",
    "rules.save": "儲存",
    "rules.delete": "刪除",
    "rules.enable": "這次掃描要套用哪些規則（可複選，全部聯集一起跑）",
    "rules.group.published": "公開規則集（Semgrep 官方）",
    "rules.group.own": "你自己的規則",
    "rules.none": "還沒有任何規則",
    "rules.ok": "規則可用",
    "rules.bad": "規則無法使用",
    "rules.saved": "已儲存：{name}",
    "rules.needName": "請先填規則名稱（小寫英數、dash 或底線）",
    "rules.confirmDelete": "確定要刪除規則「{name}」嗎？",
    "admin.title": "維護動作",
    "admin.warn": "這些動作會直接在伺服器上執行，且沒有登入保護——任何能開啟本頁的人都能按。請只在信任的內網使用。",
    "admin.update": "更新掃描工具",
    "admin.restart": "重啟服務",
    "admin.running": "執行中（{kind}）…",
    "admin.done": "已完成",
    "admin.failed": "執行失敗",
    "admin.restarting": "服務重啟中，請稍候…",
    "admin.restartSlow": "服務尚未回應，請手動重新整理確認",
    "admin.canUpdate": "可直接更新：{list}。",
    "admin.pinned": "需重建映像才能換版：{list}。",
    "admin.confirmUpdate": "確定要更新掃描工具嗎？需要下載套件，可能耗時數分鐘。",
    "admin.confirmRestart": "確定要重啟服務嗎？記憶體中的掃描紀錄會清空。",
    "find.why": "問題原因",
    "find.howToFix": "改善方式",
    "find.location": "位置",
    "find.notProvided": "（此工具未提供）",
    "find.untitled": "未命名發現",
    "find.upgradeTo": "升級至 {v} 以上版本",
    "find.fixAvailable": "有修補版本可用，執行套件管理器的升級指令即可（例如 npm audit fix）",
    "find.noFixYet": "上游尚未釋出修補版本，需改用替代套件或加上緩解措施",
    "find.installed": "已安裝 {v}",
    "find.vulnRange": "受影響版本 {r}",
    "find.fixedIn": "修補版本 {v}",
    "find.noFix": "尚無修補版本",
    "find.fix": "建議處置：{r}",

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
    "nav.report": "報告",
    "nav.monitor": "監控",
    "sec.reports": "掃描報告",
    "report.empty": "還沒有任何掃描報告。到「掃描」分頁開始第一次掃描。",
    "export.csv": "匯出 CSV",
    "export.pdf": "匯出 PDF",
    "sevbar.label": "嚴重度分佈，共 {n} 個發現",
    "sevbar.total": "共 {n} 個",

    // Docker 效能額度判讀
    "cap.ok": "資源充足",
    "cap.warn": "需留意",
    "cap.tight": "資源吃緊",
    "cap.idle": "未執行",
    "cap.mem_unlimited": "未設定記憶體上限——掃描吃滿時會排擠主機其他服務，建議在 compose 設 mem_limit。",
    "cap.mem_warn": "記憶體已用超過 75%，大型專案掃描時可能不足。",
    "cap.mem_tight": "記憶體已用超過 90%，掃描大型專案很可能被 OOM 中斷。",
    "cap.oom_killed": "曾發生記憶體配置失敗（OOM），請調高 mem_limit。",
    "cap.cpu_throttled": "CPU 曾被配額限流，掃描會變慢，可調高 cpus 設定。",
    "cap.cpu_busy": "CPU 接近滿載。掃描期間屬正常現象，持續滿載才需加核心。",
    "cap.hint": "判讀方式：記憶體看「離上限多近」（會被 OOM 中斷），CPU 看「是否被限流」（只會變慢）。掃描時再看一次這頁最準。",
    "col.capacity": "資源評估",
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
    "status.policy_review": "policy review required",
    "status.blocked": "blocked by policy",
    "status.error": "error",
    "status.cancelled": "cancelled",

    "verdict.rule": "Fixed rule: a High or Critical finding from any tool, or a leaked secret, means this must not go live. A Medium finding needs a reviewer. Low findings, or none, pass. The verdict labels this scan; it does not stop a build or a deployment.",
    "policy.gate": "Gate: {decision}",
    "policy.decision.passed": "passed",
    "policy.decision.manual_review": "manual review",
    "policy.decision.blocked": "blocked",


    "policy.blocking.title": "Findings that block release",
    "policy.blocking.note": "Fix these and scan again. There is no override on this page.",


    "phase.queued": "queued",
    "phase.running": "running",
    "tstat.unavailable": "unavailable",
    "tstat.not_applicable": "not applicable",
    "tstat.ok": "ok",
    "tstat.notApplicableFallback": "nothing to scan for this tool",
    "findings.count": "{n} findings",

    "admin.outcome.upgraded": "new version installed",
    "admin.outcome.data_updated": "database updated (applies to the next scan; no restart needed)",
    "admin.outcome.already_current": "already up to date",
    "admin.outcome.unknown": "ran",
    "admin.outcome.failed": "failed",
    "admin.needRestart": "A package changed version — press Restart service for it to take effect.",
    "findings.showMore": "Show more ({shown} of {total} shown)",
    "ruleset.why.default": "general default, widest coverage",
    "ruleset.why.owasp-top-ten": "mapped to OWASP Top 10",
    "ruleset.why.security-audit": "stricter audit rules, more false positives",
    "ruleset.why.python": "Python only",
    "ruleset.why.javascript": "JavaScript / TypeScript only",
    "ruleset.why.java": "Java only",
    "ruleset.why.golang": "Go only",
    "ruleset.why.secrets": "hard-coded secret patterns",
    "stage.probing": "checking the tool version…",
    "stage.checking": "deciding whether it applies…",
    "stage.rules": "fetching and compiling rulesets…",
    "stage.vulndb": "updating the vulnerability database…",
    "stage.advisories": "querying advisories…",
    "stage.secrets": "matching secret patterns…",
    "stage.dataflow": "analysing data flow…",
    "stage.scanning": "scanning…",
    "triage.hint": "A scanner reports a pattern; whether it matters here is your call. Read the code on the card before deciding — your mark prints into the PDF.",
    "triage.unset": "not judged",
    "triage.real": "real issue",
    "triage.falsePositive": "false positive",
    "triage.accepted": "accepted risk",
    "triage.marked.real": "confirmed as a real issue",
    "triage.marked.false_positive": "marked as a false positive",
    "triage.marked.accepted": "known and accepted",
    "rules.title": "Custom rules",
    "rules.hint": "Write your own checks in Semgrep (YAML) or Trivy (Rego). Starting from a built-in template is quickest; saving runs the rule past the scanner first to check it compiles.",
    "rules.new": "New rule",
    "rules.pick": "Editing",
    "rules.name": "Name",
    "rules.builtin": "built-in",
    "rules.readonly": "This is a built-in template and cannot be overwritten. Edit it, give it a name, and save it as your own.",
    "rules.validate": "Check rule",
    "rules.save": "Save",
    "rules.delete": "Delete",
    "rules.enable": "Which rules this scan runs (pick any; they all apply together)",
    "rules.group.published": "Published rulesets (Semgrep)",
    "rules.group.own": "Your own rules",
    "rules.none": "No rules yet",
    "rules.ok": "Rule is usable",
    "rules.bad": "Rule cannot be used",
    "rules.saved": "Saved: {name}",
    "rules.needName": "Give the rule a name first (lower-case letters, digits, dash or underscore)",
    "rules.confirmDelete": "Delete the rule “{name}”?",
    "admin.title": "Maintenance",
    "admin.warn": "These run commands on the server and are not behind a login — anyone who can open this page can use them. Keep this deployment on a trusted network.",
    "admin.update": "Update scanners",
    "admin.restart": "Restart service",
    "admin.running": "running ({kind})…",
    "admin.done": "finished",
    "admin.failed": "failed",
    "admin.restarting": "Restarting, please wait…",
    "admin.restartSlow": "No response yet — refresh to check",
    "admin.canUpdate": "Updatable here: {list}.",
    "admin.pinned": "Needs an image rebuild: {list}.",
    "admin.confirmUpdate": "Update the scanners? This downloads packages and can take several minutes.",
    "admin.confirmRestart": "Restart the service? Scan history is kept in memory and will be cleared.",
    "find.why": "Why this is a problem",
    "find.howToFix": "How to fix it",
    "find.location": "Location",
    "find.notProvided": "(not reported by this tool)",
    "find.untitled": "untitled finding",
    "find.upgradeTo": "Upgrade to {v} or later",
    "find.fixAvailable": "A fixed version exists; run your package manager's upgrade (e.g. npm audit fix)",
    "find.noFixYet": "No upstream fix yet; replace the package or add a mitigation",
    "find.installed": "installed {v}",
    "find.vulnRange": "affected {r}",
    "find.fixedIn": "fixed in {v}",
    "find.noFix": "no fix available",
    "find.fix": "Resolution: {r}",

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
    "nav.report": "Reports",
    "nav.monitor": "Monitor",
    "sec.reports": "Scan reports",
    "report.empty": "No scans yet. Start one from the Scan tab.",
    "export.csv": "Export CSV",
    "export.pdf": "Export PDF",
    "sevbar.label": "Severity breakdown, {n} findings in total",
    "sevbar.total": "{n} total",

    "cap.ok": "Healthy",
    "cap.warn": "Watch",
    "cap.tight": "Short on resources",
    "cap.idle": "Not running",
    "cap.mem_unlimited": "No memory limit set — a heavy scan can starve everything else on the host. Set mem_limit in compose.",
    "cap.mem_warn": "Memory is over 75% of its limit; a large project may not fit.",
    "cap.mem_tight": "Memory is over 90% of its limit; a large scan will likely be OOM-killed.",
    "cap.oom_killed": "A memory allocation has already failed (OOM). Raise mem_limit.",
    "cap.cpu_throttled": "CPU has been throttled by its quota; scans run slower. Raise the cpus setting.",
    "cap.cpu_busy": "CPU is near full load. Normal during a scan; only sustained load needs more cores.",
    "cap.hint": "How to read this: memory matters because hitting the limit kills a scan; CPU throttling only makes it slower. Check this tab again while a scan is running.",
    "col.capacity": "Capacity",
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
