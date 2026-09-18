# lessons — SAST Studio

## [2026-09-18] 第 14 輪 — UI 改版：分頁重構、政策可理解化、報告匯出、資源評估

### 本輪紀錄
- **需求**：使用者看不懂政策範本（「Critical 一律阻擋」不知對應哪個工具、也不知阻擋什麼）；要求掃描與報告分頁、報告可匯出 CSV/PDF、報告頁左列右詳＋條狀圖；監控頁要能判斷 Docker 效能夠不夠。
- **關鍵發現（使用者的困惑指出兩個真實缺陷）**：
  1. **政策不對應任何單一工具**——它套用在六個工具**彙整後**的結果，任何工具回報 Critical 都算。UI 從未說明，使用者自然會問「這是哪個工具的規則」。
  2. **「阻擋」什麼都沒擋**——`BLOCKED` 只是判定標籤；政策評估時掃描早已跑完，且沒有任何下游消費它（無 exit code、無 CI 整合）。名不符實。
- **決議**：語意誠實化（判定 ≠ 攔截），不新增 CI exit code 端點以免擴張範圍；API 的 decision 值維持 `blocked` 不變，只改表達層，避免破壞既有用戶端與已存報告。
- **DevSecOps**：
  - `RULE_CATALOG` 重構為帶 `trigger`／`effect`／`sources`／`counter` 的中繼資料；前端據此渲染「當任一工具發現 X → 判定為 Y」＋「會產生這類發現的工具：…」＋「本次掃描：N 個」。
  - 三分頁；報告頁 master/detail；嚴重度分佈條狀圖（單一比例條 + 圖例）。
  - CSV 由標準庫 `csv` 產生（零新相依），**防試算表公式注入**：以 `=`／`+`／`-`／`@` 開頭的欄位加前置單引號（CWE-1236）——檔名與訊息來自被掃描的程式碼，屬不可信輸入。
  - PDF 走瀏覽器原生列印 + `@media print`（零新相依，不擴大 Docker 映像弱點面）。
  - `docker_stats` 新增 `_capacity()`：記憶體對照上限（逼近上限＝會被 OOM 中斷）、上限等於主機記憶體＝根本沒設限、OOM/限流實證優先於百分比、CPU 忙碌僅提示不算失敗。
  - 政策範本文案改為語言中立，中英在地化各自維護。
- **QA / 驗證**：37 測試全通過（+2：資源評估判讀矩陣、CSV 匯出含公式注入防護）。瀏覽器實測三分頁截圖、CSV 實際下載驗證標頭／BOM／內容、PDF 實際產出 163KB、i18n 中英字典完全對稱。
- **過關狀態**：G1–G5 維持；本輪為表達層改版，未動政策判定邏輯。

### 教訓 / 準則
- **情境**：使用者說「看不懂這個設定」。
  **準則**：先分辨是**文案不清**還是**概念本身有錯**。本輪兩者皆有——「對應哪個工具」是資訊缺漏（政策本來就跨工具），「阻擋什麼」則是**功能名稱承諾了產品做不到的事**。只改文案會把第二個問題蓋掉；要改的是概念與名稱。
- **情境**：想把名不符實的狀態值改名。
  **準則**：分開處理「API 契約」與「顯示文字」。API 的 `blocked` 維持不變（既有用戶端與已存報告仍可讀），只改 UI 措辭與說明，代價最小而使用者感受到的問題完全解決。
- **情境**：匯出 CSV 給人用 Excel 開。
  **準則**：CSV 是**程式碼執行面**。以 `=`／`+`／`-`／`@` 開頭的儲存格會被試算表當公式執行（CWE-1236），而安全工具的欄位（檔名、規則、訊息）正好來自不可信的被掃描程式碼——匯出前一律中和。
- **情境**：監控頁要回答「資源夠不夠」。
  **準則**：百分比本身回答不了這個問題。要分辨**哪一種資源不足會造成什麼後果**——記憶體碰上限會直接中斷掃描（致命），CPU 被限流只是變慢（可接受）；並優先採用 OOM／throttle 這類**既成事實**，而不是用百分比預測。

## [2026-09-18] 第 13 輪 — CI 驗證（G5）與映像掃描結果判讀

### 本輪紀錄
- **需求**：執行 CI 驗證。使用者選定「直接推 main」。
- **CI 執行**：
  - Run `35350129044`（commit 8734e66）：Tests ✅、Full security scan ✅，整體綠燈。
  - Run `35350605149`（commit 64fe7f5）：同上綠燈。
- **原始碼面全數乾淨**：semgrep 0、pip-audit 0、osv-scanner 0、trivy-fs 0、gitleaks 0、bearer 0、docker-build 0。唯一非零是 `trivy-image: 1`（映像層掃描）。
- **重要判讀**：workflow 刻意把掃描器失敗降級為 warning（不擋 build），所以**綠燈不等於掃描乾淨**，必須實際下載 artifact 判讀。本輪下載兩次 artifact 逐項確認。
- **映像 11 個 CRITICAL 的歸屬**：0 個在本專案程式碼或 Python 相依；全部落在 Debian base image 的 Node.js 套件（`fix=none`，上游尚無修補）與**內嵌掃描器二進位檔自身**（osv-scanner / gitleaks / trivy 的 Go stdlib 與依賴）。
- **一個真實但最終判定為誤報的追查**：Trivy 回報 Python 層 `setuptools 70.3.0`(HIGH) 與 `msgpack 1.1.2`(HIGH)。初判為「Dockerfile 先升級 setuptools，但之後裝 semgrep 又被降回」，遂加上「semgrep 之後重新升級」的修正並推 CI 驗證。結果版本數字**完全沒變**，逐層追查後才確認真相：這兩筆的 `FilePath = None`，與其他 16 個 pip 內嵌套件（CacheControl / distlib / resolvelib / truststore…）同屬 base image 的 SBOM 中繼資料，**不是映像檔案系統中的實體檔案**；磁碟上實際存在的是 `setuptools 84.0.0` 與 `msgpack 1.2.2`（皆有真實 FilePath）。
- **修正保留與否**：`64fe7f5` 的 Dockerfile 修改保留——它確實把 msgpack 由 1.1.2 升到 1.2.2（有實體路徑佐證），對 setuptools 則是無害的冪等操作（早已是 84.0.0）。
- **過關狀態**：G1–G4 ✅ 維持；**G5 ✅**（CI 綠燈 + 原始碼面零 Critical/High + 無硬編碼密鑰）。G6 ⏳ 未進行。

### 教訓 / 準則
- **情境**：CI 綠燈，但管線把掃描器失敗設成 warning。
  **準則**：綠燈只證明「管線沒爆」，不證明「掃描乾淨」。設計成非阻擋的 gate，**必須搭配人工判讀 artifact** 才算真的過 G5；否則等於自己把安全 gate 關掉還以為過了。
- **情境**：掃描器回報某套件版本過舊，但升級後版本數字完全沒變。
  **準則**：先確認那筆發現**有沒有實體檔案路徑**。`FilePath = None` 通常來自 base image 的 SBOM 中繼資料或工具內嵌清單，不代表檔案系統真的有那個版本。用「同一份報告裡同名套件的另一筆有無路徑」交叉比對，比反覆改 Dockerfile 快得多。
- **情境**：容器映像掃出上百個 Critical/High。
  **準則**：先分層歸屬再決定行動——base image OS 套件（受上游擺布、可能 fix=none）、內嵌第三方二進位（本專案刻意打包的掃描器）、自己的應用相依（唯一完全可控）。本專案第三類為零，前兩類只能隨上游更新，硬追會變成無止境的噪音。
- **情境**：想「先修再驗」時手邊沒有 Docker daemon。
  **準則**：無法本機重現的建置類修正，就誠實走 CI 驗證一輪，並且**驗證後要回頭確認數字真的變了**——不要推完看到綠燈就當作修好。本輪正是靠這一步才發現原判斷是錯的。

## [2026-09-18] 第 12 輪 — 掃描政策（Policy Gate）收尾

### 本輪紀錄
- **需求**：完整檢視專案，接續先前未完成的「UI 與掃描規則調整」。
- **恢復程序**：專案先前沒有 `talk.md`，改以 `CoreMain.md` + `待修改.md` + `lessons.md` + **git 工作區差異**重建狀態，並補建 `talk.md`。盤點發現一批**未提交**的政策引擎變更（`app/policies.py` + 三個後端檔 + 前端四檔 + 測試），即使用者所說的「先前調整」。
- **決策**：不重做、不擴張範圍，只收尾——修正缺陷、補齊一致性，再過 G2–G4。
- **DevSecOps（修正的缺陷）**：
  - **自訂政策被整個丟棄**（最嚴重）：`customize_policy()` 產生 `standard_custom`，但 `new_job()` 只收 id 又回頭 `get_policy()` 反查，對自訂 id 必然拋錯。前端每次掃描都送 `policy_rules`，等於**所有掃描都會 500**。改成 `new_job()` 直接收已解析的 `PolicyDefinition`（仍相容字串範本名）。
  - zh 字典漏掉 `status.policy_review` / `status.blocked` → 中文介面顯示原始鍵。
  - 政策 UI 硬寫「Scan policy / 掃描政策」雙語字串，繞過第 7 輪建立的 i18n 機制 → 全面改用 `t()` + `data-i18n`；範本名稱／說明在前端在地化，後端維持語言中立。
  - 例外端點 if/else 兩個分支產生**完全相同**的 dict（死碼）→ 移除。
  - 誤報例外**後端有端點、前端沒有任何入口** → 補上 blocked 狀態的例外表單。
  - 輪詢終止清單漏掉兩個新狀態 → `policy_review` / `blocked` 會**無限輪詢**。
  - 進度條在新狀態下整個隱藏，但工具其實已跑完 → 保持 100%。
- **QA / 驗證**：34 測試全通過（+2 檔案、+4 案例）。關鍵：新增的自訂規則測試**經反向驗證**——把修好的那行改回舊寫法，測試確實失敗（ValueError: unknown policy 'standard_custom'），確認測試真的攔得住這個 bug。另以真實 orchestrator 驗證三種判定（critical→blocked、high→policy_review、low→passed）、report_only 不阻擋、自訂政策貫穿；實跑伺服器驗證例外／審查端點的 404/400/409/422 防呆；i18n 以腳本驗證 zh/en 兩本字典**完全對稱**且所有動態鍵可解析。
- **安全自檢**：新程式無 `shell=True`／`eval`／`exec`／`subprocess`；前端所有 `innerHTML` 都只賦值空字串（清空），發現內容一律走 `textContent`／`createTextNode`，掃描器輸出無法注入標記。
- **未驗證項**：Windows 無 semgrep wheel（本專案部署目標為 Ubuntu/Docker），故未用真實掃描器產生 finding，改以真實 orchestrator + fake adapter 驗證政策判定；瀏覽器實截本輪未做（環境無 Playwright），改以 i18n 鍵覆蓋腳本驗證雙語完整性。
- **過關狀態**：G1 ✅ / G2 ✅ / G3 ✅ / G4 ✅ / G5 ⏳ / G6 ⏳

### 教訓 / 準則
- **情境**：接手「工作區裡有一批未提交變更」的專案。
  **準則**：恢復狀態時 `git diff` 與 `git status` 和 `待修改.md`、`lessons.md` 同等重要——未提交的變更就是「上一輪做到一半的地方」，先讀懂它再決定要不要動，不要重做也不要無視。
- **情境**：一個功能「測試全過」但其實主要路徑是壞的。
  **準則**：測試通過不等於功能正確——要問「**使用者實際會走的那條路徑**有沒有被測到」。本輪自訂政策的測試只測了錯誤範本名（400），從未送過 `policy_rules`，於是必然 500 的主路徑毫無覆蓋。補測試後**刻意把修正改回去確認測試會紅**，才算證明這個測試有價值。
- **情境**：新增狀態機狀態（`policy_review` / `blocked`）。
  **準則**：加狀態要順著它會流經的**每一處**檢查一遍——i18n 字典、輪詢終止條件、進度條顯示、清理／保留邏輯、UI 分支。本輪這四處全都漏了，而且每一處都只在特定狀態才看得出來。
- **情境**：專案已建立 i18n 機制，後來新增的 UI 卻硬寫雙語字串。
  **準則**：既有機制要當成契約遵守。硬寫「英文 / 中文」看似省事，實際上讓語言切換失效、字典不對稱、也破壞既有準則。新 UI 一律走 `t()`；後端只回語言中立的鍵或值，在地化留在前端。

## [2026-09-17] 第 11 輪 — 完整掃描後的依賴與映像優化

### 本輪計畫
- 依完整 CI 掃描結果修正可確認的依賴與 Docker 安全問題，並重新驗證。
- 保留 Bearer 的疑似誤報供人工複核，不直接關閉規則。

### 掃描基線
- Semgrep：0 個發現；Gitleaks：未發現密鑰。
- Bearer：1 Critical、3 High，初步檢視為安全實作造成的疑似誤報。
- OSV：`requirements.txt` 的 `python-multipart>=0.0.9` 允許已知弱點版本。
- pip-audit：CI 工具環境的 setuptools 版本過舊。
- Trivy：Dockerfile 缺少 HEALTHCHECK；映像內基礎套件與工具鏈仍有多項弱點。

### 本輪修正
- 將 `python-multipart` 下限提升至 `0.0.30`。
- Dockerfile 與 Ubuntu `setup.sh` 升級 `pip/setuptools/wheel`。
- Dockerfile 建置時更新 Debian 套件並加入 HTTP health check。
- CI 測試與安全掃描同步使用新版 Python 打包工具鏈。

### 驗證結果
- CI run `35220466017` 成功；測試、Docker build、報告上傳皆通過。
- Semgrep、pip-audit、Trivy filesystem/IaC、Gitleaks、Bearer 均完成；OSV 已無發現。
- Docker image 仍有基礎 Debian 與內嵌掃描器二進位檔的弱點，需持續隨上游版本更新；目前 CI 以報告警告、不阻擋建置。

## [2026-09-16] 第 10 輪 — Ubuntu / Docker 自動安裝腳本補強

### 本輪紀錄
- **需求**：檢視整個 `sast-` 專案並完成可實際使用的自動安裝流程。
- **專案盤點**：確認 FastAPI + adapter/orchestrator、六個掃描器、Docker Compose/nginx、30 個測試、CI workflow 與既有 `setup.sh`；安裝目標收斂為 Ubuntu 與 Docker。
- **DevSecOps**：
  - 強化 `setup.sh` 與 `scripts/install-tools.sh`：Ubuntu 平台檢查、逐工具繼續、原子下載、可寫安裝目錄、最終列出缺少工具；修正 OSV asset URL 與失效的 Trivy version pin。
  - 保留 `uvicorn[standard]`，因部署目標固定為 Ubuntu 及 Python 3.11 Docker image。
  - 更新 README（中英）、目前計畫與過時的五工具描述；保留歷史輪次紀錄不改寫。
- **QA / 驗證**：
  - Python 測試、Node.js `--check`、Docker Compose `config --quiet`、`git diff --check` 通過。
  - Git Bash 的 `bash -n` 語法檢查通過；OSV-Scanner、Trivy、Gitleaks pinned release asset URL 回傳 HTTP 200。
- **未完成的環境驗證**：本機沒有可用 Docker daemon，也不是 Ubuntu，因此未做 Docker build 或 Ubuntu 實際安裝；需在 Ubuntu 主機/CI 執行最後驗收。

### 教訓 / 準則
- 安裝器不能只驗證「指令跑完」；要驗證 release asset 仍存在、工具實際可被找到，並對 optional scanner 缺失做明確摘要。
- 安裝器應把「必要的 app 相依」與「可降級的外部掃描器」分開：前者失敗即停，後者逐項繼續並誠實回報。
- 固定部署目標為 Ubuntu/Docker 後，可以保留 `uvicorn[standard]` 與 Linux binary 路徑，避免為不在範圍內的平台增加分支。

## [2026-08-16] 第 9 輪 — 工具更新機制 + Docker 監控分頁

### 本輪紀錄
- **需求**：後續掃描工具更新怎麼處理；做一個分頁看每個 docker 的效能狀態。
- **更新機制**：
  - 釐清策略——弱點 DB 掃描時自動更新，只有工具二進位要管版本；二進位釘版於 install-tools.sh／Dockerfile。
  - `scripts/install-tools.sh` 加 `FORCE`（`want()` 判斷）以支援重裝更新；`setup.sh --update` 用 pip -U 更新 Semgrep + FORCE 重裝二進位。
  - 監控分頁顯示每個工具的已安裝版本；README（中英）新增「更新掃描工具」段（含 Renovate/Dependabot 建議）。
- **Docker 監控**：
  - `app/docker_stats.py`：用標準庫走 unix socket 讀 Docker Engine API（列容器 + 一次性 stats），自算 CPU%／記憶體／網路；預設關閉（`SAST_ENABLE_DOCKER_STATS`），因為掛 docker.sock 屬高權限。
  - `GET /api/system` 回傳容器效能；前端新增「掃描／監控」view 切換 + 監控頁（工具版本 + 容器 CPU/記憶體/網路表，每 3 秒更新），中英雙語。
  - docker-compose 加註解的 socket 掛載與 env 旗標並標警語。
- **QA / 驗證**：30 測試全通過（+3：CPU%/記憶體計算、docker 預設關閉、/api/system）；`node --check`、`bash -n` 通過；Playwright 實截監控分頁（工具版本 + Docker 未啟用提示）中英兩版。
- **安全界線**：誠實標示「掛 docker socket 是高權限」，預設關閉並要求明確開啟——不因為方便就預設暴露。

### 教訓 / 準則
- **情境**：要在會跑不受信任程式碼的服務裡加「看 Docker 效能」這種需要特權的功能。
  **準則**：預設關閉 + 明確 opt-in（env 旗標 + 需手動掛 socket）+ 文件警語 + 唯讀用途；把風險說清楚交給部署者決定，而不是預設打開。
- **情境**：不想為了讀 Docker stats 引入 docker SDK 相依。
  **準則**：Docker Engine API 是 HTTP over unix socket，用標準庫 `http.client` 自訂連線即可，維持零新相依（符合簡單原則）。

## [2026-08-16] 第 8 輪 — 合併 main + 一鍵安裝腳本 + README 使用方式

### 本輪紀錄
- **需求**：先把功能分支合併到 main；建立自動安裝腳本（含套件與完整建立）；README 補上使用方式。
- **交付**：
  - 以 fast-forward 把 `claude/security-scan-tools-web-ffc5mb`（7 個功能 commit）合併進 `main` 並推送。
  - 新增 `setup.sh`（一鍵安裝與建立）：檢查系統相依（apt 有則自動裝 git/curl/node/python3-venv）、建立 venv、裝 Python 相依 + semgrep、呼叫 `scripts/install-tools.sh` 裝四個二進位工具、跑測試驗證、印出啟動指令；支援 `--run`／`--docker`／`--no-tools`／`--no-venv`／`--help`。pip 自我升級失敗改為非致命（Debian 系統 pip 不可反安裝）。
  - README（中英）：Quick start 新增「一鍵安裝」為首選；使用方式擴充（進度、讀報表、語言切換、findings 原文說明）＋ REST API 對照表。
- **QA / 驗證**：`bash -n` 語法檢查；真實跑 `./setup.sh --no-tools`（建 venv → 裝相依 → 27 測試全過 → 印啟動指引）；`--help` 輸出正確。
- **過關狀態**：G1–G4 維持；本輪主要為交付（合併 + 安裝腳本 + 文件）。

### 教訓 / 準則
- **情境**：一鍵安裝腳本要在各種環境穩健。
  **準則**：系統相依用「有 apt 才裝、非 root 才 sudo」；會因環境而失敗的步驟（pip 自升級、工具下載）一律 `|| warn` 非致命，讓腳本能走完並在最後誠實回報；工具二進位裝到可寫的 BIN_DIR（root→/usr/local/bin，否則 ~/.local/bin）並提示 PATH。用「跑測試」當建立成功的驗收關卡。

## [2026-08-16] 第 7 輪 — 介面中文化（中／英雙語切換）

### 本輪紀錄
- **需求**：新增中文描述——四項全要：每個工具中文說明、整個介面中文化、findings 中文說明、中文 README。
- **DevSecOps**：
  - 新增 `app/static/i18n.js`：中／英字典 + `t(key, params)` + `applyStaticI18n()`（掃 `data-i18n` / `data-i18n-ph` 屬性）+ `setLang()`（存 localStorage、切根 lang、觸發 `onLangChange`）。預設中文。
  - index.html 靜態文字改用 `data-i18n`；右上角加語言切換鈕。
  - app.js 全面改用 `t()`：狀態、進度、確認框、盤點、工具列、findings（含中文嚴重度與「嚴重度說明」sevnote）；`onLangChange` 即時重繪（工具清單、篩選、當前 job、scan-picker 標籤）而不重載。
  - 每個工具的中文說明與需求、以及不適用原因，都以工具名為鍵放在前端字典（後端保持語言中立）。
  - 新增 `README.zh.md`，雙 README 互相連結。
- **QA / 驗證**：27 後端測試維持通過；`node --check` 驗證 JS 語法；Playwright 實截中文預設頁與按 EN 後即時切換的英文頁，確認整頁雙語正確、切換不需重載。
- **界線**：findings 內文來自掃描工具本身（英文），無法翻譯；以中文嚴重度標籤 + sevnote 提供中文脈絡。

### 教訓 / 準則
- **情境**：既有無框架前端要中文化，且要保留英文。
  **準則**：用「字典 + t() + data-i18n 屬性 + onLangChange 重繪」的輕量 i18n，比硬換字串或引入框架更合適；把「顯示文字」與「資料」分離——後端回語言中立的鍵（工具名、狀態碼、reason 對應工具），前端負責在地化，就能同時支援雙語且後端零改動。
- **情境**：部分內容（工具原生輸出）無法在地化。
  **準則**：誠實區分「可控 UI 文字（翻）」與「工具產生內容（保留原文，另加在地化脈絡）」，不假裝全翻。

## [2026-08-16] 第 6 輪 — upload/git 的「準備→確認→掃描」兩階段流程

### 本輪紀錄
- **需求**：把 upload/git 也做成「準備好後、正式掃描前先盤點並讓使用者確認」。
- **DevSecOps**：
  - Job 狀態機新增 `AWAITING`（awaiting_confirmation）與 `CANCELLED`；`Job.applicability` 於暫停時填入。
  - orchestrator 把單一 `_run_job` 拆成兩階段：`_prepare_and_maybe_scan`（準備 source + 盤點；若 confirm 則算 applicability、把 scan_root 存進 `_pending`、暫停在 AWAITING，**不清工作區**）與 `_scan`（真正跑工具後清理）。新增 `confirm()`／`cancel()`。
  - API 新增 `POST /api/scans/{id}/confirm`、`/cancel`；create_scan 增 `confirm` 參數，預設 upload/git=True、path=False（path 本就可事前 inspect，直接跑）。
  - 前端：AWAITING 時顯示確認框（盤點摘要 + 不適用工具警告 + Run scan / Cancel）；輪詢遇 AWAITING 停下等使用者；confirm 後恢復輪詢至 done。
- **QA / 驗證**：27 測試全通過（+4：confirm/cancel 狀態機、upload 端到端 await→confirm、confirm 錯狀態 409/404）。Playwright 實截 upload 兩階段：AWAITING 確認框 + 按 Run 後 DONE（semgrep 掃到 eval、npm_audit not_applicable 附因）。
- **過關狀態**：G1–G4 維持。

### 教訓 / 準則
- **情境**：非同步 job 要中途暫停等使用者輸入，之後再續跑。
  **準則**：把「準備」與「執行」拆成兩個可獨立提交到執行緒池的階段，中間狀態（已準備的工作區路徑）存在 manager 端 `_pending`，用明確的 AWAITING 狀態當交接點；確認/取消各自負責續跑或清理，工作區只在「真的跑完」或「取消」時刪，避免準備成果被提前清掉。
- **情境**：同一個「盤點/適用性」能力要同時服務 path 的事前 inspect 與 upload/git 的事中確認。
  **準則**：把 applicability/inventory 做成純函式與 adapter 方法，兩條路徑（/api/inspect 與 orchestrator 暫停點）共用同一套邏輯，不重複實作。

## [2026-08-16] 第 5 輪 — 專案盤點 + 語言防呆（誠實面對「per-file 進度」）

### 本輪紀錄
- **需求**：想顯示「專案有多少檔案、每個檔案掃描進度」；並問工具語言不支援時如何通知/防呆。
- **決策（誠實界線）**：不做「逐檔進度」——六個工具都是批次掃描器，沒有可靠的機器可讀 per-file 進度串流；SCA 工具（npm audit/OSV）根本是掃 lockfile 而非逐檔。硬做要為每個工具寫脆弱的 TTY 進度爬取，違反「簡單、不過度設計」。改做**專案盤點**（檔案數/大小/語言分佈）——這才是誠實且有用的粒度。
- **DevSecOps**：
  - 新增 `app/inventory.py`：`inventory()`（走訪、跳過 node_modules/.git 等噪音、統計檔數/位元組/語言直方圖、上限保護）與 `has_language()`（早退語言偵測）。
  - adapter 新增 `languages` 與 `requirement` 中繼資料，並把 `applicable()` 升級為 `applicability() -> (bool, reason)`；bearer 用語言偵測、npm_audit 用 package.json、osv 用 lockfile，各自回可讀原因。
  - orchestrator 掃前算 `job.inventory`；`ToolResult.message` 帶 not_applicable 原因。
  - API：`/api/tools` 增列 languages/requirement；新增 `POST /api/inspect`（僅本機路徑）回傳盤點 + 每工具適用性。
  - 前端：工具清單顯示「needs: …」；本機路徑可「inspect project」→ 顯示盤點卡 + 「Won't apply」清單 + 不適用工具標橘；選到不適用工具底部橘框警告；整批不適用時 Start 擋下。結果列顯示 not_applicable 原因與盤點摘要。
- **QA / 驗證**：23 測試全通過（+5：inventory、bearer/npm 適用性、/api/inspect 與拒絕非 path、/api/tools 中繼資料）。Playwright 實截 C-only 專案的 inspect 畫面：正確列出 bearer/npm_audit/osv_scanner 不適用原因、npm_audit 橘框警告。
- **過關狀態**：G1–G4 維持。

### 教訓 / 準則
- **情境**：使用者要求一個「聽起來合理但技術上做不到/會很脆弱」的功能（逐檔進度）。
  **準則**：誠實說明界線並提出等價、可靠的替代（專案盤點），比硬做脆弱功能好。先分辨「工具實際能提供的粒度」再設計 UI。
- **情境**：多工具各自支援不同語言/輸入，使用者可能選錯。
  **準則**：把「適用性」做成資料（每工具宣告 languages/requirement）+ 可解釋原因（applicability 回 reason），就能同時支撐「事前 inspect 警示」「事後 not_applicable 說明」「UI 需求標示」三個防呆點，而不散落硬編碼。

## [2026-08-16] 第 4 輪 — 進度表與即時狀態

### 本輪紀錄
- **需求**：網頁要有進度表與即時狀態。
- **DevSecOps**：
  - 後端 models 新增 `ToolPhase`（pending/running/finished）與 `ToolResult.phase`、`started_at`；`Job` 新增 `progress`（total/finished/running/pending/percent）與 `stage`（人類可讀當前步驟）。
  - orchestrator 改用 `run_one` 包裝：工具開跑前設 RUNNING+起始時間、結束設 FINISHED，並在每個工具完成後即時 `compute_progress()`；改用 `as_completed` 讓完成順序即時反映。source 準備階段（clone/extract）設 `stage` 供「Preparing…」不定進度條。
  - 前端新增進度條（百分比 + 準備中 indeterminate 動畫）、job 狀態 pill、每工具 phase 呈現（queued 灰標 / running 轉圈+即時秒數 / finished 狀態徽章+耗時）；輪詢由 1.5s 縮短為 1s。加上 `prefers-reduced-motion` 關閉動畫。
- **QA / 驗證**：18 測試全通過（新增 progress/phase 斷言）。Playwright 實截三態：掃描中 50% 進度條 + semgrep 轉圈 1.1s + npm not_applicable；完成 100% 綠條 + 各工具耗時 + finding。
- **過關狀態**：G1–G4 維持。

### 教訓 / 準則
- **情境**：要顯示「即時進度」，但工具是並行的黑箱子行程。
  **準則**：把「執行階段（phase）」與「最終結果（status）」分成兩個維度——phase 給 UI 畫即時狀態，status 給最終結論；並行以 `as_completed` + 每完成一個就更新 progress，前端輪詢即可呈現即時感，不需 WebSocket（維持簡單）。
- **情境**：source 準備（git clone）階段還沒有工具在跑，進度無法用「完成幾個工具」表示。
  **準則**：用 `stage` 文字 + indeterminate（不定）進度條表示「準備中」，等有工具數才切成百分比進度條。

## [2026-08-16] 第 3 輪 — 加入 nginx 反向代理

### 本輪紀錄
- **需求**：使用者要求網頁走 nginx 代理，並要看網頁畫面。
- **DevSecOps**：新增 `nginx/nginx.conf`（反向代理 FastAPI、`X-Forwarded-*` 標頭、`client_max_body_size 200m` 對齊上傳上限、proxy timeout 拉長給慢掃描、`/healthz` 健康檢查）；`docker-compose.yml` 新增 nginx 服務（對外 8080→80），後端改為 `expose` 不再對主機公開。修正 UI tagline「five→six」。
- **QA / 驗證**：沙箱無 docker daemon，改以本機安裝 nginx + 修改 /etc/hosts 讓 `sast-studio` 解析到本機後端，用**已提交的 nginx.conf** 實跑：`nginx -t` 通過、經代理 `GET /`、`/healthz`、`/api/tools` 皆 200（Server: nginx）。並用 Playwright（指向環境內建 chromium）截圖落地頁與掃描結果頁，真實 Semgrep 掃到 eval 注入正確呈現。
- **過關狀態**：G1–G4 維持；新增交付面（反向代理）已驗證。

### 教訓 / 準則
- **情境**：環境沒有 docker daemon，無法用 compose 驗證 nginx。
  **準則**：不要因為「不能照原路徑驗證」就跳過驗證——換等效手段（本機裝 nginx + hosts 覆寫）實跑**同一份設定檔**，一樣拿到 `nginx -t` 通過 + 經代理 200 的證據。
- **情境**：截圖工具版本與環境內建瀏覽器不符（Playwright 要下載新版被擋）。
  **準則**：用 `executable_path` 指向環境既有的 chromium（/opt/pw-browsers/chromium-1194），不硬連網下載。
- **情境**：截圖抓到掃描「running」中途狀態、且被前一個已完成 job 的殘留 DOM 誤判。
  **準則**：截動態畫面要等到明確終態（`status: done` + 目標元素同時成立），並先清空既有 job（重啟後端）避免殘留 DOM 造成 race 誤判。

## [2026-08-16] 第 2 輪 — 以免費工具取代 CodeQL（Trivy + Bearer）

### 本輪紀錄
- **觸發**：使用者無法支付 CodeQL 對私有程式碼的授權費，要求免費替代。
- **PM**：先澄清事實（CodeQL 對開源/研究免費、僅私有碼自動化掃描需付費 GHAS），再提供免費選項讓使用者選；使用者選 **Trivy + Bearer** 同時導入。主題由「五工具」更新為「六個全免費工具」。
- **DevSecOps**：移除 `codeql.py`（含 SARIF parser，屬 dead code 一併清掉）；新增 `TrivyAdapter`（vuln/secret/misconfig 三類 Results 解析、secret 遮罩）與 `BearerAdapter`（按 severity 分組 JSON、cwe_ids 前綴 CWE-、warning→low）。更新 registry、Dockerfile、install-tools.sh、docker-compose、README、CoreMain、待修改。
- **QA**：18 個測試全通過（100%）。移除 codeql SARIF 測試，新增 trivy（三類別 + secret 遮罩驗證）與 bearer（severity 映射 + CWE 前綴）parser 測試，並更新 API 工具名集合。真實工具驗證：沙箱網路對 GitHub releases 受限，無法現裝 Trivy/Bearer 實跑；但兩者沿用已被 Semgrep 實跑驗證過的同一 BaseAdapter 模板，parser 以真實輸出結構單元測試涵蓋。
- **過關狀態**：G1 ✅ / G2 ✅ / G3 ✅（本體安全不變）/ G4 ✅

### 教訓 / 準則
- **情境**：使用者對某依賴（工具/服務）有成本或授權疑慮。
  **準則**：先分辨「事實上的授權界線」再決策——把 CodeQL「開源免費、私有付費」講清楚，讓使用者在知情下選擇，而不是一聽到「費用」就盲目換掉。
- **情境**：要替換掉一個能力格（深度 SAST）。
  **準則**：adapter 架構讓替換是「加/減一個檔案 + 改 registry」的局部變更——移除 codeql.py、新增兩個 adapter、其餘 orchestrator/UI/輸入層完全不動。這正是當初選 adapter 契約的回報。
- **情境**：一格換兩個工具反而更好。
  **準則**：Trivy 免費且多能（順帶補上全套原本沒有的 IaC misconfig），Bearer 補語意 SAST——用兩個免費工具覆蓋 > 原本一個付費工具，且不增加架構複雜度。

## [2026-08-16] 第 1 輪 — 五工具整合 Web 應用 MVP（SAST Studio v1.0.0）

### 本輪紀錄
- **PM**：主題 = 「一個網頁統一跑五個安全工具」。範圍 = 五 adapter + orchestrator + 單頁 UI + 三種輸入。Exit Criteria 三維度合一（功能/資安/品質）。與使用者確認架構（FastAPI + adapter + docker-compose）與 Docker 授權疑慮（伺服器用 Engine/Compose 免費）。
- **DevSecOps**：
  - 實作 5 adapter（semgrep/codeql/npm_audit/osv_scanner/gitleaks）+ BaseAdapter 模板（probe / applicable / _execute + 計時/逾時/錯誤包裝）。
  - orchestrator：記憶體 job store + ThreadPool 平行執行 + 狀態機（queued→running→done/error）。
  - 三種輸入安全處理：Zip Slip/Bomb、Git URL scheme 限制、本機路徑驗證、secret 遮罩。
  - 自檢：無 shell=True/os.system/eval/exec；全部外部指令走單一 `run_command`（list 參數 + shell=False + timeout）；`subprocess.run` 只出現 1 次（在 choke point）。→ 資安 Critical/High = 0。
  - 漏洞密度：0 Critical/High（結構性防護 + grep/測試佐證）。
- **QA**：17 個測試全通過（100%）。涵蓋可用性偵測、五工具正規化、SARIF 解析、輸入安全（zip slip/git url/path）、orchestrator 狀態機、API（tools/404/bad-scheme/端到端 path 掃描）、secret 遮罩。另做兩項真實工具驗證：npm audit 實際執行 OK；semgrep 1.173 用本機規則掃到 eval 注入並正確正規化（ERROR→high、CWE-95、OWASP A03）。
- **CI/CD**：CI workflow 範本已附（tests + self-SAST + gitleaks gate）；本輪未做正式部署（docker-compose 提供本機/Staging 起服務）。
- **過關狀態**：G1 ✅ / G2 ✅ / G3 ✅ / G4 ✅ / G5 ⏳（待實際觸發）/ G6 ⏳（本輪不含上線）

### 教訓 / 準則
- **情境**：整合多個外部 CLI 工具、但執行環境不保證每個都裝。
  **準則**：一律用「adapter + 可用性偵測 + 優雅降級」而非硬性依賴——沒裝就回 `unavailable` + 安裝指引，其餘工具照跑。這讓產品「有幾個工具就用幾個」，可實跑也可 demo。
- **情境**：一個會「跑別人程式碼」的安全工具，本體安全風險高。
  **準則**：所有外部指令收斂到單一 `run_command`（list 參數、shell=False、timeout）當唯一 choke point，容易稽核（grep 一次就能證明）；輸入端（zip/git/path）三個常見攻擊面各自在 `source.py` 就地防護並寫測試。
- **情境**：不同工具輸出格式天差地別（semgrep JSON / SARIF / npm map / OSV / gitleaks）。
  **準則**：定義單一 `Finding` 正規化契約，讓 orchestrator 與 UI 完全不理解各工具格式；每個 adapter 各自把原生輸出映射到嚴重度/CWE/OWASP/位置。新增工具只需再寫一個 adapter。
- **情境**：CodeQL 重、bundle 數百 MB、對專有碼有授權限制。
  **準則**：不預裝進 image、對編譯型語言不硬猜 build 指令——降級回報「需手動設定」，把成本與授權風險留給使用者決定，不擋住其他四個工具。
- **情境**：Docker 授權疑慮。
  **準則**：先釐清事實再決策——Linux 伺服器的 Docker Engine/Compose 免費，只有 Desktop GUI 對大型企業收費；伺服器部署不需 Desktop。誠實回答比直接改方案更有價值。
- **過程原始輸出位置**：測試與 smoke test 於對話中執行，結論已落地本檔與 `待修改.md`；如需重跑：`pytest -q`。

---

## 第 15 輪（2026-09-19）— CD 部署到 VM，並揪出潛伏已久的 Semgrep 失效

### 背景
CI 已綠燈，使用者要求把既有 VM（192.168.99.145，跑前幾版）更新到目前版本。

### 做了什麼
1. 發現「目前版本」有歧義：VM 在 `30ef0e8`，`origin/main` 在 `25e794a`，本機還有 3 個**未推送**的 UI 改版 commit。先問清楚再動作，使用者選「推送 + 過 CI 再部署」。
2. 推 `6d105c1`，CI run 35403653584 綠燈；依第 13 輪紀律下載 artifact 逐項判讀，而非相信綠燈。
3. 部署採「先建後換」：先把線上映像標成 `sast-studio:rollback-30ef0e8`，build 成功才 `up -d`。
4. Smoke test + E2E（上傳 zip → 確認閘門 → 完成 → 政策判定）。

### 最重要的教訓：綠燈、健康檢查、通過的 E2E，都可能同時掩蓋「工具根本沒跑起來」

E2E 跑完是 `status=done`、政策判定 `passed`、summary 全 0——**看起來完美**。
但 `tools_run: 1` 而我要求了兩個工具。追進去才發現 Semgrep 每次都 error：

```
Cannot create auto config when metrics are off.
```

`app/adapters/semgrep.py` 寫死 `--metrics=off`（第 1 輪的隱私決定，正確），
設定預設 `SAST_SEMGREP_RULES=auto`（也很合理）。**兩個各自正確的決定互相衝突**，
而且是在 semgrep 某次版本更新後才變成硬錯誤。

為什麼長期沒人發現：
- CI workflow 刻意把掃描器失敗降為 warning（第 13 輪就記過這件事），所以 CI 不會紅。
- 容器 healthcheck 只看 HTTP 有沒有回應，不看掃描器能不能用。
- 「0 findings」在資安工具裡看起來像好消息，其實是最危險的假訊號。

**準則**：對一個「整合 N 個工具」的系統，驗收條件不能只有「掃描完成」，
必須是「**每個被要求的工具都回報 ok**」。`tools_run` 少於 requested 就該是紅燈。

### 修法與取捨
改 `p/default` 而不是開啟 metrics。理由回到 `CoreMain.md` 的安全紀律：
這是「跑別人程式碼的資安工具」，不該把被掃描專案的資料回傳給第三方。
保留 `--metrics=off`，換掉規則集。已在容器內實測 `p/default` + `--metrics=off` 可正常執行並抓到 shell injection。

同步修 `config.py` / `docker-compose.yml` / `.env.example` / README 中英四處，
避免只修 compose、下次有人照文件設 `auto` 又壞掉。

### 新增的防線
回歸測試 `test_semgrep_ruleset_is_compatible_with_metrics_off`，
斷言「規則集不是 auto」且「`--metrics=off` 仍在」。
**實測過**：`SAST_SEMGREP_RULES=auto` 時測試會失敗——會失敗的測試才是有效的測試。

### 下一輪建議
CI 把掃描器失敗降為 warning 是這次缺陷能潛伏的根因。
建議區分兩種失敗：「掃到漏洞」（可警告）vs「工具沒跑起來」（應擋 build）。
