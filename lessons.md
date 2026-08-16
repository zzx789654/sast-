# lessons — SAST Studio

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
