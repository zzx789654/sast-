# lessons — SAST Studio

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
