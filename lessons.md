# lessons — SAST Studio

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
