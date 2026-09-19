# talk — 指令與決議紀錄（SAST Studio）

> 每次使用者下指令就追加一則（提示詞原意 + 決議回應）。
> 要做功能變更前先讀本檔，比對是否與既有決議一致。
> 本檔進版控，一律不寫入任何憑證。

## [2026-09-18] #001 — 完整檢視專案並接續先前的 UI 與掃描規則調整

- **使用者指令（提示詞原意）**：用 secure-sdlc-orchestrator skill 完整檢視 `sast-` 專案；先前已進行 UI 與掃描規則的調整，請接續完成。
- **對照既有決議**：本檔為首次建立（先前輪次只有 `lessons.md` 與 `待修改.md`）。恢復程序改以 `CoreMain.md` + `待修改.md` + `lessons.md` + git 工作區差異重建狀態。
- **盤點結果**：工作區有一批**未提交**的「掃描政策（policy）」變更 —— 新增 `app/policies.py`，並改動 `main.py` / `models.py` / `orchestrator.py` / 前端四檔 / 測試。這就是使用者所說「先前的 UI 與掃描規則調整」，屬第 12 輪進行中。
- **決議回應**：不重做、不擴張範圍，只**收尾既有的第 12 輪**——修正檢視中確認的缺陷，補齊 i18n 與缺少的 UI，再過 G2–G4。
- **理由**：對照 `CoreMain.md` 的「簡單、順手、不複雜」與工程紀律「改動要小」；政策引擎已符合主題（統一介面上對彙整結果做決策），缺的是正確性與一致性，不是更多功能。
- **影響範圍**：`app/policies.py`、`app/main.py`、`app/static/*`、`tests/test_app.py`；`待修改.md` 與 `lessons.md` 補第 12 輪。
- **後續動作**：見 `待修改.md`〔本輪〕分區的缺陷清單。

## [2026-09-18] #002 — 先幫我執行 CI 驗證

- **使用者指令（提示詞原意）**：執行 CI 驗證（接續第 12 輪結案後的階段 5 / Gate G5）。
- **對照既有決議**：與 #001 一致——第 12 輪已結案並標示「G5 待實際觸發」，本次即為觸發。`待修改.md` 的 CI/CD 分區原本就記著「驗證目標待使用者選定」。
- **決議回應**：先問驗證目標（推送屬對外不可逆動作），使用者選「直接推 main」。推送 8734e66 → CI 綠燈；判讀 artifact 後發現映像層 Python 套件疑似過舊，推 64fe7f5 修正並再驗一輪。
- **理由**：workflow 把掃描器失敗設為 warning 而非擋 build，因此綠燈不足以證明資安 Exit Criteria 達標，必須下載 artifact 逐項判讀才算真的過 G5。
- **影響範圍**：`Dockerfile`（semgrep 後重新升級 setuptools/msgpack）、`lessons.md`、`待修改.md`、`talk.md`。應用程式碼未動。
- **後續動作**：G5 已達標。G6（CD 上線）尚未進行，待使用者決定是否要做。

## [2026-09-18] #003 — UI 改版：掃描/報告分頁、政策說明重寫、Docker 效能判讀

- **使用者指令（提示詞原意）**：(1) 掃描與報告拆成兩個分頁；(2) 政策範本看不懂——「Critical 一律阻擋」不知道對應哪個工具、也不知道阻擋什麼，請重新設計說明與 UI；(3) 報告頁左列歷次掃描、右側細節，上方加條狀圖摘要，並可匯出 CSV/PDF；(4) 監控頁想看出每個 Docker 效能是否足夠、掃描時會不會不夠用。
- **對照既有決議**：與 #001/#002 不衝突。#001 建立的政策引擎本身保留，本次是**表達層與資訊架構**的改版，不推翻政策判定邏輯。
- **關鍵發現（使用者的困惑是對的）**：
  1. 「Critical 一律阻擋」**不對應任何單一工具**——政策作用在六個工具**彙整後**的結果上，任何工具回報 Critical 都算。UI 從未說明這件事。
  2. 「阻擋」**其實什麼都沒擋**——`BLOCKED` 只是判定標籤，掃描早已跑完，沒有任何下游消費它（無 exit code、無 CI 整合）。名不符實。
- **決議回應**：
  1. **語意誠實化**：「阻擋」改為「不通過／需處理」，明講這是稽核判定而非技術攔截。不新增 CI exit code 端點（避免擴張範圍）。
  2. **政策 UI 重設計**：每條規則改寫成「當任一工具發現 X → 這次掃描判定為 Y」，並明示哪些工具會產生該類發現，另顯示本次掃描的實際命中數。
  3. **分頁重構**：掃描／報告／監控三分頁；報告頁左列歷次掃描、右側細節 + 上方嚴重度條狀圖。
  4. **匯出**：CSV 由後端標準庫 `csv` 產生（零新相依）；PDF 用瀏覽器原生列印 + `@media print` 樣式（零新相依，不擴大 Docker 映像弱點面）。
  5. **Docker 效能**：以既有 `docker_stats`（已算 CPU%／mem used/limit/%）加上「額度判讀」——標示是否接近上限、是否未設限制，並提供掃描期間的觀察提示。
- **理由**：對照 `CoreMain.md`「簡單、順手、不複雜」與「套件優先免費且精簡」——CSV/PDF 都選零新相依路徑；政策改為情境式敘述是為了讓人**不看說明就懂**，正是 CoreMain 的「順手」。
- **影響範圍**：`app/policies.py`（規則文案與中繼資料）、`app/main.py`（CSV 匯出、docker 額度判讀）、`app/static/*`（三分頁、報告頁、列印樣式）、`app/docker_stats.py`、測試、README 中英。
- **後續動作**：實作後跑測試 + 瀏覽器實測三分頁與匯出。


## [2026-09-19] #004 — CD 部署到 VM 192.168.99.145（G6）

- **使用者指令（提示詞原意）**：接續 sast- 專案，CI 已過，請進行 CD 部署；VM 已裝過前幾版，請更新到目前版本。
- **對照既有決議**：與 #002 一致——#002 結尾記著「G6（CD 上線）尚未進行，待使用者決定」，本次即為執行。
- **盤點結果**：VM 在 `30ef0e8`（落後 9 個 commit），本機另有 **3 個未推送**的 UI 改版 commit。「目前版本」因此有歧義。
- **決議回應**：
  1. **先推送 + 過 CI 再部署**（使用者選定）。推 `6d105c1` → CI run 35403653584 綠燈；依 #002 既有紀律下載 artifact 判讀，原始碼面六項全數 0，映像層 11 CRITICAL 與 G5 基線完全相同（7 個 Debian base image 且 `fixed=NONE`、4 個掃描器二進位），確認 3 個 UI commit 未引入新曝險。
  2. **先建映像再切換**（使用者選定）：先把線上映像標記 `sast-studio:rollback-30ef0e8`，再 build，成功後才 `up -d`，中斷僅數秒。
- **E2E 發現的既有缺陷（本次部署未造成）**：Semgrep 每次掃描都失敗——`app/adapters/semgrep.py` 寫死 `--metrics=off`（隱私考量），但設定預設 `SAST_SEMGREP_RULES=auto`，semgrep 1.177 拒絕「metrics 關閉時建立 auto config」。兩個各自正確的決定互相衝突，且因 workflow 把掃描器失敗降為 warning 而長期無人察覺。
- **理由**：修正選 `p/default` 而非開啟 metrics——本專案是「跑別人程式碼的資安工具」，`CoreMain.md` 的安全紀律要求不讓程式碼資料外流，故保留 `--metrics=off`，改動規則集。已在容器內實測 `p/default` + `--metrics=off` 可正常執行並抓到漏洞。
- **影響範圍**：`app/config.py`、`docker-compose.yml`、`.env.example`、`README.md`、`README.zh.md`、`tests/test_app.py`（新增回歸測試，實測還原 `auto` 會失敗）。
- **後續動作**：修正推上 CI 後重新部署並複驗 Semgrep。

## [2026-09-19] #005 — 發現卡片改版：問題原因／改善方式／位置三段式 + 識別碼標籤

- **使用者指令（提示詞原意）**：(1) 目前的政策只會影響 Semgrep 嗎？(2) 六隻工具掃同一份程式碼差異為何這麼大？(3) 發現卡片想改成「告警標題／告警原因／改善方式」，工具沒給的欄位留空白，CWE/CVE 等用小標籤顯示。
- **對照既有決議**：與 #003 一致——#003 已把政策語意誠實化，本次延續同一方向，處理「看得到但看不懂、不知道怎麼修」的問題。不改判定邏輯，只改表達層。
- **關鍵發現（使用者的困惑再次是對的）**：
  1. 政策**不只影響 Semgrep**。`policies.py:169` 把六個工具的 findings 攤平後才評估，使用者自己那次掃描的 `blocked` 正是來自 npm_audit/osv_scanner 的 critical，與 Semgrep 無關。
  2. **修補建議其實有資料，但 UI 沒顯示**：npm_audit 回傳 `fix_available: true` 但不帶版本號，而舊版 `app.js` 只在有 `fixed_version` 或 `fix_available === false` 時顯示，兩個分支都不符合就什麼都不畫。
  3. Bearer 的 `message` 本身是 `## Description … ## Remediations …` 的 markdown，舊版整塊塞進 `.fmsg`，變成使用者截圖裡那一大片看不懂的文字牆。
- **決議回應**：
  1. 卡片改為三段式固定結構：**問題原因 / 改善方式 / 位置**。欄位缺資料時**保留欄位並標示「（此工具未提供）」**，不隱藏——缺漏本身就是資訊，也讓每張卡片形狀一致。
  2. 新增 `splitRemediation()`：把 Bearer 的 markdown 拆成 cause / fix 兩半，各自歸位。
  3. 新增 `packageFixText()`：相依工具的修補是「版本」而非文字，依 `fixed_version` → `resolution` → `fix_available` 逐層退化成可執行的建議。
  4. 新增 `cveIds()`：CVE/GHSA 不是獨立欄位，從 rule_id 與 references 萃取後以標籤呈現；CWE/CVE/OWASP/rule 四類標籤以顏色區分。
- **理由**：對照 `CoreMain.md`「順手」——使用者要的不是更多資訊，而是**看完知道要做什麼**。缺漏欄位保留空白而非隱藏，是刻意選擇：對資安工具來說「沒有修補建議」和「有但沒顯示」必須能一眼分辨。
- **影響範圍**：`app/static/app.js`（renderFinding 重寫 + 三個新函式）、`app/static/i18n.js`（8 組中英鍵）、`app/static/style.css`、`tests/test_app.py`（i18n 鍵回歸測試）。後端與政策判定邏輯未動。
- **後續動作**：過 CI 後部署至 VM 供使用者確認。

## [2026-09-19] #006 — 監控分頁強化、維護動作、部署先下載再建置

- **使用者指令（提示詞原意）**：(1) 監控分頁要看得到 Docker 效能，若需額外 Docker 設定請實測並寫進自動化部署腳本；(2) 監控畫面可手動更新掃描工具、重啟服務；(3) 部署太久，改成「先下載再部署」；(4) 完成後跑 CI/CD 並更新 VM 供測試。
- **對照既有決議**：與 CoreMain「不做帳號系統」一致。使用者明示選擇**維護動作不加任何開關、直接開放**，此決策記為已知風險。
- **決策**：重啟 = 重啟應用程序（不給 docker.sock 寫入權）；快取 = 主機先下載、build 直接用。
- **關鍵發現（實測才抓得到，非紙上推論）**：
  1. **docker.sock 權限**：光是掛載 socket 不夠。socket 是 `root:988 rw-rw----`，容器跑 `appuser`(1000) → `Permission denied`，監控頁全空。解法 `group_add: ["${DOCKER_GID}"]`，且 gid **每台主機不同**，因此由 `deploy.sh` 自動偵測寫入 `.env`——這正是使用者要求的「可執行方式加入自動化部署腳本」。
  2. **重啟節流失效**：`last_restart_at` 放記憶體，而**重啟本身就會清掉它**，導致節流在真實情境永遠無效（VM 實測連按兩次都成功）。改存到 workspace volume 的 `.last-restart` 檔才真的擋得住。
  3. **Trivy 快取檔損毀**：兩次下載都被 600 秒硬上限截斷，產生「非空但損壞」的檔案。若沒有 checksum，build 會把它當有效快取使用。改抓上游官方 checksums 檔（僅數 KB）比對。
- **資安（security-scanner 兩輪複驗）**：首輪 7 項（2 High）；修完複驗 High 歸零，但新抓出我自己引入的 FIND-009（重啟佔住 job slot 且無路徑歸還，SIGTERM 失效就永久鎖死）與 FIND-008（遮罩殘留）。全部修完並補測試。
- **影響範圍**：新增 `app/admin.py`、`scripts/fetch-vendor.sh`、`scripts/deploy.sh`；改 `docker_stats.py`（依 label 限縮容器清單）、`main.py`、前端四檔、`Dockerfile`（vendor 快取）、`docker-compose.yml`、README 中英、測試（37→61）。
- **量測**：VM 重建 **138 秒**（先前多次 40 分鐘以上且失敗）。
- **後續動作**：過 CI 後部署至 VM 供使用者測試。

## [2026-09-19] #007 — 移除可設定的掃描政策，改為固定判定規則

- **使用者指令（提示詞原意）**：(1) 更新完成後要告知是否需重啟；(2) 移除「掃描政策」區塊，改為固定規則：高以上→不可上線、中→人員審查、低→通過、外洩密鑰→不可上線；(3) 詢問六個工具是否都能寫自訂規則。
- **對照既有決議**：#003 曾把政策語意誠實化並重新設計 UI，本次更進一步——**直接移除選擇**。與 `CoreMain.md`「不複雜、不過度設計」一致：這件事本來就只有一個合理答案，不該讓使用者決定。
- **決議回應**：
  1. **判定規則固定化**：Critical/High 或密鑰 → blocked；Medium → manual_review；Low/Info/零發現 → passed。使用者確認「零發現算通過」。
  2. **誤報例外一併移除**（使用者選擇）：blocked 不再提供任何略過途徑，UI 改為列出擋住的發現並說明「修好再掃」。
  3. **更新結果明講**：新增 `_classify()` 判讀每個指令的輸出，分成 upgraded / data_updated / already_current / unknown，並在面板顯示；只有 upgraded 才提示需重啟。解決使用者「要不要重啟」的疑問，不必自己讀 pip 輸出。
  4. **進度條摺疊**：`_collapse_progress()` 只保留每行 
 後的最終狀態，114MB 下載的數十行重複輸出收斂成一行。
- **理由**：使用者原本的困惑（截圖裡的政策表單）根源不是說明不夠，而是**這個選擇本身沒有必要存在**。移除比解釋更能達成「順手」。
- **影響範圍**：`app/policies.py`（236→112 行，移除 PolicyDefinition/範本/客製化）、`main.py`（移除 exceptions 端點與政策參數）、`models.py`、`orchestrator.py`（移除 add_exception）、前端四檔（移除政策表單與例外 UI，i18n 刪 76 個鍵）、README 中英、測試。淨減 426 行。
- **量測**：測試 61 → 70（新增參數化的判定階梯測試涵蓋 9 種組合）。
- **附帶回答**：六個工具中 Semgrep / Trivy / Gitleaks / Bearer 可寫自訂規則（Semgrep 最強），npm audit 與 OSV-Scanner 不行——它們是查詢漏洞資料庫，沒有規則可寫。

## [2026-09-19] #008 — 掃描頁新增自訂規則編輯器（Semgrep YAML / Trivy Rego）

- **使用者指令（提示詞原意）**：掃描右側空白處新增自訂規則編輯器，先做 Semgrep 與 Trivy，提供範本，可編輯／儲存／選用（預設範本不可改），儲存時要能檢查規則可用。
- **對照既有決議**：填滿第 17 輪之後閒置的右側版面。與 `CoreMain.md` 一致——這是「用一個網頁統一跑六個工具」的延伸，不是新主題。
- **決議回應**：
  1. 規則存 Docker volume（使用者選定），不進版控。
  2. 可複選：自訂規則**加在**預設規則集之上，不取代（使用者選定）。
  3. 儲存前一律先請掃描器實際編譯，不過就不存檔。
  4. 內建範本唯讀，改了要另存新名。
  5. 掃描開始時把規則**複製**進工作區，避免掃描中改規則影響進行中的掃描。
- **資安（security-scanner 獨立複驗，6 項）**：
  - **FIND-001 Critical 已實測確認並修復**：Trivy 的 Rego 可呼叫 `http.send`，我在容器內實測**真的打出 HTTP 請求並拿到 200**。因為編輯器無登入保護，等於任何人都能讓伺服器對內網發請求或外傳被掃描的原始碼。修法：在規則執行**之前**以 denylist 擋掉 `http.send` / `net.lookup_ip_addr` / `opa.runtime` / `rego.parse_module` / `trace`，並實測原始 exploit 現在被拒。
  - FIND-002 High：驗證端點無併發上限 → 加 Semaphore(2)、timeout 120→60 秒。
  - FIND-003 High：規則數無上限 + 我把 rules 與 workspaces 併成同一個 volume（自己引入的退化）→ 改回兩個獨立 volume，並加每 engine 100 條上限。
  - FIND-004 Medium：ReDoS → semgrep 加 `--timeout 30 --timeout-threshold 3`。
  - FIND-005 Medium：寫入非原子 → 改 temp file + `os.replace`。
  - FIND-006 Low：`$` 會匹配結尾換行 → 改 `\Z`。
- **理由**：Semgrep 是宣告式 YAML，風險有限；Trivy 的 Rego 是**真正的程式語言**，這是本輪唯一真正危險的地方。不做沙箱而用 denylist，是因為合法的檢查規則本來就只需要讀 `input`，不需要網路、時鐘、環境變數。
- **影響範圍**：新增 `app/rules.py`；改 `main.py`（5 個端點）、`config.py`、`models.py`、`orchestrator.py`、`adapters/base|semgrep|trivy.py`、前端四檔、`Dockerfile`、`docker-compose.yml`、README 中英、測試 92→106。
- **附帶回答**：六個工具中只有 Semgrep／Trivy／Gitleaks／Bearer 可寫規則；npm audit 與 OSV-Scanner 是查漏洞資料庫，沒有規則語言。本輪只接前兩個。

## [2026-09-19] #009 — 大量結果的畫面修正、規則集多選、掃描階段進度

- **使用者指令（提示詞原意）**：(1) 掃 zip 後出現多餘畫面、圖卡沒正常渲染？(2) 能否把 Semgrep 預設規則改成 auto / p/owasp-top-ten / p/python？(3) Trivy 掃描時是直接執行程式嗎？(4) 掃描狀態做成進度條，依各工具流程顯示階段。
- **問題 1 根因**：`renderBlockedBox` 會把**全部** blocking_findings 列出。使用者這次掃到 1066 個阻擋項，整個畫面被它佔滿，真正的發現卡片被推到下方。不是渲染失敗，是「重複顯示且沒有上限」。決議：**整個移除該區塊**（使用者選定）——下方完整列表本來就有相同資訊，而且有篩選與詳細內容。
- **問題 2**：`--config auto` **無法採用**——第 15 輪已實證 semgrep 在 `--metrics=off` 時拒絕 auto，而 metrics=off 是刻意保留的隱私決定。改為**多選清單**（使用者選定），預設 `p/default + p/owasp-top-ten`，另提供 security-audit / python / javascript / java / golang / secrets。semgrep 的 `--config` 可重複，所以是聯集不是取代。
- **問題 3（澄清我先前的說法）**：**Trivy 掃描時不執行被掃描的程式碼**。六個工具都只把檔案當資料讀。先前的 Critical 是指 **Rego 規則**本身是程式語言、由 Trivy 執行——風險在「誰能寫規則」，不在「掃描誰的程式碼」。這點我上一輪表達不清，已明確區分。
- **問題 4**：`ToolResult` 新增 `stage` 欄位，每個 adapter 宣告自己的 `first_stage`（semgrep=編譯規則 / trivy=更新弱點DB / osv,npm=查詢情資 / gitleaks=比對密鑰 / bearer=資料流分析），base 的 template method 在 probe→applicability→execute 三點回報。前端顯示階段文字而非只有「執行中」。
- **附帶修正**：1343 筆發現一次全塞 DOM 會卡頓，改為每頁 100 筆 + 「顯示更多」。
- **影響範圍**：`models.py`、`config.py`、`adapters/base|semgrep|trivy|osv_scanner|npm_audit|gitleaks|bearer.py`、`orchestrator.py`、`main.py`（/api/rulesets）、前端四檔、README 中英、測試 107→113。

## [2026-09-19] #010 — 移除人工審查表單，判定保留給 PDF

- **使用者指令（提示詞原意）**：移除人工審查表單，改為匯出 PDF 交給負責人處理。
- **決議回應**：移除表單、`/api/scans/{id}/review` 端點與 `JobManager.review()`；**保留「需人員審查」判定**（使用者選定），讓 PDF 上仍印得出來。
- **理由**：這個網頁沒有登入保護、掃描紀錄存在記憶體（重啟即清空），本來就不適合當正式簽核場所。把簽核移到 PDF 流程反而更誠實。一併移除後端端點而非只藏 UI——留著一個無認證、能改判定的端點比表單更糟。
- **順帶修正（實際會影響使用者的缺陷）**：第 19 輪把發現列表改成分頁後，**列印只會抓到已渲染的前 100 筆**——1343 筆的掃描匯出 PDF 會靜默少掉 1243 筆。已修：按匯出 PDF 前先渲染全部。這個缺陷是我自己上一輪引入的，而且正好踩在使用者這次要用的工作流上。
- **影響範圍**：`app/main.py`、`app/orchestrator.py`、前端三檔（含列印樣式）、README 中英、測試 113→115。

## [2026-09-19] #011 — 合併重複的規則選擇（使用者指出）

- **使用者指令（提示詞原意）**：Semgrep 規則集不是應該在自訂規則內嗎？這樣會產生重複的功能項目。
- **使用者是對的**：我在第 19 輪把「Semgrep 規則集」做成掃描頁左側的獨立 fieldset，但右側編輯器早就有「這次掃描要套用的自訂規則」勾選清單。**兩個清單在回答同一個問題**——這次掃描要跑哪些規則——卻分在畫面兩側兩個面板。
- **決議回應**：合併成一個清單，底下分兩組：「公開規則集（Semgrep 官方）」與「你自己的規則」。移除左側 fieldset 與 `ruleset.legend` / `ruleset.hint`，標題改為「這次掃描要套用哪些規則（可複選，全部聯集一起跑）」。
- **理由**：正是第 17 輪自己寫下的教訓——「當使用者說某個介面難懂，先問這個選擇有必要嗎」。這裡選擇有必要，但**不該被拆成兩個**。使用者腦中是一個問題，介面就該是一個清單。
- **影響範圍**：`app/static/index.html`、`app.js`、`i18n.js`、`style.css`。後端未動（API 本來就分開，`custom_rules` 與 `rulesets` 語意不同，只是 UI 呈現要合一）。
