# SAST — 安全掃描稽核紀錄（SAST Studio）

> 每次安全確認（G3）追加一則，最新在上，不覆蓋。命中密鑰只記位置與類型。
> 第 42 輪以前的紀錄在 `待修改.md` 各輪與 `lessons.md`。

## [2026-10-07] 第 47 輪 — 每日預先建置、網頁核准套用、說明文字網址

### 自動掃描
| 類別 | 工具與範圍 | 結果 |
|---|---|---|
| SAST | Semgrep `p/default`，`app/`、`scripts/`、`tests/` | 9 項，本輪改動部分 0 項：`tests/test_updater.py` 的刻意 setuid 測試樣本（第 45 輪已記錄）＋ 8 項在本輪未改動的檔案（`accounts.py`／`events.py` 的 sqlalchemy 參數化查詢、`releases.py` 已指定 ssl context 的 HTTPSConnection、3 支 JS 測試以 eval 載入被測檔），皆為既有項目 |
| Secret | Gitleaks 8.30.1，整個工作目錄 | 0 |
| 抑制註解 | `app/`、`scripts/` | 0 |
| SCA | 無相依變更 | — |

### 人工複核（獨立子代理）
- 結果：Critical 0、High 0、Medium 4、Low 6，**全部修正並各補測試**（明細見 `待修改.md` 第 47 輪）。
- 已確認守住：被攻破的容器無法指定版本、無法套用未驗收的映像、無法重放舊候選或繞過 14 天期限；主機狀態檔不在容器可寫範圍；前端通知全用 textContent。
- Medium 摘要：
  - recover 讀不可信的 status.json，可讓 cron 永久停擺或偽造事件 → 改用主機狀態檔的 `running` 標記；
  - 手動部署後舊候選可把程式退回 → 候選綁定 base／image 映像 ID；
  - 說明文字判定會藏住 curl 指令與不加引號的 HTML 屬性 → 改白名單判定。
- 已接受殘餘（Low）：候選 id 容器讀得到，可不經管理員套用「已驗收且仍有效」的候選（`架構.md` §2C）。

### CI 報表判讀（G5，run 37638073675，commit 0bf0588；基準第 46 輪 37622017263）
- semgrep／pip-audit／pip-audit-semgrep／osv／trivy-fs／gitleaks 0；trivy-image 與基準相同（373 個 CVE，無新增）。
- bearer 6→8：新增 2 筆都在 `app/main.py` 本輪未改動的既有程式，只是行號位移 4 行，經判讀為誤判：
  - `path_traversal` 1653：`_save_upload` 的目的地是伺服器產生的 job 目錄＋固定檔名 `upload.zip`；
  - `regex_using_user_input` 1077：固定正規式比對 Host 標頭，比對前已限長、無巢狀量詞。
  其餘 6 筆與基準相同（行號位移）。

### 實測
- .145 容器（Python 3.11）706 passed、1 failed（`test_orchestrator_stores_map_and_verdict_is_unchanged`，容器內有真掃描器，已知環境差異）；`sast_updater.py`、`attack_surface.py` 行＋分支 100%；JS 測試 3 支通過。

## [2026-10-07] 第 46 輪 — 攻擊面準確度、proxy 收斂、清除抑制註解

### 自動掃描
| 類別 | 工具與範圍 | 結果 |
|---|---|---|
| SAST | Semgrep `p/python`＋`p/javascript`，`app/`、`scripts/`、`tests/` 41 檔 | 1 項：`tests/test_updater.py` 的刻意 setuid 測試樣本（第 45 輪已記錄） |
| Secret | Gitleaks 8.30.1，整個工作目錄 | 0 |
| 抑制註解 | `app/`、`scripts/` | 38 → **0**（17 處改具體例外、19 處最後防線改一般註解、2 處 S603 改說明、1 處私有存取改公開函式） |
| SCA | 無相依變更 | — |

### 人工複核（獨立子代理，四輪）
推論功能的主要風險是「方向錯誤時把風險藏起來」，四輪皆以「無法確定就不推論」處置：
- 第一輪：High×1（全域旗標＝任何檔案的 401/403 middleware 讓整個專案路由都變「全域認證」）、Medium×3（部分條件閘門、公開路徑漏判與名稱比對過寬、`docs/`／`examples/` 可能藏正式程式）、Low×5（標示、admin／ClientDisconnect／naive datetime 例外缺口、container_name 單機限制）。
- 修正：閘門以「檔案＋app 物件」為範圍、範例檔不參與；只認「最後一個敘述是 401 或導向登入」的 middleware；公開路徑改從放行分支的條件抽取；範例目錄縮為明確的測試目錄、範例中的風險照列（只不計數）、密鑰一律計數；推論加 `auth_inferred` 旗標並於 MCP 列出。
- 第二～四輪：同名檔案鍵碰撞（High）、否定條件、巢狀放行、看不懂的路徑判斷、router 同時掛在無閘門的 app、絕對 import 尾端比對多檔、把 request 交給輔助函式——**全部改為不推論**並各有測試。第三、四輪判定 G3 達標。
- 已接受殘餘（Low）：固定 `container_name` 使單機只能一套部署；`/containers/json` 的 filters 由呼叫端決定（容器名稱／映像清單可見，既有）；推論仍是啟發式（例如身分檢查函式以名稱判斷），畫面與 MCP 均標「推論，請確認」。

### CI 報表判讀（G5，run 37622017263，commit be05763；基準第 45 輪 37461611822）
- semgrep／pip-audit／pip-audit-semgrep／osv／trivy-fs／gitleaks 0；bearer 與基準完全相同。
- trivy-image：CRITICAL 5（同）、HIGH 190→194。新增 4 筆皆為 **CVE-2026-19445**（Debian 13 系統套件 python3.13／libpython3.13-*，2026-09-30 公布、**尚無修補版本**），來自基底映像 OS 套件、因漏洞資料庫更新而出現，非本輪引入；SAST Studio 執行於 /usr/local 的 Python 3.11。列為上游未修補的既有項目。

### 實測
- 本專案自我掃描：未偵測到認證 53→0（全域認證 43、公開 10，與 `_auth_gate` 實際放行一致）；計數風險 3→0（3 筆範例風險照列並標示）；外部連線 52→8。
- Linux 633 passed（1 項既有環境差異）；`attack_surface.py` 行＋分支 100%；新增 `tests/test_failure_handling.py` 驗證收窄後的例外處理。

 — 網頁觸發的掃描工具升級（主機服務、docker proxy）

### 自動掃描
| 類別 | 工具與範圍 | 結果 |
|---|---|---|
| SAST | Semgrep `p/python`＋`p/javascript`（同 CI），`app/`、`scripts/`、`tests/` 共 40 檔 | 1 項：`tests/test_updater.py` 刻意建立 setuid 檔（驗證主機會清掉），屬測試樣本；已改用具名常數 `stat.S_ISUID…` 表達意圖 |
| SAST（稽核） | Semgrep `p/security-audit`，四個新模組 | `dynamic-urllib-use-detected` ×2 → 改用 `http.client`、只連 https＋白名單主機（擋 `file://`）；`httpsconnection-detected` ×1 → 已明確傳入 `ssl.create_default_context()`，測試斷言憑證與主機名稱驗證開啟 |
| SAST（bearer） | 四個新模組 | os_command_injection（`_run`）：argv list、`shell=False`、只允許 `docker`／`bash`、可變部分皆經格式驗證 → 誤判；path_traversal ×2（rmtree、open 鎖檔）：路徑皆為程式常數 → 誤判 |
| Secret | Gitleaks 8.30.1，整個工作目錄 | 0（`selfcheck.py` 的假 AKIA 於執行時組出，不在檔案中） |
| SCA | 無新增 Python 套件；docker proxy 改用既有的 nginx 映像（digest 固定），移除原計畫的第三方 socket-proxy | 以 CI 的 pip-audit／osv／trivy 為準（G5） |

### 人工複核（獨立子代理，兩輪）
- 第一輪：Critical 0／High 0／Medium 6／Low 11。處置：回退完整化（FIND-001）、proxy 改 nginx 路徑白名單（002）、冷卻改看 asset 與 PyPI 最新檔（003/004）、ops 清理與去 setuid（006）、RecursionError 與目錄處理（007）、drain 只接受 int 0（008）、confirm 競態（009）、re-exec 鎖（010）、回退映像依 image 保留（011）、.env 以 0600 建立（012）、cron 路徑（013）、`.dockerignore`（014）、Trivy 報表解析（015）、未啟用帳號時拒絕升級（016）、app 端 FIFO（017）。
- 第二輪：17 項中 11 已修、5 部分、1 延後；修正引入 Medium×2（NEW-01 路徑 chmod 會跟隨 symlink、NEW-02 tidy 例外使 updater 當機）與 Low×5，**全部已修**：fchmod 於描述元、逐項例外處理、`--prev` 無法略過鎖、nginx 拒絕路徑含 `%`／`..`／`//`（查詢字串不受影響）並以 digest 固定、`.env` 寫入失敗時明確警告、cron 只接受單純路徑、下載後重新查核發布時間。
- proxy 實測（.145 真實 socket）：`/containers/json`（含 app 實際送出的編碼過濾參數）、`/containers/<id>/json`、`/stats`、`/info` → 200；`archive`、`export`、`logs`、`images`、`/v1.43/`、`%2e%2e`、`..`、`//`、編碼斜線、POST create/stop → 403。

### CI 報表判讀（G5，run 37461611822，commit 5c63608；基準 37311828371）
| 工具 | 結果 | 判讀 |
|---|---|---|
| semgrep／pip-audit／pip-audit-semgrep／osv／trivy-fs／gitleaks | 0 | — |
| trivy-image | CRITICAL 5、HIGH 190（同基準）；MEDIUM 209→205、LOW 159→159 | 未增加 |
| bearer | 新增皆在 `scripts/sast_updater.py`：os_command_injection（`_run`）、file_permissions ×2（`fchmod` 設 0644／0600，是**收緊**權限、去 setuid）、path_traversal ×4（rmtree／unlink 的對象為 `ops/` 掃描出的項目名稱，不含 `/`；其餘為程式常數） | 皆誤判；其餘與基準相同（含 bearer 不穩定的 `main.py` 兩筆） |

### 殘餘風險（接受，列下一輪）
- FIND-005：Semgrep 遞移相依未鎖 hash；Bearer 未釘版本；二進位 checksum 與檔案同源（防不了 release 本身被竄改）→ 簽章／provenance 驗證。
- FIND-002 殘餘：`/containers/<id>/json` 可讀任一容器設定（含環境變數），監控分頁讀記憶體上限需要。
- 既有 38 處抑制註解（10 個檔案）未處理，另開一輪。

## [2026-10-05] 第 44 輪 — Semgrep 獨立 venv（Dockerfile、admin.py、部署與安裝腳本、CI）

### 自動掃描
| 類別 | 工具與範圍 | 結果 |
|---|---|---|
| SAST | Semgrep（舊映像 33d55f4 內正常版本）`p/python`、`p/javascript`、`p/dockerfile`、`p/github-actions`；`app/admin.py`、`app/adapters/semgrep.py`、`tests/test_app.py`、`ci.yml` | 0 項、0 錯誤。Dockerfile 第 13 行（既有 ENV 多行寫法）semgrep 無法解析，改人工；shell 腳本無可用規則集（`p/bash` 不存在），以 `bash -n`＋人工 |
| Secret | Gitleaks 8.30.1，整個工作目錄 | 0 |
| SCA／授權 | 無新增套件；semgrep 由「未釘版本」改為釘 1.179.0（LGPL-2.1，既有）。CI 新增 `pip-audit-semgrep` 審核 semgrep venv | 以 CI 的 pip-audit／pip-audit-semgrep／trivy-image 為準（G5） |

### 人工複核（獨立子代理，兩輪）
| # | 嚴重度 | 問題 | 處置 |
|---|---|---|---|
| FIND-001 | High | 舊主機 `.venv` 殘留 semgrep 仍在 PATH 前面，衝突會重現；`want semgrep` 看到它就跳過獨立 venv | `setup.sh` `drop_semgrep_from_app_venv`（兩條路徑）；`install_semgrep` 只認 `$SEMGREP_VENV`，並比對 PATH 上 semgrep 的 realpath |
| FIND-002 | Medium | `/opt/semgrep` chown 給 appuser，執行期帳號可改寫掃描器本體 | 移除 chown；維持 root 擁有 |
| FIND-003 | Medium | semgrep 未釘版本，網頁就地升級從 PyPI 直拉、繞過 CI 與映像掃描 | 釘 `SEMGREP_VERSION=1.179.0`（Dockerfile／CI／install-tools，有一致性測試）；網頁不再就地升級 semgrep。殘餘：無 `--require-hashes`（Low，接受） |
| FIND-004／005 | Medium／Low | `_semgrep_python()` 由 PATH 推導直譯器，非 venv 安裝時判斷錯誤 | 隨就地升級一併刪除 |
| FIND-006 | Low | 疑 `--version` 不經 Python 端 | 實測：壞映像 `semgrep --version` 確實 ImportError；建議的 `import semgrep.main` 在壞映像上**成功**（抓不到），故不採用 |
| FIND-007 | Low | 探測在切換後才跑 | 移到切換前，以 `docker run --rm` 測新映像；失敗即標回舊映像（首次部署則刪除新 latest）並停止 |
| FIND-008 | Low | BIN_DIR 結尾斜線 | 去除；python3-venv 缺少時記為安裝失敗（殘餘，接受） |
| FIND-009 | Low | chown 造成映像多一份 venv | 隨 FIND-002 移除 |
| FIND-010 | Low | pip-audit 不涵蓋 semgrep venv | CI 新增 `pip-audit-semgrep` |
| FIND-011 | Low | 安裝提示仍是 `pip install semgrep` | 改為 install-tools.sh／pipx |
| NEW-001～003 | Low | 第二輪：已安裝時跳過 symlink 檢查；首次部署失敗留下壞 latest；清除舊 semgrep 時未帶 timeout | 皆已修 |

第二輪判定：Critical／High = 0；無抑制註解；無硬編碼密鑰。G3 有條件通過，相依套件 CVE 以 G5 CI 報表確認。

### CI 報表判讀（G5）
| run | commit | 判讀 |
|---|---|---|
| 37311211524 | d5aaeef | 綠燈，但 `pip-audit-semgrep` = 1：pip 24.0、setuptools 79.0.1。原因是 CI 的 venv 沒有比照 Dockerfile 升級 pip／setuptools，審到的不是映像實際的環境；trivy-image 的 Python 套件發現與基準 37209215637 **完全相同**（msgpack、setuptools 70.3.0、urllib3，既有） |
| 37311828371 | 438876a | CI venv 改為與 Dockerfile 相同步驟後：semgrep 0、pip-audit 0、**pip-audit-semgrep 0**、osv 0、trivy-fs 0、gitleaks 0；trivy-image CRITICAL 5／HIGH 190（同基準）。bearer 多出 `main.py:1590` path traversal（High）與 `main.py:1014` regex（Medium）：第 44 輪未改 `main.py`，同一 commit f0b4ceb 的兩次 CI（37172467199 有、37209215637 無）結果不同，屬 bearer 結果不穩定。人工確認為誤判：寫入路徑是 `job_dir(伺服器 id)/"upload.zip"`，不使用上傳檔名；regex 前已限制長度 ≤ 260、無巢狀量詞 |

### 實測證據（.145）
- 線上壞映像：`semgrep --version` → `ImportError: cannot import name '_ExtendedAttributes'`；opentelemetry-api 1.45.0 vs sdk 1.37.0（FastAPI 0.142.2 要求 >=1.44）。
- 新探測：壞映像 rc=1（semgrep NOT AVAILABLE）、舊映像 33d55f4 rc=0。

## [2026-10-04] 第 43 輪 — 攻擊面盤點（app/attack_surface.py 等）

### 自動掃描
| 類別 | 工具與範圍 | 結果 |
|---|---|---|
| SAST | Semgrep `p/python` + `p/javascript`（同 CI），`app/`、`tests/` | 0 項、0 錯誤 |
| Secret | Gitleaks 8.30.1（checksum 與 `scripts/fetch-vendor.sh` 固定值相符），新檔與修改的前端 | 無洩漏 |
| SCA／授權 | 無新增相依（`requirements.txt` 未變；前端未引入函式庫） | 不適用；完整 pip-audit／osv／trivy 由 CI 執行 |
| 資料流 | 人工：不可信輸入（被掃程式碼）→ 擷取 → JSON／畫面 | 見下方人工複核 |

### 引入確認
| 元件 | 授權 | 已知漏洞 | 決定 |
|---|---|---|---|
| （無新增） | — | — | 圖表為手寫 SVG；LinkFinder 只參考思路，未複製程式碼 |

### 人工複核（獨立子代理，兩輪）
| # | 嚴重度 | 問題 | 修正 | 驗證 |
|---|---|---|---|---|
| 1 | High | 前端呼叫網址未遮罩帳密；密碼含 `/` `@` `?` `#`、超長帳號、主機為空時查詢字串中的密碼外洩 | `mask_credentials` 改寫（最後一個 `@`、`?password=` 類參數遮罩），套用到所有離開模組的網址；連線字串 key 不含查詢字串 | `test_mask_credentials`（14 例）、`test_credentials_in_frontend_urls_never_leave_the_module` |
| 2 | High | YAML／Spring／Laravel 擷取超線性（200 KB 需 23–229 秒），時間預算只在檔案之間檢查 | 有界視窗、單次括號配對、堆疊掃描；每個比對迴圈 `tick()` 檢查預算 | `test_adversarial_inputs_stay_linear`（5 例）；2 MB 實測皆 < 1 秒 |
| 3 | Medium | 呼叫×路由比對 O(n×m)（5k×12.5k＝23 秒） | 依尾段索引；超時則不判斷「無人呼叫／後端找不到」並註明 | `test_matching_many_calls_and_routes_is_fast`（0.27 秒）、`test_time_budget_while_matching` |
| 4 | Medium | Laravel 無 closure 的群組誤取下一個 `{`，使未認證路由顯示「偵測到認證」 | 只接受直接傳入的 `function (...) {` closure | `test_laravel_group_without_a_closure_claims_no_routes` |
| 5 | Low | FIFO 會讓讀取卡住；檢查與讀取間可被換成 symlink | `O_NOFOLLOW|O_NONBLOCK` 開檔、fstat 確認一般檔案、讀取中限制大小 | `test_fifo_is_skipped_without_blocking`、`test_read_regular_refuses_a_symlink` |
| 6 | Low | Python 解析不可中斷、檔案清單先全部列出 | 解析前檢查期限、ast 迴圈 tick；走訪到上限即停 | `test_python_file_is_not_parsed_after_the_deadline`、`test_file_count_limit` |

複核確認成立：不執行程式、不連網、不跟隨 symlink；新端點沿用 `_may_see_scan`、MCP 走既有授權；前端一律 textContent／SVG 文字節點；判定不讀取攻擊面；無抑制註解。

### CI 報表判讀（run 37171578433，commit 17328d7；基準 run 37168663866 = 改動前程式碼）
| 工具 | 本輪 | 基準 | 判讀 |
|---|---|---|---|
| semgrep／pip-audit／osv／trivy-fs／gitleaks | 0 | 0 | — |
| bearer | critical 3、high 1、medium 1 | critical 1、high 2、medium 2 | **新增 2 筆**：`i18n.js` 鍵名 `surface.risk.frontend_secret` 被「寫死密鑰」規則誤判（鍵名含 secret）→ 依原則 7 改名為 `frontend_leak`，不加抑制；本機 bearer 2.1.1（同 CI checksum）重掃 i18n.js／attack_surface.py：0。其餘 `base.py:65`（subprocess，list 參數＋shell=False 為既有設計）、`orchestrator.py` rmtree、`mcp.py` exception、`main.py` 為**既有**，非本輪引入 |
| trivy-image | CRITICAL 5、HIGH 190 | CRITICAL 5、HIGH 190 | 完全相同，來自基底映像，非本輪引入 |

- 已知限制：bearer 對 `app/static/app.js`（約 120 KB）逾時略過（debug log：`context deadline exceeded`，第 41 輪已記錄），本輪前端新增程式碼改以獨立人工複核確認（textContent／SVG 文字節點，無 innerHTML 注入）。
- 發現：先前各輪 CI 判讀寫「程式掃描皆 0」，但基準報表顯示 bearer 一直有上述既有項目——`summary.txt` 的 0 是結束碼（bearer 以 `--exit-code 0` 執行），不是發現數。判讀必須打開報表本體。

### G5 複查（run 37172074875，commit d2d2d5d）
bearer：`base.py:65` critical、`orchestrator.py:281` high、`mcp.py:279` medium，皆為基準既有項目；i18n.js 誤報已消失。trivy-image CRITICAL 5／HIGH 190，與基準相同。其餘工具 0。→ **G5 通過**。

### G3 判定
Critical 0／High 0（已修）／無硬編碼密鑰／無新增相依 → **通過**。
