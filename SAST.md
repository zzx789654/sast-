# SAST — 安全掃描稽核紀錄（SAST Studio）

> 每次安全確認（G3）追加一則，最新在上，不覆蓋。命中密鑰只記位置與類型。
> 第 42 輪以前的紀錄在 `待修改.md` 各輪與 `lessons.md`。

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

### G3 判定
Critical 0／High 0（已修）／無硬編碼密鑰／無新增相依 → **通過**。
