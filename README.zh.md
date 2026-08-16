# SAST Studio

> [English README](README.md)

一頁搞定六個**免費**資安掃描器。指向一份程式碼，它就會跑 **Semgrep**、**Bearer**、
**Trivy**、**npm audit**、**OSV-Scanner** 與 **Gitleaks**，然後把所有發現彙整成
一張依嚴重度排序的報表——不必分別安裝每個工具、記它們的參數、或讀六種不同格式的輸出。
六個工具全部免費使用（不需付費授權）。

| 工具 | 做什麼 | 類型 |
|------|--------|------|
| **Semgrep** | 基於規則的靜態程式碼分析（Python 引擎） | SAST |
| **Bearer** | 語意／資料流 SAST，找安全與隱私風險 | SAST |
| **Trivy** | 相依弱點 ＋ 密鑰 ＋ IaC 設定錯誤 | SCA／密鑰／IaC |
| **npm audit** | Node 相依套件弱點（npm 資料庫） | SCA |
| **OSV-Scanner** | 多生態系相依套件對比 OSV.dev | SCA |
| **Gitleaks** | 掃描硬編碼的密鑰／憑證 | 密鑰 |

> **為什麼不用 CodeQL？** 它的 CLI 只有對開源／研究免費，掃描私有程式碼需要付費的
> GitHub Advanced Security 授權。改用 **Bearer**（語意 SAST）與 **Trivy**（另補上
> IaC 設定錯誤掃描）零成本取代。這裡六個工具全部免費。

## 架構

```
瀏覽器 ──► nginx（反向代理）──► FastAPI ──► Orchestrator ──► 6 個 Adapter ──► 工具
            :8080  →  :8000       REST API     （工作管理）    （一工具一個）
```

- **nginx 反向代理**：Docker 佈署時 nginx 是對外入口（`:8080`），轉發給內網的 FastAPI 後端；
  後端連接埠不對主機公開。
- **Adapter 模式**：每個工具一個 adapter，只做三件事：*偵測可用性*、*執行*、*把輸出正規化*
  成統一的 `Finding` 格式。Orchestrator 不需要理解任何工具的原生格式。
- **優雅降級**：沒安裝的工具會標示為「未安裝」並附安裝指引——掃描照樣跑其他工具。
- **專案盤點 ＋ 語言防呆**：每次掃描會回報專案的檔案數、大小與語言分佈；每個工具宣告它
  需要什麼，本機路徑可在掃描前先「檢查專案」看哪些工具不適用（及原因）。
  （刻意顯示誠實的盤點，而非假的逐檔進度——這些工具是批次掃描器，沒有可靠的逐檔進度串流，
  而且 SCA 工具是掃相依鎖定檔而非逐檔。）
- **簡單至上**：記憶體工作佇列、HTTP 輪詢看進度、無框架的原生 JS 前端。沒有資料庫、沒有建置步驟。
- **中／英雙語**：介面預設中文，右上角可一鍵即時切換中／英。

## 快速開始

### 方式 A — 一鍵安裝（推薦）

`setup.sh` 會自動安裝所有東西（系統相依、含全部相依套件的 Python 虛擬環境、以及六個
掃描工具），跑測試驗證建立成功，並告訴你怎麼啟動：

```bash
./setup.sh              # 完整本機安裝：venv + 相依套件 + 掃描工具 + 驗證
./setup.sh --run        # …並直接在 http://localhost:8000 啟動服務
```

其他參數：`./setup.sh --docker`（改用 Docker Compose 建立並啟動）、`--no-tools`
（只裝 Python app，掃描工具會優雅降級）、`--no-venv`（裝進當前環境）、`--help`。

### 方式 B — Docker（Linux 伺服器免費）

Docker Engine 與 Compose 在 Linux 上免費（Apache-2.0）；只有 Docker **Desktop** GUI
對大型企業收費，而伺服器佈署不需要它。

```bash
docker compose up --build
# 開啟 http://localhost:8080   （nginx → FastAPI 後端）
```

會啟動兩個服務：**nginx**（對外，8080 埠）反向代理到**後端**（內網）。後端映像檔內建六個
掃描器，全部免費。要用標準 80 埠，把 `docker-compose.yml` 的 nginx 對應改成 `80:80`。

### 方式 C — 手動本機安裝

```bash
pip install -r requirements.txt
bash scripts/install-tools.sh        # 盡力安裝各掃描器
uvicorn app.main:app --reload        # http://localhost:8000
```

任何你沒安裝的工具就只會顯示為未安裝。

## 使用方式

1. **選擇來源**：上傳 `.zip`、貼 **Git 網址**、或給一個**伺服器本機路徑**。
2. **勾選工具**（未安裝的會反白停用）。每個工具會顯示中文說明與它需要什麼；本機路徑可先按
   **檢查專案**看檔案／語言盤點與哪些工具不適用（不適用的會標橘色警告）。
3. **開始掃描。**
   - **本機路徑**會直接開始（本來就能先檢查）。
   - **上傳或 Git 網址**會先抓取並盤點，然後**暫停等待確認**：你檢視檔案／語言盤點與不適用
     工具的警告後，再按**執行掃描**（或**取消**，會清掉已準備的暫存工作區）。
4. **看進度**：進度條 + 每個執行中的工具會顯示轉圈與經過秒數；工具一完成就顯示它的發現。
5. **讀報表**：嚴重度統計（嚴重 → 資訊）、每個工具一列（發現數／耗時，或未安裝／不適用及原因）、
   每個發現一張卡片（嚴重度、工具、檔名:行號、CWE／OWASP 標籤）。可用嚴重度、工具、檔名篩選。
6. **切換語言**：右上角一鍵切換**中文 / English**（選擇會被記住）。

> 發現的內文來自掃描工具本身，所以是該工具的原文（多為英文）；介面會在旁邊補一行中文嚴重度說明。

### REST API

介面只是這個小型 JSON API 的前端，方便你寫腳本／接 CI：

| 方法與路徑 | 用途 |
|---|---|
| `GET /api/tools` | 工具可用性 + 每個工具需要什麼 |
| `POST /api/inspect` | 盤點本機路徑 + 每工具適用性 |
| `POST /api/scans` | 開始掃描（`source_kind`=`upload`/`git`/`path`、`tools`…） |
| `GET /api/scans/{id}` | 掃描狀態、進度、結果 |
| `POST /api/scans/{id}/confirm` \| `/cancel` | 執行或放棄等待確認的掃描 |
| `GET /api/health` | 健康檢查 |

## 工具本身的安全

它會跑別人的程式碼過掃描器，所以自身的加固很重要：

- **不經 shell**：所有外部指令都走單一 `run_command` 收斂點：list 參數、`shell=False`、一律有 timeout。使用者輸入永不拼接進 shell。
- **Zip Slip／Zip Bomb 防護**：逃出目的地的壓縮檔成員會被拒絕；解壓大小與檔案數有上限。
- **Git clone 有界限**：只允許 `http`/`https`、不互動提示、depth-1、有 timeout。
- **密鑰遮罩**：Gitleaks 的比對結果在送到 API／UI 前先遮罩，報表不會再洩漏密鑰。
- **隔離工作區**：每次掃描在自己的目錄執行，結束後清理。

## 設定

全部可選，透過環境變數（見 `.env.example`）：工作區目錄、各工具 timeout、上傳／解壓上限、
`SAST_ALLOW_LOCAL_PATH`、允許的 git scheme、以及 `SAST_SEMGREP_RULES`
（`auto` 需要網路；離線可指向本機規則集）。

## 開發

```bash
pip install -r requirements.txt pytest
pytest -q          # 測試在未安裝任何掃描器下也能跑
```

測試會把 subprocess 層造假、並直接測純解析函式，所以又快又不依賴環境。API 測試會啟動真正的 app。

## 專案文件

`CoreMain.md`（專案中心思想）、`待修改.md`（當前計畫／關卡狀態）與 `lessons.md`（每輪輪結）
記錄了產生本專案的 secure-SDLC 流程。
