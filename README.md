# EveAegis — AI-Native GitHub Portfolio Governance MCP

**AI 原生 GitHub 軟體資產組合治理 MCP**

當一個人或一間公司擁有數十至數百個倉庫時，真正需要的已不再是 GitHub 操作工具，而是一個能理解**專案身分、來源、風險與責任**的治理控制平面。

EveAegis 不是 Git GUI、不是 GitHub Desktop 替代品、不是 REST API 包裝器，也不會讓 AI Agent 直接持有你的 GitHub 憑證。

```
Inventory → Origin & Provenance → Classification → Policy
         → Plan → Approval → Execution → Audit
```

實作自技術白皮書《AI 原生 GitHub 多倉庫治理 MCP v0.1》（Neo.K，一言諾科技有限公司／EveMissLab，2026-07-23）。

---

## 三條不可跨越的邊界

整套系統存在的理由，就是守住這三條線：

| 邊界 | 意義 |
|---|---|
| `Dependency ≠ Upstream Source` | `node_modules/` 不是你的上游。依賴、vendored、generated 內容在計算「保留了多少上游」之前就必須被分離。 |
| `Agent Capability ≠ Agent Authorization` | Agent 能呼叫某個工具，不代表它被授權執行。能力 ⊆ 政策授權 ⊆ GitHub 安裝權限。 |
| `Machine Inference ≠ Public Legal Claim` | 機器推論出「這大概是原創的」，不等於可以對外宣稱原創。未知來源永遠不自動宣稱。 |

## 五條安全公理

1. **代理不持有長期憑證** — Agent 只提交動作請求，憑證由 broker 掌握，短期、限定範圍、每次使用都檢查到期。
2. **能力不等於授權** — `Agent Capability ⊆ Policy Authorization ⊆ GitHub Installation Permission`。
3. **所有寫入先形成計畫** — `Inspect → Plan → Preview → Approve → Apply`。
4. **未知來源不得自動公開宣稱原創** — 內部判定與對外標籤永遠分離儲存。
5. **高風險操作必須縮短權限生命週期** — 風險↑ ⇒ token 範圍↓、存活時間↓、審批強度↑。

---

## 安裝

需求：Python 3.11+、Git、[GitHub CLI](https://cli.github.com/)（`gh_cli` 憑證後端使用）。

```bash
git clone https://github.com/kakon77777-commits/eveaegis-mcp.git
cd eveaegis-mcp
pip install -e ".[dev]"
cp config/config.example.yaml config/config.yaml
```

確認 GitHub CLI 已登入：

```bash
gh auth status
```

---

## 憑證模型

`config/config.yaml` **永遠不放密鑰**。憑證在呼叫當下由 broker 取得，並包在一個會拒絕序列化、`repr` 會遮蔽、過期即失效的 `Grant` 裡。

| 後端 | 憑證型態 | 最高範圍 | 需要的前置作業 |
|---|---|---|---|
| `gh_cli`（預設） | GitHub CLI keyring 的委派 OAuth token | `write_metadata` | 無，`gh auth login` 即可 |
| `github_app` | Installation Token（GitHub 自身即會過期） | `admin` | 需在 github.com 註冊 GitHub App 並安裝 |

`gh_cli` 誠實地說明它是什麼：它滿足公理 1 的**結構面**（Agent 永遠碰不到憑證、每次使用都有範圍與到期、全程稽核），但**不滿足密碼學面**——底層 token 仍是長期且帳號級的。因此這個後端硬性拒絕發出高於 `write_metadata` 的範圍。要進入程式碼寫入階段，必須改用 GitHub App 後端。

---

## 專案結構

```
src/eveaegis/
├── taxonomy.py          §5-§17 封閉詞彙表（每個都有 UNKNOWN 成員）
├── models.py            §4-§16 領域實體（pydantic）
├── db.py                §20 SQLite schema，audit 表有 append-only 觸發器
├── config.py            設定載入（不含任何密鑰）
├── core.py              GovernanceCore — 所有模組共用的接線
├── credentials/         公理 1 的執行點：broker + Grant + 兩個後端
├── githubapi/           REST/GraphQL client，範圍守衛 + 主動速率限制
├── audit/               §18 hash-chained append-only 稽核帳本
├── inventory/           Phase 1 資產目錄同步
├── provenance/          Phase 2 來源血緣引擎
├── classification/      Phase 3 分類引擎
├── policy/              §11-§12, §15 RBAC/ABAC + 風險引擎
└── mcpserver/           §13 高階 MCP 工具集
```

---

## 對真實 portfolio 的實跑結果

v0.1 對 `kakon77777-commits` 的 **55 個倉庫**做過完整唯讀實跑（sync → origin → classify），167 筆稽核事件、雜湊鏈驗證通過：

| | |
|---|---|
| 倉庫 / 快照 | 55 / 216 |
| 正式 Fork | 16 — 全部 `READ_ONLY` + `NEEDS_REVIEW` + 零原創宣稱 |
| `ORIGINAL_WITH_DEPENDENCIES` | 28（信心 0.88） |
| `DERIVATIVE_PROJECT` / `PLUGIN_OR_EXTENSION` | 1 / 2 |
| 來源無法判定 | 1 — 降級為 `READ_ONLY` |
| 授權狀態 | CLEAR 8、NOTICE_REQUIRED 5、ATTRIBUTION_REQUIRED 3、REVIEW_REQUIRED 8、UNKNOWN 31 |

值得注意的是**引擎自己抓到的三個錯誤**，因為它們都是同一條邊界的實例：

- 某專案因 `package.json` 的 devDependencies 有 `vite-plugin-svgr`，被判成「外掛專案」— 把**依賴當成專案自身性質**
- 某專案因 NOTICE 致謝了靈感來源，被判成來源不明 — **致謝不等於血緣**
- 兩個專案因為有 `ai/governance/license.md`（自己寫的 AI 權利宣告頁）被送去法務審查 — **談論授權的文件不是被嵌入的第三方授權**

三個都已修正並有回歸測試。第三個修正後保留了 `documentary_license_files` 欄位：被排除的東西仍然看得見，讓覆核的人看到的是判斷，而不只是判斷的結果。

## 第一版明確不做

自動合併程式碼 PR、自動刪除倉庫、自動改 License、自動改 Visibility、自動搬移 Organization、自動操作 Secrets、執行倉庫任意程式、對外宣稱百分之百原創、跨全網程式碼抄襲判定、任何法律結論。

分析工作區永遠不執行被分析倉庫裡的程式（`npm install`／`pip install`／`make`／build script／Git hooks 一律禁止）。

---

## 用法

```bash
aegis doctor                      # 檢查設定、憑證、資料庫、稽核鏈
aegis sync                        # Phase 1：同步資產目錄
aegis origin --all                # Phase 2：來源判定（--deep 加做 commit/blob 比對）
aegis classify --all --apply      # Phase 3：分類
aegis matrix                      # §19.2 Repository Matrix
aegis review list                 # 待人工覆核的來源判定
aegis review set <repo> confirm   # 確認判定（僅限人類，agent 無此工具）
aegis policy <tool> --explain     # 問政策引擎「如果做這件事會怎樣」
aegis audit verify                # 驗證雜湊鏈
aegis serve                       # 以 MCP stdio 提供給本地 agent
```

接到 Claude Code 等 MCP 客戶端的方式見 [docs/MCP.md](docs/MCP.md)。

## 目前進度

Phase 0–3 完成（安全骨架、Inventory、Origin & Provenance、Classification + Policy）。

Phase 4（Metadata Governance）與 Phase 5（Safe Documentation PR）尚未實作 —
它們需要寫入權限，而寫入權限需要先把憑證後端換成 GitHub App。在那之前
`governance.read_only` 維持 `true`，所有寫入工具**不存在於工具清單**，而不是存在但會拒絕。

## 授權

MIT © 2026 EVEMISS TECHNOLOGY CO., LTD.（一言諾科技有限公司）／Neo.K（許筌崴）

實作自技術白皮書《AI 原生 GitHub 多倉庫治理 MCP v0.1》。與白皮書的唯一刻意差異：
§5.4 的 `Criticality` 增加了 `UNKNOWN` 成員，理由見 `src/eveaegis/taxonomy.py` 模組註解。
