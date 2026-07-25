# 把 EveAegis 接到本地 Agent

EveAegis 以 stdio transport 提供 MCP server。啟動方式：

```bash
aegis serve
```

或不安裝套件直接跑：

```bash
PYTHONPATH=src python -m eveaegis.mcpserver.server
```

## Claude Code

```bash
claude mcp add eveaegis -- aegis serve
```

或手動寫入 `.mcp.json`：

```json
{
  "mcpServers": {
    "eveaegis": {
      "command": "aegis",
      "args": ["serve"],
      "env": { "EVEAEGIS_CONFIG": "D:/path/to/eveaegis-mcp/config/config.yaml" }
    }
  }
}
```

## 其他 MCP 客戶端

任何支援 stdio 的客戶端都用同一組指令：`command = aegis`、`args = ["serve"]`。設定檔位置以環境變數 `EVEAEGIS_CONFIG` 指定。

---

## Agent 看得到什麼、看不到什麼

這是刻意設計的邊界，不是尚未完成的功能。

| 工具集 | v0.1 狀態 |
|---|---|
| §13.1 Inventory | 完整開放（唯讀） |
| §13.2 Provenance | 完整開放（唯讀分析） |
| §13.3 Classification | 開放，`apply` 預設為 false（提案而非套用） |
| §13.4 Governance | 只開放 `evaluate_action_policy` / `explain_action_policy` |
| §13.5 Metadata | 只開放唯讀目錄產生 |
| §13.6 Documentation | 未開放 |
| §13.7 Administration | **永不對一般 Agent 開放** |

Plan／Approve／Execute 屬於 Phase 4-5，它們**不存在**於工具清單裡，而不是存在但會拒絕。沒有註冊的工具就無法被呼叫，不管政策檔怎麼寫。

**人類專屬動作**：確認來源判定（`aegis review set`）只在 CLI，沒有任何 agent 可呼叫的對應工具 — 依白皮書 §19.3，這是人的決定。

## 每一次呼叫發生了什麼

```
Agent 呼叫工具
  → 組成 ActionRequest（含 actor、targets、requested_level）
  → PolicyEngine.evaluate()  ← 五條公理在這裡變成程式碼
  → 拒絕：回傳 PolicyDecision（不是例外訊息），寫入 tool_denied 稽核事件
  → 允許：執行 handler，寫入 tool_completed 稽核事件（含憑證型態與範圍）
```

被拒絕時回傳的是**決策物件本身**，agent 可以讀懂為什麼被擋、風險等級是什麼、需要什麼審批。請不要換個說法重試。
