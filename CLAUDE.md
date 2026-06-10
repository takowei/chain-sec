# chain-sec — 智能合約安全研究與合法 bug bounty

> 目標：在**授權範圍內**自動化掃描加密貨幣協議的鑄幣/增發類漏洞與相關弱點，產出可提交的負責任揭露報告，透過 Immunefi / Code4rena / HackenProof 等平台領取**協議方自願支付**的賞金。
> 每個 session 自動載入。**動工前先讀 `RULES-OF-ENGAGEMENT.md`，那是不可逾越的紅線。**

## 狀態（2026-06-10）

🚧 剛建立。章程與授權邊界已定，靜態分析管線待 dev-lead 實作。

## 這個專案是什麼 / 不是什麼

| ✅ 是                                        | ❌ 不是                                |
| -------------------------------------------- | -------------------------------------- |
| 對**有公開授權 scope** 的協議做靜態/動態分析 | 對任何未授權目標掃描或測試             |
| 在本地 fork 的測試鏈上驗證 PoC               | 在主網對真實合約執行任何交易           |
| 找到洞 → 不碰資金 → 負責任揭露               | 從協議轉出任何資金（無論事後是否補洞） |
| 領取協議方**自願支付**的賞金                 | 自行「拿酬勞」——那是盜竊，不是賞金     |
| 提交修補建議（patch suggestion）給協議方     | 未經授權直接改動他人合約               |

> **唯一合法的報酬路徑**：協議方在 bug bounty 合約條款下，於你負責任揭露後**主動付款**。錢從對方手上來，不從鏈上自取。這條紅線寫死在 RULES-OF-ENGAGEMENT.md，違反即停止專案。

## 技術棧

Python 3.11+，ruff lint，pytest 測試。
外部工具（dev-lead 接入時安裝）：Slither、Mythril、Aderyn（靜態分析）；Foundry/anvil（本地 fork PoC）。

## 漏洞焦點（鑄幣/增發為主）

- Unchecked / unauthorized `mint()`（缺 access control、缺 cap 檢查）
- Integer overflow/underflow 導致超額鑄造（舊 Solidity / unchecked block）
- Reentrancy 導致重複鑄造或重複領取
- 供應量會計錯誤（totalSupply 與實際餘額不一致）
- Access control 缺陷（onlyOwner/role 缺失或可繞過）
- 預言機操縱導致的鑄造/清算套利
- Proxy/upgrade 邏輯漏洞（可被改寫鑄幣邏輯）

## 規劃目錄結構

```
RULES-OF-ENGAGEMENT.md   ← 授權紅線（最高優先，先讀）
src/
  scanners/      ← Slither/Mythril/Aderyn 包裝與 mint-pattern 規則
  targets/       ← 授權目標分流（只收有公開 scope 的協議）
  poc/           ← 本地 fork PoC harness（anvil，禁主網）
  report/        ← 負責任揭露報告產生器
tests/           ← pytest
disclosure-sop.md ← 揭露與領賞標準流程（待建）
```

## 委派

| 任務                                      | 負責                                 |
| ----------------------------------------- | ------------------------------------ |
| 紅線/授權邊界/SOP 文件                    | 主對話（Root 層，不下放）            |
| 靜態分析管線、PoC harness、報告產生器實作 | dev-lead                             |
| 授權目標分流（讀 Immunefi 公開 scope）    | general-purpose agent（S2 公開資訊） |
| 跑掃描、回報結果                          | test-runner（worktree）              |

## 常用指令

```bash
python -m pytest
ruff check src
ruff format src
```

## 下一步

- [ ] dev-lead：實作 `src/scanners/` Slither 包裝 + mint-pattern 規則集
- [ ] dev-lead：`src/poc/` anvil fork harness（硬性禁止主網 RPC）
- [ ] general-purpose：彙整 Immunefi 上有 mint-related scope 的授權目標清單
- [ ] 主對話：撰寫 `disclosure-sop.md`（揭露模板 + 領賞流程）
