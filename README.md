# chain-sec — 智能合約安全靜態分析工具（研究 / 防禦用途）

基於 Slither 的智能合約掃描管線，外加自製「鑄幣 / 取整一致性」不變量偵測規則，針對 ERC-4626 類金庫的會計漏洞面。**僅用於授權目標與防禦研究**——交戰守則見 `RULES-OF-ENGAGEMENT.md`。

## 設計重點

- **自製偵測器**：
  - `MINT-*`：無上限/無存取控制的鑄幣路徑；含 interface / abstract / view / 非 public 過濾以**降低誤報**（對高度審計協議實測，把 CRITICAL 誤報從數百降到個位數）。
  - `INV-*`：配對代幣單邊鑄造、取整方向是否偏袒用戶、鑄幣量是否依賴可操縱 rate——協議無關、可複用。
- **端到端 CLI**（`scan.py`）：單檔與 project mode；自驅 `solc-select` 選版 + remapping，不執行目標程式碼（紅線）。
- **誤報 triage 方法論**：對成熟協議實掃 → 人工複核 → 記錄為何是 FP / out-of-scope（誠實結論：通用規則對多輪審計協議挖不到東西，需專屬 invariant 才有產出）。

## 技術棧

Python、[Slither](https://github.com/crytic/slither)、solc（透過 solc-select）。

## 快速開始

```bash
source scripts/env-vars.sh          # 必要：設定 CHAIN_SEC_SOLC 等路徑
.venv/bin/python -m pytest -q       # → 75 passed（2026-06-24 實測）
.venv/bin/python scan.py <path> --project
```

> ⚠️ 測試需先 `source scripts/env-vars.sh`，否則 CLI/solc 相關測試會因環境未設而假失敗。

## 架構

```
scan.py        CLI：單檔 / project mode 掃描入口
src/           偵測器規則（MINT-* / INV-*）+ Slither 整合
tests/         75 測試（偵測器、過濾、CLI、project mode、禁主網守衛）
docs/          invariant 規格、設計文件
RULES-OF-ENGAGEMENT.md   授權與責任揭露紀律
```

## 倫理與授權

- **只掃授權範圍內的目標**；不對未授權合約執行掃描或揭露。
- 不在掃描中執行目標程式碼。
- 漏洞循負責任揭露流程處理。

## 狀態

🟢 管線可用、75 測試全綠（需 env）。定位為防禦/學習研究工具；不含任何目標清單或漏洞細節於版控。
