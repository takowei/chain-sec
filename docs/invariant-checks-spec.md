# 供應量會計 Invariant 檢查器 — 設計規格

> 主對話（S0 安全設計）產出，2026-06-10。dev-lead 依此實作於 `src/scanners/invariant_checks.py`。
> 動機：通用 slither 掃高度 audited 協議（Pendle）零產出（見 company-status memory 的 31 HIGH 複核結論）。
> 鑄幣類賞金的命脈是**語義會計 invariant**——通用 detector 看不到的「供應量守恆 / 配對對稱 / 取整方向」。

## 設計原則

1. **不做形式化驗證**。用 Slither 的 SlithIR / AST 找出**可疑模式**，輸出供人工複核的 candidate，不宣稱「確定漏洞」。每條規則明確標注精度等級。
2. **協議無關的規則優先**。規則寫成可套用到任何 in-scope 目標（Pendle PT/YT、Euler ERC-4626 share、Usual 等），不寫死 Pendle 合約名。配對代幣 / vault share↔asset 是共通結構。
3. **誤報可接受、漏報不可接受**。這是「縮小人工複核面」的工具，寧可多標幾個讓人看，不可漏掉真的。但要附足夠 context（哪一行、哪個變數）讓複核快速排除。
4. 輸出沿用既有 `Finding` model（`src/scanners/models.py`），severity 用 MEDIUM（candidate 性質，非確證），rule_id 用 `INV-*` 前綴，與 MINT-\* 區隔。

## 背景：Pendle 的核心會計（規則的語義來源）

確認自源碼（`contracts/core/YieldContracts/`、`StandardizedYield/SYUtils.sol`）：

- **PT/YT 配對鑄造對稱**：`YieldToken._mintPY` 每次都 `_mint(YT, amountPY)` **緊接** `IPPrincipalToken(PT).mintByYT(receiver, amountPY)`——同一個 `amountPY`。PT 的 `mintByYT`/`burnByYT` 是 `onlyYT`。任何打破「PT 與 YT 等量成對鑄造/銷毀」的路徑 = 可憑空造出不對稱供應 = critical。
- **鑄幣量靠 index 換算**：`amountPY = SYUtils.syToAsset(index, amountSy) = syAmount * exchangeRate / 1e18`（向下取整，對協議有利）。`index = _pyIndexCurrent()` 是累積型，非 spot。
- **取整方向**：`SYUtils` 同時有普通版（向下，floor）與 `*Up` 版（向上，ceil）。給用戶的量用 floor、向用戶收的量用 ceil = 對協議有利。**方向反了** = 每次 round-trip 漏出一點，可反覆套利放大供應。

## 規則定義

### INV-001 — 配對代幣鑄造/銷毀的單邊性（精度：中，需人工複核）

**目標**：找出「鑄造/銷毀了某代幣，但沒有對稱地鑄造/銷毀其配對代幣」的函式。

**靜態偵測法（Slither SlithIR）**：

- 對每個具體合約（`contract.is_interface == False`）的已實作函式（`function.is_implemented`），蒐集函式體內所有 `_mint`/`_burn`/`mint*`/`burn*` 的呼叫（內部呼叫 + external high-level call，用 SlithIR 的 `InternalCall` / `HighLevelCall` 節點，`call.function.name`）。
- 標記 candidate 的條件：函式內**只出現 mint 類呼叫而無對應 burn**（或反之），且該函式對外可達（public/external，或被 public/external 呼叫鏈到達）。
- 對「配對」的啟發式：若合約持有兩個 token 位址 state var（如 `PT`、`YT`、`SY`），而某函式只動其中一個的 mint/burn → 高度可疑。
- **輸出**：合約、函式、命中的 mint/burn 呼叫行號、未配對的那一邊。

**精度說明**：會誤報（很多正當函式只動單邊，配對在別的函式）。價值在快速定位「鑄幣權力點」清單供人工掃。severity = MEDIUM。

### INV-002 — 鑄幣/贖回的取整方向偏向用戶（精度：中高，這是最值錢的規則）

**目標**：找出「給用戶的量用了向上取整（ceil/Up），或向用戶收的量用了向下取整（floor）」——對用戶有利的取整在鑄贖路徑上可被反覆套利。

**靜態偵測法**：

- 識別換算 helper 的 floor / ceil 變體：名稱含 `Up`、或實作含 `+ ONE - 1`/`+ denom - 1`/`divUp`/`mulDivUp`/`rawDivUp`（ceil）；其餘除法為 floor。dev-lead 先用名稱啟發式（`*Up`、`*Down`、`divUp`/`divDown`），可選擇進一步看 PMath 的實作。
- 在 mint 類函式（鑄出給用戶 / 算 amountOut）中，若**給用戶的 amountOut 走 ceil** → candidate。
- 在 redeem/burn 類函式中，若**向用戶收的 amountIn 走 floor**（用戶少付）→ candidate。
- **輸出**：函式、用到的取整 helper、方向判斷、為何偏向用戶。

**精度說明**：方向語義（誰得利）需要知道該變數是 amountIn 還是 amountOut——dev-lead 用變數名啟發式（`amountOut`/`netOut`/`toUser` vs `amountIn`/`netIn`/`required`）+ 是否流向 `_mint`/`_transferOut(token, user, ...)` 來判斷。這條規則命中時可利用性高，優先做好。severity = MEDIUM（命中後人工複核可升 HIGH）。

### INV-003 — 鑄幣量依賴可操縱的 rate/index（精度：中）

**目標**：鑄幣/贖回量 = f(exchangeRate)，若 rate 來自可在同筆交易內操縱的來源（spot 餘額、`latestRoundData` 即時價、AMM reserve）而非累積型 stored index，則鑄幣量可被閃電貸操縱放大。

**靜態偵測法**：

- 找鑄幣量計算依賴的 rate/index 變數，回溯其資料來源（SlithIR data dependency，Slither 有 `data_dependency` 模組）。
- 來源命中以下 = candidate：`.latestRoundData()`、`.getReserves()`、`balanceOf(address(this))`/`_selfBalance` 直接當價、`.price()`/`.getRate()` 的 external call 且非 view-cached。
- 來源是累積型（名稱含 `index`、`cumulative`、`stored`、有 `lastBalance`/checkpoint 機制）→ 排除。
- **輸出**：函式、rate 來源、資料依賴路徑。

**精度說明**：data dependency 回溯會有斷點（跨合約），命中需人工確認來源確實可操縱。severity = MEDIUM。

## 實作要求（給 dev-lead）

- 檔案：`src/scanners/invariant_checks.py`，提供 `run_invariant_checks(slither_obj) -> list[Finding]`，由 `slither_wrapper.py` 在 project mode 掃描後呼叫合併進 findings。
- 用既有 Slither `Slither`/`Compilation` 物件（不重複編譯）。以實際 Slither 0.11.5 API 為準（`compilation_unit.contracts`、`function.nodes`、SlithIR operations、`slither.analyses.data_dependency`），**動手前先查 API，不憑記憶**。
- 三條規則各自獨立函式、各自可關閉（config flag）。INV-002 優先級最高，先做且測試最紮實。
- 測試：在 `tests/fixtures/` 加正樣本（故意單邊鑄造 / 故意 ceil 給用戶 / 故意 spot-rate 鑄幣）與負樣本（Pendle 風格正確會計），pytest 驗證各規則命中正樣本、不命中負樣本。
- 既有測試保持綠（先 `source scripts/env-vars.sh`）。ruff 過。小步提交。
- 完成後對 Pendle 重掃，回報 INV-\* 各命中數與命中清單（供主對話人工複核）。

## 誠實的預期

Pendle 主代碼這三條 invariant 幾乎篤定被官方測過 → 對 Pendle 大概率仍零真漏洞。本規格的真正價值：

1. **可複用資產**——套到 Euler($7.5M, ERC-4626 share↔asset)、Usual($16M)、Pendle 較新的 cross-chain/limit 模組。
2. INV-002（取整方向）是 vault/換算類協議**最常見的真漏洞型態**，做好它在其他目標上才有 edge。

> 下一步順序：①等 MINT-001 FP 修完（避免 scanners 目錄衝突）②發 dev-lead 實作本規格 ③換目標（Euler/Usual）重跑全套規則。
