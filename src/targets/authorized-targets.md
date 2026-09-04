# 授權目標清單 — 鑄幣/增發類漏洞偵查

> **用途**：公開 bug bounty 平台上「有 in-scope 鑄幣/供應量/staking 增發類漏洞、且目前 active」的授權目標編目。
> **僅供合法靜態分析使用**。動工前先讀 `../../RULES-OF-ENGAGEMENT.md`。本清單只記錄**公開**的上架資訊，未與任何 live 系統互動、未掃描、未測試。
> **編目日期**：2026-06-10
> **資料來源**：各平台公開 scope 頁面（每筆標 URL）。賞金數字與 scope 重點均引自公開頁面；不確定處標「待確認」。

## 重要免責

- 賞金數字隨平台更新而變動，提交前**務必**重新核對該目標當下的 scope 頁面。
- 「原始碼位置」欄記錄公開 GitHub repo；若 repo 與 scope 頁所指版本/commit 不一致，以 scope 頁釘選的 commit 為準（多數平台會釘 commit hash，需逐一到頁面確認）。
- 所有目標的共同 out-of-scope（鐵律層級）：禁止主網/公測網測試（只能本地 fork）、禁止 DoS、禁止社工、known issues 與先前已揭露的不計。
- Code4rena 已宣布結束營運（active 競賽會跑完），故本清單以 Immunefi / Cantina / Sherlock 為主，不新增 C4 競賽目標。

---

## 🎯 進行中競賽（實際入場 — 最高優先）

### dreUSD（DRE App）— Sherlock 競賽【校準場，2026-06-11 入場】

- **平台 / scope URL**：Sherlock 競賽 — https://audits.sherlock.xyz/contests/1259
- **授權日 / 授權性質**：2026-06-11。**競賽 = 公開授權靜態審查**（平台機制即邀請審計），落在紅線1 in-scope。
- **獎池**：**$60,000 USDC**。Sherlock 計分：High=10 pts、Medium=3 pts，duplicate 按比例縮減；Low/Info 另有保留池（確切分配待從頁面確認）。
- **scope（引自公開頁）**：dreUSD ERC-20 穩定幣（1:1 贖回 USDC，由現金等價物+不動產信貸+短期擔保貸款背書）、**dreUSDs ERC-4626 vault**、on-chain **mint / redemption / rewards distribution 邏輯**、LayerZero **OFT adapters**。
- **原始碼**：⚠️ **待確認**——Sherlock 慣例為 `github.com/sherlock-audit/<YYYY-MM-name>`，未經頁面確認不臆造。**需 Root clone（`--ignore-scripts`）或解 WebFetch 才能取得正確 repo 與 scope 釘選 commit。**
- **截止日**：⚠️ **待確認**——開工前必須確認競賽仍開放且剩餘天數足夠（深審需數日）。
- **鑄幣/會計重點（我們的 edge 面）**：①穩定幣 mint/redeem 1:1 會計與 peg 維持；②**ERC-4626 share↔asset 取整方向**（INV-002 本行，vault 類最常見真漏洞）；③rewards distribution 的供應量一致性；④**OFT 跨鏈鑄造**——LayerZero OFT 的 mint/burn 在來源鏈與目標鏈的供應量守恆是高風險面（跨鏈訊息重放/不對稱鑄造）。
- **out-of-scope**：待從 scope 頁確認（Sherlock 通例：禁主網測試、DoS、社工、known issues 不計）。**提交前以頁面釘選 commit 為準，非 HEAD。**

---

## 排序清單（按「鑄幣漏洞可能性 × 賞金 × 原始碼可取得性」）

### 1. Pendle Finance（Cantina）⭐ 最優先

- **平台 / scope URL**：Cantina — https://cantina.xyz/bounties/fb1f1c54-0cb9-4201-8791-fb1e78e6e600
- **賞金**：Critical 最高 **$1,000,000**（capped 10% 經濟影響）；High **$10,000–$100,000**
- **原始碼**：**公開** — https://github.com/pendle-finance/pendle-core-v2-public （含 audits 目錄）
- **鑄幣相關重點**：PT / YT / SY 收益代幣的**鑄造/贖回機制**正是掃描器專長；market factory、staking 與 reward 分配系統皆 in-scope。供應量會計（PT↔YT↔SY 換算）是高風險面。
- **out-of-scope**：底層 yield source 被攻破而未經 Pendle V2 合約利用者不計；需外部協議（flash loan/DEX 操縱）的攻擊會降級，除非 Pendle 使用者直接受損；非 whitelisted/inactive market（除非影響系統層）。設有 SEAL Safe Harbor。
- **為何優先**：mint 邏輯豐富 + 七位數賞金 + 原始碼完全公開且文件齊全 → 三軸俱佳。

### 2. Euler（Cantina）⭐

- **平台 / scope URL**：Cantina — https://cantina.xyz/bounties/4d285eee-602e-440a-845e-25e155cec26a
- **賞金**：最高 **$7,500,000**（USDC + rEUL + USUAL；對影響 USL vaults 的發現有 boosted reward）— 具體 critical/high 分級**待確認**（需到頁面核對）
- **原始碼**：**公開** — https://github.com/euler-xyz/euler-vault-kit （EVK）；亦含 EVC、EPO（Euler Price Oracle）。fixes repo：https://github.com/euler-xyz/evk-cantina-fixes
- **鑄幣相關重點**：EVK 是 **ERC-4626 vault**（share 代幣鑄造/銷毀）+ 借貸；share↔asset 換算、債務會計是供應量錯誤高發區。scope 限「deployed vaults 直接依賴的 master/main 分支合約」。
- **out-of-scope**：High 定義為可永久鎖定合約或從所有使用者提款/核心功能損壞；僅特定條件下發生的損失歸 Medium。需到頁面核對完整 OOS。
- **為何優先**：ERC-4626 share 鑄造邏輯 + 八位數賞金池 + 原始碼公開。

### 3. Usual（Sherlock）⭐

- **平台 / scope URL**：Sherlock — https://sherlock.xyz/bug-bounties （另見 https://tech.usual.money/security-and-audits/bug-bounty）
- **賞金**：Critical **$16,000,000**（目前公開最大單一賞金）— high 級距**待確認**
- **原始碼**：合約文件在 https://tech.usual.money/smart-contracts/ ；**公開 GitHub repo 待確認**（需到 tech.usual.money / Sherlock scope 頁找釘選 repo+commit）。已部署於 **Ethereum Mainnet only**。
- **鑄幣相關重點**：直接命中本掃描器專長 —— **USD0 ERC20 stablecoin 的 mint/burn**（宣稱 ≥1:1 RWA 抵押）、USD0++（yield-bearing）、USUAL 治理代幣 reward 增發、ETH0 合成資產鑄造。stablecoin issuance 與供應量抵押會計是核心 in-scope。
- **out-of-scope**：非 Ethereum mainnet 的部署（其他網路/測試網）全部 OOS。Sherlock 對 severity/reward 有最終裁量權。
- **為何優先**：mint 漏洞可能性極高（純 stablecoin 鑄造協議）+ 賞金天花板最高。**唯一扣分**：需先確認公開原始碼位置（合約已上鏈，最差情況可從鏈上拿 verified source）。

### 4. Olympus DAO（Immunefi）

- **平台 / scope URL**：Immunefi — https://immunefi.com/bug-bounty/olympus/information/
- **賞金**：Tier 2（treasury 直接經濟損失）最高 **$3,333,333**；Tier 1（使用者/存款資金）**$333,333**；Tier 3 雜項 **$16,942**
- **原始碼**：**公開** — https://github.com/OlympusDAO/olympus-v3 （Bophades，72 assets in scope）；舊版 https://github.com/OlympusDAO/olympus-contracts
- **鑄幣相關重點**：**OHM 代幣鑄造/供應控制**、bonding 機制（折價取得協議代幣明列為「經濟損失」）、treasury。OHM 的 rebase/mint 邏輯是歷史高風險點。
- **out-of-scope**：資產仍留在協議內的 rebalancing/會計移轉不計；第三方系統/oracle 測試；先前已揭露的不計。
- **為何優先**：mint/supply 機制是 Olympus 核心 + 七位數 + 原始碼公開。

### 5. GMX（Immunefi）

- **平台 / scope URL**：Immunefi — https://immunefi.com/bug-bounty/gmx/scope/
- **賞金**：Critical 最高 **$5,000,000**
- **原始碼**：**公開** — https://github.com/gmx-io/gmx-synthetics （scope 涵蓋 github.com/gmx-io 下所有 repo）
- **鑄幣相關重點**：**GM / GLP 流動性代幣鑄造/贖回**、價格 feed 驅動的 mint 數量計算 → 預言機操縱導致超額鑄造是典型攻擊面。
- **out-of-scope**：聚焦防止直接竊取使用者資金（at-rest/in-motion），unclaimed yield 除外；所有報告需附 code PoC。
- **為何優先**：八位數賞金 + 公開 repo；GM 代幣鑄造受 oracle 影響，符合掃描器的「預言機操縱導致鑄造」規則。

### 6. Aave（Immunefi）

- **平台 / scope URL**：Immunefi — https://immunefi.com/bug-bounty/aave/information/
- **賞金**：Critical smart contract 最高 **$1,000,000**（10% 受影響資金，min $50,000）；High **$75,000**；Medium $10,000；Low $1,000
- **原始碼**：**公開**（Aave 各 repo 在 https://github.com/aave）；具體釘選版本待到 scope 頁核對（83 assets in scope）
- **鑄幣相關重點**：**GHO stablecoin 生態（facilitator 鑄造上限/bucket）**、**aToken 鑄造**、Safety Module（stkAAVE / stkABPT / stkGHO staking 與 reward）。GHO facilitator 的 mint cap 邏輯是直接命中的 mint-pattern。
- **out-of-scope**：tokenization 的 precision 機制（除非引發新攻擊）；未來 reward 損失（只算已累積 reward）；Aave Labs/BGD 開發者與審計過該碼者不符資格；可能需 KYC。
- **為何優先**：GHO facilitator mint cap + aToken mint 是高價值面；賞金實質、原始碼公開。

### 7. Kiln（Cantina）

- **平台 / scope URL**：Cantina — https://cantina.xyz/bounties/607dd012-08ad-4080-bf4a-78dc1c28faa9
- **賞金**：最高 **$1,000,000** USDC — critical/high 分級**待確認**
- **原始碼**：**待確認**（需到 scope 頁找釘選 repo / 合約地址）
- **鑄幣相關重點**：**liquid staking 與 validator abstraction** —— LST 代幣鑄造、reward 增發/分配、1:1 representation 會計。
- **out-of-scope**：待到頁面核對。
- **為何次之**：staking/LST mint 高度相關，但原始碼位置需先確認。

### 8. Coinbase / Base（Cantina）

- **平台 / scope URL**：Cantina — https://cantina.xyz/bounties/55316f42-3c5e-4746-9bd0-0f18dcbc344b
- **賞金**：最高 **$5,000,000**（中心化交易所最大）
- **原始碼**：部分公開（cbETH / cbBTC 等為 verified onchain；Coinbase 部分 repo 公開），**逐項待確認**
- **鑄幣相關重點**：**cbETH（staking reward 累積）、cbBTC 的鑄造/贖回**、staking 基礎設施、DEX 聚合器。cbETH 匯率/cbBTC 鑄造是 mint/supply 相關面。
- **out-of-scope**：「所有 Coinbase Web3 production 智能合約」範圍廣，但分散；需逐一確認哪些有公開 source。
- **為何次之**：賞金高 + cbETH/cbBTC 鑄造相關，但 source 取得性不均、需逐項核對。

### 9. Kinetiq（Cantina）

- **平台 / scope URL**：Cantina（Kinetiq x Cantina $5M program）— 入口 https://cantina.xyz/blog/kinetiq-cantina-2025-securing-liquid-staking （**精確 bounty scope URL 待確認**）
- **賞金**：策略性 **$5,000,000** program — critical/high 分級**待確認**
- **原始碼**：**待確認**
- **鑄幣相關重點**：**kHYPE liquid staking** —— 1:1 representation of staked HYPE、delegation accuracy、oracle reliability。LST 鑄造/匯率會計直接相關。
- **為何列入**：liquid staking mint 高度相關 + 大賞金，但需補 scope URL 與 source 位置。

### 10. Morpho（Cantina）

- **平台 / scope URL**：Cantina — https://cantina.xyz/bounties/35a5f0a1-2ffd-432c-8f3b-77d169add8c3
- **賞金**：最高 **$2,500,000** USDC
- **原始碼**：Morpho 合約多為公開（github.com/morpho-org），**釘選版本待確認**
- **鑄幣相關重點**：MetaMorpho / Vaults V2 是 **ERC-4626 vault（share 鑄造）**、isolated markets、permissionless lending。share↔asset 會計相關。
- **為何次之**：vault share 鑄造相關 + 七位數，但 mint 面不如純 stablecoin/LST 直接。

---

## 待補項目（後續偵查）

- Usual / Kiln / Kinetiq / Coinbase 的**公開原始碼釘選位置**（repo + commit 或合約地址）需逐一到 scope 頁確認。
- Euler / Kiln / Coinbase / Kinetiq 的 **critical vs high 精確分級數字**待從各 scope 頁取得。
- 各目標 scope 頁通常釘選**特定 commit hash**；掃描前須以該 commit 為準，不可直接抓 repo HEAD。
- Sherlock 平台其餘 mint 相關程式（如 SatLayer BTC restaking reward distribution 最高 $200K）可視掃描器產能再評估。

---

## 來源彙整

- Cantina 程式總覽：https://cantina.xyz/blog/cantina-bug-bounty-programs
- Sherlock 2026 最高賞金彙整：https://sherlock.xyz/post/best-web3-bug-bounties-in-2026-the-highest-paying-programs-on-every-platform
- Immunefi 各程式頁（aave / gmx / olympus）：見各條目 URL
- Pendle 文件 / repo：https://docs.pendle.finance/pendle-v2/Security ・ https://github.com/pendle-finance/pendle-core-v2-public
- Euler code reveal：https://www.euler.finance/blog/euler-v2-code-reveal
- Usual x Sherlock $16M：https://www.theblock.co/post/349204/usual-sherlock-crypto-bug-bounty-16-million-usd-critical-vulnerability
