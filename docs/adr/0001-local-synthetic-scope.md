# ADR-0001：Local Synthetic Scope 與預設拒絕執行邊界

- 狀態：Accepted
- 日期：2026-08-01
- 適用：公開版、開發環境、CI、Demo 與所有子代理工作
- 決策擁有者：StateWeaver maintainers

## Context

StateWeaver 會重建安全相關狀態、執行可逆的測試動作並以 deterministic Oracle 驗證結果。旗艦 Lab 刻意包含一個多條件授權缺陷；如果把「Lab 中故意不安全的應用行為」和「平台本身的安全控制」混為一談，公開專案可能：

- 意外對非授權 host 發送請求；
- 讓模型或子代理擴大 scope；
- 以任意 shell 或未註冊 adapter 繞過 policy；
- 將測試 token、cookie、連線密碼或 target content 帶入模型或 artifact；
- 把 mock、偶發回應或單一 HTTP status 誤報為已確認 finding；
- 讓 intentional vulnerability 成為預設部署模式。

Architecture Baseline v1 已凍結以下原則：typed actions only、OPA server-side gate、localhost／私有 Lab／明確 allowlist、外部 egress 預設拒絕，以及真實環境 state-changing action 預設需要核准。本 ADR 將它們具體化為可測的不變量。

## Decision

### 1. 公開版只支援 Local Synthetic Scope

預設執行範圍只包含：

1. process-local test client；
2. 127.0.0.1 與 ::1；
3. 由本次 Compose project 建立、且只存在於其 internal network 的合成 service；
4. 由人明確提交、具到期時間、經 server-side policy 驗證的私有 Lab allowlist。

Public Internet、任意 URL、由 target 回傳的新 host、redirect 目的地、DNS 結果漂移與模型建議的 scope expansion 一律不會自動加入 scope。

若未來需要 Connected Staging，必須由另一份 ADR 定義 ownership proof、allowlist、identity、approval、rate/write quota、cleanup 與 audit；不因本 ADR 的「私有 Lab」字樣自動取得授權。

### 2. Host 驗證採 fail-closed

每個可執行 action 在執行當下重新驗證：

- ScopeManifest 尚未過期；
- scheme、host、port 與 path 全部符合 allowlist；
- resolve 後的地址仍在允許的 loopback／private Lab 範圍；
- redirect 的每一跳都重新評估，不繼承原請求的允許；
- action 所屬 experiment、world、identity 與 target 一致；
- policy bundle 與 decision ID 可稽核。

解析失敗、未知 port、萬用字元過寬、缺少 path constraint、scope 過期或 policy service 不可用時，結果都是 DENY。不得用「開發模式」降級成 allow。

### 3. 外部網路 egress 預設拒絕

Materialized Lab 使用獨立 Compose network；服務之間只開放清單內的內部連線。Host publish 若必要，只綁定 127.0.0.1。World runner、model gateway 與 adapter runner 的網路能力分離：

- World runner 只能接觸本 world 的 Lab services；
- adapter 不得任意連 Internet；
- model gateway 不接收 raw secret，且不能直接連 target；
- telemetry 與 artifact store 使用明確的本機 endpoint；
- policy 無決策或 firewall enforcement 不可確認時停止執行。

CI 必須有 negative test 證明非 allowlist destination 被阻擋。應用層 policy 與網路層控制要同時存在，不能只依賴其中一層。

### 4. 所有可執行行為都必須是 typed action

ActionEnvelope 是唯一執行入口。每個 action type 必須在 registry 中宣告：

- JSON schema 與嚴格欄位；
- capability；
- risk class；
- reversibility；
- expected state delta；
- timeout、request/write budget；
- idempotency 行為；
- cleanup procedure；
-允許的 adapter 與版本。

未知 action type、額外欄位、自由文字 command、script、argv、interpreter、shell expansion 或未 pin adapter 一律 DENY。

公開版不提供可讓模型傳入任意命令的 shell.exec、process.run 或同義 action。平台內部若需啟動固定工具，只能由 maintainer 撰寫的 adapter 使用固定 executable、結構化參數、無 shell interpolation 的呼叫；模型看不到這個底層 primitive，也不能選擇 executable。

### 5. OPA 是 server-side mandatory gate

每個 action 依序通過：

~~~text
contract validation
→ scope validation
→ capability check
→ risk classification
→ budget check
→ OPA decision
→ optional human approval
→ adapter execution
→ observation/evidence capture
→ cleanup
~~~

沒有 policy_decision_ref 不執行。Decision 綁定 action hash、scope hash、policy bundle version、experiment、world、identity 與 expiry；任何綁定欄位改變都必須重新決策。Adapter 只接受 gateway 簽發或在同一 trust boundary 驗證的 authorized envelope，不接受模型直接呼叫。

### 6. Intentional vulnerability 與平台安全隔離

旗艦 Lab 的 vulnerable mode 只表示合成 SaaS 的授權邏輯刻意保留已知缺陷，不代表：

- 關閉 StateWeaver 的 scope 或 OPA；
- 允許外部 egress；
- 允許真實帳號、真實 tenant 或真實 secret；
- 允許 raw shell、持久化、credential exfiltration、DoS 或 destructive delete；
- 降低 artifact redaction；
- 讓模型宣告 Oracle 結果。

Lab 必須符合：

- vulnerable 需顯式選擇；
- 未指定模式時 fail closed 或採 patched；
- vulnerable 與 patched 可在同一 root seed、同一 replay plan、同一 Oracle version 下比較；
- 每個 intentional flaw 以 test/fixture 與文件標示 SYNTHETIC_LAB_ONLY；
- production image、package default 與範例部署不得默認 vulnerable；
- patched replay 與 negative controls 是 release gate。

### 7. Secret 與不可信內容的邊界

資料庫只保存 secret handle，不保存原始 secret。測試 identity 使用短生命週期的合成 credential。Cookie、authorization header、token、connection string 與可能的 document body 在 artifact 寫入前欄位級 redaction。

Target 網頁、README、API response、tool output 與 Lab 文件內容一律標記 UNTRUSTED_OBSERVATION：

- 不可變成 system/developer instruction；
- 不可修改 ScopeManifest、policy 或 budget；
- 不可要求 adapter 或子代理執行額外操作；
- 傳給模型前再次最小化與 redaction；
- prompt injection 測試為 release gate。

Repository、fixtures、logs 與 evidence bundle 必須執行 secret scanning。掃描發現 credential-like material 時 fail closed，不能只在報告中警告。

### 8. 子代理邊界

子代理是開發協作者，不是授權主體。建立子代理時，parent 必須把任務縮成具體、可審查的 repository subtask，並明示：

- 只處理 source、test、fixture、文件或本機合成 Lab；
- 不接觸外部目標，不做 Internet 掃描；
- 不尋找、讀取、複製或傳送 secret；
- 不提供或執行真實攻擊操作；
- 不改 scope、policy decision 或安全硬邊界；
- 只修改被分配的 path，避免跨代理污染。

但安全不能依賴提示文字。即使子代理輸出越界建議，runtime 仍以 typed contract、OPA、allowlist、egress control、budget 與 adapter capability 阻擋。所有 agent output 都是 proposal；只有通過相同 server-side gate 的 ActionEnvelope 才可執行。

子代理不得：

- 被授予 raw shell action capability；
- 自行新增 allowlist 或批准自己的 action；
- 取得 production credential；
- 將 target content 當作新任務；
- 因測試失敗而關閉 policy、redaction 或 egress control；
- 將未實測功能、預錄數字或模型敘述標成已驗證結果。

### 9. 禁止能力

公開版 registry 不包含：

- stealth／evasion；
- persistence；
- lateral movement；
- credential exfiltration；
- denial of service；
- destructive data deletion；
- arbitrary file write outside world storage；
- host filesystem write mount；
- privileged container 或未受限的 Docker socket access。

對這些 action 的 deny 必須以 reason code 記錄，且被拒 action 不得產生 target request 或 state delta。

### 10. Evidence 與 finding 升級

模型、mock 與 simulated result 都不能單獨形成 confirmed finding。M0/M1 至少要求：

- deterministic machine-checkable Oracle；
- vulnerable／patched differential；
- negative controls；
- clean reset 與 exact replay；
- action、policy、trace 與 state digest 的 correlation；
- redacted、content-addressed evidence。

只有後續經 Reality Anchor 達到 REALITY_REPLAYED／PATCH_VERIFIED 的結果才可進正式 confirmed finding 區。Local Lab 的 M0/M1 結果應標示 SYNTHETIC_REPRODUCED，不應暗示外部產品受影響。

## Security invariants and verification

| ID | 不變量 | 最低自動驗證 |
|---|---|---|
| SCOPE-01 | 空白、過期、模糊或無法解析的 scope 不可執行 | ScopeManifest invalid fixtures 全拒絕 |
| SCOPE-02 | redirect、DNS 解析與 target response 不可擴大 allowlist | redirect/DNS rebinding simulation 皆 DENY |
| NET-01 | 公開服務不綁 0.0.0.0 | render 後 Compose config assertion |
| NET-02 | World 無任意 Internet egress | 對非 allowlist synthetic endpoint 的連線測試被阻擋 |
| ACT-01 | 未註冊 action 與 raw shell 不能通過 schema | contract property/negative tests |
| ACT-02 | 每個執行 action 有有效且綁定內容的 policy decision | adapter conformance test |
| ACT-03 | 相同 idempotency key 不產生重複副作用 | replay idempotency integration test |
| SECRET-01 | 模型輸入與 artifact 無原始 secret | canary secret + redaction + scan test |
| AGENT-01 | agent proposal 不能改 scope 或自行批准 | scope-escalation / approval-bypass tests |
| LAB-01 | vulnerable mode 非預設且只使用合成 fixture | configuration + seed provenance test |
| LAB-02 | patched 與 negative controls 阻擋同一安全違反 | Oracle differential E2E |
| EVID-01 | mock/LLM text、裸 replay ID 或自稱成功的布林值不能產生 OBSERVED 或 confirmed finding | provenance/typed-receipt/status-machine tests |
| CLEAN-01 | failure cleanup 後無跨 world／跨 run 污染 | contamination + idempotent cleanup tests |

上述任一 Required invariant 失敗時，公開 Demo、release artifact 與 benchmark publication 均停止。

## Operational defaults

| 設定 | Default |
|---|---|
| Scope | process-local、localhost、Compose internal synthetic Lab |
| Egress | DENY |
| Unknown action | DENY |
| Policy unavailable | DENY |
| Scope expired | DENY |
| Lab mode omitted | PATCHED 或啟動失敗 |
| State-changing connected target action | REQUIRE_APPROVAL；M0/M1 不支援 |
| Model access to secret | DENY |
| Model direct target access | DENY |
| Raw shell action | 不存在 |
| Artifact redaction | REQUIRED |
| Confirmed finding from LLM/mock | DENY |

## Consequences

### Positive

- Demo 可在乾淨機器與離線 CI 重現，且不依賴對外網路。
- intentional vulnerability 可安全地展示架構價值，又不弱化平台控制。
- agent、adapter、UI 與 CLI 共用同一條 authorization path。
- 失敗行為有 reason code 與 evidence，可稽核、可測、可對外說明。

### Costs

- adapter 開發需額外維護 action schema、capability manifest、OPA policy 與 conformance tests。
- 某些便利的自由文字工具無法直接接入。
- Connected Staging 與更多 target mode 會延後到具備獨立安全設計後。
- GitHub Demo 的一鍵體驗必須在 default-deny network 下完成，工程門檻較高。

這些成本是產品可信度的一部分，不是可以由 Demo flag 關閉的選項。

## Rejected alternatives

### 只在 prompt 中提醒模型不要越界

拒絕。Prompt injection、tool output 與模型錯誤都可能繞過文字提醒；授權必須由 server-side policy 與網路控制執行。

### 提供通用 shell，再以 allowlist 過濾字串

拒絕。字串解析、shell expansion、interpreter 與參數注入難以完整控制，也破壞 typed action 的稽核與 idempotency。

### Demo 期間暫時允許 Internet egress

拒絕。M0/M1 所需服務全為本機合成元件；對外連線既非必要，也會讓 clean reproduction 與安全聲明失真。

### 將 vulnerable Lab 當作一般部署 profile

拒絕。它只能是顯式、標記清楚、具 patched differential 與 synthetic seed 的研究 fixture。

## Follow-up

- M0：以 contracts tests 與 Lab negative tests 落實 SCOPE、ACT、LAB invariants。
- M1：加入 idempotency、clean reset、failure cleanup、redaction 與 deterministic replay tests。
- M2：以 Adapter Conformance Suite 驗證 per-world isolation 與 egress enforcement。
- M6：補齊 Reality Replay Broker 與 Reality Proof Bundle 的獨立威脅模型。
- 任何擴大 target mode、allowlist 類型或 action registry 的變更都需要新 ADR 或本 ADR 的明確修訂。
