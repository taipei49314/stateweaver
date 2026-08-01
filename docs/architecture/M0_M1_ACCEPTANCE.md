# M0 / M1 驗收規格

狀態：Normative draft  
適用範圍：M0 Contracts + Lab、M1 Deterministic Replay Kernel  
架構基準：StateWeaver Architecture Baseline v1

## 1. 驗收目標

M0/M1 必須先證明兩件事：

1. 合成 Lab 的安全違反可由機器判定，不靠 LLM、文字摘要或人工猜測。
2. 同一個 root、seed 與 replay plan 能從乾淨狀態穩定重播；失敗時可定位到確切步驟。

這不是完整 StateWeaver 的驗收。World tier、Semantic Twin、Chain Compiler、Reality Anchor 與 Benchmark 分別屬於 M2–M7；它們不得被 UI mock 或預錄數字冒充已完成。

## 2. 安全與語意邊界

### 2.1 兩種「安全」必須分開

| 面向 | 定義 | 驗收判定 |
|---|---|---|
| Intentional lab vulnerability | 多租戶文件 SaaS 中刻意保留、只供 localhost 合成 Lab 重現的舊 session、延遲 queue 與 stale policy cache 組合缺陷 | vulnerable 模式的完整計畫觸發 Tenant Isolation Oracle；patched 模式與 negative controls 不觸發 |
| Platform safety | StateWeaver 自身限制 scope、action、secret、network、budget 與 evidence 的控制面 | 未知或越界 action 拒絕；無 raw shell；外部 egress 預設拒絕；測試資料不含真實 secret |

Lab 的 intentional vulnerability 不是平台安全例外。它仍只能經 typed action、有效 ScopeManifest 與 server-side policy gate 操作。

### 2.2 本文件禁止作為外部目標操作手冊

所有自動測試只可對：

- process-local ASGI test client；
- 綁定 127.0.0.1 的本機服務；
- Compose 內部的合成 Lab service name。

不得將示例 host、resource reference、session、request sequence 或 Oracle 移植到任意外部目標。M0/M1 CI 必須在無 Internet egress 的情況下可完成。

## 3. 判定規則

### 3.1 結果詞彙

| 結果 | 意義 |
|---|---|
| PASS | 測試完成，斷言成立，必要 evidence 可驗證 |
| FAIL | 斷言不成立、缺少必要 evidence、artifact hash 不符，或發生非預期網路／policy 行為 |
| NOT RUN | 未執行。不得計為里程碑完成 |
| INAPPLICABLE | 只可用於矩陣明示的可選項，且須記錄理由 |

M0 或 M1 只有在該里程碑所有 Required row 均為 PASS 時才可退出。重跑後的偶發 PASS 不能覆蓋先前失敗；非確定性必須先被分類與修正。

### 3.2 可接受的 evidence

每次 acceptance run 應建立獨立目錄：

~~~text
artifacts/acceptance/<run-id>/
├─ foundation/
│  └─ source.json
├─ run-manifest.json
├─ junit/
│  ├─ contracts.xml
│  ├─ policy.xml
│  ├─ lab.xml
│  └─ replay.xml
├─ oracle/
│  ├─ vulnerable.json
│  ├─ patched.json
│  └─ negative-controls.json
├─ replay/
│  ├─ root-state.json
│  ├─ plan.json
│  ├─ attempts.json
│  ├─ failure-localization.json
│  └─ action-log.json
├─ policy/
│  └─ decisions.json
└─ artifact-manifest.sha256
~~~

M0 實作由無 socket 的 in-process adapter 直接取得 ReplayRunResult、OracleResult 與最小 state digest；不建立 authenticated HTTP 管理介面。CI evidence collector 負責把這些 typed results 保存並驗證 hash。Lab 本身不必為了通過 M0 寫入持久檔案。

run-manifest.json 至少記錄：

- repository commit SHA 或 working-tree marker；
- Python 與 Docker/Compose 版本；
- target mode 必須為 `differential`，同一 bundle 同時保留 vulnerable 與 patched replay；
- root seed 與 controlled clock epoch；
- test command 與 exit code；
- app image／source digest；
- ScopeManifest、replay plan 與 Oracle definition 的版本或 hash；
- 開始／結束時間；時間欄位不得參與 semantic fingerprint。

artifact-manifest.sha256 必須涵蓋本次 acceptance 目錄內所有必要檔案，manifest 本身除外。含 cookie、token、authorization header 或連線密碼的欄位，保存前必須 redaction；真實 secret 出現即 FAIL。

低階 verifier 的保證邊界是「相對於 supplied JUnit 與 caller 提供的獨立 provenance，檔案完整且因果一致」。高階 `foundation verify-evidence` 會在 process-local network guard 下重新執行 installed deterministic foundation，並要求其 semantic hash、installed source/Oracle bytes 與 locked runtime dependency bytes 全部吻合 bundle。兩者都不驗證惡意 producer 的身分，也無法單靠自含 bundle 證明 producer 真正執行了 XML 中命名的 testcase。公開發布的 proof artifact 仍必須另有外部 CI attestation；在該 M6 信任根落地前，不得把 local verification 描述成 producer 身分證明。

## 4. 標準執行入口

從 repository root 執行：

~~~powershell
uv run pytest packages/contracts/tests -q
uv run pytest packages/policy/tests -q
uv run pytest labs/multitenant-saas/tests -q
uv run pytest packages/replay/tests adapters/environments/in_process_lab/tests apps/cli/tests -q
~~~

建議 CI 入口：

~~~powershell
$staging = "artifacts/acceptance/junit"
New-Item -ItemType Directory -Force $staging | Out-Null
$acceptanceStartedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
uv run pytest packages/contracts/tests -q --junitxml=$staging/contracts.xml
uv run pytest packages/policy/tests -q --junitxml=$staging/policy.xml
uv run pytest labs/multitenant-saas/tests -q --junitxml=$staging/lab.xml
uv run pytest packages/replay/tests adapters/environments/in_process_lab/tests apps/cli/tests packages/evidence/tests -q --junitxml=$staging/replay.xml

uv run stateweaver foundation collect-evidence `
  --output-root artifacts/acceptance/runs `
  --run-id <run-id> `
  --repository-marker <commit-or-working-tree-marker> `
  --started-at $acceptanceStartedAt `
  --junit-contracts $staging/contracts.xml `
  --junit-policy $staging/policy.xml `
  --junit-lab $staging/lab.xml `
  --junit-replay $staging/replay.xml
uv run stateweaver foundation verify-evidence artifacts/acceptance/runs/<run-id>
~~~

JUnit 先寫入 staging，且 `--started-at` 必須在第一個 normative 測試前擷取；因此 bundle 的 run window 同時涵蓋四組 JUnit 與後續 foundation verification。collector 會以 `exist_ok=false` 原子建立最終 run 目錄，拒絕覆寫或混入既有檔案。collector 使用同一次 foundation verification 產生 `source.json`、五次 vulnerable replay、patched replay、negative controls、policy decisions 與所有 derived views；verifier 不只重算 SHA-256，也重新驗證跨檔案的 root／plan／action／Oracle／policy 因果綁定。

若 adapter integration suite 尚未存在，M1 為 NOT RUN，而不是 PASS。測試檔可重構，但下表的 requirement ID、assertion 與 evidence contract 必須保持穩定。

## 5. M0：Contracts + Lab 驗收矩陣

### 5.1 Contracts

| ID | Required | 需求 | 自動測試／斷言 | 必要證據 | 退出條件 |
|---|---:|---|---|---|---|
| M0-C01 | Yes | ScopeManifest 具版本、模式、include/exclude、identity、action、limit 與 validity | packages/contracts/tests：有效 manifest 可 round-trip；過期、空 allowlist、未知欄位、deny/allow 衝突均拒絕 | contracts.xml；canonical manifest hash | schema 驗證為 deterministic，invalid fixture 全部拒絕 |
| M0-C02 | Yes | ActionEnvelope 只接受註冊的 typed action | 驗證 action_type、typed parameters、risk_class、idempotency_key、policy_decision_ref；shell/command/script/argv 類未註冊 action 拒絕 | contracts.xml；accepted/rejected fixture IDs | 任意字串命令無法通過 contract |
| M0-C03 | Yes | Security State IR 可表示 Entity、Relation、Fact 與 provenance | OBSERVED 必須有 evidence ID；HYPOTHESIZED 不得偽裝 OBSERVED；confidence 範圍與 taint enum 受驗證 | contracts.xml；canonical state fixture hash | 同一 semantic state 序列化 hash 穩定 |
| M0-C04 | Yes | Transition Fragment 明示 preconditions → action → effects → observables → evidence | 缺少任一必要段落拒絕；source 與 evidence/fidelity 一致性受驗證 | contracts.xml；fragment fixture hash | fragment 可被機器解析，不依賴自然語言結論 |
| M0-C05 | Yes | World Manifest pin root、seed、clock、capability、snapshot、lineage 與 fingerprint | parent/root 關係、tier enum、snapshot reference、status enum 驗證；時間欄位不污染 semantic fingerprint | contracts.xml；兩次 canonical hash 比較 | 相同 semantic input 得到相同 fingerprint |
| M0-C06 | Yes | OracleResult 包含 invariant、result、observed、evidence 與 deterministic flag | 支援至少 SATISFIED／VIOLATED；deterministic=true 時缺 evidence 或 machine-readable observation 必須拒絕 | contracts.xml；OracleResult fixtures | Oracle 結果不需要 LLM 欄位或模型呼叫 |
| M0-C07 | Yes | Public import surface 穩定 | 由 stateweaver.contracts 匯入 M0 六種契約；package-local tests 在乾淨環境可執行 | contracts.xml；package install log | 不需從 adapter 或 app 私有模組匯入 domain contract |
| M0-C08 | Yes | Canonicalization 對 key order 與非語意 metadata 穩定 | property test 隨機改變 mapping order、產生時間與展示 label；semantic hash 不變；語意欄位變更時 hash 必變 | contracts.xml；property seed | 100 個以上生成案例無碰撞或漂移 |

### 5.2 合成多租戶 SaaS Lab

Lab 必須以明確建構參數 create_app("vulnerable") 與 create_app("patched") 切換，不以殘留的全域環境變數決定安全模式。

| ID | Required | 需求 | 自動測試／斷言 | 必要證據 | 退出條件 |
|---|---:|---|---|---|---|
| M0-L01 | Yes | 固定 root seed 建立 Tenant A、Tenant B、測試身分、角色、文件、policy generation 與 queue 初態 | seed 兩次後逐項比較 semantic state；公開 ID 可隨 seed 變化但同 seed 必相同 | lab.xml；root state digest | 同 seed 同 state digest；無真實資料或 secret |
| M0-L02 | Yes | vulnerable 與 patched 是可稽核的獨立模式 | 相同 seed、身分與計畫分別建立兩個 app instance；測試確認 mode 不跨 instance 污染 | lab.xml；兩個 app/source digest | 模式切換不依賴 process-global mutable state |
| M0-L03 | Yes | 完整合成條件只在 vulnerable 模式造成跨 Tenant 未遮罩讀取 | 本機 authenticated test 依 typed plan 執行；OracleResult.result == VIOLATED、deterministic == true，且 observed actor/resource tenant 不同 | vulnerable.json；最小 evidence/state digest | 連續兩次由乾淨 seed 得到相同 verdict 與 terminal predicate |
| M0-L04 | Yes | patched 模式阻擋同一計畫 | 對相同 root seed 與相同 plan 重播；OracleResult 不得為 VIOLATED；回應不得含受保護欄位 | patched.json；同 plan hash | 修復差異由 Oracle 判定，不以 HTTP status 單獨判定 |
| M0-L05 | Yes | masked 200 decoy 不得誤報 | 斷言 status 可為 200，但 protected fields 不存在或已遮罩，Tenant Isolation Oracle 為 SATISFIED | negative-controls.json | 不把 status 200 當作漏洞 |
| M0-L06 | Yes | mock-only decoy 不得升級為真實 finding | 斷言 mock observation taint == MOCKED，不能成為 deterministic reality evidence | negative-controls.json | mock 單獨存在時 Oracle 不違反 |
| M0-L07 | Yes | fresh session 與 same-tenant control 行為正確 | fresh session 跨 Tenant 被阻擋；same-tenant 合法讀取成功且 Oracle 不誤報 | negative-controls.json | 兩個 controls 均符合預期 |
| M0-L08 | Yes | Oracle 是純程式／policy 判定 | 測試環境不配置任何模型 key；封鎖 model gateway；完整 suite 仍通過 | lab.xml；run-manifest 中 model_calls=0 | model_calls 必須精確為 0 |
| M0-L09 | Yes | Lab 只可本機存取 | M0 的 in-process adapter 不建立 socket，且 policy test 拒絕非 allowlist host；M2 Compose variant 另驗證只綁 127.0.0.1 或不 publish | policy decisions；adapter boundary assertions | 無 0.0.0.0 bind，無任意 Internet egress |
| M0-L10 | Yes | intentional vulnerability 有清楚標記且不進 production default | 測試確認 vulnerable mode 需顯式選擇；未指定模式時 fail closed 或採 patched | lab.xml；configuration snapshot | 不可能因缺省設定意外啟用 vulnerable mode |

### 5.3 M0 里程碑退出

M0 只有在下列條件同時成立時完成：

1. M0-C01 至 M0-C08 全部 PASS。
2. M0-L01 至 M0-L10 全部 PASS。
3. vulnerable 與 patched 使用同一 root seed、同一 typed replay plan、同一 Oracle version。
4. vulnerable 為 VIOLATED；patched 與所有 negative controls 不為 VIOLATED。
5. model_calls == 0。
6. acceptance evidence 無未遮罩 credential，且 sha256 manifest 可驗證。

## 6. M1：Deterministic Replay Kernel 驗收矩陣

### 6.1 Capture、reset 與 replay

| ID | Required | 需求 | 自動測試／斷言 | 必要證據 | 退出條件 |
|---|---:|---|---|---|---|
| M1-R01 | Yes | Root seed pin application、DB、Redis、Queue 與 controlled clock 初態 | seed → capture → reset → capture；比較 canonical root fingerprint | root-state.json；replay.xml | reset 前後 root fingerprint 相同 |
| M1-R02 | Yes | Browser session capture 可重播且已 redaction | capture 只保存測試 identity handle、storage schema 與 token hash；restore 後 session generation 符合計畫 | session manifest；redaction assertions | artifact 不含可直接使用的 cookie/token |
| M1-R03 | Yes | HTTP action log 有完整順序與因果識別 | 每步含 step_id、action_id、idempotency_key、policy_decision_ref、trace_id、request template hash、observation hash | plan.json；action log | 無未授權 action；step_id 唯一且順序固定 |
| M1-R04 | Yes | DB／Redis／Queue capture 足以重建安全相關狀態 | capture/restore 後比較 tenant ownership、role/policy generation、cache generation、pending jobs | state digests；replay.xml | 三個 provider 的 semantic digest 均相同 |
| M1-R05 | Yes | Clean reset 清除前次 replay 污染 | 第一次重播後注入可識別的 test marker；reset 後 marker、pending job、cache key、session 全部不存在 | reset diff；replay.xml | 零殘留；任何殘留即 FAIL |
| M1-R06 | Yes | Exact replay 固定 root、seed、plan、clock 與 adapter version | 從 clean reset 連續重播至少 5 次；比較 ordered step verdicts、terminal predicate、Oracle verdict 與 semantic fingerprint | attempts.json；每次 run hash | 5/5 verdict 一致，terminal fingerprint 一致 |
| M1-R07 | Yes | 時序由 controlled clock／barrier 表達，不靠任意 sleep | 靜態或 runtime test 拒絕 replay plan 的裸 sleep action；時間推進以 typed clock/barrier action 記錄 | plan.json；replay.xml | 測試不依賴 wall-clock 抖動取得 PASS |
| M1-R08 | Yes | Action idempotency 防止重複副作用 | 同一 idempotency_key 重送兩次，第二次回傳既有 observation 或明確 duplicate verdict；DB/Queue 不增加第二份副作用 | attempts.json；state diff | 副作用次數精確為 1 |
| M1-R09 | Yes | 失敗定位到確切 step | 在 patched mode 執行同一 plan；ReplayResult 記錄 first_failed_step_id、reason_code、expected/observed predicate 與 evidence IDs | failure-localization.json | 不得只回報「replay failed」 |
| M1-R10 | Yes | 非確定性有顯式結果 | 測試注入受控的 observation mismatch；結果標為 NONDETERMINISTIC 或 MODEL_DIVERGENCE，不可升級 finding | replay.xml；classification fixture | mismatch 不被吞掉或誤報成功 |
| M1-R11 | Yes | 失敗後 cleanup 可重入 | 在每個 capture/execute boundary 注入一次受控 exception；cleanup 執行兩次皆安全，下一次 reset 可成功 | replay.xml；cleanup events | 無孤兒 process、job、namespace 或測試 identity |
| M1-R12 | Yes | Policy decision 與 budget 在 replay 中仍強制執行 | 缺 policy_decision_ref、超 write quota、未知 action type 的 replay step 均在執行前拒絕 | decisions.json；replay.xml | 被拒 action 不產生 target observation 或 state delta |

### 6.2 Determinism 比對欄位

重播穩定不代表所有 bytes 完全相同。以下欄位必須正規化後比較：

| 類別 | 必須相同 | 比較前排除或正規化 |
|---|---|---|
| Plan | ordered step IDs、typed parameters、preconditions、expected effects、plan hash | 產生時間、顯示 label |
| State | principal/role/tenant、session generation、resource ownership、policy/cache generation、pending jobs、capabilities、controlled time bucket | DB physical page、row order、container ID |
| Observation | status class、response schema、protected field presence、Oracle-relevant values、trace causal edges | Date header、ephemeral port、span ID 本身 |
| Result | first failed step、reason code、terminal predicate、Oracle verdict | wall-clock duration |
| Evidence | artifact type、producer version、content hash after normalization、redaction policy | 臨時檔案路徑 |

任何被排除欄位若影響 Oracle 結果，就不再是「非語意 metadata」，必須納入 fingerprint 或將結果標為 NONDETERMINISTIC。

### 6.3 M1 里程碑退出

M1 只有在下列條件同時成立時完成：

1. M1-R01 至 M1-R12 全部 PASS。
2. vulnerable replay 從 clean root 連續 5 次得到相同 ordered verdict、terminal fingerprint 與 VIOLATED OracleResult。
3. patched replay 使用完全相同 plan hash，穩定停止在可解釋的 boundary step，且不洩漏受保護欄位。
4. 每次 replay 前 clean reset 通過；前次 run marker 不存在。
5. 每個 action 都有 policy_decision_ref、idempotency_key 與 evidence correlation。
6. CI 無模型 key 亦可完成，model_calls == 0。

## 7. CI 建議分層

| Job | 網路 | 內容 | 失敗處理 |
|---|---|---|---|
| contracts | 完全離線 | M0-C01–C08、property tests | 阻擋 merge |
| lab-process | 完全離線 | process-local vulnerable/patched/controls | 阻擋 merge |
| lab-compose | default-deny egress，僅本機與 Compose internal network | bind、health、policy、provider integration | 阻擋 merge |
| replay-determinism | default-deny egress | 5 次 replay、reset、failure injection | 阻擋 merge；不得以 rerun 隱藏 flaky |
| evidence-audit | 完全離線 | schema、redaction、sha256 manifest | 阻擋 release |

測試重試只可用來收集診斷，不能把「任一次成功」當作 PASS。Replay determinism job 出現一次不一致即失敗，並保存所有 attempts。

## 8. Release evidence review

發布 M0/M1 tag 前，reviewer 應能只靠 acceptance artifact 回答：

- 這次測的是哪個 commit、app mode、root seed、plan 與 Oracle version？
- vulnerable 與 patched 是否真的是相同計畫？
- Oracle 為何判定 VIOLATED／SATISFIED？可否追到 machine-readable observation？
- negative controls 是否證明 200、mock 與合法 same-tenant access 不會誤報？
- 5 次 replay 的哪些欄位一致？哪些欄位被正規化？理由為何？
- patched replay 首次在哪一個 step 被修復阻擋？
- 是否有任何模型呼叫、越界 host、raw shell、未決 policy 或未遮罩 secret？

任何一題無法由 evidence 回答，對應里程碑不得標記完成。
