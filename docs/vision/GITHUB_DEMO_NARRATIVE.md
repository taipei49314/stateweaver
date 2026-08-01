# StateWeaver GitHub 旗艦 Demo 敘事

狀態：Production target；未通過各 frame 的 release gate 前不得宣稱完成  
片長：90 秒  
核心句：Fork security states, not just agent conversations.

## 1. Demo 要讓人記住什麼

90 秒後，觀眾應能準確說出：

> StateWeaver 不是把 Agent 對話分叉，而是把應用的安全狀態分叉；它把不同世界的局部發現編譯成一條從乾淨 root 可重播的鏈，交給 machine-checkable Oracle 判定，再以同一計畫證明 patched 版本會阻擋。

真正的「震撼」來自三個可驗證反差：

1. 很多候選世界，只有少數值得實體化。
2. 每個局部發現單獨都不是 finding，合成並 clean replay 後才成立。
3. vulnerable 成功與 patched 失敗使用同一 root seed、同一 plan hash、同一 Oracle version。

Demo 不以聊天泡泡、模型語氣、掃描動畫或無來源的百分比製造戲劇性。主角是 World DAG、Transition Fragment、Replay timeline 與 Evidence。

## 2. 公開聲明的邊界

畫面與 README 必須同時顯示：

- SYNTHETIC LOCAL LAB；
- localhost / default-deny egress；
- machine-checkable Oracle，非 LLM verdict；
- vulnerable mode 是刻意建立的研究 fixture；
- patched comparison 與 negative controls；
- exact commit、run ID、seed、plan hash 與 evidence manifest。

在 StateChainBench 公開 holdout 結果前，不使用：

- zero-day；
- autonomous exploitation of arbitrary targets；
- beats every pentesting tool；
- production-proven；
- 任何未附 equal-budget protocol、樣本數與 confidence interval 的倍數宣稱。

架構文件中的 48 → 12 → 6 → 3 是旗艦 Demo 的預期搜尋形狀，不是可預錄的 KPI。影片只能顯示當次 run event log 計算出的實際數字；若實際為 43 → 11 → 5 → 3，就誠實顯示 43 → 11 → 5 → 3。

## 3. 90 秒 Storyboard

### 共同視覺語言

- Ghost：低亮度空心節點。
- Replay：藍色節點。
- Simulated：紫色節點。
- Materialized：高亮實心節點。
- Verified evidence edge：白色實線。
- Hypothesis／mock edge：灰色虛線，並帶 provenance label。
- Policy deny／patched block：琥珀色，不用與錯誤共用紅色。
- Oracle violation：紅色只保留給已由機器驗證的 invariant violation。
- 左上角常駐：LOCAL SYNTHETIC LAB。
- 右上角常駐：run ID、commit short SHA；點擊或片尾可展開完整值。

### 分鏡

| 時間 | 畫面 | 旁白／字幕 | Live source | Release gate |
|---:|---|---|---|---|
| 00–06 | 黑底只出現一句 Fork security states, not just agent conversations. 隨後一個 Root State 節點亮起 | 「多條件漏洞藏在狀態之間，不在下一句 prompt 裡。」 | 當次 root-state.json 與 root fingerprint | root capture 真實成功；不是設計稿 |
| 06–14 | 終端執行單一 demo 入口；旁邊 scope card 顯示 localhost、3 個 test identities、egress DENY、model calls 0 | 「一個本機合成 Lab。所有 action 都有型別、policy 與預算。」 | 真實 command output、ScopeManifest、OPA decisions | 從乾淨 clone 可執行；無外網、無模型 key |
| 14–27 | Root 分叉成 World DAG；tier counter 隨事件實際更新，低價值路徑被標記 PRUNED | 「我們先便宜地展開候選，再只把少數世界升級到真實環境。」 | world.forked、world.promoted、world.pruned events | counter 由 event store 計算；不得硬編 48/12/6/3 |
| 27–40 | 鏡頭依序聚焦三張 Transition Fragment 卡：前置條件、typed action、效果、evidence、fidelity；decoy 以 MOCKED／MASKED／BLOCKED 淡出 | 「局部發現被保存成可執行轉換，不是模型的一句結論。」 | Transition Fragment JSON、evidence IDs、provenance | 至少三個 fragment 皆可追溯；decoy Oracle 正確 |
| 40–52 | Fragment graph 自動連成 Candidate Replay Plan；畫面標示 common root，snapshot merge 出現劃線禁止符號 | 「Chain Compiler 合成 transition，不合併世界快照。」 | chain.compiled event、plan hash、constraint result | plan 由 compiler 產生；不是手寫動畫 |
| 52–66 | Clean reset 後逐步 replay；每步顯示 policy ✓、trace ✓、state delta ✓，controlled clock 前進 | 「從乾淨 root 精確重播；每一步都有 HTTP、DB、cache 與 queue 證據。」 | replay events、trace correlation、state digests | clean reset 通過；first run 之外至少重播驗證穩定 |
| 66–75 | Tenant Isolation invariant 展開；actor tenant 與 resource tenant 不同，protected field presence 使 Oracle 變成 VIOLATED | 「不是 LLM 說可能有問題。Oracle 直接判定隔離不變量被違反。」 | OracleResult 與最小 redacted evidence | deterministic=true；model_calls=0；evidence hash 可驗 |
| 75–84 | 左右分屏。左：vulnerable replay VIOLATED。右：patched 用相同 plan hash 在明確 step 顯示 BLOCKED_BY_FIX；下方兩個 negative control 為 SATISFIED | 「同一計畫、同一 Oracle。修復版阻擋，對照組不誤報。」 | patched replay、failure localization、negative controls | plan/seed/Oracle version 相同；不是只比較 status code |
| 84–90 | Evidence Bundle 像收束的卡片列出 manifest、trace、diff、Oracle、patched replay；最後顯示 clean-machine reproduction command 與 GitHub repo | 「每個畫面都能回到證據。Clone、重播、自己驗證。」 | artifact-manifest.sha256、release asset | bundle hash 通過；README quickstart 在乾淨 runner 通過 |

## 4. 畫面中的三個 Transition Fragment

為避免影片變成真實攻擊教學，卡片只呈現合成 Lab 的安全語意，不展示可移植的外部 target 操作細節：

### Fragment A：Historic session retained

~~~text
precondition: test identity has an older session generation
typed action: synthetic role transition
effect: current role no longer matches session claim
evidence: session manifest + DB role delta
~~~

### Fragment B：Async policy propagation delayed

~~~text
precondition: synthetic queue job is pending
typed action: controlled queue barrier
effect: policy propagation has not completed
evidence: queue digest + trace causal edge
~~~

### Fragment C：Stale authorization decision observed

~~~text
precondition: cache generation trails policy generation
typed action: scoped local document-read template
effect: synthetic cross-tenant protected field becomes observable
evidence: redacted HTTP exchange + cache digest + OracleResult
~~~

卡片必須標 provenance：OBSERVED、INFERRED、HYPOTHESIZED 或 MOCKED。只有具 Runtime Trace 與可驗證 State Delta 的 OBSERVED fragment，才能在片中用實線證據邊。

## 5. Demo command contract

### M0/M1 可立即驗證的入口

在 M1 完成前，README 只能把下列內容稱為 Foundation Demo 或 M0/M1 Acceptance：

~~~powershell
uv run pytest packages/contracts/tests -q
uv run pytest labs/multitenant-saas/tests -q
uv run pytest packages/replay/tests adapters/environments/in_process_lab/tests -q
~~~

它證明 contracts、vulnerable/patched Oracle differential、negative controls 與 deterministic replay；它不證明 World Search 或 Chain Compiler。

### 完整旗艦入口的 release contract

完整 90 秒旗艦 Demo 應收斂為 repository root 的單一、非互動入口，例如：

~~~powershell
make demo
~~~

名稱可依跨平台工具鏈調整，但入口必須：

1. 驗證 Docker、Compose 與 Python 版本；
2. 驗證 scope 僅包含 local synthetic Lab；
3. 建置 pinned images；
4. 產生或還原 deterministic seed；
5. 執行真實 pipeline，不播放預先生成的 success transcript；
6. 輸出 run ID 與 artifact directory；
7. 在任何步驟失敗時回傳非零 exit code；
8. 無論成功或失敗都執行 cleanup；
9. 不要求模型 API key即可跑 deterministic reference path；
10. 在 README CI 的 clean runner 中定期驗證。

在這個入口尚未存在並通過 clean-machine test 前，README 不顯示 make demo 為可用命令。

## 6. README 工程敘事

### 6.1 Above the fold

首屏只放六件事：

1. StateWeaver 名稱與核心句。
2. 一句精確定義：Reality-tethered state exploration for multi-condition security failures in an authorized synthetic Web SaaS lab.
3. 真實 run 製作的 hero visual。
4. 三個 proof chips：Deterministic Oracle、Clean-root Replay、Patched Differential。
5. 目前 maturity 標籤，例如 M0 complete / M1 in progress；不可用含糊的 production-ready。
6. Foundation quickstart 或已通過 release gate 的完整 demo command。

安全字樣 SYNTHETIC LOCAL LAB 應在 hero visual 內可見，不藏在頁尾 disclaimer。

### 6.2 建議 README 順序

~~~text
Hero + precise claim
→ 30-second visual proof
→ What just happened
→ Reproduce it locally
→ Evidence, not narration
→ Architecture: State DAG / World tiers / Transition compose
→ Vulnerable vs patched vs controls
→ Current milestone status
→ StateChainBench protocol and published results, when available
→ Safety boundary
→ Development and contribution guide
→ Citation / license
~~~

### 6.3 「What just happened」應回答

- Root state 是什麼？
- 實際 fork/promote/prune 了多少 worlds？
- 三個 fragment 各自提供哪個 precondition 或 effect？
- Compiler 為何認為它們可組合？
- 哪個 Oracle invariant 被違反？
- patched 版本在哪個 step 阻擋同一 plan？
- 哪些 negative controls 排除了假 IDOR、mock-only 與 fresh-session 近似路徑？
- evidence bundle 到哪裡下載，如何驗 hash？

### 6.4 Milestone status 必須可稽核

README 使用明確矩陣：

| Milestone | Status | Evidence |
|---|---|---|
| M0 Contracts + Lab | Not started / In progress / Verified | CI run + acceptance artifact |
| M1 Deterministic Replay | Not started / In progress / Verified | 5-run determinism artifact |
| M2 World Engine | Not started / In progress / Verified | sibling isolation test |
| M3 Semantic Twin | Not started / In progress / Verified | trace-backed fragment |
| M4 Search | Not started / In progress / Verified | actual tier event counts |
| M5 Chain Compiler | Not started / In progress / Verified | clean replay plan |
| M6 Proof Bundle | Not started / In progress / Verified | clean-machine reproduction |
| M7 StateChainBench | Not started / In progress / Verified | equal-budget report |
| M8 Public UX | Not started / In progress / Verified | README clean-run test |

Verified 必須連到永久 CI artifact、release asset 或 content-addressed report，不能只連 issue 或 roadmap。

## 7. GIF、影片與截圖清單

### 7.1 Hero GIF

- 內容：Root → actual World DAG → 3 fragments → chain → Oracle → patched block。
- 長度：20–30 秒循環；完整 90 秒版另放 release asset 或網站。
- 尺寸：建議 1280×720 原始錄製，README 內顯示寬度約 960。
- 影格：以文字可讀為優先，通常 12–15 fps 足夠。
- 無聲也能理解：所有關鍵旁白有短字幕。
- 不剪掉 command、run ID、scope badge 與 plan hash matching。
- 不用動畫重畫結果；UI 必須讀取保存的真實 run artifact。
- 壓縮後仍要能看清 step ID、verdict 與 provenance；過大則以短 GIF + 高畫質 MP4 連結。

### 7.2 必備靜態圖

- Architecture overview：五個 plane 的最小圖，不塞入全部 adapter。
- World DAG：包含 tier legend、pruned reason 與 actual counter。
- Fragment inspector：precondition/action/effect/evidence/fidelity。
- Replay evidence：單一步驟與 HTTP/trace/state diff correlation。
- Vulnerable vs patched：相同 plan hash 的左右比較。
- Proof Bundle：artifact manifest 與 sha256 verification。
- Benchmark：只有在 M7 有公開資料後加入，需同時呈現樣本數與不確定性。

每張圖的 caption 記錄 commit、run ID 與「live」「saved run」「design concept」之一。Design concept 不得放在 Results 區。

## 8. Evidence 呈現清單

README 的示例 finding 或 release asset 應包含：

- scope.yaml；
- target.lock 與 image/source digest；
- adapter.lock；
- root-state.json 與 root fingerprint；
- world event summary 與實際 tier counts；
- transition-fragments/；
- chain.plan.json 與 plan hash；
- replay attempts 與 determinism summary；
- replay trace；
- redacted HTTP exchanges；
- DB／Redis／Queue semantic diffs；
- Oracle definition、version 與 results；
- negative-controls.json；
- patched-version-replay.json 與 first_failed_step_id；
- redaction manifest；
- artifact-manifest.sha256；
- report.md，且每個結論可回連到 artifact。

公開 bundle 不包含：

- 可直接使用的 cookie/token/password；
- production host、real tenant 或 real user data；
- model prompt 中的未遮罩 target content；
- 未使用的原始 dump；
- evaluator-hidden 內容；
- 只為畫面好看、但不在 manifest 中的偽造 event。

## 9. 數字與 Benchmark 誠信

### 9.1 可直接顯示

- 當次 run 的 actual world counts；
- materialized world 數；
- target request、write request、model call 與 token 使用量；
- replay attempt 數與一致 verdict 數；
- chain step 數與 minimization 前後差異；
- policy deny 數；
- wall-clock time，並標硬體與 cold/warm run。

### 9.2 必須有實驗設計才可宣稱

- 比 linear agent 更高的 complete-chain success rate；
- verified finding per token／request；
- false-positive rate；
- materialized worlds per success；
- human intervention minutes；
- 任何百分比提升或倍數。

這些宣稱必須附：

- 同模型、同工具、同 token、同時間與同 request budget；
- challenge family、source visibility track 與樣本數；
- 多個 random seeds；
- holdout family；
- hidden Oracle；
- mean/median 之外的不確定性；
- 原始 machine-readable results；
- 失敗案例，而非只選成功錄影。

若資料不足，README 寫「Benchmark infrastructure in progress」，不要放估計圖。

## 10. 可重現性 release gate

旗艦 Demo 發布前，乾淨 runner 必須：

1. 只依 README 安裝 prerequisites；
2. clone 指定 tag；
3. 在無模型 key、無 Internet egress 的執行階段啟動 synthetic Lab；
4. 完成 vulnerable replay；
5. 完成 patched replay；
6. 完成 negative controls；
7. 驗證 artifact-manifest.sha256；
8. cleanup 後無 container、network、volume 或 test process 殘留；
9. 產生與 release schema 相容的新 run ID；
10. 將 console transcript、JUnit、evidence bundle 與環境資訊保留為 CI artifact。

建議另外在一台非 maintainer 開發機做 release candidate 驗證。手動修正步驟若未寫入 README，驗收視為失敗。

## 11. 錄製前 checklist

### Truth

- [ ] 畫面所有 counter 來自本次 run events。
- [ ] vulnerable、patched 與 controls 使用相同 seed、plan hash、Oracle version。
- [ ] 沒有把 HYPOTHESIZED／MOCKED 畫成 OBSERVED。
- [ ] 沒有把 M0/M1 Foundation Demo 稱為完整 autonomous search。
- [ ] 沒有未發布 Benchmark 宣稱。

### Safety

- [ ] LOCAL SYNTHETIC LAB badge 全程可見。
- [ ] scope 僅 localhost／Compose internal allowlist。
- [ ] egress deny test 已通過。
- [ ] model_calls 為 0，或若後期影片含模型探索則精確顯示實際值。
- [ ] credential、cookie、token、document body 已 redaction。
- [ ] 沒有展示可移植到真實外部目標的操作細節。

### Reproduction

- [ ] clean-machine command 在 pinned tag 通過。
- [ ] artifact manifest 可驗證。
- [ ] README 的 prerequisites 與實際版本一致。
- [ ] 失敗可定位到 step，cleanup 可重入。
- [ ] 影片、GIF 與 release bundle 都標 commit 與 run ID。

### Visual quality

- [ ] 文字在 GitHub 預設寬度仍可讀。
- [ ] 顏色不是唯一 verdict 訊號；同時有 label/icon。
- [ ] 動畫節奏保留足夠時間讀懂 Oracle 與 patch differential。
- [ ] 終端沒有無關 build noise、機器路徑或個人資訊。
- [ ] hero 不以聊天 UI 取代 World DAG。

## 12. M0/M1 階段如何先令人信服

完整 90 秒影片要等 M2–M6 的 live pipeline 成立。M0/M1 仍可先發布一段誠實的 Foundation clip：

~~~text
typed contracts validate
→ local synthetic seed
→ vulnerable Oracle VIOLATED
→ masked/mock/fresh-session controls SATISFIED
→ patched same-plan BLOCKED
→ clean reset
→ five identical replay verdicts
→ exact failed step
~~~

片尾文字應是：

> Foundation verified: deterministic contracts, Oracle differential, and replay. Tiered worlds and chain compilation are next.

這比用 mock UI 預演尚未存在的 M2–M6 更有說服力，也為後續每個 milestone 留下一個可公開驗證的成長節點。
