# Issue #33 证据与 READY 判定矩阵

## 结论摘要

| AC | 状态 | 证据边界 |
|---|---|---|
| AC1 | [x] | App schema/CAS/flush/restore 和 Host owner/CAS/manifest/control 源码逐项核对；存储原子性不外推到目标板。 |
| AC2 | [x] | 真实 App v3 `lc_bus`/`lc_ctrl` 编译测试 + Host 固定 commit 的真实 App state store 故障测试 + 明确标注的 schema3 候选模型。没有端到端 Host-App target 集成。 |
| AC3 | [x] | 文档给出 signed opt-in 新 major 控制契约/尺寸候选和 v3 负例；没有宣布 production ABI/capability/layout 已冻结。 |
| AC4 | [x] | 下表明确软件 PASS、目标板 NOT_RUN、跨仓新 major transport UNKNOWN，并给出复现命令与锚点。 |

**给 A 的 #30 READY 输入：BLOCKED。** 软件研究可以描述最小候选，但真实旧 v3 运行路径已复现降级后继续计数，尚无 Host trusted-major rollback gate 或新 major end-to-end transport。Paused 未在产品 App 中实现。

## 源码版本

| 仓库/面 | 固定版本 | 复现锚点 |
|---|---|---|
| App `ne30x-app` | `main` = `27b768bdefb3283652e4ab3318cfe9f9dbf693e8`，即本 worktree execution base | `apps/line-crossing/app/lc_stateblob.h/.c`; `lc_bus.c::{lcbus_restore,lcbus_flush,lcbus_on_event,lcbus_on_idle,maybe_close_window,close_window,submit_window_report}`; `lc_ctrl.c::{wire_header_valid,lc_ctrl_poll}`; `lc_app_entry_v3.c` event loop |
| Host `ne301` | `experiment/app-host-poc` = `884bb0ff0bea9b04534f91cd1c7c9af5a45c2798` | `Custom/Services/AppHost/app_state_store.{h,c}`; `app_sidecar_lifecycle.c::sc_uninstall_local_cleanup_locked`; `app_host_session.{h,c}`; `app_admission.{h,c}`; `tests/app_state/*`; `tests/app_sidecar_lifecycle/test_app_sidecar_lifecycle.c` |
| Host state-storage prior design | #95 candidate `eb543bea67c5cd814325447cc3658ce90418e378`; merged `9b710f5eb6863d013a1d00d42bd57f085658974c` | Candidate review only; Host target-side durability/rollback gate is not established by this reference. |
| Product decision | `ne30x-app` Issue #30 comment `6184753690` | Pause clears current window/tracker; does not emit a partial report or advance `report_seq`; keeps cumulative counters and historical queued reports; remains paused over restart; resume begins a new window. |

## 可复现软件测试

### App 真源码 + 候选模型隔离夹具

```sh
CC=cc bash tests/enable-persistence-study/run.sh
```

结果：`ENABLE-PERSISTENCE-STUDY RESULT: PASS (64 checks)`。

```sh
CC=clang bash tests/enable-persistence-study/run.sh
```

结果：`ENABLE-PERSISTENCE-STUDY RESULT: PASS (64 checks)`。

测试命名锚点：`test_schema_codec_and_crc`、`test_real_migration_and_repeat_start`、`test_real_corrupt_and_unknown_storage`、`test_real_commit_faults_and_cas_conflict`、`test_real_frame_and_idle_report_paths`、`test_candidate_pause_resume_and_both_gates`、`test_candidate_crash_unknown_conflict_and_reinstall`、`test_v3_rejects_new_command_but_downgrade_counts`。

`run.sh` 编译真实 App 文件：`lc_app_entry_v3.c`、`lc_bus.c`、`lc_ctrl.c`、`lc_bus_config.c`、`lc_stateblob.c`、`lc_cfgcodec.c`、`lc_json.c`、`lc_arena.c`、`lc_tracker.c`、`lc_line_cross.c`，并复用现有测试 stub。`study_model.c` 是新增研究模型，不是生产实现。

覆盖和证据界限：

| 条件 | 测试事实 | 边界 |
|---|---|---|
| schema1/2 CRC PASS、坏 CRC | `test_schema_codec_and_crc` 对152/160 B blob 作真实 codec encode/decode 和损坏拒绝 | 软件 codec，不含 NVS bit-flip 行为 |
| schema1 首迁/重复启动 | `test_real_migration_and_repeat_start` 调真实 `lcbus_restore/flush`，检查总数/window/seq/gen、CAS revision 及重复启动无二次写 | 当前生产 schema1→2；schema3 首迁是 model |
| corrupt/IO/UNKNOWN/CAS conflict | `test_real_corrupt_and_unknown_storage`、`test_real_commit_faults_and_cas_conflict` 调真实 `lc_bus`，确认坏字节保留、未知读取不造空状态、写 IO/UNKNOWN 与冲突不覆盖已存状态 | `host_stub` 故障注入，不是目标 Host NVS |
| FRAME + idle 会关窗提交 | `test_real_frame_and_idle_report_paths` 调真实 `lcbus_on_event/on_idle`，检查 `report_seq` 与 report count 都增1 | 证明两个业务入口都必须受 Paused gate 保护 |
| Pause/Resume、累计值/seq/队列 | `test_candidate_pause_resume_and_both_gates` 对候选 model 检查 pause clear window/tracker、保留 totals/seq/queue/pending，resume 开新 window | gate wrapper 调用真实 bus；model 提供 Enable state 和 CAS store |
| 提交前后崩溃、torn write、读回 | `test_candidate_crash_unknown_conflict_and_reinstall` 注入 IO-before、UNKNOWN-after、torn blob、坏 CRC，检查 pre-commit 仍旧 Enabled、commit receipt 丢失可读回 Paused、坏/未知保持受限 | 研究 store adapter，不等同 Host backend 的一体化端到端运行 |
| 过期 session/revision、clean reinstall | App model 拒绝 stale session/revision，空状态重装为 Enabled/零历史；Host `test_confirmed_uninstall_purge_gate_and_reinstall` 证明确认卸载后 App state 为 NOT_FOUND | 新 rollback marker 与该清理点的联动未实现 |
| 旧 v3 parser/降级反例 | `test_v3_rejects_new_command_but_downgrade_counts` 用真实 `lc_ctrl_poll` 检查新命令无回复拒绝；真实 restore 后把 crossing 输入真实 tracker，`total_in` 仍增1 | 直接证明 Host rollback gate 是完整产品不变量所需条件 |

### Host 真实 App state store 源码测试

在临时目录获取固定 Host commit 源码快照，然后执行其仓库自带测试（不修改另一个 checkout）：

```sh
study_tmpdir=$(mktemp -d /tmp/ne301-state-study.XXXXXX)
gh api 'repos/harryhua-ai/ne301/tarball/884bb0ff0bea9b04534f91cd1c7c9af5a45c2798' > "$study_tmpdir/host.tar.gz"
tar -xzf "$study_tmpdir/host.tar.gz" -C "$study_tmpdir"
study_repo=$(find "$study_tmpdir" -mindepth 1 -maxdepth 1 -type d | head -1)
make -C "$study_repo/tests/app_state" CC=cc test
make -C "$study_repo/tests/app_sidecar_lifecycle" CC=cc test
```

结果：`app_state_store: 188 checks, 0 failures`；`app_state_faults: 260 checks, 0 failures`。

卸载生命周期结果：`test_app_sidecar_lifecycle: 351 checks, 0 failures`。Host `app_sidecar_lifecycle.c::sc_uninstall_local_cleanup_locked` 在确认清理路径调用 `app_state_store_purge_locked`；`test_confirmed_uninstall_purge_gate_and_reinstall` 检查取消/清理未确认不会 purge，确认路径成功后 state read 返回 NOT_FOUND。

这些执行的是 Host 固定 commit 中的真实 `app_state_store.c`、卸载 lifecycle、session/installer/admission/trust-anchor 和 vendored MbedTLS，IO backend 为测试内存 adapter。它们验证 Host 源级身份、quota、revision CAS、恢复、故障处理及确认卸载清除 App state；不证明实际设备 KV/NVS 的耐久性，也没有将该 backend 与本研究 App 候选 model 组成端到端运行。report queue 的 uninstall 生命周期没有在此矩阵验收。

## READY 判定矩阵

| #30 条件/风险 | 正向证据 | 负向证据 | 当前结论 |
|---|---|---|---|
| schema尺寸、CRC、旧状态迁移与历史计数 | App `lc_stateblob.c`；`test_schema_codec_and_crc`、`test_real_migration_and_repeat_start` | 当前旧 schema 不含 Enable | 软件 PASS；schema3 仅候选 |
| App state CAS / flush / restore / UNKNOWN | `lc_bus.c::{lcbus_restore,lcbus_flush,try_commit,verify_stored}`；Host `app_state_store.c::{app_state_read,app_state_commit,app_state_store_recover}`；两组 C 测试 | adapter/源码 tests 不能证明 target NVS 故障模型 | 软件 PASS；板级 NOT_RUN |
| pause 后无报告、无序号变化 | 候选 wrapper tests 检查 FRAME 和 idle 都在真实 bus 调用前短路；固定产品 comment `6184753690` | 当前真实 `maybe_close_window→close_window→submit_window_report` 两入口均会递增 seq；生产无 Enable gate | 候选模型 PASS；产品实现未做 |
| 坏状态/UNKNOWN 后 fail closed | 候选 model 把无效状态置 UNKNOWN/受限；真实 App 对真实 storage UNKNOWN 有受限 latch | 当前 App `lcbus_storage_restricted()` 排除 CORRUPT；新 schema3 在当前 v3 恢复为 CORRUPT 后仍处理 FRAME，fixture `total_in==1` | 现有降级安全性 FAIL；需要 Host major 回退栅栏 |
| 受信新 major 控制、能力 opt-in、同 revision 请求/回执 | `app_state_store` owner identity/CAS；Host session/control API 表；#95/#91 决策锚点；本研究候选契约 | 无已集成新 major、签名 manifest opt-in、实际 control transport、回执读回 | UNKNOWN / 未冻结 |
| CONFIG_APPLY/RESET/live snapshot 并发 | 现有 App v3 控制当前同一状态 revision；候选要求共享 CAS 并让 snapshot 只读同 revision | 未有 Enable 新 major 并发集成测试 | UNKNOWN / 待实现验证 |
| 目标板 RAM/Flash/NVS/耐久/断电 | 无 | 未上板、未 Flash、未做断电/电源故障测试 | NOT_RUN，不可据软件测试推定 |
| 新 major 跨仓 transport/信任锚/key rotation | 无 | 无 target Host + signed package E2E，未测 rollback/clean-uninstall marker/key rotation | UNKNOWN |

## 未知项与交给 A 的开放问题

1. Host 应把“已确认 Paused 后拒绝旧 major”的单调回退信息放在哪里，怎样与 `publisher/app/key/native_tbs/boot/session` 绑定，并保证 Host 重启后仍生效？
2. 哪些显式 clean uninstall 情形可以清除 Paused 记录和 major floor？异常卸载、重装失败、key rotation 与恢复操作分别如何判定？
3. 新 major 的 manifest opt-in、capability 协商、wire length、结果码、snapshot 字段与 API 表变化由谁冻结；现有 4096 B state quota 对未来扩展是否仍满足？
4. 目标板 NVS 的单记录/commit marker 写入保证、最大 blob、实际 RAM/Flash、故障读写结果是什么？没有这些测量前，软件 PASS 不等于设备持久性 PASS。
5. 新 major timeout/UNKNOWN 的用户可见读回路径如何提供，同时确保 App 在结果确认前不能进入 FRAME/idle 业务路径？
