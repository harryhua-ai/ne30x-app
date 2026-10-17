# Issue #33：Enable 持久化与控制边界研究

## 判定

**软件层存在一个可比较的最小候选；现有代码还不能满足 #30 的完整条件。** 候选可把 Enable 与累计计数、窗口计数和 `report_seq` 放进同一份 App private state CAS 提交；但当前 v3 App 遇到该候选 schema 时会将状态报为 CORRUPT 后继续处理 FRAME。测试实际复现了旧 v3 在已 Paused 状态上继续计数。因此，仅升级 App state 格式不足以满足“已确认 Paused 后降级不得回落 Enabled”。完整实现还需要 Host 可信的 major 回退栅栏，并在新 major 中协商控制能力。该栅栏和跨仓 transport 尚未实现或验收。

这份研究不实现产品 Enable，也不冻结 schema3、ABI major、magic、layout 或 capability 编号。供 A 判定 #30 READY 的当前结论是 **BLOCKED**：源码反例已证伪“只改 App state 就够”；新 major/回退栅栏及目标板持久性仍无验收证据。

## 已核实的现有状态边界

### App private state

App 当前 `lc_stateblob` schema1 为 **152 B**，schema2 为 **160 B**，最大缓冲为 **512 B**。CRC32 位于偏移8，覆盖偏移12至 blob 末尾。两版均含配置、累计 `total_in/total_out`、当前 window、`report_seq`；schema2 另含 `config_generation`。`lc_st_encode_gen` 将 156–159 置零，所以这里可作为候选字段空间；它不是已批准 ABI 扩展。

当前 App 通过 state read/commit 读写 Host 私有状态，commit 带 expected revision。`lcbus_restore` 区分已验证不存在、坏 blob 与读取未知；`lcbus_flush` 遇到 CAS 冲突会读回并避免覆盖新值，IO/UNKNOWN 会进入降级或未知状态。但 `lcbus_storage_restricted()` 不包含 CORRUPT；CORRUPT 状态下 event loop 仍调用 FRAME/idle 入口。

Host App state 的 owner identity 包含签名 SPKI SHA-256、publisher ID、app ID，并有 quota。签名 key 变化会形成不同身份空间；除非 Host 提供已授权的身份迁移，不应把“找不到旧 key 的状态”解释为可安全恢复的 Enabled。Host store 有 134 B metadata 和 280 B commit marker；这些结构和当前存储 API 不能证明目标板 NVS 的写入原子性或耐久性。

Report 队列属于 Host 报告交付面，不在这 160 B App blob 中。Enable 迁移不得以队列内容反推或重造计数，也不得借暂停清除队列。Host 当前确认卸载路径会调用 `app_state_store_purge_locked`；这会清除 App state，累计历史和 Enable 值不能从该 state 恢复。report queue 的卸载生命周期与未来回退栅栏的清除条件需分别验证；本任务只固定暂停期间保留历史队列。

### Host v3 控制边界

Host 当前 App API 表 v2/v3 为 48 B/60 B；v3 提供 state read/commit、control receive/reply、snapshot publish 等函数。当前 App v3 控制包头为 32 B，控制缓冲上限256 B、snapshot上限1024 B；已识别命令只有 `CONFIG_APPLY` 和 `COUNTERS_RESET`。现有 v3 `CONFIG_APPLY` 负载为 144 B，request 头要求 state revision 为0。它不是 Enable 控制原语。

现有 signed manifest 有 v1 160 B、v2/v3 192 B 版本。当前 v3 控制 capability 已知至 bit7（mask `0xFF`）；没有已验收的 Enable capability。#95 已说明 v3 无可信新增控制或 live publish 原语。Host App state API 可提供身份绑定、quota、revision CAS 和读回；这些接口可用于研究，但不能替代可信的新 major 协商。

## 最小 App-owned 状态演进候选（研究模型）

研究夹具在现有 160 B schema2 尺寸上构造了一个**仅供比较**的 schema3：用偏移156的 4 B 表示 Enabled/Paused，改 schema 字段并重算 CRC。候选语义如下：

1. 只有 CRC/content 正确的 schema1/2 才在首迁时映射为 Enabled；迁移以当前 Host revision CAS 写入单一完整记录。重复启动不再写入。
2. 新的 Pause/Resume 都将 desired state、计数、window、`report_seq` 放在一个 CAS 记录中。只有 commit 成功且读回确认后才返回 Applied。IO failure 返回失败；CAS conflict 返回冲突；UNKNOWN、torn/corrupt/readback 失败均使 Enable 状态为 UNKNOWN/受限，不能默认 Enabled。
3. Pause 清 `window_in/out` 与 tracker，保留累计计数、`report_seq`、Host report queue；不调用 close/submit。Resume 从新 window 开始，不重置累计历史或报告序号。
4. 控制和状态读取使用同一 owner identity、session、expected revision。Host 确认卸载会清除 App state；空 state 重装的候选模型回到默认 Enabled 且累计历史为0。未来回退栅栏是否随确认卸载清除，必须由 Host 生命周期契约明确授权。

此模型在 isolated C fixture 中调用真实 App `lcbus_on_event` / `lcbus_on_idle`，但通过测试 wrapper 在入口前模拟 Paused gate。模型没有改写生产 App，也未证明正式 tracker reset、目标板存储，或 App-to-Host 端到端提交。Host 另有真实确认卸载/purge 生命周期测试，但其 memory backend 不验证目标板持久性。**模型通过只证明此状态演进可以被模拟和反例检验。**

### 必须由 Host 解决的降级反例

Fixture 将候选 schema3 的 Paused blob 提供给当前 v3 App。真实 `lcbus_restore` 返回 CORRUPT，随后真实 `lcbus_on_event` 仍可处理 crossing，`total_in` 从0增至1。当前 idle 也无 Enable gate，并可经 `maybe_close_window → close_window → submit_window_report` 关闭窗口和递增序号。因而“坏/未知/新 schema 后 fail closed”必须覆盖 event loop 和旧 major 启动权；只在新 App parser 中拒绝控制不够。

在 Pause 被确认后，Host 需要保留与 App 签名 owner、publisher/app、签名 key、已验证 native TBS、boot 和 session 绑定的回退状态；拒绝旧 major 读取/运行该 App state。只有显式 clean uninstall 的授权路径能清除这一状态。key rotation、包恢复、损坏恢复和 rollback policy 需分别定义，不能隐式改用另一个空 state namespace。

## 新 major opt-in 控制契约候选（未冻结）

以下是给 A 的 review 输入，不是 ABI 冻结：

- **可信主体**：Host 从验签后的 publisher/app、SPKI key、canonical native TBS digest 建立 active session，并加入 Host boot ID 和 app session nonce。App 不得自行声明这些值。只有签名 manifest 明确 opt-in 且 Host 显式协商成功，才可返回候选 `ENABLE_STATE_V1` capability；不在现有 v3 capability mask 上占用新 bit。
- **请求**：候选 wire 总长约48 B（32 B 控制封套 + 16 B 小 payload），包括 session/request identity、期望 state revision、目标 Enabled/Paused 和协议版本。新 major 的精确 magic/layout 尚未定。
- **回执**：候选约48 B，回传同一 boot/session/request identity、请求期望 revision、实际提交 revision、最终 Enable 状态和结果码。Applied 仅在 CAS 成功并读回同一 revision/state 后成立；duplicate request 可返回已记录结果或 ALREADY，不得重复改变状态。
- **失败语义**：拒绝、取消、超时与 storage UNKNOWN 都要求读回状态/revision。超时或 UNKNOWN 期间 App 进入受限态，暂停 FRAME/idle 业务入口；取消发生在持久提交后不可撤销提交，必须回报已提交读回，逆向操作是新请求。
- **并发语义**：Enable、CONFIG_APPLY、COUNTERS_RESET 共用单一 per-app state revision CAS。竞争者只能成功一个；其他请求读回后报 conflict/retry，不得覆盖计数或 Enable。snapshot 是只读视图，必须带同一 revision/Enable 状态；Paused 时不得制造窗口进展或 partial report。
- **兼容性负例**：当前 v3 parser 会无回复拒绝未知 Enable type；当前 v3 在 schema3 Paused 状态下仍处理 crossing。旧 v3 不得被误判为支持能力，也不能作为回退时的默认 Enabled 路径。

### 尺寸与资源取舍

候选 App state 仍为160 B（相对 schema2 不增）；Host 当前 signed state quota 示例为4096 B，Host metadata/marker 为134/280 B。候选48 B request/receipt 低于当前256 B控制上限，不要求大消息缓存；可复用现有 state CAS、control receive/reply 和 readback。Host v3 table 是60 B；若新 major 仅增加一个显式 capability-negotiation function pointer，32-bit target 上候选表为64 B，若 capability 可由签名 manifest/major 固定，表大小可不变。实际 manifest capability 字段会改变签名对象和 package compatibility，尺寸/布局应待 A 与 Host owner 冻结。

该取舍避免引入第二份 App 状态 blob或独立 Enable 写事务。代价是 Host 必须提供可验证的回退栅栏、统一 CAS 仲裁、可信 session readback 和受控 key rotation/uninstall 生命周期。RAM、Flash/NVS 用量与目标持久原子性均未在目标板量测。
