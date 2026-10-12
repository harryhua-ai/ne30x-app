# Line Crossing v3 config-only 候选 schema 与业务快照投影公开文档（#21 交接）

状态：Issue #21 Candidate 交付物。上游 wire/容器语义以已合并受审的
`docs/app-package-protocol-v3.md`（#19）为准；本文档是 **App 自有业务层**的
权威公开 schema（v3 规范 §6.2/§8.1/§12.3 明确把该字段集与校验归 App #21），
供 NE301 #57 独立重建全量编辑草稿与只读展示，不修改、不放宽任何 #19 冻结语义。

- 候选 schema 版本：`schema = 1`（`LC_CFG_SCHEMA`，编码内字段）
- 快照投影 schema 标识：`"schema": "line-crossing/1"`
- 实现：`apps/line-crossing/app/lc_cfgcodec.c`（候选）、`lc_ctrl.c`（快照）、
  `lc_bus_config.h`（权威字段与取值范围）
- 一键复现全部正负向量：`bash tests/line-crossing-v3/run_tests.sh`
  （证据输出 `docs/evidence/p7-line-crossing-v3/`）

## 1. 所有权边界（#54 冻结；本文档可测试化）

| 数据 | 所有权 | 可由 Web/Host 写入？ |
| --- | --- | --- |
| 配置候选（本文 §2，144B） | App 自有 config-only 输入 | 经 `CONFIG_APPLY` 提交，App 校验后生效 |
| 累计 IN/OUT、窗口 IN/OUT | App-owned 运行事实 | **否**（仅出现在快照只读投影） |
| `report_seq` | App-owned 报告序号 | **否** |
| 状态 blob（152B/160B，含 magic/schema/CRC） | App 私有持久状态 | **否**（§2.5 形状候选在解码层整体拒绝） |
| `config_generation` / `state_revision` | App 自有世代/物理版本 | **否**（仅回执/快照中出现） |

## 2. CONFIG_APPLY 配置候选（config-only，144B 载荷）

命令整体 = 32B 统一头（v3 规范 §6.3）+ 144B 本候选载荷；全部多字节字段
u16-le/u32-le。Host 不解析本载荷（有界 opaque 转发）；唯一解释者是 App。

### 2.1 布局（总长 144B；`LC_CFG_CAND_SIZE`）

| 偏移 | 长度 | 字段 | 约束 |
| --- | --- | --- | --- |
| 0..3 | 4 | `magic` | `0x3343434C`（wire 字节序 `4C 43 43 33` = ASCII `LCC3`，u32-le）；其余值拒绝 |
| 4..7 | 4 | `schema` | 必须为 1；其余拒绝 |
| 8..11 | 4 | `total_len` | 必须为 144，且等于命令 `total_len - 32`；其余拒绝 |
| 12..15 | 4 | `flags` | 必须为 0（保留）；其余拒绝 |
| 16 | 1 | `target_class_name_len` | 1..31 |
| 17..48 | 32 | `target_class_name` | UTF-8（无代理/超长编码/控制字符/`"`/`\`/DEL..0x9F），长度后字节必须全 0 |
| 49 | 1 | `counter_name_len` | 1..63 |
| 50..113 | 64 | `counter_name` | 同上；长度后字节必须全 0 |
| 114..125 | 12 | `line` 6×u16 | `x1,y1,x2,y2,outside_x,outside_y` permille，各 ≤1000；(x1,y1)≠(x2,y2) |
| 126..127 | 2 | `conf_threshold_permille` | ≤1000 |
| 128..129 | 2 | `max_dist_permille` | 1..1000 |
| 130 | 1 | `track_history_k` | 4..16 |
| 131 | 1 | `max_miss` | ≥1 |
| 132 | 1 | `k_confirm` | ≥1 |
| 133 | 1 | `toggles` | bit0=`tracks_report_enable`，bit1=`heat_grid_enable`，bit2..7 必须 0 |
| 134..135 | 2 | `window_minutes` | 1..1440 |
| 136..143 | 8 | `reserved` | 全 0；任一非零拒绝 |

语义与 `lc_bus_config_valid` 一致；候选必须整体通过校验才进入事务
（T3），任何字段非法 → 整体拒绝（`REJECTED_INVALID`），无部分生效、无截断。

### 2.2 命令头约束（App 侧权威校验；v3 规范 §6.4 的镜像）

`proto_magic=NFC3`、`header_version=1`、`msg_type∈{1,2}`、`total_len` 与实际
长度一致、`session_generation≠0`、`request_id≠0`、
`expected_config_generation≠0` 且等于 App 活跃世代（否则
`REJECTED_STALE_CONFIG`）、命令 `state_revision=0`、flags 仅 bit0
（`destructive_confirmed`）、`COUNTERS_RESET` 载荷必须为空、
`CONFIG_APPLY` 载荷必须非空。违规命令不消费、不回执、不可观测地丢弃于
App 计数器 `wire_rejected`（Host 登记层本就不得交付此类命令）。

### 2.3 回执（App → Host，32B，无载荷）

`msg_type=3`；`session_generation`/`request_id` 回显所回复命令；
`config_generation`：APPLIED 时为切换后的新世代，其余为当前活跃世代（非零）；
`state_revision`：APPLIED 为新 #46 CAS 版本，其余为当前版本；
`flags`=`result_status`（v3 规范 §7.2 八值枚举）。

### 2.4 业务事务语义（T1..T7 实现；v3 规范 §9.5）

- 仅改 `counter_name`/阈值/窗口/线/追踪参数：累计、窗口、`report_seq`、
  世代无关的计数一律保留；仅 `config_generation` 恰 +1。
- 目标类切换：必须携带 `destructive_confirmed=1`（否则
  `REJECTED_UNCONFIRMED`）；应用后累计/窗口清零、tracker 重建，`report_seq`
  不倒退，历史报告不删除。
- 独立 `COUNTERS_RESET`：必须确认；清零计数、保留 `report_seq`、
  **不前进** `config_generation`、推进 `state_revision`。
- 一致事件边界：命令只在该 App 单线程业务循环内消费；提交（CAS）成功后才
  一次性切换活动配置/线/tracker；失败路径绝不先改 RAM
  （V09 负例：commit IO 失败 → `FAILED_STORAGE_IO`，RAM 与已存储字节逐字节
  不变——修复 v2 `lcbus_apply_config` 先改 RAM 后 flush 失败仍返回 0 的缺陷；
  v2 内部 helper 语义保持不变，v3 命令路径一律走
  `lcbus_txn_prepare/commit_config` 事务）。
- 目标类切换的可失败准备全部前置在 CAS 之前（v3 规范 §9.5 T3）：准备阶段
  完成 `model_meta`/`class_name` 目标/模型解析并构造完整新绑定，预分配
  切换后 tracker 与线对象；任一失败（含查询故障/失权、tracker 分配失败）
  以 `REJECTED_INVALID`/`REJECTED_RESOURCE` 拒绝，旧配置/旧计数/已提交
  字节不变（V24/V25 负例）。CAS 之后的切换只做已预备资源的纯内存安装，
  不再发起任何 Host 查询；若切换前置条件不成立（防御路径），不回报
  `APPLIED`，App 进入 `FAILED_STORAGE_UNKNOWN` + 受限只读对账语义
  （v3 规范 §9.5 T6、§9.6）。
- 失败矩阵：`REVISION_CONFLICT`→`FAILED_STATE_CONFLICT`；
  `IO_ERROR`→`FAILED_STORAGE_IO`；`STORAGE_UNKNOWN`→
  `FAILED_STORAGE_UNKNOWN` 且 App 进入受限态（后继有副作用命令一律
  `FAILED_STORAGE_UNKNOWN`，不动状态），直至 `state_read` 对账确认一致。
- 重复/并发：同 `request_id` 同语义 → 重放缓存结果不重做；同 ID 异语义 →
  `REJECTED_INVALID`（Host 登记层为 `DUPLICATE_ID_CONFLICT`）。
- `config_generation` 与 `state_revision` 分离：统计 flush 只推进 revision；
  generation 仅在已确认配置变更时 +1（u32 耗尽为 fail-closed
  `REJECTED_RESOURCE`）。

### 2.5 私有状态 blob 形状拒绝

以 App 私有状态 blob（magic `0x5341434C`，v2 152B / v3 160B 编码）为候选
载荷的命令在解码层返回 `state_blob_shape` 拒绝（`LC_CFG_ERR_STATE_BLOB` →
`REJECTED_INVALID`）。这是 §6.2 冻结的"禁止把持久状态 blob 当配置候选"的
业务校验实现；累计/`report_seq`/内部 CRC 因此不可经控制面伪造或回填。

## 3. 业务快照投影（App → Host，`"schema": "line-crossing/1"`）

32B 头（v3 规范 §6.3 快照列）+ 严格 UTF-8 单 JSON 对象载荷。
头字段：`session_generation=0`、`request_id=0`、`flags=0`、
`config_generation`=活跃世代（非零）、`state_revision`=最新已持久版本。
载荷由 App 生成：无重复键、无 `NaN/Infinity`、无尾随数据（Host 侧
`lcstub_snapshot_valid_json` 边界校验由测试正向覆盖）。周期 ≥5s（§8.4），
配置切换后立即强制发布。

### 3.1 字段集（顶层；全部只读投影，Host 不解释业务键但 #57 消费）

| 键 | 类型 | 语义 |
| --- | --- | --- |
| `schema` | string | 固定 `"line-crossing/1"` |
| `config_generation` | u32 | 活跃配置世代（非零） |
| `state_revision` | u32 | 最新已持久 #46 CAS 版本 |
| `app_state` | string | `running` / `unbound`（模型未绑定或目标类无效）/ `restricted`（存储不可信：degraded/corrupt/conflict/unknown） |
| `storage` | object | `state`: `ok`/`none`/`degraded`/`corrupt`/`conflict`/`unknown`；`withheld`: bool，true=持久化受限，不得视为当前可信 |
| `report_seq` | u32 | 已用报告序号（运行事实，非可写配置） |
| `cumulative` | object | `in`/`out` 累计计数（运行事实） |
| `counters` | object | 当前窗口 `in`/`out`（运行事实） |
| `gap` | object | `gaps`/`lost`/`lost_unknown`/`unusable`：显式 GAP 与数据质量计数 |
| `model` | object | `valid`（模型绑定且目标类有效）、`generation`、`class_generation`、`target_class`（当前绑定目标名） |
| `active_config` | object | **全部可编辑配置字段**（§3.2），可整体重建编辑草稿 |

### 3.2 `active_config`（与 §2 候选一一对应；字段名取自 `lc_bus_config.h`）

`counter_name`、`target_class_name`、
`line{x1_permille,y1_permille,x2_permille,y2_permille}`、
`outside{x_permille,y_permille}`、`conf_threshold_permille`、
`max_dist_permille`、`track_history_k`、`max_miss`、`k_confirm`、
`window_minutes`、`tracks_report_enable`、`heat_grid_enable`。
线坐标为 permille 整数；布尔为 JSON `true/false`；名称字符串为 UTF-8
（含 `"`/`\` 时由 App JSON 转义，合法性不破坏）。

### 3.3 可信标注（AC4）

陈旧/异常状态**不标当前可信**：存储受限时 `storage.state` 给出具体类别、
`withheld=true`、`app_state="restricted"`；模型无效时 `model.valid=false`、
`app_state="unbound"`。新鲜度由 Host 侧 5s/10s 规则判定（§8.4），App 保证
≥5s 周期发布并在切换后立即发布。快照整体超配额时整条拒绝、不截断
（S06；`snapshots_rejected` 可观测）。

## 4. 真实最大占用与声明额度（AC5 量化）

| 项 | 实测最大合法占用 | 包声明额度（签入 manifest） | 余量 |
| --- | --- | --- | --- |
| `CONFIG_APPLY` 命令（32B 头+候选） | **176B**（候选固定 144B；最长 63B UTF-8 计数名 + 31 字符目标类名可容纳） | `control_max=256` | 80B |
| 业务快照（32B 头+JSON） | **981B**（最坏合法配置：63B UTF-8 名称、全部计数/世代 u32 最大、all-1000 permille、双开关开、1440 分钟窗口） | `snapshot_max=1024` | 43B |
| 回执 | 32B | `control_max=256` | — |

- 声明 manifest：`required_host_caps=0x000000FF`（bit2..7 为 line-crossing-64
  必需位）、`run_profile=2`、`event_max=2048`、`state_quota=4096`、
  `report_max=6144`、`control_max=256`、`snapshot_max=1024`——与 #19/#20
  Host 模拟容量参考值一致；**这仍是签名请求，不是设备容量事实**（§14）。
- 溢出/超限拒绝向量（可复现）：
  - 候选 145B/167B 等尺寸不符 → 整体 `REJECTED_INVALID`（V22：168B 载荷）；
  - 超出声明 `control_max` 的命令不可能被合规 Host 交付（§4.1 上界）；
  - Host 实际容量收紧（control 175/snapshot 980）时：验签层
    `RESOURCE_LIMIT`（`host-policy-reject.log`）、打包层 fail-closed 拒绝
    （`pack-overflow-reject.log`）；
  - 快照超 Host 配额 → 整条拒绝不截断（S06）。
- 不把黄金示例的 256/1024B 当作设备固定容量；真实设备容量由 NE301
  #55/#56 验证，不相容时按 §4.2/A 复审流程上报。

## 5. v2 → v3 同身份迁移（AC3）

- 判定：v3 会话（`state_schema=2`）读到 v2 私有状态 blob（schema 1，152B，
  CRC 通过、内容合法）即视为同槽位 v2 遗留状态：配置、累计、窗口、
  `report_seq` 全量兼容恢复，`config_generation` 安全初始化为 1（§13.6），
  随后首次提交把 blob 原子升级为 v3 schema 2（160B，新增
  `config_generation` 字段，其余逐字节兼容 v2 布局）。
- 证据：V19/C03（迁移 + 计数保留 + 迁移 blob 落盘 + 重启稳定）；V04（世代
  推进后 blob 为 160B schema 2）。
- 反向（v3→v2 降级）：v2 App 读到 schema 2 blob → CRC/校验不过 → 按既有
  v2 损坏路径字节保留、不清零、不写入（v2 套件全量回归锁定该行为）。
- 身份边界：跨发行者/换钥/异 `app_id` 的接管在安装/升级层被 Host 拒绝
  （v1 §3 `APP_IDENTITY_CONFLICT` 等继承语义，未放宽）；App 只从本 App
  槽位读状态，对无法通过完整性/内容校验的遗留 blob 一律"损坏保留、不假
  归零、不假恢复"（V20），损坏态下恢复路径为显式确认 `COUNTERS_RESET`
  原子替换（V16，继承 v2 语义）。

## 6. 正负测试向量索引（一键复现：`tests/line-crossing-v3/run_tests.sh`）

| 族 | 测试锚 |
| --- | --- |
| 候选编解码正例/边界长名称 | U01、U02 |
| 候选负例（magic/schema/长度/flags/保留 136..143 与 140..143/名称非法/toggles 越界/内容越界/状态 blob 形状） | U03 |
| 状态 blob gen 编解码 + v2 兼容 | U04 |
| 快照 JSON Host 边界（重复键/尾随/顶层数组/NaN/坏 UTF-8/嵌套重复键） | U05 |
| 陈旧世代/未确认/资源/无效目标拒绝 | V01、V02、V03、V07、V08 |
| **flush 失败仍成功缺陷修复负例** | **V09**（commit IO 失败 → 失败回执，RAM/存储逐字节不变）、V10（CAS 冲突）、V11（STORAGE_UNKNOWN + 受限态 + 对账恢复） |
| 世代推进/report_seq 保留/目标切换重置/窗口边界切换 | V04、V05、V06、V15 |
| 去重缓存/异语义冲突 | V12、V13 |
| 命令 wire 负例族（§6.4 全族） | V14 |
| 损坏/降级存储不动状态 | V16、V18、V20 |
| v2→v3 迁移正例/损坏遗留不假恢复 | V19、C03、V20 |
| 会话权威（NO_EVENT/UNAUTHORIZED fail-closed） | V21、C05 |
| 快照投影完整性/可信标注/新鲜度/配额/转义 | S01、S03、S04、S05、S06、S07 |
| 入口校验/跨 ABI 拒绝 | C01（v3 入口拒 v2 ABI）；v2 套件 C01（v2 入口不变） |
| 打包/验签/容量溢出拒绝 | run_tests.sh 步骤 6/7（`native-v3-package.log`、`host-policy-reject.log`、`pack-overflow-reject.log`） |
| v2 全量回归（v2 业务/契约/单元/native v2 包离线验真） | `v2-regression.log`（RESULT: PASS） |
| 冻结 spec-v3 套件（M1–M11 跨版本拒绝矩阵） | `spec-v3-regression.log`（RESULT: PASS） |

## 7. 边界（如实标注；继承 v3 规范 §14）

本 Issue 无真实设备写入、无 Web 热配置闭环、无 MQTT 送达证明；native 侧为
cortex-m55 目标编译 + 静态断言 + 离线签名/验真与 Host ABI 仿真（stub）故障
回归；`control_max=256`/`snapshot_max=1024`/5s 快照在真实 Host 上的可承载性
由 NE301 #55/#56 验证。仿真 Host 的命令交付/快照拷贝未建模 64 框持续 AI
会话下的时序（v3 规范 §14.4 同款缺口），不声称真机热配置 PASS。
