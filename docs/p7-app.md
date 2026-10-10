# p7-app — 独立 Line Crossing App：Host ABI v2 组合（Issue #11）

本文记录 `apps/line-crossing/app/` 独立 Line Crossing App 的架构、与 v2 规范
的调用面映射、与冻结 counting 业务原则的对照、构建/测试/打包复现命令与
证据。它证明的技术事实只有一个：**已验收的过线算法核心已被组合为一个可
目标编译（cortex-m55 / ARM GNU 15.2）、生成正式受签 v2 包并通过 #13 工具
离线验真、并在宿主侧契约测试中逐一满足冻结 v2 wire/错误合同的独立 App。**

它**不等于**：设备安装/验签、持续推理会话、MQTT/Webhook 远端送达或断电
恢复已验证（见第 8 节边界；属 NE301 #29/#30/#31/#37/#43/#44/#46/#48）。

- 证据（全部来自实际运行输出）：[docs/evidence/p7-app/](evidence/p7-app/)。
- 一键复现：`bash tests/line-crossing-app/run_tests.sh`

## 1. 源与依赖

| 项 | 值 |
| --- | --- |
| 算法核心 | #8 已验收的 `apps/line-crossing/include+src`（lc_tracker/lc_line_cross/lc_types），**逐字节未改动**；回归权威 `tests/line-crossing/run_tests.sh` 全绿 |
| wire/ABI 权威 | `docs/app-package-protocol-v2-draft.md`（#12 集成基线）；本 App 不自造任何字段/偏移/返回码 |
| 业务原则对照 | `ne301 counting@de25a6f1`（只读本地检出）：`line_counting.c`、`line_counting_config.{h,c}` |
| 打包工具（只读使用） | `package/neapp_pack_v2.py` + `package/neapp_verify_v2.py` + `tests/package/gen_dev_key.py`（#13 产物；`package/**` 未做任何修改） |
| 签名身份 | 每次运行重新生成的**非生产** dev P-256 测试钥（gitignored，零入仓） |

## 2. App 层结构

```
apps/line-crossing/
  include/ src/            # #8 核心原样（不动）
  app/
    lc_app_abi_v2.h          # v2 ABI 唯一消费头：48B 表、返回码、事件 wire、
                             # model_meta 128B、mod-2^32 帮助函数
    lc_app_abi_v2_layout_asserts.h  # §6.2 目标静态断言（32 位编译强制）
    lc_app_entry.h/.c        # app_entry：入口校验、10 函数适配层、事件主循环
    lc_bus.h/.c              # 业务层：绑定/计数/窗口/质量/持久化/报告
    lc_bus_config.h/.c       # counting 对齐的业务配置（默认值/校验/UTF-8）
    lc_stateblob.h/.c        # 状态 blob 显式 LE 序列化 + CRC-32
    lc_json.h/.c             # 溢出检测 JSON writer（报告构造，无截断提交）
    lc_arena.h/.c            # 静态 arena 分配器（LC_MALLOC/LC_FREE 注入缝）
    lc_compat.h lc_libc_mini.c  # freestanding 字符串/内存原语 + VSQRT sqrtf
    lc_app.ld                # 链接脚本（0x93E00000/2MiB，.data==0 链接期断言）
    pack_v2_image.py         # NEA1 v2 镜像打包（abi_version 钉 0x00020000）
    Makefile                 # image / package 目标
tests/line-crossing-app/     # 宿主测试 + 证据套件（host_stub + 3 个测试 bin）
```

## 3. 10 个 v2 函数的调用面映射

| 表偏移 | 函数 | App 消费点 |
| --- | --- | --- |
| 8 | `log` | `lc_bus` 全部状态迁移日志（恢复/降级/冲突/退出原因）经适配层输出 |
| 12 | `tick_ms` | 窗口计时、持久化节流、重绑节流；**恒按 mod 2³² 差分**（§6.3 例外，C07 覆盖跨回绕关窗） |
| 16 | `event_next` | 主循环唯一事件来源（2048B 有界缓冲、1000ms 有限等待）；NO_EVENT/STOPPING/UNAUTHORIZED/契约违约各自可观察 |
| 20 | `model_meta` | 入口绑定 + 代次变化重绑；128B 严格解码（NUL/UTF-8/reserved 全零/result_type==1），违例即 UNSUPPORTED |
| 24 | `class_name` | 代次绑定扫描 `(model_gen, class_gen, index)`；BUFFER_TOO_SMALL 视为"不可能匹配目标"继续扫描；代次过期→TARGET_CLASS_INVALID；绝无指针裸传 |
| 28 | `report_submit` | 窗口关闭时提交 schema_version=1 报告；JSON 内嵌 `report_seq` 与参数一致（stub 按 §6.6 交叉验证）；OK=平台接受 |
| 32 | `report_status` | pending 环逐报告轮询；五态枚举区分接受/PENDING/送达/失败/未配置；接受≠送达分别计数 |
| 36 | `state_read` | 启动恢复：NOT_FOUND=验证过的无旧状态；STORAGE_UNKNOWN=不可判定→降级可见；blob CRC/内容校验失败→CORRUPT 可见 |
| 40 | `state_commit` | `expected_revision` 受控原子提交；REVISION_CONFLICT→重读再提交一次，仍冲突→CONFLICT 态停自动提交（计数继续、可见） |
| 44 | `should_stop` | 每轮轮询；1=协作退出（先强制 commit 再返回）；负数=Host 故障计数，绝不误读为停止 |

入口 `app_entry` 校验顺序：api 非空 → `table_size == 48` → `abi_version == 0x00020000` → 10 个函数指针全部非空；违例分别返回 -1/-2/-3/-4。
会话退出码：0=协作停止；-5=UNAUTHORIZED；-6=Host 连续契约违约；-7=持续分配耗尽。
目标编译强制 `_Static_assert`（48B 表、偏移 8..44、`sizeof(void*)==4`，§6.2）。

## 4. 业务语义与 counting 原则对照

| 场景 | counting@de25a6f1 原则 | 本 App | 测试 |
| --- | --- | --- | --- |
| 目标筛选 | 单一 `target_class_name`，conf 阈值过滤，中心点输入 | 相同（class_index 代次绑定解析，阈值 permille/1000） | B04/C08 |
| 窗口 IN/OUT | `lc_tracker_check_line_crossings` 窗口增量累加，窗口到期关闭并清零 | 相同（事件时戳域驱动跟踪，tick 域驱动窗口） | B01/B02/B03/C08 |
| 累计 | total 跨窗口持续，仅目标切换/手动重置清零 | 相同 | B03/B06/B07 |
| 目标切换 | totals+window 清零、transient 清、重绑 | 相同 | B06 |
| counter name 编辑 | **不重置计数**（纯标签） | 相同；报告携带新名 | B05 |
| 手动重置 | 全零+持久化；report_seq 延续 | 相同 | B07 |
| 模型不兼容/恢复 | UNSUPPORTED_MODEL 状态机，代次变化重绑 | 相同（meta 严格解码 + UNSUPPORTED/TARGET_CLASS_INVALID，恢复后继续计数） | B14/B15/C09 |
| 缺帧/背压 | 上游无独立 App 语义（v2 新增） | GAP 事件/gap flag/lost_frame_count 全部进入窗口质量账目；报告 `data_quality.complete=false`+量化丢失；**绝不静默当完整统计** | B16/C12 |
| NO_EVENT vs 空帧 | —（v2 新增） | 分别计数（no_event_polls / frames_empty） | B18 |
| 持久化 | 双槽 totals 文件 + 事务记录 | Host state blob（§6.7）单 blob + revision 原子提交 + CRC；窗口计数跨重启**带 carried 标注恢复**（AC3 扩展，见 §6） | B01/B08–B13/C02/C13 |
| 上报 | 自管 delivery queue + MQTT/Webhook 客户端 | **不做**：report_submit/report_status 全交 Host（§6.6）；无网络凭据/Topic/URL | B19/B20/C11/C14 |

## 5. 报告 schema

`schema_version=1`、`type=line_counting`，字段与 counting 消费者兼容：
`device_id`（App 身份串）、`boot_id`（Host 绑定输出）、`report_seq`、
`clock_valid:false`/`reported_at:null`（App 无 RTC，诚实缺省）、
`window{start_time,end_time,start_ms,end_ms,duration_sec,in,out,carried_in,
carried_out,data_quality{complete,gaps,lost_frames,lost_unknown,
frames_unusable,persist_ok}}`、`total{in,out}`、`counter.counter_name`、
`target.class_name`、`model{name,version}`、`line{x1..outside_y}`（permille
精确三位小数）、`config.confidence_threshold`，可选 `tracks[]`（≤12 段、
每段 ≤8 点）与 `heat_grid`（16×16）。**构造超容量即整份丢弃并计数，绝不
截断提交**（§4.1）；`data_quality`/`carried_*`/`app{app_id,sw_version}` 为
本 App 的加法字段（JSON 消费者向后兼容）。

## 6. 与 counting 的明确差异（均为 v2/AC3 要求，非遗漏）

1. 持久化从自管文件改为 Host state blob；窗口计数跨重启恢复并以
   `carried_in/out` 显式标注（counting 不持久化窗口；AC3 明确要求窗口与
   累计可恢复且不得默默归零）。
2. enable 开关由"管理员显式启动的会话"本体取代；MQTT/Webhook/backlog
   配置项删除（传输归 Host #44）。
3. 运行期配置编辑/手动重置在业务层实现并随状态提交；**当前 v2 ABI 无管理
   控制通道**，这两项由宿主测试直接驱动业务层验证（管理面属设备侧任务）。
4. counter name 默认值沿用 counting（"客流统计"），报告设备标识为 App 身份
   串而非 MAC（App 无法经 ABI 读取设备信息；身份可追踪性由
   `app{app_id,sw_version}` + Host 绑定的 `boot_id` + `report_seq` 承担）。

## 7. 构建/测试/打包复现

```sh
# 一键全套（核心回归 + 3 个宿主测试 + native 构建 + 签名 + 离线验真）
bash tests/line-crossing-app/run_tests.sh

# 核心 #8 等价回归（独立运行）
bash tests/line-crossing/run_tests.sh

# native v2 镜像（arm-none-eabi/cortex-m55，入口 app_entry）
make -C apps/line-crossing/app image    # -> apps/line-crossing/app/build/lc-line-crossing.bin

# dev 钥签名 + 离线验真（钥/包在 tests/line-crossing-app/work/，gitignored）
make -C apps/line-crossing/app package
```

实测（本 worktree，2026-10-10；含 AC3 四态持久化修正后的复跑）：

- native 镜像 13184B（32B NEA1 v2 头 + 13152B payload），`text=13152
  data=0`（.data==0 链接断言通过）、`bss=108120`（arena 96KiB 等），
  entry_offset `0x9cc`，abi `0x00020000`，target `0x93E00000`；
  **重复构建逐字节一致**（sha256
  `9fc4ad6101ea21c1dfaa4baf8ee6cde86e3eeca888dc27d5e4a0a5296718a929`；
  上一轮 Candidate 为 12328B/`20ff0408…`，本轮 lc_bus.c 持久化语义变更
  后镜像哈希如实换新）。
- 签名包 `caps=0x3f、event_max=2048、state_quota=4096、report_max=6144、
  run_profile=1`；`neapp_verify_v2.py --expect PASS` 结果 PASS（完整 JSON
  见 `docs/evidence/p7-app/native-build.log`；包 sha256 为每轮 dev 钥签名
  的运行身份，非固定产物；镜像哈希固定可复现）。
- 宿主测试：unit 50 + business 214 + contract 52 = **316 项断言全过**；
  #8 核心回归（上游 15 场景 + 17 场景 golden trace）仍逐字节一致。

## 8. 明确边界（本 Issue 无 PASS 的部分）

Host stub 与离线 fixture **只证明 App 侧调用与错误合同**；以下各项不在本
Issue 证明范围内，属 NE301 设备侧任务：

1. 板卡验签/安装/卸载与 Web 入口（NE301 #29/#30/#31/#37/#39）；
2. Host 长会话、持续 AI 事件投递、64 框吞吐与安全注销回收（#43/#46）；
3. NE301 自有 MQTT + Webhook 上行与报告队列真实容量（#44）；
4. 设备状态持久化/掉电恢复/原子提交实测（#46）；
5. 断电、多 App 并发、开机自启（均无；App 不自启为 v2 §7 规范行为）；
6. 真实 Host 资源配额对 `2048/4096/6144` 声明的满足（§4.2 逐项验证属设备）。

任何把本套件 PASS 写成"设备已验证"的引用都是错误的（v2 规范 §12）。

## 9. 设计要点（解释自实现注释迁移，代码内无注释）

本节承载 Candidate 首轮实现中写在代码注释里的设计解释；按 User 代码洁净
约束（#11 issuecomment-6095201082），代码不再携带解释性注释，全部集中于此。

### 9.1 入口与主循环（lc_app_entry.c）

- 入口校验顺序：api 非空 → `table_size==48` → `abi_version==0x00020000` →
  10 个函数指针全非空；退出码 `-1/-2/-3/-4` 一一对应，`0`=协作停止，
  `-5`=UNAUTHORIZED，`-6`=Host 连续契约违约，`-7`=持续分配耗尽。
- 主循环不变量：所有等待有界（max_wait_ms=1000）；NO_EVENT、空 FRAME、
  MODEL_CHANGED、GAP、STOPPING 五种可观察语义互不混同；tick 差分恒 mod 2³²；
  任何 UNAUTHORIZED 在尽力强制 commit 后以 -5 结束；持续 Host 违约以
  -6 结束而非被吸收。
- 违约连击（fault streak）策略：**只有成功消费一个事件才清零连击**；
  NO_EVENT/should_stop==0 不是"Host 已恢复"的证据，不清零。连续 3 次
  should_stop 负值或 event_next 非法返回 → `-6`。
- 每轮循环上限 10⁶ 次迭代（runaway guard，同时约束宿主测试时长）。
- 退出前执行一次 force flush（尽力而为；锁定态下仍只验证不覆盖，见 9.2），
  退出不是静默状态丢失。

### 9.2 业务层状态机（lc_bus.c）

- model_meta 严格解码返回三态：0=wire 违例（UNSUPPORTED）、1=可用、
  2=严格合法但业务不可用（未加载/result_type≠PP_TYPE_OD）。不可用态仍保留
  generations/class_count/名称，用于后续代次变化检测。
- 代次不变 + 绑定存活 → 短路 RUNNING（counting `lc_rebind` 对拍）；代次变化
  → 清 transient（tracker 销毁并顺延 next_id、heat 清零），计数器保留。
- class_name 扫描以 64B 缓冲查询：`BUFFER_TOO_SMALL` ⇒ 名称长于 63B，
  永远不可能等于 ≤31B 的目标标签 → 继续扫描（§5.4：绝不把过长标签截断成
  "看似合法"的业务类别）；`INCOMPATIBLE`（代次过期）→ TARGET_CLASS_INVALID
  交由 idle 路径限频重试。
- GAP 账目规则：flags bit0/bit1 可搭载任何事件 kind；GAP kind 是专用间断
  信号。任一 gap 信号 → `gaps_window++`；bit1 或 lost==0xFFFFFFFF 记未知
  丢失（lost_unknown_window=1），否则累加已知丢失帧数。无法解码的事件
  （malformed）同样计入 gap——不可解码即间断，绝不静默。
- 窗口关闭顺序：先快照+构造+提交报告（报告读到的是关闭前计数），再清零
  窗口/质量账目并重置 window_start。tracks 快照仅在 tracks_report_enable
  且 tracker 存活时生成。
- report_seq 在提交结果无关的情况下递增（身份连续性）；提交 OK 才登记
  pending（环容量 8，满时逐出最旧并计 status_unresolved）。状态轮询对每条
  pending 上限 240 次，超限未决同样计入 unresolved。
- 持久化四态机：OK（存储内容已验证并采纳）/ NONE（Host 验证过的确实
  不存在，不是数据丢失宣称）/ DEGRADED（读不可判定：STORAGE_UNKNOWN/
  IO 等或提交通道失败）/ CORRUPT（blob 存在但 App 内部 CRC/schema/内容
  校验失败）/ CONFLICT（存储内容可信且与内存分叉）。只有 OK/NONE 允许
  直接 CAS 提交；三种锁定态默认保留旧字节，普通改配置、过线计数、窗口
  关闭、定期 flush 与退出 force flush 都不得自动清零覆盖。
- 锁定态恢复 = 每次 flush 机会先做一次验证读（v2 §6.7：NOT_FOUND 与
  STORAGE_UNKNOWN 明确分离）：返回 NOT_FOUND → 验证过的缺席（NONE），
  此时待写内容方可提交；读到有效内容且与内存编码逐字节相同 → 只采纳
  存储 revision 不重写（对账"提交已落盘但响应丢失"）；读到有效内容且
  内存从未基于它发生业务变更（如 boot 降级后无事件/无配置）→ 整体采纳
  恢复（配置/计数/report_seq/revision 全部来自存储，零写入）；读到有效
  内容但内存已分叉 → CONFLICT：存储字节为权威，内存业务继续，报告
  `data_quality.persist_ok=false`，验证读失败 → 保持 DEGRADED。
- REVISION_CONFLICT 处理不再"采纳存储 revision 重提交内存"：CAS 相符只
  证明版本一致，不证明内存内容应当胜出。冲突后必经验证读，按上一条
  分派（相同→对账 / 分叉→旧字节胜出 / 缺席→NONE 后重提交 / 不可读→
  DEGRADED）；一次 flush 内最多三次提交尝试（有界）。
- CORRUPT 的唯一受控恢复前提是显式手动重置（既有 AC2 业务动作，非新增
  产品面）：重置时置 armed 前提，flush 复读仍损坏才以存储 revision 为
  CAS 预期替换为有效全零状态并计 commits_ok；任何自动路径（含退出
  flush）永不替换损坏字节。冲突分叉（两边内容都可信）没有任何自动或
  自服务丢弃路径——丢弃可信旧计数属 User-owned 产品决策，本实现不做、
  也不默认重置；状态保持 CONFLICT 并完全可见。
- 恢复语义：NOT_FOUND → NONE + revision 0；读失败 → DEGRADED（可判定前
  不写也不宣称）；成功恢复/采纳的窗口计数以 `window_carried/carried_in/
  carried_out` 显式标注到下一次窗口报告。
- 重绑/flush 均按 tick 域限频（1000ms/5000ms）；force 绕过节流（配置变更、
  窗口关闭、退出路径）。
- 分配耗尽：tracker/line 创建失败 → 帧记 unusable（可见）+ 连击计数，
  连续 16 次 → resource_fatal → 入口以 `-7` 退出。

### 9.3 状态 blob 布局（lc_stateblob，152B，显式小端）

```
0   magic 'LCAS'        4   schema_version(1)    8   CRC-32(反射 IEEE, [12..152))
12  target_class_name[32]   44  counter_name[64]
108 line/outside 6×u16 permille      120 conf_threshold_permille u16
122 max_dist_permille u16            124 k/max_miss/k_confirm u8×3 + flags u8
                                     (flags bit0=tracks_report, bit1=heat_grid)
128 window_minutes u16 (pad 2)
132 total_in/out、window_in/out 4×u32 148 report_seq u32
```

编码器不校验配置（业务层只编码合法配置）；解码端按"尺寸→magic→schema→
CRC→内容有效"顺序拒绝，因此 CRC 正确但内容非法（如空目标类别）返回
ERR_CONTENT 而非 ERR_CRC。

### 9.4 freestanding 目标支撑（lc_arena/lc_libc_mini/lc_compat）

- lc 核心的 LC_MALLOC/LC_FREE 缝在目标构建注入静态 arena 分配器
  （96KiB .bss，8 字节对齐，首次命中+前后合并；分裂时尾块 payload 不含
  自身块头）。耗尽返回 NULL（fail-closed），由 9.2 的耗尽策略处置。
  arena 零初始化 .bss：Host loader 不初始化 .data，链接脚本以
  `SIZEOF(.data)==0` 断言守护。
- sqrtf 用 Cortex-M55 FPU 的 `VSQRT.F32`（IEEE-754 正确舍入，与宿主
  libm 数值一致）；Newlib sqrtf 拖入 `__errno`，与 -nostdlib 冲突。
  负数/NaN 输入返回 0（核心只传平方差，不可达）。
- lc_libc_mini 同时定义编译器可为结构赋值生成的 ISO 符号
  （memcpy/memmove/memset/strlen/strcmp/strncmp/memcmp），宿主构建走
  <string.h> 包装（lc_compat.h 一条实现缝）。

### 9.5 工具与测试脚手架

- pack_v2_image.py 逐字段镜像 tools/pack_app_image.py（P3/#6 布局权威），
  唯一差别是 NEA1 头 abi_version 钉死 0x00020000（§3.3 交叉检查：
  manifest required_host_abi 必须等于原生头 abi_version；v1-ABI 镜像永远
  不能被当成 v2 App 打包）。
- host_stub 的 `log(const char*)` 签名无上下文指针（v2 ABI 如此），stub 以
  文件静态 g_cur 绑定当前实例（测试一次绑定一个 stub，lcstub_make_table
  重绑）；stub 的 report_submit 按 §6.6 做同一会话一致性验证——解析 JSON
  中 `"report_seq":N` 并与 app_report_seq 参数比对，不一致返回
  INVALID_ARGUMENT，从 Host 侧反向钉住 App 的报告身份义务。
- stub/state fault 注入分离通用 per-function 通道与 state_read/state_commit
  专用通道（次数消耗型），以便精确构造 REVISION_CONFLICT 单次/双次等序列。
- run_tests.sh 的 [1/6]–[6/6] 流水线即第 7 节命令的编排；证据全部来自
  实际运行输出（native-package-hashes.txt 记录镜像固定哈希与包的每轮
  签名身份）。

## 10. 测试清单（316 项断言的构成）

unit（50）：arena 分配/合并/耗尽/churn；JSON u32/i32/bool/null/转义/
permille/coord/溢出锁存（含 NUL 保留字节）；状态 blob 往返 + SIZE/MAGIC/
SCHEMA/CRC/CONTENT/容量负例；counting 对齐默认值/校验/UTF-8（含多字节）。

business（B01–B25，214）：B01 窗口 IN+计数+提交；B02 OUT；B03 跨窗口
累计与窗口复位；B04 类别+置信度过滤；B05 counter name 编辑不重置（报告
携带新名）；B06 目标切换清零+重绑；B07 手动重置（report_seq 延续）；
B08 重启恢复（totals/config/report_seq/窗口 carried）；B09 验证过的无旧
状态≠数据丢失；B10 开机 STORAGE_UNKNOWN→降级，仅在验证缺席后才允许
提交（验证读可见）；B11 单次 REVISION_CONFLICT 经验证缺席恢复；B12 与
分叉存储态冲突→CONFLICT 持续、停自动 commit、存储旧字节胜出（原字节
与 revision 复核）；B13 腐坏 blob→CORRUPT 可见、配置变更与定期 flush
均不覆盖、显式手动重置为唯一受控替换前提、之后正常 CAS 续写；B14 模型
未加载→帧 unusable→恢复计数；B15 result_type 错→UNSUPPORTED；class 表
变更需 class_generation 递增才可观察（无 bump 保持绑定）；B16 GAP/flag/
未知丢失全账目+报告 data_quality；B17 wire 负例 9 连（未知 kind、未知
flags、bit1 携带有限 lost、非 FRAME 带检测、total_len 不一致、
reserved0≠0、Inf 位型、class_index 越界、截断头）全拒且计入 gap；
B18 NO_EVENT≠空帧；B19 QUOTA 丢弃可见、report_seq 仍递增、窗口照常
关闭；B20 接受≠送达/失败/未配置分通道计数；B21 MODEL_CHANGED 清
transient 保计数；B22 开机 STORAGE_UNKNOWN 而旧 blob 实际存在→配置
变更零覆盖（字节/revision 逐字节复核）、计数内存继续、报告
persist_ok=false；B23 不同可信内容 REVISION_CONFLICT→旧内容胜出、内存
永不静默胜出（force flush 亦不覆盖、报告 persist_ok=false）；B24 相同
内容冲突→仅采纳存储 revision 对账、零重写、后续正常续写；B25 开机
STORAGE_UNKNOWN 后验证读到有效旧态→内存未分叉即整体采纳（零写入、
revision 延续）。

contract（C01–C14，52）：C01 入口四类校验（含 v1 ABI 0x00010000 拒绝）；
C02 干净会话（绑定/轮询/最终 commit/退出 0）；C03 未授权会话 -5 且零
存储零报告；C04 event_next INVALID_ARGUMENT×3→-6；C05 should_stop
负值×3→-6（绝不误读为停止）；C06 STOPPING 事件协作退出；C07 tick 跨
2³² 回绕的窗口关闭（duration_sec=60）；C08 E2E 过线计数+报告 schema/
身份/字段；C09 腐坏 meta 会话安全降级；C10 event_next UNAUTHORIZED→-5；
C11 report_submit UNAUTHORIZED→-5；C12 GAP/backpressure 在提交报告可见；
C13 STORAGE_UNKNOWN 开机会话存活且全程零状态写入（存储不可判定即拒写，
fail-closed）；C14 JSON report_seq 与提交参数一致性（stub 反向验证）。
