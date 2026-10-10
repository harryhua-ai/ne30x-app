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

实测（本 worktree，2026-10-10）：

- native 镜像 12328B（32B NEA1 v2 头 + 12296B payload），`text=12296
  data=0`（.data==0 链接断言通过）、`bss=108120`（arena 96KiB 等），
  entry_offset `0x9cc`，abi `0x00020000`，target `0x93E00000`；
  **重复构建逐字节一致**（sha256
  `20ff04084037998ce7e61e0f4c81a5d6b150e10477a9d31494e8e6115fa1f0c2`）。
- 签名包 `caps=0x3f、event_max=2048、state_quota=4096、report_max=6144、
  run_profile=1`；`neapp_verify_v2.py --expect PASS` 结果 PASS（完整 JSON
  见 `docs/evidence/p7-app/native-build.log`；包 sha256 为每轮 dev 钥签名
  的运行身份，非固定产物；镜像哈希固定可复现）。
- 宿主测试：unit 50 + business 134 + contract 50 = **234 项断言全过**；
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
