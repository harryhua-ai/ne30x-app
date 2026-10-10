# line-crossing 过线算法核心移植（Issue #8，P7 核心）

本文记录 `apps/line-crossing` 过线统计业务核心的移植来源、边界、构建与
测试方式，以及等价性验证结果。它证明的只有一个最小技术事实：**ne301
counting 的跟踪/越线判定算法核心已作为独立可编译、主机可测试的纯业务
代码存在于本仓库，且与 pinned 上游在相同输入序列下行为一致。**

它**不等于**：完整 Line Crossing App、真机 PASS、持续 AI 事件接入、
配置/持久化、统计窗口生命周期或上报已就绪（见第 7 节）。

- 构建证据：[docs/evidence/p7-line-crossing/](evidence/p7-line-crossing/)（全部数字来自实际运行输出）。

## 1. 源码来源与版本

| 项 | 值 |
| --- | --- |
| 上游仓库 | `harryhua-ai/ne301`，分支 `counting` |
| Pinned commit | `de25a6f1f431a631a37ff1cda87f616e293e8836`（本地只读检出，未改动其任何文件与 git 状态） |

已移植文件与角色（上游路径 → 本仓库路径）：

| 上游文件 | 角色 | 本仓库路径 | 移植方式 |
| --- | --- | --- | --- |
| `Custom/Tasks/Inc/lc_types.h` | 基础类型/记录布局/序列号工具 | `apps/line-crossing/include/lc_types.h` | 仅替换分配器平台缝（见第 2 节），其余逐字节相同 |
| `Custom/Tasks/Inc/lc_tracker.h` | 跟踪器/轨迹/段记录公开接口 | `apps/line-crossing/include/lc_tracker.h` | 逐字节相同 |
| `Custom/Tasks/Inc/lc_line_cross.h` | 越线判定公开接口 | `apps/line-crossing/include/lc_line_cross.h` | 逐字节相同 |
| `Custom/Tasks/Src/lc_tracker.c` | 目标匹配/历史环形缓冲/确认与丢失/归档记录 | `apps/line-crossing/src/lc_tracker.c` | 逐字节相同 |
| `Custom/Tasks/Src/lc_line_cross.c` | 越线方向判定（含 anti-bounce `counted_dir` 状态） | `apps/line-crossing/src/lc_line_cross.c` | 逐字节相同 |
| `tests/host/test_lc_engine.c` | 上游行为回归输入（15 个场景） | `tests/line-crossing/test_lc_engine.c` | 逐字节相同（针对移植后核心编译运行） |

上游源文件 sha256（pinned 检出，实测值，见
`docs/evidence/p7-line-crossing/upstream-baseline.log`）：

```
cfee6d6d8ce70d497a50ae55037db95ee49dd277472dbdd6cc6fcc98e0cd1918  lc_tracker.c
6ed794972ae465fc7da513f4b842478098c261c8c8eaa5822894beabe3ed28fb  lc_line_cross.c
776018c46f864c77ffbf76159f0657715ba5e3713d3bedc4676946f765e7f8be  lc_types.h
78ce91ebabb24a642026e52c8f066aa378ff1ed1b8ad6baee1c0877eb1c533e1  lc_tracker.h
ec1b94173a3cca305f055caa74dc74fe3066b487b9e49675a1991dc36fa607e0  lc_line_cross.h
4e4cbebec1dab597b00dc052631ed2eb50831d1d588fa2b8945eb384d92fa9a3  test_lc_engine.c
```

## 2. 移植 / 暂不移植边界

已移植（本次交付）：

| 能力 | 说明 |
| --- | --- |
| 贪心最近邻目标匹配 | 每帧按 `last_match_ts`/`miss_count`/`id` 排序的确定性匹配顺序，`max_dist_permille` 阈值 |
| 轨迹历史（history 环形缓冲） | 深度 `track_history_k`（clamp 4..16），越线判定输入 |
| 轨迹 trail 采样 | 100ms 最小间隔、≥500ms 强制采样、0.02 距离去重、容量淘汰 |
| 确认/丢失/退役 | `k_confirm` 确认年龄、`max_miss` 丢失上限、`LC_SEG_DEPARTED` 归档 |
| 段记录归档 | `lc_track_record_t`（含点列按 0/333/1000ms 间隔子采样）、窗口快照 `LC_SEG_CROSSING` 段链 |
| 越线方向判定 | 法线定向（outside 锚点）、IN/OUT 事件、`counted_dir` 同段防抖 |
| 公开事件输出 | `lc_cross_evt_t{track_id, ts_ms, direction}`、窗口/累计计数器、稳定轨迹遍历 |

剥离的平台依赖（不复制、不引用）：

| 上游依赖 | 处理 |
| --- | --- |
| `mem.h` / `hal_mem_alloc_any` / `hal_mem_free`（NE301 HAL） | `lc_types.h` 唯一改动点：默认 C 标准库 `malloc/free`，嵌入方可通过预定义 `LC_MALLOC`/`LC_FREE` 注入平台分配器，算法代码零改动。实证：`docs/evidence/p7-line-crossing/provenance.patch` 全部差异仅此一处 hunk |
| Camera/AI 订阅、线程/定时器、Flash/配置持久化、MQTT/Webhook 上报 | 属于上游 `line_counting.c` 周边，**不移植**（合同 non_goals） |

暂不移植 / 留待后续任务：

| 能力 | 归属 |
| --- | --- |
| AI 检测结果交付（检测中心点输入的真实来源） | P6 Host 侧平台任务 |
| Host ABI `tick_ms`/`log` 之外的运行时能力 | P6 / 平台任务（本任务不新增任何 Host ABI） |
| 配置持久化、统计窗口生命周期、事件上报（MQTT/Webhook） | P6 / P3 / P4 各自闭合 |
| App 打包（.neapp）、安装、常驻调度、真机验收 | P3 / P4 / P5 / P7 集成阶段 |

## 3. 公开接口（后续 App 接入面）

`apps/line-crossing/include/` 三个头文件构成全部公开接口：

- 输入：`lc_tracker_update(t, lc_point_t* detects, n, now_ms, ...)` ——
  消费每帧**检测中心点**（归一化坐标）与**时间戳**；
- 状态：`lc_tracker_active_count` / `lc_tracker_next_id` /
  `lc_tracker_for_each_stable`（**跟踪 ID**、位置、年龄、丢失计数）；
- 输出：`lc_tracker_check_line_crossings(...)` 产出**进出方向事件**
  `lc_cross_evt_t{track_id, ts_ms, direction=LC_CROSS_IN/OUT}` 与
  win/total in/out 计数器；`lc_tracker_window_snapshot` 产出轨迹段记录；
- 判定配置：`lc_line_cross_create(x1,y1,x2,y2, outside_x,outside_y)` 线段
  + 外侧锚点；`lc_tracker_config_t{max_dist_permille, track_history_k,
  max_miss, k_confirm}`。

## 4. 构建与测试命令

```sh
# 独立编译核心库（主机端，无任何 NE301 依赖）
make -C apps/line-crossing clean all     # -> apps/line-crossing/build/liblinecross.a

# 一键离线等价测试（默认模式不需要 ne301 检出）
tests/line-crossing/run_tests.sh

# 可选（需要 pinned counting@de25a6f1 检出，路径可用 NE301_SRC=... 覆盖）
tests/line-crossing/run_tests.sh --regen-golden   # 从上游源重建 golden trace
tests/line-crossing/run_tests.sh --provenance     # 逐文件 diff + 上游实时对拍
```

编译标准：`cc -Wall -Wextra -Werror -std=c11 -O2`（macOS clang / Linux gcc
均可），链接 `-lm`（Linux 需要；macOS 可省）。

## 5. 等价性验证（两层）

**第 1 层：上游回归输入原样对拍。** `tests/line-crossing/test_lc_engine.c`
是上游 `tests/host/test_lc_engine.c` 的逐字节副本（15 个场景：贪心匹配、
IN/OUT 防抖、零检测退役、age 饱和、记录增长、越线边界、窗口快照、trail
采样/去重/容量/独立性、越线用 history 而非 trail），针对移植后核心编译，
输出 `all lc engine tests passed`（证据：`evidence/p7-line-crossing/
test_lc_engine.log`）。未降低任何断言标准。

**第 2 层：确定性全量 trace golden 对拍。** `tests/line-crossing/
lc_equiv_harness.c` 以固定输入脚本驱动 17 个场景，逐步打印全部可观测
状态（轨迹快照含 id/位置/age/miss/counted_dir/段状态、history 与 trail
环形缓冲逐点内容、归档记录全字段+点列、方向事件与计数器、容量/ID 连续
性、序列号回绕、NULL 安全）。同一 harness 源码：
- 针对 pinned 上游源编译 → golden trace
  （`tests/line-crossing/golden/lc_equiv_trace.expected.txt`，283 行）；
- 针对移植核心编译 → 实测 trace，与 golden **逐字节一致**
  （sha256 `9d5751d675a61444e0c9db9932b1cd1aa5fd766559182f2e0f78091f1e2aa0c0`，
  证据：`evidence/p7-line-crossing/equiv-diff.log`）。

**测试有效性（非空转）验证**：对移植核心注入行为变异
（`max_miss` 阈值 +1）后，上游回归测试即失败（崩溃退出），harness trace
与 golden 出现 diff——两层测试均能捕获行为差异，非恒过测试。

## 6. 发现的等价性差异与限制

- **算法行为差异：无。** 逐字节同源 + 双层对拍全过；唯一源码差异是
  `lc_types.h` 分配器缝（`provenance.patch` 仅一个 hunk），不影响任何
  算法行为（golden 与移植 trace 的 sha256 完全相同）。
- **浮点确定性**：golden trace 含 `%.6f` 浮点输出，由同机同编译 flags
  生成。跨机器/跨编译器重建 golden 时应使用 `--regen-golden` 在目标环境
  重新生成后再对拍（默认模式的 golden 由 pinned 上游在本机 clang 生成）。
- **输入面缺口（属于上游，未扩大范围）**：`test_lc_engine.c` 未覆盖
  64 轨容量打满与单帧 >64 检测 clamp、序列号回绕工具、线上点（side==0）
  等路径；harness 第 2 层已显式补足这些场景（合同允许的合法补足），同样
  与上游逐字节一致。
- **同一物理穿越的 IN/OUT 语义取决于 outside 锚点配置**（`n` 的定向随
  `outside_*` 翻转）；这是上游原语义，harness 双锚点场景已锁定该行为。
- `lc_line_cross_check` 中 `proj>0 且 IN 已计数` 的防重复分支在纯几何
  输入下不可达（侧翻方向与 `disp·n` 符号一一对应），属上游防御性代码，
  原样保留。

## 7. 明确的"未完成"边界

本任务**不**宣称以下任何一项已就绪：

1. 完整 Line Crossing App（无 AI 数据接入、无主循环、无上报）；
2. 真机 PASS（本任务未连接任何设备）；
3. 持续 AI 事件（P6 Host 侧 AI 结果交付任务未做）；
4. 配置/持久化、统计窗口生命周期、MQTT/Webhook 上报；
5. .neapp 打包、安装、Web 可安装、常驻运行。

后续 P6 Host 接口设计与完整 App 集成应以本核心的公开接口（第 3 节）
与本文证据为输入，另行立项。
