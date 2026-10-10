# NE301 × ne30x-app 独立应用平台开发路线图

> 维护责任：Role A / Project Steward。本文是跨仓库长期产品与架构规划，不是 `ght` Execution Plan、实施授权、当前进度数据库或已批准的产品发布规范。
>
> 当前状态核对日期：2026-10-10。动态执行状态以各仓库的 GitHub Issues、Task Contracts、`ready`、`refs/ght/*`、PR 和最新验证证据为准；本文的阶段状态仅为该日期的快照。
>
> 核心目标：**让管理员最终能够通过 NE301 Web 界面安全安装、运行、更新和卸载由 `ne30x-app` 独立构建的应用，不因更换业务 App 而重新编译或刷写 NE301 主固件。** 普通用户可用与生产发布需经过独立安全、稳定性与发布验收。

## 1. 已验证事实与尚未完成的工作

### 1.1 已完成：NE301 最小 App Host PoC

- [ne301#25](https://github.com/harryhua-ai/ne301/issues/25)：已完成并关闭（`completed`）；[PR #26](https://github.com/harryhua-ai/ne301/pull/26) 已合并至 **`experiment/app-host-poc`**。
- 唯一固定实验 Host 基线：[`ne301/experiment/app-host-poc@a5b4bf3dd25931d612680aff200e4e0ac8d8e64e`](https://github.com/harryhua-ai/ne301/commit/a5b4bf3dd25931d612680aff200e4e0ac8d8e64e)，原始运行代码证据来自 `90f641f8cac87ea89fbbfc0f448ba1df71eb34df`。
- **公开 ABI 的唯一源文件**：[`Custom/Common/Inc/app_host_abi.h`](https://github.com/harryhua-ai/ne301/blob/a5b4bf3dd25931d612680aff200e4e0ac8d8e64e/Custom/Common/Inc/app_host_abi.h)。当前 ABI v1（`0x00010000`），函数表仅包含 `log` 与 `tick_ms`。
- 真实开发板已证明：从 LittleFS 读取独立测试镜像，在预留的 2 MiB PSRAM 区域完成验证、装载、调用版本化 Host API、执行并返回；损坏镜像遭拒绝，重启默认不自动执行。适用验证板型为 **64 MiB PSRAM**，32 MiB 配置被禁止。
- **不是安装器**：PoC 仅在 `APP_HOST_POC=1` 的受控开发配置下启用，UART 控制台 `apphost info`、`apphost load <path>` 只能加载已经存入文件系统的镜像；尚无用户 Web 安装入口、`.neapp` 安装器、生产签名、权限隔离或完整 App 生命周期。
- 真机测试结束后，**App1/OTA 已恢复原先状态**；LittleFS 仍留有两个惰性测试文件，NVS 内容未读取。**不得假设当前开发板已运行实验 Host**。恢复范围、哈希与已知限制见 [NE301 验证报告](https://github.com/harryhua-ai/ne301/blob/a5b4bf3dd25931d612680aff200e4e0ac8d8e64e/Docs/design/app-host-poc.md)。

### 1.2 当前 ne30x-app 状态

**已完成（CLOSED / `completed`）**：

- [ne30x-app#1](https://github.com/harryhua-ai/ne30x-app/issues/1)：独立 App 可行性调查（DONE）。
- [ne30x-app#2：独立 hello-app 构建与 NE301 Host ABI 集成验证](https://github.com/harryhua-ai/ne30x-app/issues/2)：已完成。独立编译的 hello-app V1/V2 镜像在不重刷主固件的前提下于实验 Host 上完成真机替换运行；证据见 [docs/app-hello-poc.md](app-hello-poc.md)。
- [ne30x-app#4](https://github.com/harryhua-ai/ne30x-app/issues/4)：**包协议 v1 已定稿入库**，canonical 文本为 [`docs/app-package-protocol-v1.md`](app-package-protocol-v1.md)（内容 blob `c7df6e79e53845c6a08416e9940b84fa4e19fbaf`），经 [PR #7](https://github.com/harryhua-ai/ne30x-app/pull/7) 合并。
- [ne30x-app#6](https://github.com/harryhua-ai/ne30x-app/issues/6)：**v1 签名打包与离线验证已完成**（`package/neapp_pack.py` / `package/neapp_verify.py`，说明见 [docs/p3-packaging.md](p3-packaging.md)），经 [PR #10](https://github.com/harryhua-ai/ne30x-app/pull/10) 合并。其中 hello-app `1.0.0 → 2.0.0` 是**同应用的两份 v1 `.neapp` 包**，与下述 v2 容器/ABI 无关。
- [ne30x-app#8](https://github.com/harryhua-ai/ne30x-app/issues/8)：counting 过线（Line Crossing）算法核心已离线等价移植至 `apps/line-crossing`（[PR #9](https://github.com/harryhua-ai/ne30x-app/pull/9) 合并）；**离线 PASS 不等于真机 PASS**。
- [ne30x-app#12](https://github.com/harryhua-ai/ne30x-app/issues/12)：**持续业务 App 包及 Host ABI v2 规范已定稿入库**（[PR #14](https://github.com/harryhua-ai/ne30x-app/pull/14) 合并）。现行唯一已集成 v2 规范基线 = [`docs/app-package-protocol-v2-draft.md`](app-package-protocol-v2-draft.md)（文件名中的 "draft" 为历史命名）+ `tests/spec-v2/**`。v2 是**独立 major**（独立容器/manifest magic、`required_host_abi` 编号与函数表），不是 v1 的向后兼容延伸。
- [ne30x-app#13](https://github.com/harryhua-ai/ne30x-app/issues/13)：**v2 受信签名打包与跨版本离线验证工具已完成**（`package/neapp_pack_v2.py` / `package/neapp_verify_v2.py`，说明见 [docs/p6-packaging.md](p6-packaging.md)），经 [PR #15](https://github.com/harryhua-ai/ne30x-app/pull/15) 合并。

**在途（OPEN，修正中，均未 ACCEPTED / 未完成）**：

- [ne30x-app#11](https://github.com/harryhua-ai/ne30x-app/issues/11)：独立 Line Crossing App 统计业务与 Host 组合；[PR #16](https://github.com/harryhua-ai/ne30x-app/pull/16) 收到 A 的 REQUEST_CHANGES，正在修正。
- [ne301#37](https://github.com/harryhua-ai/ne301/issues/37)：LittleFS/NVS 非破坏性启动与故障恢复安全基线；[PR #53](https://github.com/harryhua-ai/ne301/pull/53) 收到 A 的 REQUEST_CHANGES，正在修正。

设备端可行性核验 [ne301#27](https://github.com/harryhua-ai/ne301/issues/27)（安装事务/验签/故障恢复，只读）与 [ne301#32](https://github.com/harryhua-ai/ne301/issues/32)（签名验签与公钥信任模型，离线）亦已完成。上述打包/移植证据均为**离线**验证；安装后端、Web 管理入口与真机端到端链路尚未落地（见第 3、5 节）。

## 2. 双仓库责任边界

| 能力/交付物 | `ne301`（设备端） | `ne30x-app`（应用端） |
| --- | --- | --- |
| 原生镜像装载、校验、执行内存边界、Host API | **唯一实现/规范来源** | 通过固定版本的公开 ABI 消费 |
| Camera、AI、网络、存储等底层服务 | 保有实际实现，按业务需要提供受控公开接口 | 不复制平台私有实现 |
| 独立应用源码与业务逻辑 | 不嵌入具体业务 App | **唯一实现来源** |
| App 独立构建、镜像打包、应用元信息、开发者工具 | 定义/验证所需 ABI 与安装兼容规则 | 生成与检查交付物 |
| 设备端接收、验签、安装、更新、卸载、存储及恢复 | 负责 | 生产符合规范的包 |
| NE301 Web「应用管理」入口及管理 API | 负责 | 可为 App 提供元信息/后续专属 UI |
| 真实业务 App（例如越线检测） | 提供必要的平台能力 | 负责业务行为与测试 |
| 真机联调、端到端验收 | 共同参与，守住设备安全 | 共同参与，证明 App 独立性 |

**硬边界：** 本路线图不授权更改 `ne301/main` 或 `ne301/counting`，不授权将 PoC 自动迁入正式固件；所有实验仅使用经 A 确认的固定实验基线和受权开发板。应用方不得通过复制 NE301 私有头、Camera/AI/HTTP/RTOS 实现来绕开 Host ABI。

## 3. 分阶段路线图（建议目标，非已经授权的任务）

| 阶段 | 当前状态（2026-10-10） | 独立可验收的主要成果 | 主责 | 进入下一阶段的证据 |
| --- | --- | --- | --- | --- |
| **P0** 基线/设备准备 | 基线已固定并由 P1 使用；安全基线 ne301#37 在途 | 固定 ABI/Host SHA，核实板卡、保护范围、恢复方案 | A 定义边界，B 做技术核对 | 可安全复现的设备与固定依赖 |
| **P1** 跨仓库 hello-app PoC | **已完成**（ne30x-app #2） | 从 `ne30x-app` 独立编译两个版本、真机替换运行 | `ne30x-app` | 不重刷主固件的两次运行、坏镜像拒绝、分区哈希 |
| **P2** 包与运行协议 | **已完成**（v1=ne30x-app #4，v2=ne30x-app #12；设备可行性=ne301 #27/#32） | 决定包格式、兼容规则、安全边界和生命周期 | A 主导双方确认 | 可实施、可测试的版本化规则 |
| **P3** App 构建/打包 | **已完成**（v1=ne30x-app #6，v2=ne30x-app #13） | 独立生成可验证包及相应工具 | `ne30x-app` | 可复现产物、签名/兼容性验证 |
| **P4** 安装后端 | 待实现（ne301 #29/#30/#31，Prepared） | 在设备端可靠接收、验证、安装、更新与卸载 | `ne301` | 有故障恢复证据的安装管理 API |
| **P5** Web 安装 MVP | 待实现（ne301 #39/#40，Prepared） | Web 查看、上传、安装、运行、更新、卸载受信任 App | `ne301` | 全程不接串口、不重刷固件的演示 |
| **P6** 平台能力与执行模型 | 应用侧 v2 打包已完成（ne30x-app #13）；设备侧待实现（ne301 #47/#43/#44/#46/#49，Prepared） | 按首个业务 App 的实际需求扩展 Host API/生命周期 | `ne301` | API 兼容、资源边界与故障恢复验证 |
| **P7** 首个真实业务 App | 算法核心离线移植已完成（ne30x-app #8）；Host 组合在途（ne30x-app #11）；设备全链路待实现（ne301 #48，Prepared） | 以 Line Crossing 为候选，独立消费 Camera/AI 所需公开能力 | `ne30x-app` | 业务 App 安装/更新和系统隔离的真实验收 |
| **P8** 生产发布准备 | 未开始 | 安全、稳定性、断电/异常恢复、OTA 兼容、回退验证 | 双方 | User 明确的产品发布授权 |

**依赖关系**：`P0 → P1 → P2 → (P3 与 P4 可并行) → P5`，形成首个 Web 安装 MVP；`P6 → P7 → P8` 面向真实业务与生产化。P0–P3 的应用侧成果已完成；设备侧主线现为安全基线（[ne301#37](https://github.com/harryhua-ai/ne301/issues/37)）→ 口令认证基线（[ne301#36](https://github.com/harryhua-ai/ne301/issues/36)）→ P4（#29/#30/#31）→ P5（#39/#40），以及 P6/P7 链（#47/#43/#44/#46/#49 → #48），逐步按各 Issue 现行 `ght-contract` 授权。安全/恢复验证应贯穿每个实现阶段，而不等到 P8 才考虑。阶段不是自动激活的 Issue；真正的实现要由 A 按可独立评审的行为建立/授权 Task Contract。

### P0 — 固定跨仓库与硬件验证基线（基线已完成；安全基线在途）

**已固定并投入使用**：`ne301/experiment/app-host-poc@a5b4bf3d...`、唯一公开 ABI 头、64 MiB PSRAM 限制。该基线上的既有证据须严格区分归属：P1（ne30x-app #2）的 hello-app 独立镜像替换运行为**真机**证据（真机日志与分区哈希见 [docs/app-hello-poc.md](app-hello-poc.md) 与 [docs/evidence/](evidence/)）；P3（ne30x-app #6/#13）的 v1/v2 签名打包与验签为**离线 PASS**，未涉及设备端安装/验签；P4/P5 的设备端安装与验签仍待实现。

**持续约束（受控设备授权/数据备份，不因阶段完成而失效）**：开发板当前固件/boot slot、LittleFS/NVS/WEB/AI 等需保护数据的核实与可恢复性仍是硬约束；不得把历史开发板授权解释为允许覆盖未知现有数据。若板卡承载需要保留的 `counting` 演示数据且不能证明恢复方案，停止刷写并报告 A。该非破坏性安全基线现由在途的 [ne301#37](https://github.com/harryhua-ai/ne301/issues/37) 承载（PR #53 修正中）。

**完成判据（已满足部分）**：可固定取得 ABI 与实验 Host；板卡与备份/恢复方案可复核，缺失时如实报告，不把真机实验标为 PASS。

### P1 — 跨仓库 hello-app PoC（已完成：ne30x-app #2）

[ne30x-app#2](https://github.com/harryhua-ai/ne30x-app/issues/2) 已按其现行 `ght-contract` 完成并关闭：独立编译 hello-app V1/V2 两个版本，唯一消费 NE301 公开 ABI；在部署的一次性实验 Host 上运行、替换并再次执行；验证了读取真实 Host 信息、非法/不兼容镜像拒绝，以及更换 App **没有重新编译、重刷 NE301 主固件、改写基础 Web**。构建步骤、ABI/产物尺寸、真机日志、前后镜像和分区完整哈希、失败路径证据见 [docs/app-hello-poc.md](app-hello-poc.md) 与 [docs/evidence/](evidence/)。

该阶段的边界约束（不把 PoC 扩张成 Line Crossing、产品安装器、多 App 调度、动态加载器或 Web 管理 UI；无设备授权时停在静态验证，不冒称真机通过）对后续阶段仍然有效。

### P2 — 安装包与执行模型决策（已完成：v1 与 v2 两份规范已定稿入库）

安装包扩展名 `.neapp` 的格式已定稿为两份独立规范：

- **v1**：[`docs/app-package-protocol-v1.md`](app-package-protocol-v1.md)（[ne30x-app#4](https://github.com/harryhua-ai/ne30x-app/issues/4)，PR #7 合并）。覆盖版本化应用 ID/版本、签名/身份、严格 DER、未知能力位与未知容器版本拒绝、hello-app 单次运行语义；ABI `0x00010000`（16B 函数表，仅 `log`/`tick_ms`）不变。
- **v2**：[`docs/app-package-protocol-v2-draft.md`](app-package-protocol-v2-draft.md)（[ne30x-app#12](https://github.com/harryhua-ai/ne30x-app/issues/12)，PR #14 合并；文件名为历史命名，内容为已定稿规范）。v2 是**独立 major**：独立容器/manifest magic、`required_host_abi` 编号与函数表，不复用 v1 保留位扩权；为持续业务 App 引入能力声明与 Host ABI v2 调用面。

**关键区分**：hello-app `1.0.0 → 2.0.0`（P3/#6 基线）是**两份 v1 `.neapp` 包**的同应用升级，与 v2 容器/ABI（独立 major）有别，不得混用叙述。

安装/运行的产品语义决策保持不变：首版 Web MVP 只允许管理员安装可信来源、签名可验证的应用；未经认证的文件上传不等于执行授权；CRC/SHA 只证明数据完整性，**不是来源认证**；原生程序可能共享主固件执行环境，缺少可信故障隔离时不得对不受信任第三方 App 承诺沙箱安全。不能把 PoC **同步执行后返回**当成完整后台应用生命周期，也不能假设已有强制停止机制。设备端安装事务/验签可行性已由 [ne301#27](https://github.com/harryhua-ai/ne301/issues/27) 与 [ne301#32](https://github.com/harryhua-ai/ne301/issues/32) 完成（只读/离线），安装后端本身仍待 P4 实现。如涉及开放第三方代码或允许普通用户直接执行原生代码，仍由 User 决定风险取舍。

### P3 — ne30x-app 构建和打包（已完成：v1 与 v2 工具均已落地）

原定最低结果已达成：在本仓库独立生成固定 ABI 的原生镜像及符合 P2 规范的包，版本可追溯，可重复生成/离线校验，构建不修改 NE301 工作树，不静态链接平台私有代码；失败路径覆盖错误版本、目标板、入口/尺寸、损坏包和不可信签名。

- **v1**：[ne30x-app#6](https://github.com/harryhua-ai/ne30x-app/issues/6)（PR #10 合并）——`package/neapp_pack.py` / `package/neapp_verify.py`，覆盖 hello-app `1.0.0 → 2.0.0` 两份 v1 包，说明见 [docs/p3-packaging.md](p3-packaging.md)。
- **v2**：[ne30x-app#13](https://github.com/harryhua-ai/ne30x-app/issues/13)（PR #15 合并）——`package/neapp_pack_v2.py` / `package/neapp_verify_v2.py`，含跨版本验证与 v1 回归，说明见 [docs/p6-packaging.md](p6-packaging.md)。

以上均为**离线**验证产物；离线 PASS 不等于真机 PASS。

### P4 — NE301 设备端 App 安装服务（待实现）

设计受认证、具授权的安装 API，借鉴已有文件上传与 OTA 的受控流式传输能力，**不直接把普通文件上传或调试 CLI 等价为任意代码安装**。最低语义：接收并暂存、包/签名/ABI/资源检查、原子或可恢复安装提交、应用清单、升级、卸载及故障状态。不得覆盖 FSBL、APP1/APP2、OTA、基础 Web 或 AI 分区；必须真实验证意外断电、空间不足、写入/校验失败与回滚行为。

对应 Prepared Issue：[ne301#29](https://github.com/harryhua-ai/ne301/issues/29)（验签/兼容检查/管理准入）、[ne301#30](https://github.com/harryhua-ai/ne301/issues/30)（安装升级/卸载与掉电恢复）、[ne301#31](https://github.com/harryhua-ai/ne301/issues/31)（已安装 App 手动单次执行）；前置为安全基线 [ne301#37](https://github.com/harryhua-ai/ne301/issues/37) 与口令认证基线 [ne301#36](https://github.com/harryhua-ai/ne301/issues/36)。逐步授权以各 Issue 现行 `ght-contract` 为准，本文不构成授权。

### P5 — NE301 Web「应用管理」MVP（待实现）

目标不变：管理员能在 Web 页面查看已安装应用、上传 `.neapp`、看到兼容性/签名验证结果、安装/手动执行一次性 App、更新、卸载、查看结果与失败原因。**第一个 MVP 的验收**：无需串口或开发者刷写工具，从 Web 安装 hello-app V1、替换为 V2 并运行，主固件及基础 Web 前后不变；失败时可恢复到一致状态。App 商店、在线分发、复杂多任务管理不是首版目标。该 MVP 中的 hello-app V1/V2 仍是**两份 v1 包**。

对应 Prepared Issue：[ne301#39](https://github.com/harryhua-ai/ne301/issues/39)（Web 可信 App 管理界面与失败状态）、[ne301#40](https://github.com/harryhua-ai/ne301/issues/40)（V1→V2 跨仓库端到端验收）。

### P6 — 按真实业务需求扩展 Host API 与运行模型（应用侧 v2 打包已完成，设备侧待实现）

实验 Host 当前公开 ABI 仍只有 `log` / `tick_ms`（v1）。v2 规范（[ne30x-app#12](https://github.com/harryhua-ai/ne30x-app/issues/12)）已为持续业务 App 定义能力声明与 Host ABI v2 独立调用面：Camera 图像/AI 检测结果、配置、存储、网络事件等必须由 NE301 按需暴露为**稳定、受控、可版本协商**的接口，应用只消费这些接口。应用侧 v2 受信签名打包/离线验真工具已由 [ne30x-app#13](https://github.com/harryhua-ai/ne30x-app/issues/13) 完成；设备侧对应 Prepared Issue：[ne301#47](https://github.com/harryhua-ai/ne301/issues/47)（v2 验签准入与能力版本分派）、[#43](https://github.com/harryhua-ai/ne301/issues/43)（AI 检测结果供给与运行会话）、[#44](https://github.com/harryhua-ai/ne301/issues/44)（业务结果回传/MQTT/Webhook 上行）、[#46](https://github.com/harryhua-ai/ne301/issues/46)（业务配置与累计状态持久化）、[#49](https://github.com/harryhua-ai/ne301/issues/49)（Web 会话管理与状态），均未开始实施。优先考虑暴露检测结果而非整个驱动/AI Runtime；后台生命周期、资源回收、CPU/内存预算、App 故障影响均须独立验证；不要无证据承诺原生 App 不能使系统崩溃。

### P7 — 第一个业务 App（算法核心已离线移植；Host 组合在途；设备全链路待实现）

Line Crossing 已确定为首个业务 App：算法核心已由 [ne30x-app#8](https://github.com/harryhua-ai/ne30x-app/issues/8)（PR #9 合并）离线等价移植至 `apps/line-crossing`（[docs/p7-line-crossing-port.md](p7-line-crossing-port.md)），但**离线 PASS 不等于真机 PASS**。统计业务与 Host 组合（[ne30x-app#11](https://github.com/harryhua-ai/ne30x-app/issues/11)，PR #16）正在按 A 的 REQUEST_CHANGES 修正，未 ACCEPTED；设备端全链路与非刷机替换验收对应 [ne301#48](https://github.com/harryhua-ai/ne301/issues/48)，待其 P4/P5/P6 依赖按各自 Contract 完成后逐步授权。实现仍由 `ne30x-app` 独立承担业务判断，验证安装、更换、运行、事件输出、资源占用与错误恢复；NE301 不重新链接具体业务 App，不复制业务规则。

### P8 — 系统级验收与发布（未开始）

覆盖至少：签名与身份授权、恶意/不兼容/损坏包拒绝、分区与数据隔离、更新断电/回滚、重启恢复、运行故障与资源约束、主固件 OTA 与已安装 App 的兼容策略、长时间稳定性及真实用户工作流。先做受控可信发行方产品，不宣称已实现不可信 App 沙箱。任何向 NE301 正式分支集成、生产刷写及正式发布，均需后续独立审查与 **User 明确授权**。

## 4. 开发执行与验收治理

1. **权威来源**：长期产品方向与阶段边界由本文件承载；当前执行内容由各仓库的 Issue `ght-contract` 承载，实时状态、授权、Candidate、评审与合并以 GitHub/`ght` 为准。本文不得与这些权威状态形成第二套授权/进度记录。
2. **工作分割**：一个 Issue 对应一项可独立验证的行为成果；实现与对应测试一般同一 Issue，不按技术步骤机械拆分。跨仓库集成有真实验收缺口时再建立集成任务。
3. **A/B 边界**：A 负责 WHY/WHAT/边界/验收、重要安全与架构决策、READY 与 exact-SHA 评审；B 负责 HOW、隔离实施、测试和正式交付；User 保留重大产品取舍与发布决策。
4. **证据和安全**：区分静态测试/仿真与真机，保留完整哈希、实际运行日志、环境/版本、备份恢复映射；不能重刷未知用户数据或使用生产设备验证未签名原生代码。
5. **审查收敛**：优先复用已闭合且不受新 delta 影响的证据；不能因修文档反复重开已验证的 NE301 App Host PoC。新问题必须与本次变更或 Contract 的实质验收直接相关。
6. **授权边界**：本路线图写入不等于创建执行任务或颁发 `ready`；P2–P8 的协议和产品关键选择仍需要按阶段落地，避免一次性扩大范围。

## 5. 最近的下一步（按优先级，截至 2026-10-10）

1. **在途修正优先**：完成 [ne301#37](https://github.com/harryhua-ai/ne301/issues/37)（[PR #53](https://github.com/harryhua-ai/ne301/pull/53)）与 [ne30x-app#11](https://github.com/harryhua-ai/ne30x-app/issues/11)（[PR #16](https://github.com/harryhua-ai/ne30x-app/pull/16)）的 REQUEST_CHANGES 修正与评审收敛；二者均未 ACCEPTED/完成，低优先级文档任务不抢占其修复。
2. **按 canonical 依赖逐步授权**：#37 之后是口令认证基线 [ne301#36](https://github.com/harryhua-ai/ne301/issues/36)；随后 P4/P5 链（[#29](https://github.com/harryhua-ai/ne301/issues/29) → [#30](https://github.com/harryhua-ai/ne301/issues/30) → [#31](https://github.com/harryhua-ai/ne301/issues/31) → [#39](https://github.com/harryhua-ai/ne301/issues/39) → [#40](https://github.com/harryhua-ai/ne301/issues/40)）与 P6/P7 链（[#47](https://github.com/harryhua-ai/ne301/issues/47) → [#43](https://github.com/harryhua-ai/ne301/issues/43) / [#44](https://github.com/harryhua-ai/ne301/issues/44) / [#46](https://github.com/harryhua-ai/ne301/issues/46) → [#49](https://github.com/harryhua-ai/ne301/issues/49) → [#48](https://github.com/harryhua-ai/ne301/issues/48)）仍待实现，每一步都以该 Issue **现行 `ght-contract`** 为准、经 A READY/评审授权推进；本文不建立第二套授权。
3. **待实现主线**：Web 安装 MVP（hello-app V1→V2 两份 v1 包端到端）、持续业务 v2 设备链路（验签准入、AI 结果供给、结果回传、持久化、会话管理）与首个业务 App 设备全链路验收均未落地；真机验收不得以离线 PASS 代替，向正式分支集成、生产刷写与发布仍需 **User 明确授权**。

## 6. 关键链接

- [ne301#25：最小 App Host PoC（DONE）](https://github.com/harryhua-ai/ne301/issues/25)
- [ne301 PR #26（已合并，仅实验分支）](https://github.com/harryhua-ai/ne301/pull/26)
- [固定 Host/ABI 基线](https://github.com/harryhua-ai/ne301/tree/a5b4bf3dd25931d612680aff200e4e0ac8d8e64e)
- [Host 原始设计和真机证据](https://github.com/harryhua-ai/ne301/blob/a5b4bf3dd25931d612680aff200e4e0ac8d8e64e/Docs/design/app-host-poc.md)
- [ne301#27：安装事务/验签/故障恢复可行性（DONE）](https://github.com/harryhua-ai/ne301/issues/27) · [ne301#32：签名验签与信任模型可行性（DONE）](https://github.com/harryhua-ai/ne301/issues/32)
- [ne30x-app#1：独立 App 可行性调查（DONE）](https://github.com/harryhua-ai/ne30x-app/issues/1)
- [ne30x-app#2：独立 hello-app 构建与 Host ABI 集成验证（DONE）](https://github.com/harryhua-ai/ne30x-app/issues/2) / [说明 docs/app-hello-poc.md](app-hello-poc.md)
- [协议 v1 规范（已集成）：docs/app-package-protocol-v1.md](app-package-protocol-v1.md)（[ne30x-app#4](https://github.com/harryhua-ai/ne30x-app/issues/4)，[PR #7](https://github.com/harryhua-ai/ne30x-app/pull/7)）
- [协议 v2 规范（已集成，历史文件名）：docs/app-package-protocol-v2-draft.md](app-package-protocol-v2-draft.md)（[ne30x-app#12](https://github.com/harryhua-ai/ne30x-app/issues/12)，[PR #14](https://github.com/harryhua-ai/ne30x-app/pull/14)）
- [ne30x-app#6：v1 打包与离线验证（DONE）](https://github.com/harryhua-ai/ne30x-app/issues/6) / [说明 docs/p3-packaging.md](p3-packaging.md)
- [ne30x-app#13：v2 打包与跨版本离线验证（DONE）](https://github.com/harryhua-ai/ne30x-app/issues/13) / [说明 docs/p6-packaging.md](p6-packaging.md)
- [ne30x-app#8：Line Crossing 算法核心离线移植（DONE）](https://github.com/harryhua-ai/ne30x-app/issues/8) / [说明 docs/p7-line-crossing-port.md](p7-line-crossing-port.md)
- [ne30x-app#11：Line Crossing 统计业务与 Host 组合（OPEN，修正中，未 ACCEPTED）](https://github.com/harryhua-ai/ne30x-app/issues/11) / [PR #16](https://github.com/harryhua-ai/ne30x-app/pull/16)
- [ne301#37：LittleFS/NVS 非破坏性启动与故障恢复基线（OPEN，修正中，未 ACCEPTED）](https://github.com/harryhua-ai/ne301/issues/37) / [PR #53](https://github.com/harryhua-ai/ne301/pull/53)
- [ne301#36：App 管理入口口令保护与认证授权基线（Prepared）](https://github.com/harryhua-ai/ne301/issues/36)
- [ne301#29 / #30 / #31：P4 验签准入、安装升级/卸载、手动单次执行（Prepared）](https://github.com/harryhua-ai/ne301/issues/29)
- [ne301#39 / #40：P5 Web 管理界面与 V1→V2 端到端验收（Prepared）](https://github.com/harryhua-ai/ne301/issues/39)
- [ne301#47 / #43 / #44 / #46 / #49：P6 设备侧持续业务链路（Prepared）](https://github.com/harryhua-ai/ne301/issues/47)
- [ne301#48：独立 Line Crossing App 设备全链路验收（Prepared）](https://github.com/harryhua-ai/ne301/issues/48)

---

**阶段决策原则（不变）：跨仓库独立 App 的真实替换已由 hello-app 证明；当前主线是先把可信安装与用户 Web 管理端到端做实，再扩展 Camera/AI 持续业务和生产级安全。**
