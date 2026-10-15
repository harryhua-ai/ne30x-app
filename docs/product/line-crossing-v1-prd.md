# ne30x-app / Line Crossing 首版 PRD v1.0 — Frozen Product Scope

> 状态：**FROZEN PRODUCT SCOPE v1.0 / 2026-10-15**（User 已要求完成联合 PRD 冻结；与 NE301 `PLAT-01..08` 同一产品验收范围）；维护人：Role A / Project Steward。PRD 冻结不是产品功能 PASS、READY、设备写入或正式发布授权。
> 产品：NE301 独立 App 平台 + 首个 Line Crossing。配对 PRD：`harryhua-ai/ne301/docs/product/app-platform-v1-prd.md`（同批审阅）。
> 本文规定 **业务 App 及其独立 UI 的 WHAT / DONE**；不是 `.neapp` / Sidecar 协议、Host 管理 API 的第二套规范、`ght` Contract、READY、真机写入或发布许可。

## 1. 首版用户与产品价值

**主要用户：** 在 NE301 Web 中使用 Line Crossing 统计、调线和查看实时视频/报告的设备管理员。

**目标：** Line Crossing 作为可独立构建、签名、安装/更新的受信 App 在 NE301 上持续计数，提供源自真实成熟 `counting` 的 Realtime / Config / Advanced 三页；用户在运行中可查看真实 IN/OUT 和活动轨迹、编辑线/业务配置、分别保存 App 业务和 Host 报告策略、诊断视频与上报状态。业务代码/UI 更新不因功能调整而要求重编译或刷写 Host 基础固件/基础 Web。

**唯一 UI 源码基准：** `ne301/counting@de25a6f1f431a631a37ff1cda87f616e293e8836`（入口 `line-counting-module.tsx`、`lineCounting/*`、`line-counting.ts`）；`people-counting` 仅备份，不能替代。源码级继承意味着页面布局、行为/错误、组件依赖与真实媒体路径可对照验收，不是截图相似或静态模拟。

## 2. 里程碑（与 NE301 平台 PRD 同义）

| 里程碑 | ne30x-app 侧可观察结果 |
| --- | --- |
| **M1 工程纵向集成（内部）** | 独立构建受信 native/UI，Host 可加载正式业务页、读可信状态并按 v3 控制事务提交已有 App-owned 配置；出错/失权可见。此阶段**不构成完整首版**。 |
| **M2 首版功能完整** | Realtime 真正的活动轨迹/IN-OUT 事件、H264 视频与线编辑，Config、Advanced 两组 Save、窗口报告、当前 App 专属传输策略及正确异常状态达到下表产品 DONE；不得用 mock 或窗口历史虚报实时。 |
| **M3 真实设备结项** | 在受授权、可恢复的指定设备上完成真实模型/摄像头、视频、配置、业务上行、安装/更新/卸载与资源/稳定性验证；未运行标 NOT_RUN。 |

## 3. Must Have：业务 App 与 UI

| ID | ne30x-app 的产品要求与可观察 DONE | 主要对应现有工作 |
| --- | --- | --- |
| **APP-01** | 独立构建/签名的原生 Line Crossing 使用真实 AI 检测持续产生 IN/OUT、窗口、报告序列并维护受信配置与累计。**卸载并确认清除后**，该 App 专属业务配置、累计 IN/OUT、报告/必要持久状态均被清除，不留下以后重装可继承的副本；重装同一受信 App 也从全新配置和零累计开始，不自动恢复。普通版本升级不应误删受审的兼容业务数据，冻结 v1/v2/v3 包与 ABI 不得静默修改。 | [App #21](https://github.com/harryhua-ai/ne30x-app/issues/21)、Sidecar [#26](https://github.com/harryhua-ai/ne30x-app/issues/26) |
| **APP-02** | 将正式成熟 `counting` UI 源码级继承为 App 自有独立资产；保留 Realtime / Config / Advanced 导航、图层、IN/OUT、统计、报错、草稿/撤销、确认和媒体体验；不同于把组件重新编入 Host Web。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25) |
| **APP-03** | Realtime 在真实业务会话中显示**活动 tracks/有限 points**和按时间/track/cursor 排序的穿线 IN/OUT 事件；继续呈现真实累计和窗口统计；新事件/轨迹过期、丢失或无权限时显示 stale/gap/unavailable。原页面每 2 秒获取的体验目标不代表 App 必须每 2 秒产生新轨迹。窗口关闭才生成的 `window report tracks[]` 不得冒充 live。 | [App #27](https://github.com/harryhua-ai/ne30x-app/issues/27)、Host [#91](https://github.com/harryhua-ai/ne301/issues/91) |
| **APP-04** | 两次点击确定检测线后，支持实际鼠标**和触摸**拖动任一端点微调；保持视频可见区自然长宽比、0..1000 permille 线/方向和 IN/OUT；拖拽/翻转仅改草稿，显式 Save 经真正 `APPLIED` 才生效，取消恢复当前受信配置。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、[#79 §10](https://github.com/harryhua-ai/ne301/issues/79) |
| **APP-05** | 视频实际播放 MSE/H264/WS，独立展示 `Live / Reconnecting / Unavailable`，与 `App: Running` 和统计 fresh/stale 状态独立；断流/持续错误/恢复与失权清理有真实场景证明，冻结帧不得称 Live。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、Host [#84](https://github.com/harryhua-ai/ne301/issues/84) |
| **APP-06** | Config 保留独立的“启用越线统计” Enable 业务开关：关闭只暂停生成新的越线计数，不停止/卸载原生 App，不清除累计 IN/OUT，关闭当前统计窗口与跟踪态；重新启用开始新的统计窗口并恢复跟踪。统计暂停与 App 运行、视频播放是不同状态。Config 仍能编辑线/方向、目标类、阈值、关联/历史/漏检/确认等追踪参数；统计窗口属于 Advanced 的 App-owned 组（APP-07）。可受审的现有 v3 配置仍经 `CONFIG_APPLY`（144B config-only）、generation CAS，实际 `APPLIED` 后才算生效；**旧 Enable 不在已冻结的 v3 配置中，须另行设计有授权、有回读、失败不假成功的业务启停能力，不能偷映射成 Host App start/stop，也不能修改原 v3 144B wire**。目标类更换/独立计数重置遵守确认与原生持久语义，失败不覆盖原值。 | [App #21](https://github.com/harryhua-ai/ne30x-app/issues/21)、[#25](https://github.com/harryhua-ai/ne30x-app/issues/25) |
| **APP-07** | Advanced **同页两组独立草稿与 Save**：App-owned 的 Window/Tracks Report/Heat Grid；Host-owned 当前 App 专属 MQTT/Webhook/Backlog Capacity。**Backlog 首版承诺为断网期间容量内暂存、恢复后尽力补发；断电/重启允许丢失尚未送达的报告，不要求可靠重启重放。容量选择 User 已批准方案 B：必须允许在目标设备实测可持续支持的范围内配置；UI 展示 Host 返回的实际上限、当前有效值和越界/资源不足错误，不必无条件支持旧控件全部 1..256，也不能把未实现的 8 槽上限冒充经验证的能力。** **User 已确认通道关闭方案 A**：当前 App 的 MQTT 或 Webhook 开关关闭并获 Host 保存确认后，取消**被关闭通道尚未开始发送**的积压任务，另一通道不受影响；之后新报告不再送入关闭通道，重新开启也不追补已取消旧报告。已开始发送的请求不保证能撤回，应显示实际结果或 UNKNOWN，不能标成已取消。** UI 要区分“策略已保存”与“报告已发送”；满队列/丢失/未知不可假装已送达。单边失败/UNKNOWN 不影响另一组已确认保存。真实策略能力未就绪时显示暂不可用而非假成功；绝不偷偷修改全设备账号/topic/url。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、Host [#88](https://github.com/harryhua-ai/ne301/issues/88) |
| **APP-08** | 按配置窗口生成真实 `line_counting` 报告和可选 track/heat 历史，交由受信 Host report_submit 统一发送 MQTT/Webhook；App 不自己建第二套网络栈，Host 上行 status≠已成功持久策略。刷新实时视图不污染队列/report_seq。 | [App #21](https://github.com/harryhua-ai/ne30x-app/issues/21)、Host [#75](https://github.com/harryhua-ai/ne301/issues/75) |
| **APP-09** | App、模型、视频、业务快照、Host 报告和权限分别显示；未授权、会话失效、模型不支持、版本错配、资源不足或配置冲突不能伪称正常。卸载**之前**提示全部该 App 专属业务数据将同时删除并取得授权管理员确认；取消则不卸载不删除。确认后旧 UI/媒体/能力均撤销，业务数据和逐 App 报告策略须已清除；部分清除/UNKNOWN 不显示完成。相同受信 App 再安装也显示初始配置/零累计，无恢复询问或自动恢复。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、Host [#84](https://github.com/harryhua-ai/ne301/issues/84) |

## 4. 合同与跨仓边界

- **App 拥有** 越线算法、实际 tracks/events producer、业务校验/持久状态、独立 UI 源码与打包。**Host 拥有** 安装、签名根/验真、媒介与模型资源、会话隔离、browser typed bridge、平台数据只读/写入门控及 MQTT/Webhook 传输/队列。不得让业务 iframe 获得 Host 管理员 cookie/token 或绕过受信权限。
- 原生 v3 `line-crossing/1` snapshot 只提供相应累计/窗口/配置等；真实实时事件/轨迹需要新**显式协商的版本化能力**，不修改既有 `.neapp` v3/144B wire；其字节、速率、额度和 clock/gap 规则仍在 Host #91 + App #27 的 A 设计门。
- 用户看到的一个完整业务结果，要由真实 producer→Host→独立 UI 的串联正/负例证成；单一离线 App 模拟、Sidecar 签名 fixture 或 Host 8 槽测试不是完整功能的 PASS。

## 5. 首版明确不做

不做新的通用 App 市场、复杂多模型编排、任意第三方代码执行、业务自己的 MQTT/Webhook 网络服务、UI 自授信的 API 权限、未获验证的无限轨迹/报告缓存、严格 exactly-once 送达。不以重编译 Host 内置私有业务 UI 替代独立交付。

## 6. 已冻结的产品行为与尚待工程证实的实现条件

**已冻结业务与交互：** 使用正式成熟 `counting@de25a6f1f431a631a37ff1cda87f616e293e8836`，保留 Realtime/Config/Advanced、真实活动轨迹/实时事件/视频和计数；两次点击画线后鼠标/触摸拖动两端，保存真正 `APPLIED` 才生效；视频 `Live/Reconnecting/Unavailable` 与 App Running 分开。Config `Enable` 只暂停计数并保留累计，重新启用开始新窗口，不等于停止整个 App。

**Advanced：** 同一页面 App-owned Window/Tracks/Heat 和 Host-owned MQTT/Webhook/Backlog 两组独立 Save。Backlog 在断网期间有界易失缓存、恢复后尝试补发，断电/重启允许丢未送达报告；真实上限由获授权的目标设备实测决定，UI 必须展示可用范围与当前值、拒绝超限，不能凭当前固定 8 槽或旧 UI 的 256 伪称可用。关闭某个通道并 Save 后仅取消**该通道尚未开始发送**的待发报告；另一个通道不受影响，已经发送中的请求不能保证撤销。

**卸载即清除，重装从零（User 最终明确纠正）：** 管理员点击卸载后，在**卸载执行前**明确展示将清除的专属业务配置、累计、持久状态、逐 App 报告策略和待发项并要求确认。拒绝/取消时保留 App 与数据；确认后才卸载、撤销授权并清除专属数据，半清除/UNKNOWN 不可称成功。即使相同受信 App 重新安装，也使用新配置和零累计，**不恢复以前的数据，也不再询问是否恢复**。其他 App、公共网络设置不受影响；普通受信升级不能当成卸载清零。

**尚待实现/核证，但不是未批准产品范围：** 新 Enable 受信控制能力、实时 tracks/events 的协商版本/实际时效、容量实测与队列公平/错误报告、NEUI 真实安装空间/恢复、卸载清除的持久数据归属/版本兼容；关键新增页面的导航与空态/错误 UI 在给 B 实施 READY 前仍需审阅示意并经 User 确认。未实现时不可把既定 Must Have 宣称 PASS，也不能用伪数据缩减产品体验。

## 7. 首版验收与需求变更

**M2 功能验收**至少实测：有目标/无目标/方向翻转、IN/OUT、连续活动轨迹与事件次序、视频断流/恢复、两端点分别拖动、保存成功/失败/未知、App/Host 两组单边成功/失败、旧 App 失权、窗口历史与 live feed 分离；取消卸载确认不卸载/不删数据；确认卸载后专属业务数据/策略清除、旧 UI/权限失效且其他 App/公共设置不变；再次安装相同受信 App 从初始配置和零累计开始，**无恢复确认/自动恢复**；普通升级不误删旧数据；失败/中断不假报成功。**M3** 只接受获授权真机真实数据，未执行标 NOT_RUN，不把离线 fixture 冒称通过。

此文件与配对平台 PRD 的 **17 项首版产品 WHAT/DONE 已成套冻结 v1.0**；范围变更优先映射 `APP-xx` 或 `PLAT-xx`，由 A 评估产品可见结果/验收/依赖，有实质产品取舍才请 User 批准。Issue 追踪工程候选，**PRD 不复制当前 Claim/PR 状态、不签发 READY**；B 的普通实现 HOW 不自动生成新产品需求。

**规范参考：** [App v3 schema](https://github.com/harryhua-ai/ne30x-app/blob/main/docs/line-crossing-v3-config-schema.md)、[平台架构决定 #79](https://github.com/harryhua-ai/ne301/issues/79)、[长期路线图](https://github.com/harryhua-ai/ne30x-app/blob/main/docs/app-platform-development-roadmap.md)。