# ne30x-app / Line Crossing 首版 PRD v1.0 — Draft

> 状态：**DRAFT / 待 User 联合评审与范围批准**；维护人：Role A / Project Steward；提出日期：2026-10-15。
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
| **APP-01** | 独立 build/打包签名的原生 Line Crossing；长期会话消费真实 Host AI 事件；按配置计数 IN/OUT，正确维护累计/窗口、报告序号和必要受信持久状态。旧 v1/v2/v3 已受审容器/ABI 不被静默修改。 | 已完成 [App #21](https://github.com/harryhua-ai/ne30x-app/issues/21)，Sidecar [#26](https://github.com/harryhua-ai/ne30x-app/issues/26) |
| **APP-02** | 将正式成熟 `counting` UI 源码级继承为 App 自有独立资产；保留 Realtime / Config / Advanced 导航、图层、IN/OUT、统计、报错、草稿/撤销、确认和媒体体验；不同于把组件重新编入 Host Web。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25) |
| **APP-03** | Realtime 在真实业务会话中显示**活动 tracks/有限 points**和按时间/track/cursor 排序的穿线 IN/OUT 事件；继续呈现真实累计和窗口统计；新事件/轨迹过期、丢失或无权限时显示 stale/gap/unavailable。原页面每 2 秒获取的体验目标不代表 App 必须每 2 秒产生新轨迹。窗口关闭才生成的 `window report tracks[]` 不得冒充 live。 | [App #27](https://github.com/harryhua-ai/ne30x-app/issues/27)、Host [#91](https://github.com/harryhua-ai/ne301/issues/91) |
| **APP-04** | 两次点击确定检测线后，支持实际鼠标**和触摸**拖动任一端点微调；保持视频可见区自然长宽比、0..1000 permille 线/方向和 IN/OUT；拖拽/翻转仅改草稿，显式 Save 经真正 `APPLIED` 才生效，取消恢复当前受信配置。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、[#79 §10](https://github.com/harryhua-ai/ne301/issues/79) |
| **APP-05** | 视频实际播放 MSE/H264/WS，独立展示 `Live / Reconnecting / Unavailable`，与 `App: Running` 和统计 fresh/stale 状态独立；断流/持续错误/恢复与失权清理有真实场景证明，冻结帧不得称 Live。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、Host [#84](https://github.com/harryhua-ai/ne301/issues/84) |
| **APP-06** | Config 能编辑线/方向、目标类、阈值、关联/历史/漏检/确认等追踪参数；统计窗口属于 Advanced 的 App-owned 组（APP-07）；候选由 App 自身验证、Host 经当前会话 v3 `CONFIG_APPLY`（144B config-only）提交、generation CAS，`APPLIED` 才可显示生效；目标类更换/独立计数重置遵守确认与原生持久语义，失败不覆盖原值。 | [App #21](https://github.com/harryhua-ai/ne30x-app/issues/21)、[#25](https://github.com/harryhua-ai/ne30x-app/issues/25) |
| **APP-07** | Advanced **同页两组独立草稿与 Save**：App-owned 的 Window/Tracks Report/Heat Grid；Host-owned 当前 App 专属 MQTT/Webhook/Backlog Capacity。单边失败/UNKNOWN 不影响另一组已确认保存。真实策略能力未就绪时显示暂不可用而非假成功；绝不偷偷修改全设备账号/topic/url。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、Host [#88](https://github.com/harryhua-ai/ne301/issues/88) |
| **APP-08** | 按配置窗口生成真实 `line_counting` 报告和可选 track/heat 历史，交由受信 Host report_submit 统一发送 MQTT/Webhook；App 不自己建第二套网络栈，Host 上行 status≠已成功持久策略。刷新实时视图不污染队列/report_seq。 | [App #21](https://github.com/harryhua-ai/ne30x-app/issues/21)、Host [#75](https://github.com/harryhua-ai/ne301/issues/75) |
| **APP-09** | App/模型、媒体、业务快照、Host 报告结果和权限分别表达；未授权、模型不支持、会话失效、版本错配、容量不足、配置信息过期等错误不能伪称正常。旧 iframe/新 native 身份不匹配时拒绝旧操作。 | [App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、Host [#84](https://github.com/harryhua-ai/ne301/issues/84) |

## 4. 合同与跨仓边界

- **App 拥有** 越线算法、实际 tracks/events producer、业务校验/持久状态、独立 UI 源码与打包。**Host 拥有** 安装、签名根/验真、媒介与模型资源、会话隔离、browser typed bridge、平台数据只读/写入门控及 MQTT/Webhook 传输/队列。不得让业务 iframe 获得 Host 管理员 cookie/token 或绕过受信权限。
- 原生 v3 `line-crossing/1` snapshot 只提供相应累计/窗口/配置等；真实实时事件/轨迹需要新**显式协商的版本化能力**，不修改既有 `.neapp` v3/144B wire；其字节、速率、额度和 clock/gap 规则仍在 Host #91 + App #27 的 A 设计门。
- 用户看到的一个完整业务结果，要由真实 producer→Host→独立 UI 的串联正/负例证成；单一离线 App 模拟、Sidecar 签名 fixture 或 Host 8 槽测试不是完整功能的 PASS。

## 5. 首版明确不做

不做新的通用 App 市场、复杂多模型编排、任意第三方代码执行、业务自己的 MQTT/Webhook 网络服务、UI 自授信的 API 权限、未获验证的无限轨迹/报告缓存、严格 exactly-once 送达。不以重编译 Host 内置私有业务 UI 替代独立交付。

## 6. 已确认产品设计与待验决策

**User 已确认**：正式成熟 UI 源来自 `counting` 而非备份；画线后任一端点可拖动微调；视频三态与 App 运行状态分开；Advanced 仍有当前 App 专属传输/Backlog 控件，与 App 业务配置独立保存/回执。详见 [NE301 #79 §10](https://github.com/harryhua-ai/ne301/issues/79)。

**尚未能视为已批准 DONE：**

- 旧 UI 的 `enable` 是单独的业务启停意图；现行 native v3 配置与 Host `app_running` 没有同义字段/动作。必须先由 A 提议可审用户行为，交 User 决定保留方式，不能假映射成启动/停止整个 native 会话。
- Backlog Capacity 旧输入为 **1..256**，现有 Host 只具 **8 个易失 6240B 槽**；[#89](https://github.com/harryhua-ai/ne301/issues/89) 尚需实证资源/恢复。**保留可编辑用途为产品目标**；目前不能承诺 256 真机可用或静默 clamp 到 8；如需缩减可见范围，必须重新经 User 产品选择。
- 新版本受信实时轨迹/事件 ABI 与真实帧率、fresh/gap 阈值、Sidecar 可安装的 RAM/FS 预算仍未知；不能用技术假设决定产品已完成。
- 安装/卸载/换包/权限变化时的新增导航、空态/异常提示如果构成重大 UX 改变，需按 A 规则提交可审示意并获得 User 明确确认。

## 7. 首版验收与需求变更

**M2 功能验收**至少实测：有目标/无目标/方向翻转、IN/OUT、连续活动轨迹与事件次序、视频断流/恢复、两端点分别拖动、保存成功/失败/未知、App/Host 两组单边成功/失败、旧 App 失权、窗口历史与 live feed 分离。**M3** 只接受获授权真机真实数据，未执行标 NOT_RUN，不把离线 fixture 冒称通过。

此文件与配对平台 PRD 须经同一 User 审阅后方可冻结 v1.0；范围变更优先映射 `APP-xx` 或 `PLAT-xx`，由 A 评估产品可见结果/验收/依赖，有实质产品取舍才请 User 批准。Issue 追踪工程候选，**PRD 不复制当前 Claim/PR 状态、不签发 READY**；B 的普通实现 HOW 不自动生成新产品需求。

**规范参考：** [App v3 schema](https://github.com/harryhua-ai/ne30x-app/blob/main/docs/line-crossing-v3-config-schema.md)、[平台架构决定 #79](https://github.com/harryhua-ai/ne301/issues/79)、[长期路线图](https://github.com/harryhua-ai/ne30x-app/blob/main/docs/app-platform-development-roadmap.md)。