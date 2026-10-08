# ne30x-app

NE30x 系列应用仓库，用于开发、测试、打包和发布面向 NE301（未来可扩展 NE302）的独立业务 App。

## 仓库责任（已确认的设计边界）

- `common/`：App 侧共用接口、契约和复用组件。只放确有共用需求的能力。
- `platform/`：NE301/NE302 的 App 侧平台适配与编译目标配置。
- `apps/`：各业务应用的独立源码、Web、测试和应用描述；首个候选为 `line-crossing`。
- `package/`、`tools/`：`.neapp` 包规范及离线构建、打包、校验工具。

上述目录描述的是**目标结构**，不表示对应代码已经实现；遵循按需增量建立的原则。

## 与设备平台的边界

1. `ne301` 是独立设备平台仓库，保留 Camera、AI runtime、网络、存储、HTTP、Web、OTA 等原有能力，以及运行独立 App 必需的最小通用 Host 支持。
2. `ne301` **不引用** `ne30x-app` 的仓库路径或源码，不含 Line Crossing 等具体业务代码。
3. `ne30x-app` 的业务 App **调用 NE301 的现有平台能力**，不复制或重建 Camera/AI/RTOS/网络等平台实现。
4. 目标是 App 独立编译、安装、更新和卸载；安装业务 App **不重新构建、不覆盖 NE301 主固件及基础 Web**。允许首次部署经过验证的通用 App Host 平台版本。
5. `.neapp` 是预定的 App 发布/安装包后缀；具体独立二进制格式、加载机制、ABI、安装安全和升级回滚规则仍待验证，**尚未定案**。

## 当前阶段

**技术可行性验证；尚无可发布 App。**

先完成 [Issue #1：独立 App Binary 与 Host API 可行性验证](https://github.com/harryhua-ai/ne30x-app/issues/1)。验证独立 `hello-app` 能否在不修改已部署 Host 固件的条件下装载、执行、调用受控 Host API，并能停止与恢复。未经证实，不把 RAM 加载、固定地址、Flash XIP 或某个内存分区当作既定生产方案。

实现变更使用可审查的分支／PR，`main` 作为集成来源；任何真机风险、内存冲突或二进制兼容阻塞必须用证据报告，不允许以削弱平台/应用边界掩盖。

平台源码：[harryhua-ai/ne301](https://github.com/harryhua-ai/ne301)。
