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

- [Issue #1：独立 App Binary 与 Host API 可行性调查](https://github.com/harryhua-ai/ne30x-app/issues/1)已完成。
- [Issue #2：独立 hello-app 构建与 NE301 Host ABI 集成验证](https://github.com/harryhua-ai/ne30x-app/issues/2)进行中：
  首个独立应用 `hello-app` 已可复现构建——见
  [docs/app-hello-poc.md](docs/app-hello-poc.md)（ABI 版本、pinned 上游头、
  执行区与入口约束、一条命令复现）与
  [docs/evidence/build-evidence.md](docs/evidence/build-evidence.md)（实际构建与坏镜像拒绝输出）。
  一条命令验证：

  ```bash
  bash tests/run_build_checks.sh
  ```

  该验证证明应用可独立编译为镜像并通过稳定函数表消费平台能力；
  真机装载/替换/拒绝路径（设备侧 AC）仍以受权开发板上的实际日志为准，
  不以模拟或源码检查代替。未经证实，不把 RAM 加载、固定地址、Flash XIP
  或某个内存分区当作既定生产方案。

实现变更使用可审查的分支／PR，`main` 作为集成来源；任何真机风险、内存冲突或二进制兼容阻塞必须用证据报告，不允许以削弱平台/应用边界掩盖。

平台源码：[harryhua-ai/ne301](https://github.com/harryhua-ai/ne301)。
