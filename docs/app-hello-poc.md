# hello-app：NE301 独立 App PoC（Issue #2）

本文描述 ne30x-app 第一个独立构建的 NE301 应用 `hello-app`：它如何消费
NE301 实验平台导出的唯一版本化 Host ABI、如何独立编译为可装载镜像、
以及如何复核构建正确性。它只证明"应用可独立编译为镜像并通过稳定函数
表消费平台能力"这一最小技术事实，不是产品化 App 框架。

- 源码版本：`ne30x-app` 分支 `agent/2/50117b15`，构建锚定 commit
  `07724f1f98a3a4151c61b876861a7e0e64539975`（apps/hello-app、tools、tests 由此提交引入）。
- 构建证据：[docs/evidence/build-evidence.md](evidence/build-evidence.md)（全部数字来自实际运行输出）。

## 1. ABI 唯一权威与锁定

| 项 | 值 |
| --- | --- |
| 上游仓库 | `harryhua-ai/ne301`，分支 `experiment/app-host-poc` |
| Pinned commit | `a5b4bf3dd25931d612680aff200e4e0ac8d8e64e` |
| 头文件路径 | `Custom/Common/Inc/app_host_abi.h` |
| 头文件 sha256 | `9337f684893cf2a06aea6f6f8c448708d91e8f9c6c86c24905ced8a7d5df23f4` |
| `APP_HOST_ABI_VERSION` | `0x00010000`（major 1, minor 0；校验规则为**精确相等**，无 minor 兼容） |
| `APP_HOST_IMAGE_MAGIC` | `0x3141454E`（小端字节序即 "NEA1"） |
| `APP_HOST_IMAGE_FORMAT_VERSION` | `1` |
| `APP_HOST_IMAGE_HEADER_SIZE` | `32` 字节 |

本仓库**不提交任何头文件副本**。唯一进入构建的方式是
`tools/fetch_abi_header.sh`：按 pinned SHA 从 GitHub 拉取（或复用
`NE301_PINNED_RO` 指向的本地 pinned 检出），无论来源都必须通过上述
sha256 锁定校验，缓存到 `apps/hello-app/build/cache/app_host_abi.h`。

## 2. 目标执行环境（平台事实）

| 项 | 值 |
| --- | --- |
| 目标板 | STM32N657（NE301 开发板），64MB PSRAM + 128MB NOR |
| 执行区 | `APP_HOST_RAM`：基址 `0x93E00000`，长度 2MB（对应上游 `Appli/STM32N657L0HXQ_LRUN.ld`） |
| 装载语义 | Host 读整文件到基址 → 校验 → `memmove` 剥离 32B 头 → cache 维护 → 以 `(基址+entry_offset)|1`（Thumb 位）C 调用 → 返回后清零执行区 |
| 运行时 | App 运行在 Host 调用者栈上；无独立栈/堆，Host 不初始化 `.data`，`.bss` 由装载前整区清零隐式清零 |
| Host 函数表 | `app_host_api_table_t { table_size, abi_version, log(const char*), tick_ms(void) }` |

镜像头（小端，`<IHHIIIIII>`，共 32B）：
`magic(u32) header_size(u16) format_version(u16) abi_version(u32)
target_addr(u32) image_size(u32) entry_offset(u32) reserved0(u32) crc32(u32)`。
`crc32` 为 zlib CRC-32，仅覆盖 payload（不含头）。

### 入口约束

- 入口符号必须是全局 `int app_entry(const app_host_api_table_t*, uint32_t)`。
- `entry_offset = nm 解析的 app_entry 地址 - 0x93E00000`；必须非负、
  小于 `image_size`、为偶数（Thumb）。
- Host 拒绝码序（`app_host_validate.c`）：`truncated → magic →
  header_size → format → abi → target → image_size → entry → crc`；
  整文件大于执行区在 `read_file` 阶段先被拒（oversize）。

### 镜像处理工具（tools/）

- `pack_app_image.py`：ELF → payload → 32B 头打包；magic/format/abi/header
  size 一律读自 pinned 头（不硬编码），entry 经 `arm-none-eabi-nm` 解析；
  `--exec-base` 默认 `0x93E00000`。
- `validate_app_image.py`：按 Host 同序复检全部字段并复算 CRC，宏数值与
  pinned 头交叉校验；输出 `VALID` 或具体拒绝原因（附 Host 侧
  `app_host_check_str` 原文，便于对设备日志）。文件尾部多余字节仅告警
  （Host 只消费 `image_size` 字节）。
- `make_bad_images.py`：由好镜像派生 8 种坏镜像（文件名即预期拒绝原因），
  供真机拒绝路径测试：`magic`、`header-size`、`format-version`、
  `abi-version`、`target-address`、`image-size`、`entry-offset`、`crc32`。

## 3. hello-app 行为语义

`apps/hello-app/main.c`，入口防御检查失败即返回负值（与上游
`tests/app_host/testapp/main.c` 参考语义同序）：

| 返回码 | 含义 |
| --- | --- |
| -1 | api 表指针为 NULL |
| -2 | `table_size < sizeof(app_host_api_table_t)`（16） |
| -3 | `abi_version != APP_HOST_ABI_VERSION`（精确比较） |
| -4 | `log` 或 `tick_ms` 函数指针为空 |
| -5 | 第一次 `tick_ms()` 返回负值 |
| -6 | 第二次 `tick_ms()` 返回负值 |
| -7 | 平台 tick 倒退（非单调） |
| **`0x4E45`（"NE"）** | **成功**（本 PoC 约定的可识别返回码；Host 日志将显示 `entry returned 20037`） |

成功路径：经 `log` 输出标识行 → 读两次平台 tick（中间为约数毫秒的忙等，
Cortex-M55 硬件循环实现，保证 1ms tick 前进）→ 把 `t1/t2/delta` 十进制
格式化（自实现整数转换，无 libc 无除法指令依赖）打进 log。

硬性禁令（链接期强制或代码审查项）：无 libc/libgcc（`-nostdlib
-fno-builtin`）、无初始化数据（链接脚本 `ASSERT(SIZEOF(.data)==0)`）、
无全局构造（`.init_array*` 被 discard）、无中断/线程/MQTT/回调。

## 4. 编译 ABI 与链接

与上游参考 `tests/app_host/testapp/Makefile` 语义一致：

```
-mcpu=cortex-m55 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard -std=gnu11
-Os -Wall -Werror -ffunction-sections -fdata-sections
-ffreestanding -fno-builtin
链接：-nostdlib -T hello_app.ld -Wl,--gc-sections
```

链接脚本 `apps/hello-app/hello_app.ld`：`MEMORY APP (rx) ORIGIN=0x93E00000
LENGTH=2M`，`ENTRY(app_entry)`，不定义 `_estack`/启动路径。

## 5. 一条命令复现

依赖：`arm-none-eabi-gcc`（PATH 或 `/Applications/ArmGNUToolchain/*/arm-none-eabi/bin`）、
`python3`、首次构建需网络（或 `NE301_PINNED_RO` 指向 pinned 检出）。

```bash
# 完整构建 + 静态验收（含可重复构建断言与坏镜像拒绝断言）
bash tests/run_build_checks.sh

# 仅构建（自动拉取/校验 ABI 头）
make -C apps/hello-app clean all
```

`run_build_checks.sh` 步骤：clean build → validate 输出 `VALID` →
再次 clean build 并断言镜像 sha256 逐字节一致 → 生成 8 个坏镜像 →
逐个断言按预期原因拒绝。

## 6. 构建产物（实际数字，见证据文件）

| 产物 | 尺寸 | sha256 |
| --- | --- | --- |
| `apps/hello-app/build/hello-app.bin`（装载镜像 = 32B 头 + 576B payload） | 608 B | `d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03` |
| `apps/hello-app/build/hello-app.payload.bin`（flat binary） | 576 B | `cc0269e71201d987e6e5837274f5d0f0d9b65d6cd5642bb8c3f084ba0cb01ef5` |
| `apps/hello-app/build/hello-app.elf` | ELF | `0d0e5c08eafd55bd3b8f8642b17af0d1a61b0bc8f97806fd7075e35cff4c7da7` |

`size` 输出：text=576 / data=0 / bss=0；`app_entry` 位于 `0x93E00050`
（entry_offset `0x50`，偶数，< image_size）；镜像头 hexdump 首字段为
`4e 45 41 31`（"NEA1"）。

## 7. 真机测试交接（协调者执行，本 Issue 构建侧不执行）

- 装载镜像：`apps/hello-app/build/hello-app.bin`（sha256 见上）。
- 拒绝路径用例：`apps/hello-app/build/bad-images/bad-*.bin`，逐个放入
  littlefs 后 `apphost load`，预期设备日志 `apphost: reject <path> (<原因>)`
  且返回 -20；原因对照 `validate_app_image.py` 输出的 Host 拒绝串。
- 成功路径预期设备日志（ Host `LOG_SIMPLE` 前缀 `[APP]`）：
  `hello-app: standalone NE301 app PoC, ABI v1.0`、
  `hello-app: tick_ms t1=<n> t2=<n> delta=<n>`（delta ≥ 1）、
  `apphost: entry returned 20037`（0x4E45）。
- 真机项（AC2/设备侧 AC3）未在本仓库验证；受权设备、备份与恢复核实
  由协调者按合同执行。

## 8. 边界声明

- 未复制 ne301 任何源码/静态库进 App；仅 pinned 头经 fetch 脚本消费。
- 未触碰 `ne301/main`、`ne301/counting` 或任何设备。
- 未创建 `apps/line-crossing/**`、`apps/intrusion-detection/**`。
- `common/`、`platform/` 目录按仓库 README"按需增量建立"原则暂未创建；
  hello-app 当前自含链接脚本与编译参数，待第二个 App/板型出现再上提。
