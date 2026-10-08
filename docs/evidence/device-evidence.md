# 设备验证证据 — hello-app PoC（Issue #2 AC2/AC3 真机项）

- 日期：2026-10-08；执行者：Primary B（ZCode 编排 + 受控 SWD/串口操作）
- 板卡：STM32N657 Rev B（Device ID 0x486），ST-LINK SN `56FF6F064984524928381287`（FW V2J46S7），与 ne301#25 平台 PoC 记录同板
- 控制台：`/dev/cu.usbserial-14130` @115200，提示符 `AICAM>`
- 完整串口会话：[device_session.log](device_session.log)

## 镜像与来源锚点

| 项 | 值 | SHA256 |
|---|---|---|
| 实验 Host 固件包 | ne301 `experiment/app-host-poc@a5b4bf3dd25931d612680aff200e4e0ac8d8e64e` 构建，v4.3.1.297，`APP_HOST_POC=1`，3,846,400 B | `65f3c0b0c1449bb61543836563635d0b7c74bcfbd57075d206ce218ff1d912b2` |
| hello-app v1（ne30x-app 构建） | 608 B（32B 头 + 576 payload），ABI `0x00010000`，target `0x93E00000`，entry_offset `0x50` | `d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03` |
| hello-app v2（替换版本） | 608 B，返回码 0x4E46、日志文案不同（源码单点变更） | `db1c6d60b398cab11a276e15770fdcdf9d42b9c96b4de6ef2cc93c1ecdec8744` |
| 设备上 Host 回读（APP1@0x70100000，3,846,400 B） | 刷写后独立回读 | `65f3c0b0…912b2`（== 包文件，逐字节一致） |

ABI 头唯一权威锁定：pinned 提交 `Custom/Common/Inc/app_host_abi.h`，SHA256 `9337f684893cf2a06aea6f6f8c448708d91e8f9c6c86c24905ced8a7d5df23f4`。

## 刷写前安全核实（合同前置门）

1. 板卡身份：Device ID 0x486 / Rev B / Cortex-M55（HotPlug 只读探查）。
2. boot slot：OTA info（0x70090000）`magic 0x5A5A5A5A`，`active_slot[FIRMWARE_APP]=SLOT_A`（APP1）。
3. 全量只读备份（写入前，双副本 + SHA256）：APP1 4MB、APP2 头、FSBL 头、NVS 64K、OTA 8K、AI_1/AI_2 各 8MB、WEB 1MB、WiFi FW 3MB、LittleFS 96MB。恢复路径：回刷 `backup_app1_full.bin` 或切 B 槽（APP2 存有完整计数固件，census OTAU 头有效）。
4. 每次写入均在 SW2 烧录位、固件停机状态下执行。

## 写入审计（全部设备写操作）

| 目标 | 内容 | 校验 |
|---|---|---|
| APP1 `0x70100000` | 实验 Host 包（`-hardRst -w … --verify`） | CubeProgrammer verify + 独立回读哈希一致 |
| LittleFS 6×4K 块（首轮注入） | hello/坏镜像 | per-block verify（**后见之明：多段小写入在 64KB 扇区粒度下相互覆盖，见"事故记录"**） |
| LittleFS 146×4K 块 / 28 段（二次修复） | — | per-run verify（同样受扇区粒度影响，未达目的） |
| LittleFS **整卷 96MB**（最终修复） | `lfs_injected_v2.img` 单命令 `-w … --verify` | CubeProgrammer verify 通过；随后功能验证（见下） |

**未触碰**：FSBL、NVS、OTA info、SWAP、APP2、AI_1/AI_2、WEB、WiFi FW 分区（写入命令全记录仅覆盖 APP1 与 0x71D00000 起的 FS 区域）。基础 WEB 与 APP2 前后一致性由"零写入 + 刷写前备份哈希"可复核。

## 真机验证序列（2026-10-08 21:02–21:04，串口实录）

```text
>>> version                         → Git Hash: a5b4bf3   ← pinned 实验固件在跑
>>> apphost info                    → exec region 0x93e00000-0x94000000 (2097152 bytes)
                                    → abi 0x0001.0000, littlefs mounted
>>> apphost load /apps/hello_v1.bin → run entry=0x93e00050 size=576 abi=0x0001.0000
   [APP] hello-app: standalone NE301 app PoC, ABI v1.0
   [APP] hello-app: tick_ms t1=74945 t2=74958 delta=13        ← 经 Host 表读到平台时钟前进
   [APP] hello-app: platform clock advanced, host APIs usable
   apphost: entry returned 20037                              ← 0x4E45（v1 约定返回码）
>>> apphost load /apps/hello_v2.bin → run entry=0x93e00050 size=576 abi=0x0001.0000
   apphost: entry returned 20038                              ← 0x4E46（v2 返回码：替换镜像独立可执行）
>>> apphost load /apps/bad-crc32.bin          → reject (crc mismatch)
>>> apphost load /apps/bad-abi-version.bin    → reject (abi version mismatch)
>>> apphost load /apps/bad-target-address.bin → reject (target address mismatch)
>>> apphost load /apps/apphost_test.bin       → run … [APP] ne301 apphost test app: abi v1 table ok
                                                 entry returned 24589   ← 平台 PoC 同板复现（0x600D，与 ne301#25 记录一致）
```

对应 AC：
- **AC2** ✓ hello-app 经唯一 Host API（`log`/`tick_ms`，ABI 0x00010000）读取真实平台能力（tick 前进 13ms）；v1→v2 两个独立构建镜像先后装载执行（替换语义）；过程零主固件重编/重刷（Host 为一次性实验固件，按 A 修订仅从 pinned 实验分支构建；APP1 刷写为该实验的授权动作本身）。
- **AC3** ✓ 三种非法镜像被实验 Host 按其校验序拒绝且未改写平台镜像；失败路径、镜像/分区哈希、执行环境、设备日志全部留存于本目录与 `device_session.log`；真机实做，无模拟替代。

## 事故记录（诚实留存，属 AC3 失败路径证据）

1. **首轮注入损坏**：lfstool 第二次调用误用同路径作输入/输出 → 部分文件数据块缺失，设备表现为 `reject (bad magic)`（hello_v1）而 hello_v2 正常——Host 对损坏内容全部安全拒绝，无一崩溃。
2. **二次修复失败**：以"备份→目标"差异做 4KB 级修补，未考虑 ① 设备状态已被首轮+固件运行时写入漂移，② CubeProgrammer 小段写入在 64KB 扇区粒度下的相互覆盖 → 固件挂载失败后**静默格式化**（`storage.c:512-514`），/apps 消失。
3. **最终修复**：从 pristine 备份单会话重新注入 → `lfs_injected_v2.img` → **整卷单命令写入**（粒度免疫）→ 全部验证通过。
4. 教训已固化为操作规程：多段小写入禁止；差异修补必须相对设备当前状态且按 64KB 扇区对齐整段写。

## 复现与恢复

- 复现：`cd /tmp/ne301-host-build && make app APP_HOST_POC=1 && make pkg-app APP_HOST_POC=1`；`STM32_Programmer_CLI -c port=SWD mode=HOTPLUG -el MX66UW1G45G_STM32N6570-DK.stldr -hardRst -w build/ne301_App_signed_v4.3.1.297_pkg.bin 0x70100000`（SW2 烧录位）。
- 恢复计数环境：回刷 `backup_app1_full.bin` 至 `0x70100000`（哈希 `ddaca651…`），或 OTA 切 B 槽；FS 即当前整卷镜像（= 备份 + 5 个测试文件，计数演示数据完整保留）。
