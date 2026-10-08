# 设备验证证据 — hello-app PoC（Issue #2 AC2/AC3 真机项）

- 日期：2026-10-08；执行者：Primary B（ZCode 编排 + 受控 SWD/串口操作）
- 板卡：STM32N657 Rev B（Device ID 0x486），ST-LINK SN `56FF6F064984524928381287`（FW V2J46S7），与 ne301#25 平台 PoC 记录同板
- 控制台：`/dev/cu.usbserial-14130` @115200，提示符 `AICAM>`
- 完整串口会话：[device_session.log](device_session.log)（真机实录，21:02:55–21:04:11）
- **整改版说明**：本文件按 A 对 e61860d 的 REQUEST_CHANGES（三点证据闭环要求）重写。
  全部哈希于整改时（2026-10-08）从持久工件重新独立计算核对；仍缺失的证据以
  `READBACK:PENDING` 占位并如实标注，不得视为已证明。分区基址/长度引自 pinned
  `ne301/experiment/app-host-poc@a5b4bf3` 的 `Custom/Common/Inc/mem_map.h:73-121`。

## 镜像与来源锚点

| 项 | 值 | SHA256 |
|---|---|---|
| 实验 Host 固件包 | ne301 `experiment/app-host-poc@a5b4bf3dd25931d612680aff200e4e0ac8d8e64e` 构建，v4.3.1.297，`APP_HOST_POC=1`，3,846,400 B | `65f3c0b0c1449bb61543836563635d0b7c74bcfbd57075d206ce218ff1d912b2` |
| hello-app v1（ne30x-app 构建） | 608 B（32B 头 + 576 payload），ABI `0x00010000`，target `0x93E00000`，entry_offset `0x50` | `d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03` |
| hello-app v2（替换版本） | 608 B，返回码 0x4E46、日志文案不同（源码单点变更） | `db1c6d60b398cab11a276e15770fdcdf9d42b9c96b4de6ef2cc93c1ecdec8744` |
| 设备上 Host 回读（APP1@0x70100000） | 刷写后独立回读 `readback_app1_after_flash.bin`（3,846,400 B） | `65f3c0b0…912b2`（== 包文件，逐字节一致） |
| pristine LittleFS 全量备份（刷写前） | `backup_littlefs.bin`（96MB，0x71D00000） | `1a8b3c69003bb94c5509bbc9f299e24643eb68325dd241dc54c125dec8acf1cd` |
| 最终注入镜像（整卷写入内容） | `lfs_injected_v2.img`（96MB） | `45c6a4086ca1c49187bb4d1f4d7c58d60360edc26eec47199d778e882f6c43e1` |
| 整卷写入前设备状态快照（事故后） | `lfs_current.bin`（96MB，见"事故记录"） | `3edfff8b29aab3467ce90e00bf7cb9e9ee5af41b524135b2fbbdd4d8d65d75d2` |

以上哈希均于 2026-10-08 整改时重新独立计算并与既有记录（`BACKUP_SHA256.txt`、
PoC 构建记录）核对一致。持久工件位置：备份 `/tmp/ne301-board-backup/`，PoC 证据
`/tmp/ne301-poc-evidence/`。

ABI 头唯一权威锁定：pinned 提交 `Custom/Common/Inc/app_host_abi.h`，SHA256 `9337f684893cf2a06aea6f6f8c448708d91e8f9c6c86c24905ced8a7d5df23f4`。

## 刷写前安全核实（合同前置门）

1. 板卡身份：Device ID 0x486 / Rev B / Cortex-M55（HotPlug 只读探查）。
2. boot slot：OTA info（0x70090000）`magic 0x5A5A5A5A`，`active_slot[FIRMWARE_APP]=SLOT_A`（APP1）。
3. 全量只读备份（写入前）：APP1 4MB、APP2/FSBL 仅头部普查、NVS 64K、OTA 8K、AI_1/AI_2 各 8MB、WEB 1MB、WiFi FW 3MB、LittleFS 96MB；哈希清单 `BACKUP_SHA256.txt` 与实际文件整改时核对一致（见下"分区保护表"）。恢复路线评估见"APP 恢复路线与验证程度"——其中 APP2 路线为**未验证备选**，不得当作可靠回退承诺。
4. 每次写入均在 SW2 烧录位、固件停机状态下执行。

## 分区保护表（地址/长度 | 备份类型 | SHA256 | 实验中被写入?）

| 分区 | 基址 / 长度（pinned mem_map.h） | 备份类型 | 备份 SHA256 | 实验中是否被写入 | 写入后校验 |
|---|---|---|---|---|---|
| FSBL | 0x70000000 / 512K | 仅头部普查（2KB） | `c28a32010be931c597d21abb0c6e02ed5f70f8761c343d35ba69e99586c4e18c` | 否 | 无（未写入；无独立回读） |
| NVS | 0x70080000 / 64K | 全量 | `ff2f0b6ee19f2f6732dc975232e8e21db9184d3e632c298938a618daad50b40e` | 否 | 无（未写入；无独立回读） |
| OTA info | 0x70090000 / 8K | 全量 | `9b9b633d9416084a53cf47c8c7b9717606d4a6e70fd220b32e145ec0dfc407ce` | 否 | 无（未写入；无独立回读） |
| SWAP | 0x70092000 / 64K | 无 | — | 否 | 无 |
| RESERVE1 | 0x700A2000 / 376K | 无 | — | 否 | 无 |
| **APP1** | 0x70100000 / 4M | 全量 | `ddaca651dcb0789fbb15c4f84f98cf0b60d98e1c846dc4970ed6c4b9504d8b12` | **是**（实验 Host 部署，一次 SWD 写） | CubeProgrammer verify + 独立回读 == 包哈希（见下对照表）；替换后回读 PENDING |
| APP2 | 0x70500000 / 4M | 仅头部普查（1KB） | `a1492ab5f43364c71645ef637abd6839cb4e6652b917918c40c6c1d1007fca35` | 否 | 无（未写入；无独立回读） |
| AI_1 | 0x70900000 / 8M | 全量 | `168790a9f1d0644bd689b4c1800c4a6761da886ff4bad47d1f10c1bc99ed5829` | 否 | 无（未写入；无独立回读） |
| AI_2 | 0x71100000 / 8M | 全量 | `a7b2cc66728ecb9d50ed764cdfe307d5fae0718dbd63c79630f65a104965114a` | 否 | 无（未写入；无独立回读） |
| **WEB** | 0x71900000 / 1M | 全量 | `a1f49644ec51229c821b55de1da6c352091fc2eb795aa4e58cdaba2b8c992ada` | 否 | 操作后回读 PENDING（见下对照表） |
| WiFi FW | 0x71A00000 / 3M | 全量 | `53695f18cca71592db1cbaf8702948f421f0add4533eb17fc2dc3b3abeab03be` | 否 | 无（未写入；无独立回读） |
| **LittleFS** | 0x71D00000 / 96M | 全量（pristine） | `1a8b3c69003bb94c5509bbc9f299e24643eb68325dd241dc54c125dec8acf1cd` | **是**（见"写入审计"；最终为整卷 96MB 单命令写） | CubeProgrammer `--verify`（转录未持久化，见"诚实性注记"）+ 持久化功能验证（device_session.log）+ 镜像级内容对照；设备级整卷回读 PENDING |
| RESERVE2 | 0x77D00000 / 3M | 无 | — | 否 | 无 |

**诚实性注记（适用于全表）**：
- "是否被写入"依据**完整写入命令审计**（下文"写入审计"表）：全部设备写命令仅覆盖 APP1 与 0x71D00000 起的 FS 区域，其余分区无写入命令记录。
- 未写入分区的"不变性"是**零写入 + 刷写前备份哈希**的推断，除 APP1（独立回读）外，未逐一做写入后回读。从未回读的分区如实标记"无独立回读"，不写成已证明。
- 首轮注入的 6×4K 块、二次修复的 28 段 / 13 段写入全部位于 LittleFS 分区内（0x71D00000–0x77CFFFFF），未越界到其他分区（写入命令与地址清单 `repair_plan.txt`/`repair_runs.txt`/`repair64_runs.txt` 留存于 `/tmp/ne301-poc-evidence/`）。

## 分区不变性对照（A 整改点 1：APP1 与 WEB）

### APP1（实验 Host 所在分区）

| 阶段 | 证据 | SHA256 |
|---|---|---|
| 部署前（原 counting 固件，实验首写前全量备份） | `backup_app1_full.bin`（4MB） | `ddaca651dcb0789fbb15c4f84f98cf0b60d98e1c846dc4970ed6c4b9504d8b12` |
| 部署后（实验 Host 一次 SWD 刷写 + CubeProgrammer verify + 独立回读） | `readback_app1_after_flash.bin`（3,846,400 B） | `65f3c0b0c1449bb61543836563635d0b7c74bcfbd57075d206ce218ff1d912b2` == 包哈希 |
| 替换后（V1→V2 两次装载执行完之后，APP1 分区回读） | <!-- READBACK:PENDING --> 协调者在设备上补读中；在回填前，"替换后 APP1 未被改写"不作为已证明结论 | — |

### WEB（基础网页，操作前/后）

| 阶段 | 证据 | SHA256 |
|---|---|---|
| 操作前（实验任何写入之前全量备份） | `backup_web.bin`（1MB） | `a1f49644ec51229c821b55de1da6c352091fc2eb795aa4e58cdaba2b8c992ada` |
| 操作后（实验全部操作完成后回读） | <!-- READBACK:PENDING --> 协调者在设备上补读中；在回填前，WEB 不变性以"零写入命令 + 操作前备份"为据，非独立回读证明 | — |

### 关键区分：首次刷写实验 Host vs 其后 V1/V2 替换

**首次刷写（唯一一次 APP1 flash 写）**：一次 SWD 写入实验 Host 包至 0x70100000
（`STM32_Programmer_CLI … -hardRst -w <pkg.bin> 0x70100000 --verify`），随后独立
回读全分区，哈希 == 包文件。此后 APP1 分区再无任何写入命令。

**其后所有 V1/V2「替换」= littlefs 文件级操作 + RAM 内执行，零 flash 写**：

- 设备侧装载路径（pinned `Custom/Services/AppHost/app_host.c`，a5b4bf3）：
  - `app_host_load_and_run`（`app_host.c:77-89`）：先 `storage_is_lfs_mounted()` 检查，再读文件；
  - `app_host_read_file`（`app_host.c:36-75`）：仅 `flash_lfs_stat`（:39）→
    `flash_lfs_fopen(path,"r")`（:52）→ `flash_lfs_fread`（:60）→ `flash_lfs_fclose`（:66），
    目标缓冲为 RAM 执行区 0x93E00000（PSRAM，非 flash 映射；`apphost info` 回报
    `exec region 0x93e00000-0x94000000`）。装载路径不含任何 flash 写调用。
- 「替换另一版本镜像」语义 = `/apps/hello_v1.bin` 与 `/apps/hello_v2.bin` 两个独立
  构建镜像先后经同一 Host API 装载执行（device_session.log:37-61），期间设备写命令
  记录为零（写入审计表仅含 APP1 部署与 FS 区域条目）。
- 因此 V1/V2 替换既不重编也不重刷主固件：APP1 分区内容自部署后仅受该一次写影响，
  替换后回读（PENDING）预期 == 部署后回读 `65f3c0b0…`。

## LittleFS 96MB：pristine → 最终注入镜像 → 设备状态（A 整改点 2）

### 哈希链

| 项 | SHA256 | 说明 |
|---|---|---|
| pristine 备份 `backup_littlefs.bin`（96MB，写入前） | `1a8b3c69…acf1cd` | 设备 FS 的原始全量快照（counting 演示环境） |
| 最终注入镜像 `lfs_injected_v2.img`（96MB） | `45c6a408…c43e1` | pristine + 5 个测试文件（见下对照），单会话重新注入 |
| 整卷写入前设备状态 `lfs_current.bin`（96MB） | `3edfff8b…5d75d2` | 二次修复失败、固件静默格式化之后的设备真实状态（事故证据） |

### 整卷写入与校验状态（诚实陈述）

- 命令：`STM32_Programmer_CLI -c port=SWD mode=HOTPLUG -el MX66UW1G45G_STM32N6570-DK.stldr -hardRst -w lfs_injected_v2.img 0x71D00000 --verify` —— **单命令整卷 96MB 写入**（对 64KB 扇区粒度免疫，区别于首轮 4K 块与二次修复的多段小写入）。
- `--verify` 结果：CubeProgrammer 终端报告写入校验通过（"Download verified successfully"）。
  **如实标注**：该 CLI 转录仅显示在操作者终端，未持久化到磁盘；本目录能独立复核的是
  以下持久化后验，而非 verify 摘录本身。
- 持久化的后验证据：
  1. `device_session.log`（整卷写入后）：21:02:55 `version` → 实验 Host 运行
     （v4.3.1.297 / Git Hash a5b4bf3）；21:03:10 `apphost info` → **`littlefs mounted`**（写入镜像成功挂载）。
  2. 同日志：`/apps/hello_v1.bin`、`/apps/hello_v2.bin`、`/apps/apphost_test.bin` 从该 FS
     装载执行成功，三种坏镜像按预期拒绝——文件级内容可用性得证。
  3. 镜像级内容对照（下节）：注入镜像相对 pristine 逐一可核。
  4. 设备级最终状态整卷回读：<!-- READBACK:PENDING --> 协调者在设备上补读中。

### 内容级对照（核心证明）

工具 `tools/fs_manifest.c`（只读挂载 littlefs、遍历整卷、逐文件输出
`路径|大小|SHA256`；几何参数与设备一致，输入镜像只读，prog/erase 即硬错误），
清单与 diff 见 [fs-manifests/](fs-manifests/README.md)：

| 清单 | 镜像 | 文件数 | 目录数 | 字节 |
|---|---|---|---|---|
| [pristine_backup.manifest](fs-manifests/pristine_backup.manifest) | pristine 备份 | 885 | 25 | 13,323,928 |
| [injected_v2.manifest](fs-manifests/injected_v2.manifest) | 最终注入镜像 | 890 | 25 | 13,326,968 |

[pristine_vs_injected.diff](fs-manifests/pristine_vs_injected.diff) 结论：

- **旧数据保留：885 个原有文件逐一保留**——路径、大小、内容 SHA256 与 pristine 备份
  完全一致（含 counting 演示数据：根目录 `/aicam.log*` 3 个日志、`/apps/apphost_test.bin`
  与 `/apps/apphost_corrupt.bin`、`/captures/data/…` 下 880 个抓拍 JPEG）。
- **仅新增 5 个测试文件**，全部在 `/apps/`，均 608 B，哈希与构建产物逐一相等：
  `hello_v1.bin`、`hello_v2.bin`、`bad-crc32.bin`、`bad-abi-version.bin`、`bad-target-address.bin`。

### 剩余风险与结论收窄（如实）

1. 设备自最终整卷写入后持续运行，固件会向 FS 追加运行时日志/抓拍（如 `/aicam.log*`、
   `/captures/`）——**设备当前 FS 内容必然已相对注入镜像存在运行时增量**。
2. 因此"旧数据保留、仅增加测试文件"的证明强度分层如下，不得混同：
   - **镜像级（已证明）**：`lfs_injected_v2.img` = pristine + 5 个 /apps 测试文件（内容哈希逐一对照，零删改）。
   - **设备级（已证明部分）**：整卷写入后设备成功挂载该镜像并装载执行 /apps 文件（device_session.log）。
   - **设备级（待闭合）**：设备当前整卷内容与注入镜像的一致性回读——READBACK:PENDING。
3. "计数演示数据完整恢复"结论据此**收窄为**：注入镜像内容级等于 pristine + 5 个测试文件，
   且设备曾从该镜像成功挂载运行；设备上非日志文件的当前完整性以最终回读为准，回填前不声称
   逐字节等于注入镜像。
4. pristine 备份当前持久化于 `/tmp/ne301-board-backup/`（单副本 + `BACKUP_SHA256.txt`
   清单，整改时核对一致）。`/tmp` 存储非耐用介质，该备份宜尽早转存至耐用介质（整改者如实记录，未执行转存）。

## APP 恢复路线与验证程度（A 整改点 3）

| 路线 | 验证程度 | 结论 |
|---|---|---|
| **APP1 备份回刷（主路线）** | 备份存在且哈希核对（`backup_app1_full.bin`，`ddaca651…`）；同物理路径（SWD `-w … 0x70100000`）本次实验 Host 部署已实际走通。**恢复动作本身未执行过**——即未实际回刷验证原 counting 固件可由此恢复 | 可行性有据，**恢复结果未实测**；执行前属"有备份支撑的计划路线"，非已验证恢复 |
| **APP2 / OTA 切 B 槽** | 仅 1KB 头部普查（`census_app2_head.bin`，OTAU 头 magic 有效）；**无全量备份、无可启动性证明、未做切槽验证** | **未验证的备选方案**。不得表述为"存有完整计数固件、可直接 OTA 切换"的可靠回退承诺 |
| FS 还原到 pristine | 备份存在且哈希核对（`backup_littlefs.bin`，96MB）；整卷单命令写入路径本次已走通（写入对象为注入镜像） | 同 APP1：路径可行有据，还原动作本身未执行；执行即丢弃设备上实验后的运行时增量 |

## 真机验证序列（2026-10-08 21:02–21:04，串口实录，整卷写入之后）

```text
>>> version                         → Git Hash: a5b4bf3   ← pinned 实验固件在跑
>>> apphost info                    → exec region 0x93e00000-0x94000000 (2097152 bytes)
                                    → abi 0x0001.0000, littlefs mounted   ← 整卷写入镜像成功挂载
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
- **AC2** ✓ hello-app 经唯一 Host API（`log`/`tick_ms`，ABI 0x00010000）读取真实平台能力（tick 前进 13ms）；v1→v2 两个独立构建镜像先后装载执行（替换语义 = littlefs 文件 + RAM 执行，见"关键区分"节代码锚点）；过程零主固件重编/重刷（Host 为一次性实验固件，按 A 修订仅从 pinned 实验分支构建；APP1 刷写为该实验的授权动作本身，且为唯一一次）。APP1/WEB 替换后/操作后回读 PENDING 项回填前，不变性结论以上表标注的强度为准。
- **AC3** ✓ 三种非法镜像被实验 Host 按其校验序拒绝且未改写平台镜像（拒绝仅发生在 Host 校验序内，无任何写命令，见写入审计）；失败路径、镜像/分区哈希、执行环境、设备日志全部留存于本目录、`fs-manifests/` 与 `device_session.log`；LittleFS 事故全程如实留存（下节）；真机实做，无模拟替代。

## 写入审计（全部设备写操作）

| 目标 | 内容 | 校验 |
|---|---|---|
| APP1 `0x70100000` | 实验 Host 包（`-hardRst -w … --verify`，唯一一次 APP1 写） | CubeProgrammer verify + 独立回读哈希一致（`65f3c0b0…`） |
| LittleFS 6×4K 块（首轮注入，`lfs_injected.img`，已废弃） | hello/坏镜像 | per-block verify（**后见之明：多段小写入在 64KB 扇区粒度下相互覆盖，见"事故记录"**） |
| LittleFS 146×4K 块 / 28 段（二次修复） | — | per-run verify（同样受扇区粒度影响，未达目的） |
| LittleFS **整卷 96MB**（最终修复） | `lfs_injected_v2.img` 单命令 `-w … 0x71D00000 --verify` | CubeProgrammer verify 通过（转录未持久化，见诚实性注记）；持久化后验 = device_session.log + 镜像级内容对照 |

**未触碰**：FSBL、NVS、OTA info、SWAP、RESERVE1/2、APP2、AI_1/AI_2、WEB、WiFi FW
分区（写入命令全记录仅覆盖 APP1 与 0x71D00000 起的 FS 区域）。上述分区的写入后
回读状态见"分区保护表"——除 APP1 外均无独立回读，如实标注。

## 事故记录（诚实留存，属 AC3 真实失败路径证据）

1. **首轮注入损坏**：lfstool 第二次调用误用同路径作输入/输出 → 部分文件数据块缺失，设备表现为 `reject (bad magic)`（hello_v1）而 hello_v2 正常——Host 对损坏内容全部安全拒绝，无一崩溃。
2. **二次修复失败**：以"备份→目标"差异做 4KB 级修补，未考虑 ① 设备状态已被首轮+固件运行时写入漂移，② CubeProgrammer 小段写入在 64KB 扇区粒度下的相互覆盖 → 固件挂载失败后**静默格式化**（`storage.c:512-514`），/apps 消失。失败时点设备真实状态快照 `lfs_current.bin`（`3edfff8b…`）及其清单 [device_state_before_full_write.manifest](fs-manifests/device_state_before_full_write.manifest)（仅 11 文件/8 目录，原始 885 文件随格式化丢失）。
3. **最终修复**：从 pristine 备份单会话重新注入 → `lfs_injected_v2.img` → **整卷单命令写入**（粒度免疫）→ 全部验证通过（证据见"LittleFS 96MB"节）。
4. 教训已固化为操作规程：多段小写入禁止；差异修补必须相对设备当前状态且按 64KB 扇区对齐整段写。

## 复现与恢复

- 复现：`cd /tmp/ne301-host-build && make app APP_HOST_POC=1 && make pkg-app APP_HOST_POC=1`；`STM32_Programmer_CLI -c port=SWD mode=HOTPLUG -el MX66UW1G45G_STM32N6570-DK.stldr -hardRst -w build/ne301_App_signed_v4.3.1.297_pkg.bin 0x70100000`（SW2 烧录位）。
- 恢复 counting 环境（主路线，验证程度见"APP 恢复路线"节）：回刷 `backup_app1_full.bin`（`ddaca651…`）至 `0x70100000`——与本次 Host 部署同一命令路径，但恢复动作本身未实测。
- FS 现状即最终注入镜像（= pristine + 5 个测试文件，对照见 `fs-manifests/`）+ 设备运行时增量；如需 FS 完全还原 pristine：整卷单命令回刷 `backup_littlefs.bin` 至 `0x71D00000`（代价：丢弃实验后运行时增量）。
- APP2/OTA 切 B 槽：未验证备选，不作为回退承诺（见"APP 恢复路线"节）。
