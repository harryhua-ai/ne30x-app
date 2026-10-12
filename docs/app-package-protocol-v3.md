# NE301 × ne30x-app — `.neapp` v3 签名容器、Host ABI v3 与受控热配置 wire 规范（受审候选）

> **文件地位**：本文是 Issue #19 依据 [NE301 #54 已冻结的 A 公共语义（2026-10-12）](https://github.com/harryhua-ai/ne301/issues/54) 整理的**唯一正式 v3 规范受审候选**。#54 是本文唯一的产品/安全语义权威；本文只把已冻结语义机械化为逐字节容器/manifest/签名/ABI/wire 规则、黄金向量与拒绝矩阵，供 A exact-SHA 审查。**未经正式 Candidate 审查并集成至 `ne30x-app/main` 前，本文不是任何 #20/#21/#55–#57 的实施许可；集成后也不代表真实 Host 编译、设备写入或 Line Crossing Web 已验证（§14）。**
>
> **v1/v2 不变基准**：已集成的 [app-package-protocol-v1.md](app-package-protocol-v1.md) 与 [app-package-protocol-v2-draft.md](app-package-protocol-v2-draft.md) 分别是 v1/v2 的唯一已集成规范。v3 是**独立容器 major 3 + 独立 Host ABI major 0x00030000**，不是 v2 的向后兼容延伸：旧包的 magic、函数表、签名与拒绝规则逐字节不变；v3 不借 v2 保留字节、未知能力位或未声明特性扩权。#54 明确：旧 Host 直接拒绝 v3；v3 Host 按原规则接收合规 v1/v2（各自旧语义、旧函数表），禁止前缀偷兼容，禁止旧包自动获得新能力。
>
> **固定证据锚点**（与 v2 规范文件头同源，容量与 ABI 数字与之对齐）：`LC_FRAME_MAX_DETECTIONS = 64`、单事件上限 1576B、`LC_DQ_SLOT_CAPACITY = 6144`、`LC_TARGET_CLASS_NAME_LEN = 32`（ne301 `de25a6f1`）；实验 Host 2 MiB 执行区（v1 §2.3/§2.5 基线）；Line Crossing 业务私有配置 blob 参考长度 **152B**（#54 §2 冻结事实：Host 不解析或改写该 blob）。
>
> **测试与黄金向量**：本文 §12 的全部正负向量由 [tests/spec-v3/](../tests/spec-v3/README.md) 一键独立生成与核对（纯 Python 标准库 + OpenSSL 独立交叉验签），证据输出到 `docs/evidence/spec-v3/`。该套件**独立实现** v3 验证逻辑，不 import `package/` 的 v2 验证器，也不复制 `tests/spec-v2` 的 parser 自证；对 v1/v2 的判定仅是互操作模拟门，v1/v2 权威仍是各自已集成规范。本文不实现打包器、Host 服务或业务 App（non_goals）。

## 目录

- §1 总则与版本化原则
- §2 受签名 v3 容器
- §3 v3 manifest（192B 定长）
- §4 能力位、run_profile 与配额
- §5 Host ABI v3 调用面（60B/13 回调）
- §6 控制命令 wire（Host → App）
- §7 回执 wire（App → Host）
- §8 业务快照 wire（App → Host）
- §9 命令状态机与事务语义
- §10 新旧互操作与拒绝矩阵
- §11 错误类别与拒绝语义
- §12 黄金向量与离线正负测试
- §13 B 最小编码选择清单（供 A 评审焦点）
- §14 没有 PASS 的边界（如实标注）
- 附录 A：#54 冻结决定 → 本文覆盖对照

## §1 总则与版本化原则

1. **独立 major，域隔离**（#54 §1 冻结）。v3 采用独立容器 magic、独立 manifest magic `NMF3`、`required_host_abi = 0x00030000`、原生头 `abi_version = 0x00030000` 与独立 60B 函数表。任何一方不得把 v3 的 192B manifest、更长函数表或新能力位当作 v1/v2 的"向后兼容延伸"来解释旧包，反之亦然。
2. **单一信任根不变**（#54 §1 冻结）。v3 复用 v1 §2.1/§4.1 与 v2 §2 的唯一信任机制：SHA-256 + ECDSA over secp256r1（P-256）+ 严格 DER + Host 内建发行者 SPKI 信任映射（`publisher_id → SHA-256(SPKI DER)` 本地映射核对）；包自带公钥/指纹不得自授信；不引入新根密钥、在线撤销、其他签名算法或第二套 NVS/网络体系。不同 major 签名域隔离（v3 TBS 只在 v3 判定域内解释）。
3. **fail-closed**（继承 v1 §1.3/v2 §1.3）。未知容器版本、未知 manifest magic、未知 profile、未知能力位（bit8..31）、非零保留字段、未知消息类型/标志位、非规范编码、截断/溢出/非法 UTF-8、未知 ABI 全部拒绝；任何失败不得被解释为部分成功或降级运行。
4. **单一权威与互操作**。本文是 v3 包字节、签名原文、能力、配额、控制/回执/快照 wire、ABI 调用面与命令状态机的唯一权威文档。打包端（#20）与设备端（#55/#56）允许不同实现做互操作验证，但不得各自定义不同容器、wire 或签名算法；不得以复制同一解析器的测试代替独立正确性证明。
5. **扩展须新版本**（继承 v2 §1.5）。manifest 保留字段、能力 bit8..31、命令/回执/快照 flags 未定义位、ABI 表越界偏移一律拒绝；未来扩展必须以新容器 major/ABI major/新 profile 经 A 受审修订，不得原版本内偷扩。
6. **非授权边界**（#54）：只有**当前已验签安装且合法受信的 v3 包**（当前会话 + 声明对应能力位）可请求/调用新能力；v1/v2 原语义不变。热配置 Line Crossing 同时要求 bits2/3/4/5/6/7（§4）。

## §2 受签名 v3 容器

### 2.1 布局（#54 §1 冻结：16B 外层头 + 192B manifest + 原生 + 严格 DER）

| 字节位置（从 0 起） | 编码 |
| --- | --- |
| `0..7` | 固定 8 字节 magic：`4E 45 41 50 50 03 00 00`（ASCII `NEAPP`、容器主版本 3、两个零保留字节；HEX `4e45415050030000`） |
| `8..11` | `manifest_len`：`u32-le`，**必须恰好为 192**（其它任何值拒绝） |
| `12..15` | `image_len`：`u32-le`，完整原生文件长度（32B 原生头 + payload），必须至少容纳 32B 原生镜像头 |
| `16..207` | 原样 192B manifest（§3） |
| `208..(208+image_len-1)` | 原样原生 App 镜像 `image_len` 字节，含未修改的 32B Host 原生镜像头及其 payload |
| 文件最后剩余字节 | **恰好一个**严格 DER `ECDSA-Sig-Value`；无签名长度字段、无额外尾部、无第二签名或证书链 |

### 2.2 签名原文与身份（#54 §1 冻结，与 v2 同机制）

- **唯一签名原文**：`TBS = 文件从偏移 0 开始，连续取 16 + 192 + image_len 字节`（原样头 + manifest + native 连续字节）。
- 签名与**幂等内容身份**均使用 `SHA-256(TBS)`：对 `SHA-256(TBS)` 用发行方 ECDSA P-256 私钥签名；相同 `SHA-256(TBS)` 视为相同内容（不同但均合法的 DER 不构成版本冲突；v1 §2.2/§7.1 幂等语义全文适用）。
- **DER 必须完整消费其尾部**：签名 DER 之外的任何附加字节拒绝；DER 长度合法区间 8–72B；严格、规范 DER，两个正整数 `r,s` 位于 `1 <= r,s < n`；拒绝 BER 非最短编码、负值、零值、越界、截断、附加字节、多重 ASN.1 对象；不要求 low-S 归一化。
- 签名算法唯一钉定（SHA-256/ECDSA P-256/DER/SPKI），无算法协商或降级；未知容器版本直接拒绝。

### 2.3 容量与校验顺序（继承 v2 §2.3 与 v1 §7.1 判定序）

- 长度加法溢出安全；DER 长度 8–72B；候选整包上限 `16 + 192 + native_file_len + DER_len <= 2,097,432` 字节（设备以实际 `region_size` 复核；实测不能支持时由 A 修订上限，不得由实现自行扩容）。`native_file_len <= 真实 Host 装载区`，**驻留量（`required_exec_region_bytes`）与装载量分别验证**（v1 §2.3 规则全文适用）。
- **判定序（结构 → 信任 → 签名 → 策略）**：①管理入口授权 → ②有界结构解析（magic、两个长度、192B manifest 唯一编码、DER 结构与尾段完整消费）→ ③可信发行者（Host 本地唯一 SPKI 映射，`PUBLISHER_UNTRUSTED` fail-closed）→ ④对**原样 TBS** 的 ECDSA 验签（Host 自有密钥，非包自带）→ ⑤策略校验（原生头交叉检查/摘要/CRC/板型/ABI/能力/配额/资源/版本/安装状态）。任一步失败不得创建可执行安装记录、不得启动。结构失败属 `BAD_PACKAGE`；不可信发行者属 `PUBLISHER_UNTRUSTED`；验签失败属 `SIGNATURE_INVALID`；策略失败按 §11 分类。该顺序使"签名段被改"与"已签 payload 被改"都得到确切归因（签名数学失败先于需要信任数据的策略项）。
- v1 §2.3 标识符字符集（小写 ASCII `a-z0-9-`、首字符 `a-z`、末字符字母或数字、右零填充逆向定界、禁止内嵌 NUL/非零填充）与 `publisher_id → SHA-256(SPKI DER)` 映射核对规则在 v3 manifest 中**同位置同语义**适用。

## §3 v3 manifest（192B 定长）

无符号整数一律小端；非空保留字段不得忽略；manifest 必须唯一编码（禁止重复字段、多义排序、非规范整数/字符串）。

### 3.1 前 160B：沿用 v2/v1 共同基础（#54 §1 冻结"0..159 字段布局沿用已受审 v2"）

| 偏移 / 长度 | 字段 | v3 取值与约束 |
| --- | --- | --- |
| `0..3` / 4B | `manifest_magic` | ASCII `NMF3`（`4E 4D 46 33`），否则拒绝 |
| `4..19` / 16B | `publisher_id` | v1 §2.3 同位置同语义 |
| `20..51` / 32B | `app_id` | v1 §2.3 同位置同语义 |
| `52..57` / 6B | `version_major/minor/patch` | 各 `u16-le`，三段整数比较 |
| `58..59` / 2B | `reserved` | **必须全零** |
| `60..63` / 4B | `target_board_id` | `u32-le`；受控实验候选 `0x00003010`（v1 §2.4 边界适用） |
| `64..67` / 4B | `required_psram_mib` | `u32-le`；当前证据仅 64 MiB |
| `68..71` / 4B | `required_host_abi` | `u32-le`，**必须为 `0x00030000`**（其它值拒绝为 v3 格式违例） |
| `72..75` / 4B | `required_host_caps` | `u32-le` v3 能力位掩码（§4） |
| `76..79` / 4B | `required_exec_region_bytes` | v1 §2.3 同位置同语义（驻留量） |
| `80..83` / 4B | `native_file_len` | 须等于外层 `image_len` 与实际原生长度 |
| `84..87` / 4B | `native_image_size` | 须等于原生头 `image_size`；`native_file_len = 32 + native_image_size` |
| `88..91` / 4B | `native_entry_offset` | Thumb 约束（`< native_image_size`、偶数/半字对齐） |
| `92..95` / 4B | `native_target_addr` | 须等于原生头 `target_addr` 且在 Host 独立已知 loader 范围内 |
| `96..127` / 32B | `native_file_sha256` | 对含头的整个原生文件求 SHA-256，恒时比较 |
| `128..159` / 32B | `publisher_key_sha256` | 对 Host 受信 SPKI DER 原始字节求 SHA-256，与 Host 本地映射核对 |

### 3.2 [160..191]：v3 扩展字段（#54 §1 冻结"沿用 v2 字段与配额位置"）

| 偏移 / 长度 | 字段 | 编码与约束 |
| --- | --- | --- |
| `160..163` / 4B | `run_profile` | `u32-le`，本版**唯一合法值 2**＝管理员显式启动的、具受控热命令的单 App 长会话；其它值（含 v2 的 1）拒绝，旧 profile 不被 v3 装载器误解释 |
| `164..167` / 4B | `event_max` | `u32-le`，AI 事件单条最大字节数上界声明（v2 同位置同语义） |
| `168..171` / 4B | `state_quota` | `u32-le`，App 状态 blob 配额声明（v2 同位置同语义） |
| `172..175` / 4B | `report_max` | `u32-le`，单条业务报告最大字节数上界声明（v2 同位置同语义） |
| `176..179` / 4B | `control_max` | `u32-le`，控制命令/回执消息（**含 32B 消息头和载荷**）的最大字节数上界声明；声明 bit6 时必须非零 |
| `180..183` / 4B | `snapshot_max` | `u32-le`，业务快照消息（**含 32B 消息头和载荷**）的最大字节数上界声明；声明 bit7 时必须非零 |
| `184..191` / 8B | reserved | **必须全零**；任何非零拒绝 |

消息长度**不得截断**：超过声明 `control_max`/`snapshot_max` 或超过 Host 实际可提供有界容量的命令/回执/快照**整体拒绝**（`QUOTA_EXCEEDED`/`RESOURCE_LIMIT`），不截断载荷。各新 quota 必须**不超过当前设备实际可提供的有界容量**；声明能力不等于 Host 实际提供能力（§4.2 反向 fail-closed 继承）。旧事件容量/报告/状态配额边界继承 v2（§4.1/§8 M7）。

### 3.3 原生镜像交叉检查（继承 v1/v2 并钉定 ABI）

原生文件仍是 `NEA1`（字节序 `4E 45 41 31`）、32B 头、`header_size = 32`、`format_version = 1`、**`abi_version = 0x00030000`**、头偏移 `24..27` 的 `reserved0` 全零。原生头各字段、SHA-256（对含头的整个原生文件）、CRC32（v1 同一反射 IEEE CRC32）与所有长度/目标地址/执行区字段按 v1 §2.3/v2 §3.3 严格交叉检查；manifest `required_host_abi` 必须等于原生头 `abi_version`。现有 `app_host_validate` 的宽松行为不可替代签名准入层更严格的检查。

## §4 能力位、run_profile 与配额

### 4.1 能力位定义（`required_host_caps`，`u32-le`；#54 §1 冻结）

| bit | 能力 | 含义 |
| --- | --- | --- |
| 0 | `log` | v2 同名函数（语义同 v1/v2，不变） |
| 1 | `tick_ms` | v2 同名函数（含 v2 §6.3 模 2³² 回绕例外语义，不变） |
| 2 | `ai_events` | v2 §5 AI 事件 wire / `event_next`（须经 `event_max` 配额约束） |
| 3 | `report_submit` | `report_submit`/`report_status`（须经 `report_max` 配额约束） |
| 4 | `app_state` | `state_read`/`state_commit`（须经 `state_quota` 配额约束） |
| 5 | `session_lifecycle` | v2 §7 受控会话生命周期 |
| 6 | `control_receive` | **v3 新增**：`control_next`/`control_reply`（§5/§6/§7；须经 `control_max` 配额约束） |
| 7 | `business_snapshot` | **v3 新增**：`snapshot_publish`（§5/§8；须经 `snapshot_max` 配额约束） |
| 8..31 | — | **任何一位为 1 均拒绝**（未知能力；即使重签合法也不放行） |

约束：

- **bits 0..5 原语义不变**（#54）；bit6/bit7 仅可由**合法受信 v3 包**声明；v1/v2 容器内出现位 6/7 仍按各自规范拒绝。
- **`run_profile = 2` 必须包含 bit5（会话生命周期）与 bit6（热命令）**；缺任一为格式违例（`BAD_PACKAGE`）。
- **配额-能力位匹配**：bit2 ⇒ `event_max > 0`；bit3 ⇒ `report_max > 0`；bit4 ⇒ `state_quota > 0`；bit6 ⇒ `control_max > 0`；bit7 ⇒ `snapshot_max > 0`。未声明对应能力位而配额非零同样拒绝（不允许"悄悄预留"）。
- **热配置 Line Crossing 业务约束**（#54 §1：同时要求 bits2/3/4/5/6/7）：凡业务判定为 line-crossing-64，缺 bits2/3/4/5/6/7 任一即 `BAD_PACKAGE`；且 `event_max >= 1576`、`report_max >= 6144`（继承 v2 §4.1）与 **`control_max >= 184`**（= 32B 消息头 + 152B Line Crossing 配置 blob，§6.4），否则 `RESOURCE_LIMIT`。
- Host 实际可提供的有界容量（事件缓冲、报告槽、状态配额、**控制消息容量与快照 RAM**）由设备实现另行验证（#55/#56）；声明超过实际即 `RESOURCE_LIMIT`，不得部分成功。

### 4.2 包声明 ≠ Host 授权（继承 v2 §4.2）

manifest 能力位只表示签名请求的上界与需求；实际安装/启动必须由 Host 按当前板型、ABI、信任、存储、可用容量**逐项验证**。没有声明的能力/函数不能被调用；包声明了**已知**能力位但当前 Host 实际不提供时，安装/启动整体拒绝（`ABI_INCOMPATIBLE`；运行期对该能力的调用返回 `UNAUTHORIZED`/`INCOMPATIBLE`）。"全部位都在已知集合内"不等于"当前 Host 都支持"。Host **不得因表更长而猜测升级可用面**：对 v1 包只给 16B 表、对 v2 包只给 48B 表、对 v3 包给 60B 表。

## §5 Host ABI v3 调用面（60B/13 回调；#54 §1 冻结）

### 5.1 ABI 版本与入口

- ABI `0x00030000`。单次入口仍为 `int32_t app_entry(const api_table *, uint32_t abi_version)`，使用**独立 v3 类型**。
- v1 16B 表（`log`/`tick_ms`）与 v2 48B 表（10 函数）**逐字节不变**；**整个 v3 表不许当 v2 前缀互换**，缺失已请求能力必须拒绝（表长/ABI 不匹配即 `ABI_INCOMPATIBLE`）。

### 5.2 v3 函数表（恰好 60B = 8B 头 + 13 × 32-bit Thumb 函数指针）

头两个 `u32-le` 为 `table_size = 60`、`abi_version = 0x00030000`：

| 表偏移 | 函数 | 语义 |
| --- | --- | --- |
| 8 | `log` | v2 同签名同语义 |
| 12 | `tick_ms` | v2 同签名同语义（§6.3 模 2³² 例外不变） |
| 16 | `event_next` | v2 同签名同语义 |
| 20 | `model_meta` | v2 同签名同语义 |
| 24 | `class_name` | v2 同签名同语义 |
| 28 | `report_submit` | v2 同签名同语义 |
| 32 | `report_status` | v2 同签名同语义 |
| 36 | `state_read` | v2 同签名同语义 |
| 40 | `state_commit` | v2 同签名同语义（#46 CAS） |
| 44 | `should_stop` | v2 同签名同语义 |
| 48 | `control_next` | **v3 新增**，见 5.3 |
| 52 | `control_reply` | **v3 新增**，见 5.3 |
| 56 | `snapshot_publish` | **v3 新增**，见 5.3 |

偏移 8..44 的 10 个能力在独立 v3 类型中沿用 v2 的**相同函数签名及既有语义**（v2 §6.3 全部签名逐字适用）。**跨 ABI 结构规则**（继承 v2 §6.2）：仅允许固定宽度整数、byte array、由整数传输的 float bits；`sizeof(void*) = 4`、函数指针宽度 = 4、正确对齐必须作为目标编译的静态断言（`_Static_assert`），缺失则拒绝该 ABI 实现；无裸私有对象指针。

### 5.3 三个新回调（签名钉定；全部返回 `int32_t`）

```c
int32_t control_next(void *out, uint32_t cap, uint32_t *actual_len);
int32_t control_reply(const void *buf, uint32_t len);
int32_t snapshot_publish(const void *buf, uint32_t len);
```

- **`control_next`**：App 在**自己的同一有序事件处理上下文**内**非阻塞**调用，取出当前会话至多一个待决命令（§6）。无待决命令时合法返回 **`NO_EVENT = 1`**（#54 对 v2 §6.4 "`NO_EVENT` 仅 `event_next`" 的**显式限定扩展**；v2 语义本身不变）。`cap` 不足以容纳完整命令（含头）时返回 `BUFFER_TOO_SMALL` 并经 `*actual_len` 输出所需长度，**命令不被消费、保持待决**。仅当前受信有效会话且声明 bit6 时可调用，否则 `UNAUTHORIZED`。禁止由 Host 异线程调用 App 裸业务函数；禁止把控制命令伪装成 AI `event_next` kind。
- **`control_reply`**：App 对**已分发给自己的命令**的确认（§7）。Host 仅在当前受信有效会话内缓存与已交付命令匹配的回执；不因 App 可调用回执函数就授予设备管理权。`len` 超过 `control_max` 返回 `QUOTA_EXCEEDED`；请求 ID/会话世代不匹配已交付命令返回 `INVALID_ARGUMENT`。
- **`snapshot_publish`**：App 发布身份会话绑定的业务快照（§8）。Host 仅检查来源（当前会话 + bit7）、格式边界（§8.4）与当前会话，并**复制到有界 RAM 快照**；Host 在其上附加来自自己 #44 服务的 MQTT/Webhook 健康（展示层，不进入 App wire）。`len` 超过 `snapshot_max` 或 Host 快照 RAM 返回 `QUOTA_EXCEEDED`；无权会话/已失效会话返回 `UNAUTHORIZED`，旧回调不得发布。
- **内存寿命**：三个调用的缓冲均为**调用方（App）所有**；Host 必须在调用返回前完成对 `control_reply`/`snapshot_publish` 缓冲的同步拷贝，**不得保留指向 App 缓冲的跨调用指针**；`control_next` 写入 `out` 的命令字节是 Host 待决命令 RAM 的副本，返回后由 App 自行持有/解析。任何一侧不得在返回后继续使用对方缓冲。
- **返回码**：沿用 v2 §6.4 固定枚举（0 `OK`、1 `NO_EVENT`、2 `NOT_FOUND`、-1 `INVALID_ARGUMENT`、-2 `BUFFER_TOO_SMALL`、-3 `UNAUTHORIZED`、-4 `INCOMPATIBLE`、-5 `QUOTA_EXCEEDED`、-6 `STORAGE_UNKNOWN`、-7 `BUSY`、-8 `REVISION_CONFLICT`、-9 `IO_ERROR`、-10 `STOPPING`），并按上文限定应用到三个新回调；`tick_ms` 仍是负数错误码通道的唯一例外。不支持的调用/能力必须返回 `UNAUTHORIZED` 或 `INCOMPATIBLE`，不能让失败作为运行成功继续。

## §6 控制命令 wire（Host → App）

### 6.1 传输模型（#54 §2 冻结）

Host 在服务端完成现有管理员逐请求鉴权、CSRF/请求来源等既有安全门（#36 基线），对**当前已验签安装身份及当前会话**保留**至多一个**有副作用的待决命令；HTTP 接收/入队**不等于**业务生效。App 在自己的同一有序事件处理上下文经 `control_next` 取命令。

### 6.2 命令仅两种（#54 §2 冻结）

| `msg_type` | 名称 | 语义 |
| --- | --- | --- |
| 1 | `CONFIG_APPLY` | 完整配置候选（非默默 merge 的 patch）；载荷为 App 业务私有配置 blob（Line Crossing 参考 152B），**Host 仅限额/转发，不解析或改写** |
| 2 | `COUNTERS_RESET` | 明确独立的破坏性计数重置动作；载荷必须为空 |

读取当前配置/计数**不发送**有副作用的控制命令；读取使用 `snapshot_publish` 的 App 自有只读投影（§8）。Web 画线、选类、调阈值、窗口与跟踪参数由 App 作为业务 schema/合法性/资源预备/计数影响的唯一解释者消费；Host 不解析业务私有 blob、不重解释 AI 事件。

### 6.3 统一 32B 消息头（命令/回执/快照共用；B 最小编码，见 §13.1）

所有 v3 控制面消息以同一定长 32B 头开始，`msg_type` 区分三类并赋予槽位语义；全字段 `u32-le`/`u16-le`，规范有界：

| 偏移 / 类型 | 字段 | 命令（type 1/2） | 回执（type 3） | 快照（type 4） |
| --- | --- | --- | --- | --- |
| `0..3` / 4B | `proto_magic` | ASCII `NFC3`（`4E 46 43 33`），其它值拒绝 | 同 | 同 |
| `4..5` / u16-le | `header_version` | 必须为 1 | 同 | 同 |
| `6..7` / u16-le | `msg_type` | 1 或 2 | 3 | 4 |
| `8..11` / u32-le | `total_len` | `= 32 + payload_len`，必须等于缓冲实际长度 | `= 32`（回执不带载荷） | `= 32 + payload_len` |
| `12..15` / u32-le | `session_generation` | Host 填写，**非零**（§9.1） | App 回显所回复命令的会话世代 | **必须为 0**：App 不自填；Host 在可信回调上下文独立绑定会话身份/世代（#54 §2 冻结） |
| `16..19` / u32-le | `request_id` | Host 分配，**非零**，会话内唯一 | App 回显所回复命令的请求 ID | **必须为 0** |
| `20..23` / u32-le | `config_generation` | `expected_config_generation`：**非零**，管理员草稿所基于的配置世代 | `new_config_generation`：APPLIED 时为切换后的新世代，其余结果为 App 当前活跃世代；**非零** | App 当前活跃配置世代；**非零** |
| `24..27` / u32-le | `state_revision` | **必须为 0** | 回执对应的 #46 CAS 物理版本（APPLIED/提交类结果为新版本；拒绝类为当前版本） | App 最新已持久 `state_revision` |
| `28..31` / u32-le | `flags`/`status` | `flags`：bit0 = `destructive_confirmed`；bit1..31 必须为 0 | `result_status` 枚举（§7.2） | **必须为 0** |
| `32..` | payload | `CONFIG_APPLY`：App 业务私有配置 blob（非空）；`COUNTERS_RESET`：空 | 无 | 严格 UTF-8 JSON 对象（§8.3） |

### 6.4 命令规范编码负例（fail-closed）

未知 `proto_magic`、`header_version != 1`、未知 `msg_type`、`total_len` 与实际长度不一致、`session_generation = 0`、`request_id = 0`、`expected_config_generation = 0`、命令 `state_revision != 0`、未知 flags 位、`CONFIG_APPLY` 空载荷、`COUNTERS_RESET` 带载荷——全部拒绝（运行期 `INVALID_ARGUMENT`/注册拒绝），不截断、不静默修正。载荷字节数受 `min(声明的 control_max, Host 控制容量) - 32` 约束，超限整体拒绝。

## §7 回执 wire（App → Host）

### 7.1 匹配与缓存（#54 §2 冻结）

回执是 App 对**已分发命令**的确认；Host 仅缓存**同一会话内与已交付命令匹配**（同 `request_id` 且 `session_generation` 等于当前会话世代）的有效回执；不匹配的回执返回 `INVALID_ARGUMENT` 且不改变命令状态。首个有效回执确定该命令的最终结果并缓存（供幂等重放复用，§9.4）；其后同一 ID 的新回执不改变已缓存结果。会话结束清除待决/已交付命令与 RAM 快照，**不把旧命令带到新会话**（§9.6）。

### 7.2 `result_status` 枚举（`flags` 槽，u32；B 最小编码，见 §13.2）

| 值 | 名称 | 语义 |
| --- | --- | --- |
| 0 | `APPLIED` | 已在事件边界完成可靠提交（#46 CAS OK）并原子切换；`new_config_generation` 为切换后世代（非零） |
| 1 | `REJECTED_STALE_CONFIG` | `expected_config_generation` 与 App 活跃世代不一致；旧配置/旧计数继续 |
| 2 | `REJECTED_INVALID` | 字段/目标类/线/方向/确认标志等业务校验失败；无状态变化 |
| 3 | `REJECTED_RESOURCE` | 资源预备失败；旧配置继续 |
| 4 | `REJECTED_UNCONFIRMED` | 破坏性动作未携带确认标志 |
| 5 | `FAILED_STATE_CONFLICT` | `state_commit` 返回 `REVISION_CONFLICT`；旧已确认数据未被覆盖 |
| 6 | `FAILED_STORAGE_IO` | `state_commit` 返回 `IO_ERROR`；旧已确认数据保留 |
| 7 | `FAILED_STORAGE_UNKNOWN` | `state_commit` 返回 `STORAGE_UNKNOWN` 或 App 处于存储不可信受限态；**结果不可判定，绝不冒充 APPLIED** |

回执负例：未知 `result_status`、`new_config_generation = 0`、回执带载荷、`request_id`/`session_generation` 为 0——全部 `INVALID_ARGUMENT`，不改变命令状态。

## §8 业务快照 wire（App → Host）

### 8.1 快照契约（#54 §2 冻结）

快照由 App 发出，承载：活动配置及世代（头字段 `config_generation`）、已持久版本（头字段 `state_revision`）与应用状态、当前窗口/累计 IN/OUT、模型/目标有效性、GAP/数据质量与持久化故障。Host 仅检查来源、格式边界和当前会话并复制到有界 RAM 快照；Host 不解释业务字段，展示层由 Host 附加自身 #44 健康事实。

### 8.2 会话绑定（#54 §2 冻结）

**启动后的 App 在收到首个控制命令前无法通过现有入口得知 Host 会话世代，因此初始/周期快照的载荷不要求 App 自填会话世代**：快照头 `session_generation`/`request_id` 必须为 0，由 Host 在当前可信回调上下文独立绑定会话身份/世代、到达时间及快照可见版本；旧回调与无权会话不得发布（`UNAUTHORIZED`）。Host 侧可见版本为每会话自 1 起单调递增的序号（B 最小编码，§13.5）。

### 8.3 载荷编码（B 最小编码，见 §13.3）

载荷为**严格 UTF-8 编码的单个 JSON 对象**文本：合法 UTF-8（非法字节拒绝）、顶层必须是对象、任意深度**重复键拒绝**、`NaN`/`Infinity` 常量拒绝、JSON 文本后不得有尾随数据、对象键为 App 自有 schema（Host 不解释业务键）。参考 Line Crossing 投影（`schema=line-crossing/1`）见 §12.4；业务字段内容正确性由 App 负责并由 #57 Web 消费，Host 仅做格式边界校验。

### 8.4 新鲜度与失效（#54 §2 冻结）

- 正常有会话时 App **至少每 5 秒**更新业务快照；
- 当前快照超过 **10 秒**未更新，Host 须标 `stale`；
- 会话失效/升级、App 停止、失信或 Host 重启后快照标 `unavailable`（RAM 快照清除）；
- `stale`/`unavailable` 不得冒充最新业务事实；设备实际不能满足这些上限时按资源不兼容由 A 复审，不偷放宽。

## §9 命令状态机与事务语义（AC3）

### 9.1 会话与世代标识

- **会话世代**（`session_generation`）：Host boot 作用域内自 1 起非零单调递增（B 最小编码，§13.4），每次会话建立 +1；**禁止回绕**（0xFFFFFFFF 之后拒绝新会话）；重启归零重来。跨世代命令/回执/快照永不匹配。
- **`config_generation`**：App 自有、持久、**只有已确认配置变化才前进**的配置世代；**正常统计与周期 `state_commit` 不得使其前进**（#54 冻结）。活跃世代非零（0 非法）；每次确认的配置变更恰好 +1（B 最小编码，§13.6）；u32 耗尽为 App fail-closed 条件。
- **`state_revision`**：#46 CAS blob 物理版本，可因持续计数提交前进；只能由 App 在单序列化业务上下文管理，**不可拿作 Web 的 expected-config-revision**（#54 冻结）。两世代分离是本规范的可测试不变量（§12.9）。

### 9.2 Host 命令登记（管理员 Save；Web 不改变 App 活动配置）

按序判定，输出仅为命令生命周期可观察状态，**绝非已生效**：

1. 鉴权/当前会话/bit6 检查失败 → `UNAUTHORIZED`；
2. `request_id` 已有最终结果：语义（type + payload 字节 + expected gen + flags）完全相同 → 返回**缓存结果**，不重做数据变更；语义不同 → `DUPLICATE_ID_CONFLICT`（相同 ID 不同 payload 立即拒绝）；
3. `expected_config_generation = 0` 或载荷形状非法 → `INVALID`；
4. 已有 `PENDING`/`DELIVERED` 命令 → `BUSY`（每会话至多一个待决有副作用请求）；
5. Host 已从快照/回执得知当前 `config_generation` 且与 `expected_config_generation` 不一致 → `CONFLICT`（不能后写覆盖）；Host 尚无基线时允许登记，App 侧世代检查仍是权威防线（B 最小，§13.7）；
6. `COUNTERS_RESET` 未带 `destructive_confirmed` → `UNCONFIRMED`；Host 侧拒绝不替代 Web 的显式确认义务；
7. 消息超配额 → `QUOTA_EXCEEDED`；
8. 通过后登记为 `PENDING`。

### 9.3 交付与回执

- App 在其有序上下文调用 `control_next`：`PENDING` → `DELIVERED`（原子单命令交付，交付后即从待决移除）；无命令 → `NO_EVENT`；缓冲不足 → `BUFFER_TOO_SMALL`（不消费）。
- 回执（§7）使 `DELIVERED` → 终态 `APPLIED` / `REJECTED_*` / `FAILED_*` 并缓存。仅 `APPLIED` 使 Host 已知 `config_generation` 前进；`FAILED_STORAGE_UNKNOWN` 等不确定结果**不冒充 APPLIED**、不前进已知世代。
- Host 侧防御（B 最小，§13.8）：会话最近结果为存储不可知或最新快照带持久化故障时，Host 拒绝新的破坏性登记；App 侧义务（冻结）见 9.5。

### 9.4 幂等、去重、防重放

- 相同 `request_id` + 相同语义在当前会话内复用已知结果（`CACHED`），不重做数据变更；
- 相同 `request_id` + 不同语义立即 `DUPLICATE_ID_CONFLICT`；
- 会话世代隔离使跨会话重放不可能：旧世代命令在会话关闭时清除，新世代会话不匹配旧世代回执/快照；
- Host 重启清除待决命令及 RAM 快照；**未知结果需只读修订对账而非自动重放**（#54 冻结）。

### 9.5 App 事件边界事务（#54 §3 冻结；T1..T7）

| 步 | 状态/动作 | 失败路径 |
| --- | --- | --- |
| T1 | 管理员草稿：Web 不改变 App 活动配置 | — |
| T2 | Host 登记单一有界请求（§9.2），仅 `PENDING/ACCEPTED` | 各注册拒绝（旧配置/旧计数继续） |
| T3 | App 取到候选：完整校验字段、目标类/线/方向、`expected_config_generation`、资源预备；**必须在旧配置仍活动时完成可失败的准备**，不能先改 RAM、清零计数或发布新快照 | `REJECTED_STALE_CONFIG`/`REJECTED_INVALID`/`REJECTED_RESOURCE`；继续旧配置/旧计数 |
| T4 | App 进入**一个业务事件边界**：停止处理业务事件直到配置确定 | — |
| T5 | 对最新已确认累计/窗口/报告序号及完整新配置构造**同一个**新 App-owned blob，经现有 #46 `state_commit` CAS 可靠持久提交 | `REVISION_CONFLICT` → `FAILED_STATE_CONFLICT`；`IO_ERROR` → `FAILED_STORAGE_IO`；`STORAGE_UNKNOWN` → `FAILED_STORAGE_UNKNOWN` 且 App 进入受限态。任何失败：旧已确认数据不被覆盖/清零，不得回报已生效 |
| T6 | **已可靠提交后**才一次性切换准备好的新运行态与对应 `config_generation`，继续消费后继 AI 事件，发布带同世代的快照与最终 `APPLIED` 回执；旧世代已处理事件不重放，新世代不混入旧 tracker/方向；**正常变更不得为切换而结束当前 App 长会话** | — |
| T7 | Host 缓存 `APPLIED`；Web 可核对结果与新世代 | — |

业务影响（冻结）：仅改 `counter_name` 不清累计/窗口/报告序号；目标类切换是经管理员显式确认的重置计数动作，重置后 `report_seq` 不倒退、已提交历史报告和 Host 未送达报告队列不删除；配置方向/线、tracking 和窗口从明确事件/窗口边界切换；独立 `COUNTERS_RESET` 亦须明确确认并可靠提交，不因普通 Save/存储损坏默认触发。

### 9.6 不确定结果、存储未知、会话结束与对账（#54 §3.5 冻结）

- **已持久成功但回执丢失**：Host 可在相同当前会话内按快照/世代**只读对账**（比较活跃 `config_generation` 证据），对账不重放命令、不改 App 状态；
- **提交后无法确认切换**：对外 `PENDING/UNKNOWN`；App 必须阻止用不一致 RAM 继续"正常计数/后续破坏性 Save"（本规范模型化为：受限态 App 对后继有副作用命令一律回 `FAILED_STORAGE_UNKNOWN`，不动状态），在有可信状态基础上安全恢复；**此时不能同时承诺持久新值与旧配置永远有效**；
- **存储未知**（`state_commit` → `STORAGE_UNKNOWN`）：结果状态 `FAILED_STORAGE_UNKNOWN`；Web/Host 不得显示 APPLIED；
- **会话结束/失信/升级/Host 重启**：清除待决命令及 RAM 快照；`DELIVERED` 未回执即结束时对外为 `UNKNOWN`（可观察记录），新会话内经快照只读对账呈现证据；快照标 `unavailable`；
- **v2 → v3 同身份迁移**（#54 §2 冻结）：v2 → v3 同受信身份（SPKI SHA-256 + `publisher_id` + `app_id` 三元组不变）可从**已验证的 v2 blob** 恢复旧累计业务状态，并**安全初始化新 `config_generation`**（初值 1，B 最小，§13.6）；换公钥/发行者/`app_id` **不自动接管**旧状态。

### 9.7 失败矩阵（#54 §3.7 冻结清单的本规范映射）

无权限/无受信身份（`UNAUTHORIZED`）、旧 v1/v2 包（§10 拒绝）、停止/升级/失信（会话清除 + `unavailable`）、并发 Save（`BUSY`）、重复 ID 相同/不同 payload（`CACHED`/`DUPLICATE_ID_CONFLICT`）、错误 `config_generation`（`CONFLICT`/`REJECTED_STALE_CONFIG`）、目标类 invalid/模型变更（`REJECTED_INVALID`）、状态 CRC 损坏/`STORAGE_UNKNOWN`（`FAILED_STORAGE_UNKNOWN` + 受限态）、state CAS 冲突/断电中断（`FAILED_STATE_CONFLICT`，旧数据保留）、已提交但活动切换未确认（`UNKNOWN` + 只读对账）、Web 超时/断线（`PENDING` 保持，`stale` 快照标注）及 App 资源不足（`REJECTED_RESOURCE`）。旧的合法包、旧用户存储和管理口令不能因新失败受损。

## §10 新旧互操作与拒绝矩阵

| # | 包 | Host | 必须结果 |
| --- | --- | --- | --- |
| M1 | v3 黄金包（caps `0x000000FF`，2048/4096/6144/256/1024） | v3 Host | 结构/签名/策略全部通过；安装仍须 Host 逐项资源验证 |
| M2 | v3 任意包 | v2 Host | **拒绝**（未知容器 magic `…03 00 00` → `BAD_PACKAGE`）；不得尝试解析 192B manifest |
| M3 | v3 任意包 | v1 Host | **拒绝**（同上） |
| M4 | v2 黄金包（§12.5 重建） | v3 Host | v2 结构/签名/策略规则**完整照旧**；仅按旧语义提供 48B 表与 v2 十能力；**不得**授予 bit6/bit7 |
| M5 | v1 黄金 TBS 包 | v3 Host | v1 规则完整照旧；仅 16B 表（`log`/`tick_ms`）单次运行语义 |
| M6 | v3 容器但 `required_host_abi = 0x00020000` 或 manifest magic `NMF2` | v3 Host | **拒绝**（`BAD_PACKAGE`，v3 格式不变量） |
| M7 | v2 容器但 manifest magic `NMF3`（重签合法） | v2 Host | **拒绝**（`BAD_PACKAGE`） |
| M8 | v3 caps bit8..31 任一置位（重签合法） | v3 Host | **拒绝**（未知能力位） |
| M9 | `run_profile != 2`、[184..191] reserved 非零、能力-配额不匹配、原生头 ABI ≠ manifest ABI（重签合法） | v3 Host | **拒绝**（`BAD_PACKAGE`） |
| M10 | 签名合法、caps 全为已知位，但 Host 实际不提供其中某能力（如 v3 Host 不提供 bit7，或模拟仅 v2 能力面） | v3 Host | **拒绝**（`ABI_INCOMPATIBLE`；运行期该能力调用 `UNAUTHORIZED`/`INCOMPATIBLE`） |
| M11 | `control_max`/`snapshot_max` 超过 Host 实际容量，或 line-crossing-64 缺 bits2..7 任一/`event_max<1576`/`report_max<6144`/`control_max<184` | v3 Host | **拒绝**（`RESOURCE_LIMIT`/`BAD_PACKAGE`，§4.1） |

升级/卸载/换钥安装事务语义（`DOWNGRADE_FORBIDDEN`、`VERSION_CONTENT_CONFLICT`、`APP_IDENTITY_CONFLICT`、`STORAGE_STATE_UNKNOWN`、`BUSY` 等）全部继承 v1 §3/§4.1/§5.1，不重复、不放宽。

## §11 错误类别与拒绝语义

v1 §7 错误主分类**原样复用**（`AUTH_REQUIRED`、`FORBIDDEN`、`BAD_PACKAGE`、`SIGNATURE_INVALID`、`PUBLISHER_UNTRUSTED`、`TARGET_INCOMPATIBLE`、`ABI_INCOMPATIBLE`、`RESOURCE_LIMIT`、`STORAGE_FULL`、`STORAGE_STATE_UNKNOWN`、`COMMIT_FAILED`、`RUNTIME_UNAVAILABLE`、`BUSY`、`APP_IDENTITY_CONFLICT`、`DOWNGRADE_FORBIDDEN`、`VERSION_CONTENT_CONFLICT`）。v3 新判定按 §2.3 判定序映射：

| v3 判定 | 错误类别 |
| --- | --- |
| 容器 magic/长度/`manifest_len!=192`/manifest magic/保留字段非零/未知 profile/未知能力位/能力-配额不匹配/manifest 唯一编码破坏/DER 非法或尾随 | `BAD_PACKAGE` |
| NMF3 内 `required_host_abi != 0x00030000` / 原生头 ABI ≠ manifest ABI | `BAD_PACKAGE` |
| 包声明 ABI ≠ 当前 Host ABI；声明已知能力 Host 不提供 | `ABI_INCOMPATIBLE` |
| `publisher_id` 不在 Host 受信映射或指纹不一致 | `PUBLISHER_UNTRUSTED` |
| 原生头任一交叉检查失败（CRC/SHA/长度/entry/reserved0） | `BAD_PACKAGE` |
| 配额/资源不足（事件/报告/状态/控制/快照/装载/执行区） | `RESOURCE_LIMIT`（运行期 `QUOTA_EXCEEDED`） |
| 板型/PSRAM 不匹配 | `TARGET_INCOMPATIBLE` |
| 控制面 wire 违例（§6.4/§7.2/§8.3） | 运行期 `INVALID_ARGUMENT`/`BAD_SNAPSHOT` 判定（登记层 `INVALID`/`UNCONFIRMED`/`CONFLICT`/`DUPLICATE_ID_CONFLICT`/`BUSY`/`QUOTA_EXCEEDED`） |

多种故障同时成立时对外优先级继承 v1 §7.1.5：未授权不泄露信息、畸形长度不进入越界解析、无签名/无信任不进入执行、未提交不标记成功、不确定不冒充 APPLIED。

## §12 黄金向量与离线正负测试

全部向量由 `tests/spec-v3/` 一键独立生成与核对：

```bash
python3 tests/spec-v3/run_all_tests.py      # 或 sh tests/spec-v3/run_tests.sh
```

纯 Python 标准库实现 v3 结构/策略/控制面 wire/状态机与 P-256（验证 + RFC6979 确定性签名 + 严格 DER），**独立于** `cryptography` 库与 `package/` 的 v2 工具；另以 OpenSSL CLI 做独立验签交叉证明。签名密钥为**公开、不安全、非生产** P-256 测试标量 `d=1`（SPKI DER 91B，`SHA-256(SPKI) = 5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3`，与 v1/v2 黄金同钥）；**绝不能成为生产信任锚**。全部黄金向量逐字节确定性可复现（RFC6979）；证据（黄金包/TBS/DER/SPKI/命令/回执/快照字节与逐向量结果、全部 SHA-256）输出至 `docs/evidence/spec-v3/`。

### 12.1 v3 容器签名正向黄金向量（line-crossing 热配置声明）

合成 36B 原生镜像（32B `NEA1` 头：`format_version=1`、`abi_version=0x00030000`、`target_addr=0x93E00000`、`image_size=4`、`entry_offset=0`、`reserved0=0`、CRC32 `0xDE8E3439`；payload `00 20 70 47`；`SHA-256(native) = aa8c3ef6e4082656c76255807bee5a7c562ad212a0c3e2a4f009a62129cdee69`）：

| 可复核量 | 精确值 |
| --- | --- |
| 容器 magic / `manifest_len` / `image_len` | `4e45415050030000` / 192 / 36 |
| manifest magic / `required_host_abi` / `required_host_caps` | `NMF3` / `0x00030000` / `0x000000ff` |
| `run_profile` / `event_max` / `state_quota` / `report_max` | 2 / 2048 / 4096 / 6144 |
| `control_max` / `snapshot_max` / [184..191] | 256 / 1024 / 全零 |
| `publisher_id` / `app_id` / 版本 | `test-publisher` / `line-crossing` / `3.0.0` |
| TBS 长度 / `SHA-256(TBS)` | 244B / `d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e` |
| 固定严格 DER（70B，RFC6979 d=1） | `304402204646fc74c70bbbefcabc29afb8228bc121ad8b432104254d0b3f09819e9b6de50220251fd81c3f8976906785871c0016bad865f5e3c7f460b67b76e6fc1cce5bab50` |
| 黄金包长度 / `SHA-256(package)` | **314B** / `c74f7e468a9b63403bbaa8d36816bfd5250ffd68f66ebffc7d994440f1e22342` |
| 独立交叉证明 | 主机纯 Python 验签 PASS；OpenSSL `dgst -sha256 -verify` 返回 `Verified OK`（exit 0） |

该向量是**新的**合成 profile=2 签名正向输入，**不是设备/解析器 PASS**（§14）。

### 12.2 控制面黄金向量

| 向量 | 构成 | 长度 | `SHA-256` |
| --- | --- | --- | --- |
| `CONFIG_APPLY` 命令 | 会话世代 7、请求 ID 42、`expected_config_generation=6`、flags 0、152B 确定性载荷 `(i*7+3) mod 256` | 184B | `e6fafa1183d9fadd84ee17721994ce2f758b8b988970a7c5b8f5fb6d7ecec3ca` |
| `COUNTERS_RESET` 命令 | 会话世代 7、请求 ID 43、expected gen 7、`destructive_confirmed=1`、空载荷 | 32B | `5d0a37ef0587533cbb141da8ad08fadb43b0e88d4ed115bb52d1ab4aeb8f43fb` |
| `APPLIED` 回执 | 会话世代 7、请求 ID 42、`result_status=0`、新世代 7、`state_revision=5` | 32B | `054b7356b81fb555d6bdbc05f6d666cedb0d84a98555476a06cb32df09d87eed` |
| 业务快照 | `config_generation=7`、`state_revision=5`、参考 JSON（12.4） | 397B | `bf489b98ed512f066756d1cb25c8d3a536367d73ccf79718b84e34b3e96b4065` |

### 12.3 参考快照 JSON（App 自有 schema 示例；Host 不解释业务键）

```json
{"app_state":"running","config_generation":7,"counters":{"in":12,"out":9},"cumulative":{"in":3456,"out":2890},"gap":{"active":false,"last_reason":null},"model":{"class_generation":2,"generation":3,"loaded":true,"target_class":"car","valid":true},"quality":{"dropped_frames":2},"report_seq":88,"schema":"line-crossing/1","state_revision":5,"storage":{"fault":false}}
```

### 12.4 必须覆盖的负例族（tests/spec-v3 实现清单）

1. **已签内容篡改**：翻转真 payload 字节/manifest 配额字节（DER 逐字节不变）→ `SIGNATURE_INVALID`；翻转 DER 字节（TBS 不变）→ `SIGNATURE_INVALID`；OpenSSL 非零退出。
2. **DER/容器结构**：合法 DER 后追加字节、截断、整包截断 → `BAD_PACKAGE`。
3. **重签后策略拒绝**（证明"签名正确 ≠ 放行"）：bit8 置位、bit6 无 `control_max`、bit7 缺失而 `snapshot_max` 非零、[184..191] 非零、`run_profile=1`、profile 2 缺 bit5/bit6、line-crossing 缺位、`event_max<1576`、`report_max<6144`、`control_max<184`/超 Host、`snapshot_max` 超 Host、配额-能力不匹配、[58..59] 非零、错板、指纹不一致、未知发行者、NMF3 内 ABI `0x00020000`、原生头 ABI 交叉不匹配、原生头 `reserved0 != 0`、v3 新能力位遇仅 v2 能力面 Host——均以 d=1 重签为合法签名后仍拒绝，且拒绝原因可归因。
4. **命令 wire 负例**：坏 magic、`header_version=2`、未知 type、`total_len` 不一致、会话世代 0、请求 ID 0、期望世代 0、命令 `state_revision` 非零、未知 flags 位、`CONFIG_APPLY` 空载荷、`COUNTERS_RESET` 带载荷、回执类型冒充命令。
5. **回执 wire 负例**：未知 `result_status`、APPLIED 带零世代、回执带载荷、世代/请求 ID 为 0。
6. **快照 wire 负例**：重复 JSON 键、非法 UTF-8、JSON 尾随数据、顶层数组、`NaN` 常量、App 自填会话世代/请求 ID（必须为 0）、世代 0、超 `snapshot_max` → `QUOTA_EXCEEDED`。
7. **状态机/事务**：无会话/无能力调用拒绝；`NO_EVENT`；`BUFFER_TOO_SMALL` 不消费；第二待决 `BUSY`；陈旧世代 `CONFLICT`；无基线可登记（App 侧权威拒绝 `REJECTED_STALE_CONFIG`）；`COUNTERS_RESET` 未确认拒绝；超配额登记拒绝；去重同语义 `CACHED`/异语义 `DUPLICATE_ID_CONFLICT`；交付后回执错误 ID 拒绝；`APPLIED` 前进已知世代、失败结果不冒充；会话结束产生 UNKNOWN、快照 `unavailable`、只读对账不重放；5s/10s 快照新鲜度；CAS 冲突/IO 错误/存储不可知不覆盖旧已确认数据；受限态阻止破坏性命令；`COUNTERS_RESET` 保持世代、推进版本、清零计数、保留 `report_seq`；v2→v3 同身份迁移/跨身份拒绝；会话世代禁回绕。
8. **互操作拒绝矩阵**：§10 M1–M11（v1/v2 黄金以文档钉定 TBS 哈希重建：v1 `5035e6512c0c003490b228b9ae0dc6351166a04b0dc96a3ff053bb7fe348fe91`（212B）、v2 `e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278`（244B）；v2 包另钉 §12.5 DER/整包哈希）。
9. **ABI 表**：60B 布局、13 回调名与偏移、`table_size`/`abi_version` 负例、48B 前缀拒绝、空指针拒绝、`control_next` `NO_EVENT=1`。

### 12.5 v2 黄金重建锚（用于 M4 互操作证明；数值引自 v2 规范 §10.1）

v2 黄金 TBS 244B 逐字节重建并以钉定哈希验证；DER 固定 70B `3044022011e9d2635e2036fb0bcbd1107a5e6d272c150473a8c1e029887604f9aa75473702205b6ca9206755a161913fcf9cdf57c789b363420bc16a74438bc439aeb80d11b0`；整包 314B `SHA-256 = 3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e`。v1 黄金仅以 TBS 哈希锚定（§12.4.8；v1 存档 DER 为随机 k 签名，本套件以 RFC6979 确定性重签重建合法包，`SHA-256(TBS)` 逐字节一致即证明重建正确）。

## §13 B 最小编码选择清单（#54 未冻结而由本文最小化；A 评审可改，不得借改扩权）

| # | 选择 | 本文锚点 |
| --- | --- | --- |
| 1 | 控制面统一 32B 定长消息头，`msg_type` 区分命令/回执/快照并复用槽位语义；协议标识 `NFC3` + `header_version=1` | §6.3 |
| 2 | 回执 `result_status` 8 值枚举置于头尾槽（命令 flags 槽复用）；枚举命名与分组 | §7.2 |
| 3 | 快照载荷为严格 UTF-8 单 JSON 对象（重复键/`NaN`/尾随数据 fail-closed）；App 自有 schema | §8.3 |
| 4 | 会话世代为 Host boot 作用域自 1 起非零单调 u32，禁回绕 | §9.1 |
| 5 | Host 快照可见版本为每会话自 1 起单调 u32 | §8.2 |
| 6 | `config_generation` 初值 1（含 v2→v3 迁移初始化），每次确认变更恰 +1，禁 0 | §9.1/§9.6 |
| 7 | Host 无世代基线时允许登记命令（App 侧世代检查为权威防线） | §9.2.5 |
| 8 | Host 侧在最近结果存储不可知/快照带故障时拒绝新破坏性登记（App 侧义务的纵深防御，非语义放宽） | §9.3 |
| 9 | Host 登记 `COUNTERS_RESET` 未确认标志即拒绝（`UNCONFIRMED`），不替代 Web 显式确认义务 | §9.2.6 |
| 10 | `control_max`/`snapshot_max` 声明与 Host 模拟容量参考值（256/1024B；Host 实际值归 #55/#56 设备事实） | §3.2/§4.1 |
| 11 | line-crossing-64 的 `control_max >= 184` 下界（32B 头 + 152B 冻结 blob 推导） | §4.1 |
| 12 | 首个有效回执定终态；后续同 ID 回执不改缓存结果 | §7.1 |
| 13 | 快照 `total_len > min(声明, Host RAM)` 整体 `QUOTA_EXCEEDED`，不截断 | §3.2/§8 |

## §14 没有 PASS 的边界（如实标注；AC4）

以下能力在本 Issue 与本规范文件中**均无 PASS**，任何引用本文的文档不得将其写成已证明：

1. **真实 Host 编译**：无任何 STM32 目标上的 v3 ABI 头静态断言编译、无 v3 表/回调目标构建、无设备端 v3 parser 已实现并通过本文向量。
2. **资源与设备写入**：`event_max=2048`/`report_max=6144`/`state_quota=4096`/`control_max=256`/`snapshot_max=1024` 只是签名请求上界与模拟策略值；设备真实可提供的事件缓冲、报告槽、状态配额、**控制命令容量与快照 RAM**、5s/10s 快照调度的可承载性均未在真实设备验证；本 Issue 无任何真实设备写入。
3. **Line Crossing Web**：热配置 Web 编辑/草稿/保存闭环（#57）未实现、未验证；#46 CAS blob、#44 报告服务与 #36 鉴权基线的 v3 集成未验证。
4. **设备 PKA 验签 / 掉电事务 / 持续 AI 会话**：v2 规范 §12 的同款缺口对 v3 全部适用（mbedTLS/PKA 设备验签、原子提交掉电实测、64 框持续会话下 Host 不阻断 AI 主回调地完成命令交付与快照拷贝）。
5. **本规范的"规范已集成"状态**：须经后续 exact-SHA A Review、merge 与 canonical ght complete 之后方可声明；本文当前仅为受审候选。产物哈希证据以测试输出为准（§12）；不存在"真机 PASS"表述。

## 附录 A：#54 冻结决定 → 本文覆盖对照

| #54 冻结决定 | 本文章节 |
| --- | --- |
| v3 = 新容器 major 3 + 新 ABI major `0x00030000`，不改 v1/v2，旧 Host 拒 v3、v3 Host 收旧包、禁前缀偷兼容 | §1.1、§5.1、§10 |
| 复用 SHA-256(TBS)/ECDSA P-256/严格 DER/SPKI 映射/原生头交叉检查与校验顺序；签名域隔离 | §2.2、§2.3、§3.3 |
| 16B 外层头 magic `4E 45 41 50 50 03 00 00`、192B manifest、`NMF3`、`required_host_abi=0x00030000`、原生 `NEA1` 32B 交叉校验 `abi_version=0x00030000` | §2.1、§3.1、§3.3 |
| manifest 160..175 沿用 v2 字段与配额位置；`run_profile=2` 专用语义；旧 profile 不被误解释 | §3.2 |
| caps bit0..5 原语义不变；bit6=`control_receive`、bit7=`business_snapshot`；bit8..31 未知拒绝 | §4.1 |
| [176..179]=`control_max`、[180..183]=`snapshot_max`（含头含载荷、不截断）、[184..191] 全零、quota 随位声明且 ≤ 实际容量 | §3.2、§4.1 |
| 热配置 Line Crossing 要求 bits2/3/4/5/6/7；旧容量边界继承 v2；声明 ≠ Host 提供 | §4.1、§4.2 |
| 60B 表（`table_size=60`、`abi_version=0x00030000`）、偏移 8..44 沿用 v2 十能力、48/52/56 三新回调 `int32_t`、Thumb/静态断言/无裸指针、表禁前缀互换、缺失已请求能力拒绝、仅当前受信会话+声明能力可调用 | §5 |
| `control_next` 无命令合法 `NO_EVENT=1`（对 v2 §6.4 的显式限定扩展） | §5.3、§12.4.9 |
| 传输模型：服务端鉴权、单会话单待决命令、App 自身上下文非阻塞取命令、禁伪装 AI 事件、`control_reply` 仅缓存匹配回执 | §6.1、§6.3、§7.1 |
| 命令仅 `CONFIG_APPLY`/`COUNTERS_RESET`；读取走快照投影；Host 不解 152B 私有 blob、不重解释 AI 事件 | §6.2 |
| wire 必备字段（协议标识/版本/类型/长度/保留/会话世代/请求 ID/期望世代/破坏性确认/载荷/结果状态/新世代/`state_revision`）；快照不由 App 自填会话世代；规范有界编码 fail-closed；超 quota 整体拒绝 | §6.3、§6.4、§7、§8 |
| `config_generation` 与 `state_revision` 分离；统计 flush 不失效 Web 草稿；普通 RESET 不算配置编辑 | §9.1、§9.5 |
| 会话内幂等/冲突/防重放；会话关闭/失信/升级/重启清除待决与 RAM 快照；未知结果只读对账不自动重放 | §9.2–§9.4、§9.6 |
| 快照契约内容、Host 有界 RAM 复制 + #44 健康附加、5s/10s/stale/unavailable、设备不满足交 A 复审 | §8 |
| 事务 T1..T7（准备/可靠提交/原子切换/回执）、失败不覆盖旧数据、不冒充 APPLIED、业务影响规则、失败矩阵 | §9.5–§9.7 |
| v2→v3 同身份迁移恢复旧累计、安全初始化新世代；换钥/发行者/app_id 不自动接管 | §9.6 |
| B 不改 A 语义、不实施 Host/App/Web；新事实证明不可行返回 A，不私改 ABI | §13、§14 |
