# NE301 × ne30x-app — 持续业务可信 App 包及 Host ABI v2 规范（受审候选草案）

> **文件地位**：本文是 Issue #12 按 [A v2 跨仓库定稿输入（2026-10-10，issuecomment-6092256674）](https://github.com/harryhua-ai/ne30x-app/issues/12#issuecomment-6092256674) 整理的**受审候选草案**。A 的该评论是本文唯一的规范设计输入；本文仅把已定字节/语义整理为单一、版本化、可独立验证的正式规范，供后续 exact-SHA 审查。**未经正式 Candidate 审查并集成至 `ne30x-app/main` 前，本文不是任何 P3/P4/P6 的实施许可；集成后也不是设备 PASS 或生产发布授权。**
>
> **v1 不变基准**：已集成的 [app-package-protocol-v1.md](app-package-protocol-v1.md) 是 v1 的唯一已集成规范。v1 的签名字节、TBS、严格 DER 规则、未知能力位拒绝、未知容器版本拒绝与 hello-app 单次运行语义**全部保持不变**；本文不借 v1 保留字节或未声明特性扩权。v1 ABI `0x00010000` 的 16B 函数表（仅 `log`/`tick_ms`）**逐字节不变**。
>
> **固定证据锚点**（真实编译器/资源/型号事实，本文所有容量与 ABI 数字与之对齐）：
> - [NE301 v1 ABI 头 app_host_abi.h](https://github.com/harryhua-ai/ne301/blob/a5b4bf3dd25931d612680aff200e4e0ac8d8e64e/Custom/Common/Inc/app_host_abi.h)（内容 blob `9c13b87d8edec34a54befb2a9bbc9f38f89e4dd1`，SHA-256 `9337f684893cf2a06aea6f6f8c448708d91e8f9c6c86c24905ced8a7d5df23f4`）：`APP_HOST_ABI_VERSION 0x00010000`、16B `app_host_api_table_t`（`table_size`/`abi_version`/`log`/`tick_ms`）、32B `app_host_image_header_t`（magic `NEA1`、`header_size=32`、`format_version=1`、Thumb 入口）。
> - [line_counting.h @ne301 counting de25a6f1](https://github.com/harryhua-ai/ne301/blob/de25a6f1f431a631a37ff1cda87f616e293e8836/Custom/Tasks/Inc/line_counting.h)：`LC_FRAME_MAX_DETECTIONS = 64`；`lc_det_t` 为 5 个 `float`（x/y/w/h/conf）加 `const char *class_name` 指针；`LC_TARGET_CLASS_NAME_LEN = 32`（含终止符，见 `Custom/Core/System/line_counting_config.h`）。
> - [pp.h @de25a6f1](https://github.com/harryhua-ai/ne301/blob/de25a6f1f431a631a37ff1cda87f616e293e8836/Custom/Common/Lib/pp/pp.h)：`od_detect_t` 仅含 5 个 `float` 与 `char *class_name` 指针，**不存在可直接跨 ABI 复制的稳定 class index**；`PP_TYPE_OD = 1`。
> - [lc_delivery_queue.h @de25a6f1](https://github.com/harryhua-ai/ne301/blob/de25a6f1f431a631a37ff1cda87f616e293e8836/Custom/Tasks/Inc/lc_delivery_queue.h)：`LC_DQ_SLOT_CAPACITY = 6144`（历史报告槽容量 6144B）。
>
> **测试与黄金向量**：本文 §10 的全部正负向量由 [tests/spec-v2/](../tests/spec-v2/README.md) 一键独立生成与核对，证据输出到 `docs/evidence/spec-v2/`。本文不实现设备 Host、签名打包器或 Line Crossing App；不修改、不扩张 P3 #6 的现行 v1 交付。

## 目录

- §1 总则与版本化原则
- §2 受签名 v2 容器
- §3 v2 manifest（192B 定长）
- §4 能力位语义与"包声明 vs Host 逐项验证"边界
- §5 AI 事件 wire（固件私有结构隔离）
- §6 Host ABI v2 调用面
- §7 会话生命周期、安全注销、更新/卸载/重启与数据归属
- §8 新旧互操作与兼容矩阵
- §9 错误类别与拒绝语义
- §10 黄金向量与离线正负测试
- §11 与 P3 #6 及其它任务的边界
- §12 没有 PASS 的边界（如实标注）
- 附录 A：A 定稿输入 → 本文覆盖对照

## §1 总则与版本化原则

1. **独立 major，域隔离**。v2 采用**严格独立的签名容器 major 与 Host ABI major**：容器 magic、manifest magic、`required_host_abi`、原生镜像头 `abi_version` 与函数表全部独立编号，绝不复用 v1 reserved/未知 bit 扩权。任何一方都不得把 v2 的较长表或 manifest 当作 v1 的"向后兼容延伸"来解释旧包。
2. **单一信任根不变**。v2 复用 v1 §2.1/§4.1 的单钥发布者信任：SHA-256 + ECDSA over secp256r1（P-256）+ 严格 DER + Host 内置 SPKI 公钥；包自带公钥/指纹不得自授信；无在线撤销、双钥过渡或自动迁移（v1 §4.1 全文适用）。
3. **fail-closed**。未知容器版本、未知 manifest magic、未知 profile、未知能力位、未知事件 kind/flags、非零保留字段、未知 ABI 全部拒绝；不支持的能力返回 `UNAUTHORIZED`/`INCOMPATIBLE`；任何失败不得被解释为部分成功或降级运行。
4. **单一权威与互操作**。本文是 v2 包字节、签名原文、能力、事件 wire、ABI 调用面与会话语义的唯一权威文档。打包端（未来工具）与设备端允许不同实现做互操作验证，但不得各自定义不同容器、wire 或签名算法；不得以复制同一解析器的测试代替独立正确性证明。
5. **扩展须新版本**。manifest 保留字段、能力 bit6..31、事件 flags bit2..31、reserved 字段、ABI 表超界偏移一律拒绝；未来扩展必须以新容器 major/ABI major/新 profile 经 A 受审修订，不得原版本内偷扩。

## §2 受签名 v2 容器

### 2.1 布局

| 字节位置（从 0 起） | 编码 |
| --- | --- |
| `0..7` | 固定 8 字节 magic：`4E 45 41 50 50 02 00 00`（ASCII `NEAPP`、容器主版本 2、两个零保留字节；HEX `4e45415050020000`） |
| `8..11` | `manifest_len`：`u32-le`，**必须恰好为 192**（其它任何值拒绝） |
| `12..15` | `image_len`：`u32-le`，完整原生文件长度（32B 原生头 + payload），必须至少容纳 32B 原生镜像头 |
| `16..207` | 原样 192B manifest（§3） |
| `208..(208+image_len-1)` | 原样原生 App 镜像 `image_len` 字节，含未修改的 32B Host 原生镜像头及其 payload |
| 文件最后剩余字节 | **恰好一个**严格 DER `ECDSA-Sig-Value`；无签名长度字段、无额外尾部、无第二签名或证书链 |

### 2.2 签名原文与身份

- **唯一签名原文**：`TBS = 文件从偏移 0 开始，连续取 16 + 192 + image_len 字节`。
- 签名与**幂等内容身份**均使用 `SHA-256(TBS)`：对 `SHA-256(TBS)` 用发行方 ECDSA P-256 私钥签名；相同 `SHA-256(TBS)` 视为相同内容（不同但均合法的 DER 不构成版本冲突，v1 §2.2/§7.1 幂等语义全文适用）。
- **DER 必须完整消费其尾部**：签名 DER 之外的任何附加字节拒绝；DER 编码规则完整继承 v1 §2.1/§2.2——严格、规范 DER，两个正整数 `r,s` 位于 `1 <= r,s < n`，拒绝 BER 非最短编码、负值、零值、越界、截断、附加字节、多重 ASN.1 对象；不要求 low-S 归一化。
- 签名算法唯一钉定（SHA-256/ECDSA P-256/DER/SPKI），无算法协商或降级；未知容器版本直接拒绝。

### 2.3 容量与校验顺序

- 长度加法须溢出安全；按固定上限限制整包长度。`native_file_len` 必须 `<= 真实 Host 装载区`（当前证据基线为实验 Host 的 2 MiB 执行区，同 v1 §2.3/§2.5），**不能拿 payload 驻留量（`required_exec_region_bytes`）冒充临时装载量**；v1 §2.3 的"驻留量与装载量分别验证"规则全文适用于 v2。DER 长度合法区间 8–72B；候选整包上限 `16 + 192 + native_file_len + DER_len <= 2,097,432` 字节（设备以实际 `region_size` 复核，实测不能支持时由 A 修订上限，不得由实现自行扩容）。
- **校验顺序继承 v1 §7.1 判定序**：①管理入口授权 → ②有界结构解析（magic、两个长度、192B manifest 唯一编码、DER 结构与尾段完整消费）→ ③可信发行者（Host 本地唯一 SPKI 映射）→ ④对原样 TBS 的密码学验签 → ⑤策略校验（原生头/摘要/CRC/板型/ABI/能力/配额/资源/版本/安装状态）。任一步失败不得创建可执行安装记录、不得启动；结构失败属 `BAD_PACKAGE`，不可信发行者属 `PUBLISHER_UNTRUSTED`，验签失败属 `SIGNATURE_INVALID`，策略失败按 §9 分类。
- v1 §2.3 标识符字符集与右零填充规则、`publisher_key_sha256` 与设备独立保存的 `publisher_id → SHA-256(SPKI DER)` 映射核对规则，在 v2 manifest 中**同位置同语义**适用。

## §3 v2 manifest（192B 定长）

无符号整数一律小端；非空保留字段不得忽略；manifest 必须唯一编码（禁止重复字段、多义排序、非规范整数/字符串）。

### 3.1 前 160B：严格复用 v1 同位置编码

manifest `[0..159]` 的位置、宽度、编码与签名交叉检查**严格复用 v1 §2.3 已集成规范**，仅以下三处按 v2 定义取值：

| 偏移 / 长度 | 字段 | v2 取值与约束 |
| --- | --- | --- |
| `0..3` / 4B | `manifest_magic` | ASCII `NMF2`（`4E 4D 46 32`），否则拒绝 |
| `58..59` / 2B | `reserved` | **仍必须全零**（v1 同位置不变量） |
| `68..71` / 4B | `required_host_abi` | `u32-le`，**必须为 `0x00020000`**（其它值拒绝为 v2 格式违例，见 §9） |
| `72..75` / 4B | `required_host_caps` | `u32-le` v2 能力位掩码（§4） |

其余字段（`publisher_id[4..19]`、`app_id[20..51]`、`version_major/minor/patch[52..57]`、`target_board_id[60..63]`、`required_psram_mib[64..67]`、`required_exec_region_bytes[76..79]`、`native_file_len[80..83]`、`native_image_size[84..87]`、`native_entry_offset[88..91]`、`native_target_addr[92..95]`、`native_file_sha256[96..127]`、`publisher_key_sha256[128..159]`）保持 v1 §2.3 的逐项约束、交叉检查与拒绝条件，本文不重述、不放宽。`target_board_id`/PSRAM 的型号映射证据边界（v1 §2.4）同样适用于 v2。

### 3.2 [160..191]：v2 扩展字段

| 偏移 / 长度 | 字段 | 编码与约束 |
| --- | --- | --- |
| `160..163` / 4B | `run_profile` | `u32-le`，本版**唯一合法值 1**＝管理员显式单受信 App 长会话；其它值拒绝 |
| `164..167` / 4B | `event_max` | `u32-le`，AI 事件单条最大字节数上界声明；声明 `ai_events` 时必须非零且满足 §4 约束 |
| `168..171` / 4B | `state_quota` | `u32-le`，App 状态 blob 配额声明（字节）；声明 `app_state` 时必须非零 |
| `172..175` / 4B | `report_max` | `u32-le`，单条业务报告最大字节数上界声明；声明 `report_submit` 时必须非零 |
| `176..191` / 16B | reserved | **必须全零**；任何非零拒绝 |

不识别任何其它 profile、未知扩展字段或非零 reserved；未来扩展须新版本（§1.5）。

### 3.3 原生镜像交叉检查（继承 v1 并钉定 ABI）

原生文件仍是 `NEA1`（`0x3141454E`，字节序 `4E 45 41 31`）、32B 头、`format_version = 1`、`abi_version = 0x00020000`、头偏移 `24..27` 的 `reserved0` 全零；原生头各字段、`SHA-256`（对含头的整个原生文件）、CRC32（v1 同一反射 IEEE CRC32）与所有长度/目标地址/执行区字段**按 v1 §2.3 严格交叉检查**：`native_file_len = 32 + native_image_size = 外层 image_len`，`native_entry_offset` 满足 Thumb 约束（`entry_offset < native_image_size` 且为偶数/半字对齐；作为入口函数指针传递时按 Host loader 语义置 Thumb bit0），`native_target_addr` 等于原生头 `target_addr` 且在当前 loader 受控执行区内。manifest `required_host_abi` 必须等于原生头 `abi_version`。现有 `app_host_validate` 的宽松行为（`header_size >= 32`、不查尾部、不查 `reserved0`）不可替代签名准入层更严格的 v1/v2 检查（v1 §2.3 原则不变）。

## §4 能力位语义与"包声明 vs Host 逐项验证"边界

### 4.1 能力位定义（`required_host_caps`，`u32-le`）

| bit | 能力 | 含义 |
| --- | --- | --- |
| 0 | `log` | v1 同名 `log` 函数（语义同 v1） |
| 1 | `tick_ms` | v1 同名 `tick_ms` 函数（语义同 v1） |
| 2 | `ai_events` | §5 AI 事件 wire / `event_next`（须经 `event_max` 配额约束） |
| 3 | `report_submit` | `report_submit`/`report_status`（须经 `report_max` 配额约束） |
| 4 | `app_state` | `state_read`/`state_commit`（须经 `state_quota` 配额约束） |
| 5 | `session_lifecycle` | §7 受控会话生命周期（`should_stop`、会话授权、安全注销） |
| 6..31 | — | **任何一位为 1 均拒绝**（未知能力） |

约束：

- **bit6..31 任一为 1 → 拒绝**（`BAD_PACKAGE` 策略项；即使重签合法也不放行）。
- **`run_profile = 1` 必须包含 bit5**；无 bit5 的 profile 1 声明为格式违例。
- **bit2/3/4 必须与非零配额相匹配**：bit2 ⇒ `event_max > 0`；bit3 ⇒ `report_max > 0`；bit4 ⇒ `state_quota > 0`。未声明对应能力位而配额非零同样拒绝（不允许"悄悄预留"）。
- **64 检测框业务约束**：对当前 Line Crossing 业务（`LC_FRAME_MAX_DETECTIONS = 64`），凡声明 `ai_events`，`event_max` 必须至少 **1576B**（= 40B 事件头 + 64×24B 记录）。任何 Host 若实际只能提供更小事件缓冲而无法满足声明，明确判**不兼容**（`INCOMPATIBLE`/`RESOURCE_LIMIT`），**不得部分成功**。
- **报告容量约束**：声明 `report_submit` 的 Host 必须能接受长度 **≤ 6144B** 的合法 `schema_version=1, type=line_counting` 报文（对齐 `LC_DQ_SLOT_CAPACITY = 6144`）；超过声明 `report_max` 或超过实际 Host 配额的报文**显式拒绝**（`QUOTA_EXCEEDED`），**不截断 JSON/轨迹/热度数据**。不要求报告无界；Host 真正可支持的上限必须经设备实现另行验证。
- **状态配额**：状态 blob 不得超过声明 `state_quota` 与真实配额（当前示例 4096B）二者。

### 4.2 包声明 ≠ Host 授权

**manifest 能力位只表示签名请求的上界与需求，实际安装/启动还必须由 Host 按当前板型、ABI、信任、存储、可用容量逐项验证**：

- 没有声明的能力/函数不能被调用；Host 不得因"表更长"或 v1 函数表长度猜测而升级可用面。
- **反向同样 fail-closed**：包声明了**已知**能力位、但当前 Host **实际不提供**该能力时，安装/启动必须整体拒绝（映射 `ABI_INCOMPATIBLE`，见 §9；运行期对该能力的调用按 §6.4 返回 `UNAUTHORIZED`/`INCOMPATIBLE`）。"全部位都在已知集合内"不等于"当前 Host 都支持"。
- 声明了的能力也只在受信身份、允许版本与对应会话授权均成立时可用（§7）。
- 当前 Line Crossing 兼容 profile 的能力全集示例 `caps=0x0000003f`、`event_max=2048`、`state_quota=4096`、`report_max=6144` 只是**签名请求的上界**，并不凭空创造实际 Host 资源；Host 逐项验证不满足时按 §9 拒绝。

## §5 AI 事件 wire（与固件私有结构隔离的可跨仓库定义）

本节是**跨仓库固定的事件 wire 定义**：32 位小端；记录中的浮点值按 IEEE-754 binary32 的原始 `u32-le` 位编码；**绝不传 `nn_result_t*` 或 `od_detect_t.class_name` 指针**；事件及 class metadata 由 Host 在调用期间拷贝出**有界数据**。

### 5.1 事件头（恰好 40B = 10 × u32-le）

| 序 | 字段 | 约束 |
| --- | --- | --- |
| 0 | `total_len` | 本事件总字节数；FRAME：`40 + 24 × detection_count`；其它 kind：`40` |
| 1 | `kind` | `1=FRAME`、`2=MODEL_CHANGED`、`3=GAP`、`4=STOPPING`；未知 kind 拒绝 |
| 2 | `sequence` | 会话内 `u32` 序号，溢出按模 2³² 顺序解释；**不跨重启作持久全局序号** |
| 3 | `monotonic_ms` | 会话内 `u32` 单调毫秒，同上回绕语义 |
| 4 | `model_generation` | 当前模型代次；代次变化后 App 必须重新查询 metadata（§6.5） |
| 5 | `class_generation` | 当前类别表代次；同上 |
| 6 | `flags` | 见 5.3；未定义位非零拒绝 |
| 7 | `detection_count` | FRAME：`0..64`；其它 kind 必须为 0 |
| 8 | `lost_frame_count` | 自前次成功交付以来丢失帧数；`flags.bit1=1` 时必须为 `0xFFFFFFFF` |
| 9 | `reserved0` | 必须为 0 |

单事件最大 **40 + 64 × 24 = 1576B**。

### 5.2 检测记录（恰好 24B = 6 × u32-le）

`x_bits`、`y_bits`、`width_bits`、`height_bits`、`confidence_bits`、`class_index` 各 `u32-le`。

- 前 5 项必须是**有限** IEEE-754 binary32（NaN/Inf 拒绝），保留现行 NE301 `od_detect_t`/`lc_det_t` 的坐标/置信度**数值与语义，不静默更改单位**。
- `class_index` 是**在当前代次元数据中查询到的类别序号**，必须 `< model_meta.class_count`。原始 `pp.h` 只有 `class_name` 指针、**不存在可直接跨 ABI 复制的稳定 index**，因此 **Host 必须把类名字节与当前有效类别表做唯一且完整匹配**；无映射、重名或编码不兼容时，Host 把当前模型判为**不可兼容**（`INCOMPATIBLE`）或投递**可见的 GAP**——**绝不能编造索引、静默丢检测然后声称帧完整**。

### 5.3 flags 与间断语义

- `flags bit0`：自前次成功交付以来存在已知或疑似丢帧。
- `flags bit1`：丢失数量未知；此时 `lost_frame_count = 0xFFFFFFFF`，**不能填 0**。
- `flags bit2..31`：必须为 0，否则拒绝。
- Host 在溢出、慢消费者、模型切换后必须通过 `GAP` 事件或带 gap flag（bit0/bit1）的下一事件报告间断。
- **可观察语义区分**：正常 `FRAME(detection_count=0)`、`NO_EVENT`（`event_next` 返回 `NO_EVENT`，无事件投递）、`MODEL_CHANGED`、`STOPPING` 四者必须有不同可观察语义，不得混同。
- **超过 64 框或帧无法完整编码时**：拒绝并把该间断以 GAP/gap flag 标记，**不截断为"完整帧"**。

### 5.4 类别标签边界

业务 `target_class_name` 上限为 **32B 含终止符**（对齐 `LC_TARGET_CLASS_NAME_LEN = 32`）；对过长、不唯一或不可匹配的标签，**不能静默截断为看似合法的业务类别**——必须显式拒绝或进入不可兼容/GAP 路径。

## §6 Host ABI v2 调用面

### 6.1 ABI 版本与入口

- ABI `0x00020000`。单次入口仍为 `int32_t app_entry(const api_table *, uint32_t abi_version)`，但**使用独立 v2 类型**。
- **v1 ABI `0x00010000` 的 `app_host_api_table_t`（16B，仅 log/tick）完全不变**；v2 Host 对 v1 包仍按 v1 §2/§6 语义提供 16B 表与单次运行。
- **不得以本表的较长前缀"兼容解释"v1 表**，反之亦然；表长/ABI 不匹配即拒绝（`ABI_INCOMPATIBLE`）。

### 6.2 v2 函数表（恰好 48B）

头两个 `u32-le` 为 `table_size = 48`、`abi_version = 0x00020000`；随后固定 10 个 **32-bit Thumb 函数指针**：

| 表偏移 | 函数 |
| --- | --- |
| 8 | `log` |
| 12 | `tick_ms` |
| 16 | `event_next` |
| 20 | `model_meta` |
| 24 | `class_name` |
| 28 | `report_submit` |
| 32 | `report_status` |
| 36 | `state_read` |
| 40 | `state_commit` |
| 44 | `should_stop` |

**跨 ABI 结构规则**：一律仅允许固定宽度整数、byte array、由整数传输的 float bits；`sizeof(void*) = 4`、函数指针宽度 = 4、正确对齐必须作为**目标编译的静态断言**（`_Static_assert`），缺失则拒绝该 ABI 实现。

### 6.3 函数签名（本版钉定；全部返回 `int32_t`，不使用浮点参数、C++ ABI、私有 RTOS 类型或跨调用保留的 App 指针）

```c
int32_t log(const char *text);
int32_t tick_ms(void);
int32_t event_next(void *out, uint32_t cap, uint32_t *actual_len, uint32_t max_wait_ms);
int32_t model_meta(void *out, uint32_t cap, uint32_t *actual_len);
int32_t class_name(uint32_t model_gen, uint32_t class_gen, uint32_t class_index,
                   void *out_utf8, uint32_t cap, uint32_t *actual_len);
int32_t report_submit(const void *json, uint32_t len, uint32_t app_report_seq,
                      uint32_t *out_host_boot_id);
int32_t report_status(uint32_t host_boot_id, uint32_t report_seq,
                      uint32_t *out_mqtt_state, uint32_t *out_webhook_state);
int32_t state_read(void *out, uint32_t cap, uint32_t *actual_len,
                   uint32_t *out_revision);
int32_t state_commit(const void *blob, uint32_t len, uint32_t expected_revision,
                     uint32_t *new_revision);
int32_t should_stop(void);
```

### 6.4 返回码（固定枚举）

| 值 | 名称 | 适用 |
| --- | --- | --- |
| 0 | `OK` | 全部 |
| 1 | `NO_EVENT` | **仅 `event_next`** |
| 2 | `NOT_FOUND` | **仅状态/报告查询不存在**（`state_read`、`report_status`） |
| -1 | `INVALID_ARGUMENT` | 全部 |
| -2 | `BUFFER_TOO_SMALL` | 带 out 缓冲的调用 |
| -3 | `UNAUTHORIZED` | 能力/会话未授权 |
| -4 | `INCOMPATIBLE` | 模型/元数据/编码不可兼容 |
| -5 | `QUOTA_EXCEEDED` | 超过声明或实际配额 |
| -6 | `STORAGE_UNKNOWN` | 状态存储不可判定 |
| -7 | `BUSY` | 无法安全回收/资源忙 |
| -8 | `REVISION_CONFLICT` | `state_commit` 版本冲突 |
| -9 | `IO_ERROR` | 持久化 IO 失败 |
| -10 | `STOPPING` | 会话正在结束 |

不支持的调用/能力必须返回 `UNAUTHORIZED` 或 `INCOMPATIBLE`；**不能让失败作为运行成功继续**。

### 6.5 模型与类别元数据

- `model_meta` 输出固定 **128B**：前 6 个 `u32-le` 依次 `loaded`、`result_type`（本业务仅支持 `1 = PP_TYPE_OD`）、`model_generation`、`class_generation`、`class_count`、`reserved0 = 0`；随后 64B `model_name`、32B `model_version`，均为严格 NUL 终止/右零填充的 UTF-8 字节串；末尾 8B reserved 全零。无法规范表示的 metadata 必须返回 `INCOMPATIBLE`，**不得截断**。
- `class_name` 查询**必须绑定传入的 `(model_gen, class_gen)` 两种代次**与 `class_index`；返回 UTF-8 **实际长度（不含终止 NUL）**，要求缓冲可容纳数据 + 1B NUL（否则 `BUFFER_TOO_SMALL`）；代次过期拒绝；**绝不以动态指针裸传类别表**。

### 6.6 报告提交与状态观察

- `report_submit` 在 Host **确认 JSON/schema/大小/会话/发布身份及其本机 report_queue 接收**后才返回 `OK`；`boot_id` 由 **Host 自己绑定/输出**（`out_host_boot_id`），并从 JSON 中的 `report_seq` 做**同一会话一致性验证**；不能让 App 自述的设备 `boot_id`/URL/topic 决定发送权限。
- 返回 `OK` **只代表平台接受**；实际 MQTT/Webhook 状态由 `report_status` 单独观察。两路枚举固定：`0=NOT_CONFIGURED`、`1=PENDING`、`2=TRANSPORT_SUCCEEDED`（只按实际协议可证明的发送边界）、`3=TRANSPORT_FAILED`、`4=UNKNOWN`。**MQTT 本地发布或排队不冒充 HTTP 2xx，也不冒充全局接收方 exactly-once**。
- 卸载/更新/失信会话、数据存储不可用时均无权继续提交（`UNAUTHORIZED`/`IO_ERROR`/`STORAGE_UNKNOWN`）。

### 6.7 App 状态 blob

- `state_read`/`state_commit` 面向**同一可信 App 身份**（已签名 publisher 公钥 SPKI SHA-256 + `publisher_id` + `app_id`）的**一个有界不透明业务 blob**；大小不得超过声明 `state_quota` 与真实配额（当前示例 4096B）。
- `revision = 0` 表示**经过验证确实不存在旧状态**；`NOT_FOUND`（确实不存在）与 `STORAGE_UNKNOWN`（不可判定）明确分离。
- `state_commit` 用 `expected_revision` 做**受控原子提交**：返回 `OK` 必须已持久且可读回；失败保留原可信 blob；`REVISION_CONFLICT` 表示并发/陈旧修订。
- App 对内部业务 schema/迁移负责；**Host 不自动迁移或归零**。
- 卸载/换钥时数据**默认保留但不可由新身份自动接管**；未经新产品授权不做清除。
- 重启恢复已确认状态，但**不自启业务会话**（§7）。

### 6.8 协作式停止

- `should_stop`：`0` = 可继续；`1` = Host 已请求协作式结束；负数 = 失效/错误。
- `event_next` 有**有限等待边界**（`max_wait_ms`）；`STOPPING` 后 App 应返回入口。
- Host 只有**确认入口返回、回调解除引用及执行区不再被使用**后才能 scrub/升级/卸载；无法确认则返回 `BUSY`、保持已有镜像不被覆盖。
- **不承诺抢占、强杀或原生代码隔离**；本 ABI 不等同于生产安全沙箱；独立 App 原生代码仍具有当前 PoC 的特权风险（v1 §4.2/§6 边界不变）。

## §7 会话生命周期、安全注销、更新/卸载/重启与数据归属

1. **会话授权**：`run_profile = 1` 表示**管理员显式发起的单受信 App 长会话**。会话绑定：当前 Host 信任映射下验签成功的发行者身份 + `app_id` + 版本 + 已验证兼容性 + 对应能力配额。会话之外（未授权、已注销、已失信）一切 v2 能力返回 `UNAUTHORIZED`，v1 fail-closed 原则不变。
2. **安全注销**：管理员显式注销 → Host 以 `should_stop = 1` 请求协作式结束 → App 按 §6.8 返回入口 → Host 确认入口返回、回调解除引用、执行区不再使用后方可回收/升级/卸载；无法确认则 `BUSY` 且保持镜像。无抢占式强杀（§6.8）。
3. **更新/卸载兼容**：安装/更新包的事务语义继承 v1 §5/§5.1（先完整验证候选、保留旧有效版本直至新版本可确认提交、中断后只有完整旧版或完整新版、失败不得虚报）。已知会话运行中，更新/卸载请求按 §6.8/§7.2 处理，不得写入运行中镜像。
4. **重启兼容**：重启后已提交的可信安装身份可查询、运行态重置、**不自动恢复业务会话**（v1 §3.2/§3.3 不自动执行原则延伸到 v2 会话）；已确认的 state blob 可读回（§6.7）；事件 `sequence`/`monotonic_ms`/会话授权均**不跨重启持续**。
5. **数据身份归属**：App 状态与报告队列归属三元组（SPKI SHA-256、`publisher_id`、`app_id`）。换发行者不得静默接管旧 ID（v1 §3.1）；换钥后旧数据默认保留但不可被新身份自动读写或清除（§6.7）；卸载不清除共享用户数据（v1 §5），App 专属状态默认保留、清除需新产品授权。
6. **与设备层任务的边界**：会话所需的入口回收、执行区确认、存储事务与掉电安全属设备实现任务（ne301 侧 #43/#44/#46 语义承接）；App 集成属 ne30x-app #11；本规范只定义上述**可观察语义**，不实现任何一侧。

## §8 新旧互操作与兼容矩阵

| # | 包 | Host | 必须结果 |
| --- | --- | --- | --- |
| M1 | v2 黄金包（`caps=0x3f`，2048/4096/6144） | v2 Host | 结构/签名/策略全部通过；安装仍须 Host 逐项资源验证（§4.2） |
| M2 | v2 任意包 | v1 Host | **拒绝**（v1 Host 见到未知容器 magic `…02 00 00` → `BAD_PACKAGE`/未知版本）；不得尝试解析 192B manifest |
| M3 | v1 hello-app 包（v1 §2.5 黄金） | v2 Host | v1 结构/签名/策略规则**完整照旧**；仅按**旧语义**提供 16B 表（`log`/`tick_ms`）单次运行；**不得**授予任何 v2 能力 |
| M4 | v2 容器但 `required_host_abi = 0x00010000` | v2 Host | **拒绝**：违反 §3.1 manifest 格式不变量（`BAD_PACKAGE`）；该判别与 M3 一起构成 ABI 0x00010000 vs 0x00020000 互操作判别 |
| M5 | 能力 bit6..31 任一置位（重签合法） | v2 Host | **拒绝**（未知能力位，`BAD_PACKAGE` 策略项） |
| M6 | `run_profile ∉ {1}` 或 manifest/native reserved 非零（重签合法） | v2 Host | **拒绝**（`BAD_PACKAGE`） |
| M7 | 历史归档 244B 样本（`event_max=1024`、`report_max=4096`） | 64 框业务 v2 Host | 签名数学上有效，但**资源不足负例**：`event_max=1024 < 1576`（声明 `ai_events` 而不满足 64 框需求）且 `report_max=4096 < 6144` → `RESOURCE_LIMIT` 拒绝。**该样本不得当作满足 64 检测框和历史最大合法报文的互操作黄金包** |
| M8 | 原生头 `abi_version` ≠ manifest `required_host_abi` | v2 Host | **拒绝**（交叉检查失败，`BAD_PACKAGE`） |
| M9 | `event_max`/`report_max`/`state_quota` 与能力位不匹配 | v2 Host | **拒绝**（§4.1 约束违例） |
| M10 | 签名合法、caps 全为已知 bit，但 Host 实际不提供其中某能力（如 `report_submit`） | v2 Host | **拒绝**（`ABI_INCOMPATIBLE`，§4.2 反向 fail-closed；运行期该能力调用返回 `UNAUTHORIZED`/`INCOMPATIBLE`） |

升级/卸载/换钥的安装事务语义（`DOWNGRADE_FORBIDDEN`、`VERSION_CONTENT_CONFLICT`、`APP_IDENTITY_CONFLICT`、`STORAGE_STATE_UNKNOWN`、`BUSY` 等）全部继承 v1 §3/§4.1/§5.1，本文不重复、不放宽。

## §9 错误类别与拒绝语义

v1 §7 错误主分类**原样复用**（`AUTH_REQUIRED`、`FORBIDDEN`、`BAD_PACKAGE`、`SIGNATURE_INVALID`、`PUBLISHER_UNTRUSTED`、`TARGET_INCOMPATIBLE`、`ABI_INCOMPATIBLE`、`RESOURCE_LIMIT`、`STORAGE_FULL`、`STORAGE_STATE_UNKNOWN`、`COMMIT_FAILED`、`RUNTIME_UNAVAILABLE`、`BUSY`、`APP_IDENTITY_CONFLICT`、`DOWNGRADE_FORBIDDEN`、`VERSION_CONTENT_CONFLICT`）。v2 新增判定按 v1 判定序（§2.3）映射：

| v2 判定 | 错误类别 |
| --- | --- |
| 容器 magic/长度/manifest_len≠192/manifest magic/保留字段非零/未知 profile/未知能力位/能力-配额不匹配/manifest 唯一编码破坏/DER 非法或尾随 | `BAD_PACKAGE` |
| manifest `required_host_abi` ≠ `0x00020000`（v2 容器内） | `BAD_PACKAGE`（v2 格式不变量违例） |
| 包声明 ABI ≠ 当前 Host 支持 ABI（未来版本容器等） | `ABI_INCOMPATIBLE` |
| 包声明**已知**能力位但当前 Host 实际不提供（§4.2） | `ABI_INCOMPATIBLE`（运行期 `UNAUTHORIZED`/`INCOMPATIBLE`） |
| manifest ABI ≠ 原生头 ABI / 原生头任一交叉检查失败 | `BAD_PACKAGE` |
| `event_max`/`report_max`/`state_quota` 超过 Host 实际可提供容量 | `RESOURCE_LIMIT`（运行期对应 `QUOTA_EXCEEDED`） |
| 原生 `native_file_len` > 真实装载区 | `RESOURCE_LIMIT` |
| 板型/PSRAM 不匹配 | `TARGET_INCOMPATIBLE` |
| 报告超过声明/实际配额 | 运行期 `QUOTA_EXCEEDED`（不截断） |
| 模型/类名不可映射 | 运行期 `INCOMPATIBLE` 或可见 `GAP`（§5.2） |

多种故障同时成立时的对外优先级继承 v1 §7.1.5（未授权不泄露信息、畸形长度不进入越界解析、无签名/无信任不进入执行、未提交不标记成功）。

## §10 黄金向量与离线正负测试

全部向量由 [tests/spec-v2/](../tests/spec-v2/README.md) 独立生成与核对（纯 Python 标准库实现 v2 结构/策略/P-256 验证与 RFC6979 重签，**独立于** `cryptography` 库；另以 OpenSSL CLI 做独立验签交叉证明），一键运行：

```bash
python3 tests/spec-v2/run_all_tests.py
```

辅助验证器 `full_accept` 严格按 §2.3 判定序执行：**有界结构/manifest 唯一编码先行 → 可信发行者对原样 TBS 的 ECDSA 验签 → 之后才做需要信任数据的原生头/CRC/SHA 交叉检查与 Host 策略**；因此"签名段被改"与"已签 payload 被改"都能得到确切的 `SIGNATURE_INVALID`，而不会先被 `BAD_PACKAGE` 掩盖。

证据（黄金包字节、TBS、DER、SPKI、逐向量结果、OpenSSL 输出、全部 SHA-256）输出至 `docs/evidence/spec-v2/`。

### 10.1 签名正向黄金向量（v2，profile=1 Line Crossing 兼容声明）

以历史归档 244B 合成 TBS 为基（见 10.2），**仅替换** `TBS[180:184] = 00080000`（`event_max=2048`）、`TBS[188:192] = 00180000`（`report_max=6144`），其余 236B 原封不动（`state_quota=4096`、`caps=0x3f`、`run_profile=1`、原生镜像 SHA 不变）：

| 可复核量 | 精确值 |
| --- | --- |
| 容器 magic / `manifest_len` / `image_len` | `4e45415050020000` / 192 / 36 |
| manifest magic / `required_host_abi` / `required_host_caps` | `NMF2` / `0x00020000` / `0x0000003f` |
| `run_profile` / `event_max` / `state_quota` / `report_max` | 1 / 2048 / 4096 / 6144 |
| 原生镜像 | 36B：32B 头（`NEA1`、`format_version=1`、`abi_version=0x00020000`、`target_addr=0x93E00000`、`image_size=4`、`entry_offset=0`、`reserved0=0`、CRC32 `0xDE8E3439`）+ payload `00 20 70 47` |
| `publisher_id` / `app_id` / 版本 | `test-publisher` / `hello-app` / `1.0.0` |
| TBS 长度 / `SHA-256(TBS)` | 244B / `e14e2cce8b3b0ecfa1d0af0538e931d3403c318a665126288c5c82b96ffbd278` |
| 签名密钥 | **公开、不安全、非生产** P-256 测试私钥标量 `d=1`；SPKI DER 91B，`SHA-256(SPKI)=5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3` |
| 固定严格 DER（70B） | `3044022011e9d2635e2036fb0bcbd1107a5e6d272c150473a8c1e029887604f9aa75473702205b6ca9206755a161913fcf9cdf57c789b363420bc16a74438bc439aeb80d11b0` |
| 黄金包长度 / `SHA-256(package)` | **314B** / `3766e8afc39b267c26bece857e4177248f847aab265ce1b9c3dbf18b27c9eb3e` |
| 独立交叉证明 | 主机 Python（`cryptography`）验签 PASS；OpenSSL `openssl dgst -sha256 -verify` 返回 `Verified OK`（exit 0）。本 Issue 内 `tests/spec-v2` 以纯 Python P-256 与 OpenSSL 双通道复核同样通过 |

该向量是**新的**合成 profile=1 签名正向输入，**不是设备/解析器 PASS**（§12）。

### 10.2 历史归档（仅作负例，不可当互操作黄金包）

2026-10-09 的完整 244B 合成 TBS（`event_max=1024`、`state_quota=4096`、`report_max=4096`）保留于 [历史归档评论](https://github.com/harryhua-ai/ne30x-app/issues/12#issuecomment-6092263046)（`SHA-256(TBS)=60e708cb083a3be066420874da75eeaefcec5ec8106844456b922fc1d9bf8226`）。按固定 counting 64 框与 6144B 报告容量，它只作为**密码学真签名/资源不足负例输入**（§8 M7），**不得**作为 Line Crossing 兼容 profile 的准入正例，也不能被解释为实际完整业务兼容样本。

### 10.3 必须覆盖的负例族（tests/spec-v2 实现清单）

1. **已签内容篡改（按黄金包真实布局动态定位）**：TBS 布局为 `[0,16)` 容器头、`[16,208)` manifest、`[208,240)` 原生 32B 头、`[240,244)` 真 payload、`[244,314)` DER 签名段。翻转**真 payload** 字节（DER 保持逐字节不变）→ `SIGNATURE_INVALID`，OpenSSL 非零退出；篡改 manifest 字节 → `SIGNATURE_INVALID`；**篡改 DER 签名字节本身**（TBS 不变）→ `SIGNATURE_INVALID`（该项只证明签名字节损坏会被验签拒绝，不作为已签 payload 覆盖的证明）。
2. **DER 结构**：合法 DER 后追加字节 → `BAD_PACKAGE`（DER 必须完整消费尾部）；DER 截断 → `BAD_PACKAGE`。
3. **重签后的策略拒绝**（证明"签名正确 ≠ 放行"）：未知能力位（bit6）、Host 不提供的已知能力（能力子集反向 fail-closed，M10）、[176..191] reserved 非零、manifest [58..59] 非零、未知 `run_profile`、profile 1 缺 bit5、能力-配额不匹配、`required_host_abi=0x00010000`（manifest 格式不变量，独立用例）、**仅原生头 ABI 改为 `0x00010000` 而 manifest 保持 `0x00020000`**（同步更新 manifest native SHA 后合法重签 → 真正验证原生头↔manifest 交叉不匹配）、原生头 `reserved0≠0`——均以 d=1 重签为合法签名后仍拒绝，并断言拒绝原因可归因到对应规则。
4. **新旧交叉拒绝**：v2 包过 v1 Host 结构规则拒绝；v1 容器声明 v2/`NMF2` 混搭拒绝；v1 黄金包过 v2 Host 仅获 v1 16B 表语义（M3）。
5. **容量判别**：1024/4096 归档样本在 64 框业务判 `RESOURCE_LIMIT`（M7）；黄金包 2048/6144 判通过（M1）。
6. **事件 wire 负例**：未知 kind、未知 flags 位、`flags.bit1=1` 但 `lost_frame_count≠0xFFFFFFFF`、65 检测（>64/>1576B）、`total_len` 与 `detection_count` 不一致、非有限 float 位型、`class_index` 越界——全部拒绝，不截断、不静默丢弃。
7. **结构不变量**：`manifest_len≠192`、原生文件长度不等外层 `image_len`、缺签名、整包截断。

### 10.4 事件 wire 正向参考编码

- `FRAME` 含 64 个检测记录：恰 1576B，`total_len=1576`，有限 float 位型、合法 `class_index`，签名/结构校验通过。
- `FRAME(count=0)`（40B）、`MODEL_CHANGED`、`GAP`（含 bit0/bit1 + `lost_frame_count=0xFFFFFFFF`）、`STOPPING` 四种编码各自可区分。

## §11 与 P3 #6 及其它任务的边界

- **P3 #6（v1 打包工具，现行 ACTIVE Contract）**：本 Issue **不改、不扩、不重审**其任何交付；v1 工具继续只服务已冻结的 `.neapp` v1。本文仅声明边界；v2 打包器是**未来独立受审任务**，不得在 #6 内偷偷实现。
- **设备 Host / 验签准入 / 存储 / 单次运行**：属 ne301 侧 #29/#30/#31 及承接 v2 的后续设备任务（#43/#44/#46 语义承接）；本文不实现设备侧任何代码。
- **App 集成**：Line Crossing App 对本规范的实际集成属 ne30x-app #11。
- 本规范不隐含自动开机启动、多 App 并发、不可信代码沙箱（同 v1 非目标）；不生成生产密钥（本文只用公开 `d=1` 测试钥）。

## §12 没有 PASS 的边界（如实标注）

以下能力在本 Issue 与本规范文件中**均无 PASS**，任何引用本文的文档不得将其写成已证明：

1. **真实 v2 解析器**：无任何设备端或固件 v2 parser 已实现并通过本文向量。
2. **目标编译/链接**：无 STM32 目标上的 v2 ABI 头静态断言编译、无 v2 App 目标构建。
3. **设备 PKA 验签**：v2 包的 mbedTLS/PKA 设备验签未测试（v1 §2.1 的同款缺口）。
4. **掉电/存储事务**：§6.7/§7 的原子提交、重启恢复语义无掉电实测。
5. **AI 持续运行**：64 框持续会话下 Host 能否不阻断 AI 主回调地映射标签、复制完整事件并协作式安全回收——**未证明**；这是 A 材料指认的最脆弱假设。
6. **真实 Host 容量**：`event_max=2048`/`report_max=6144`/`state_quota=4096` 只是签名请求上界；设备真实可支持的事件缓冲、报告槽与状态配额须由设备实现另行验证。任何 Host 实际配额小于声明即不兼容（§4.1），不得部分成功。
7. **本规范的"规范已集成"状态**：须经后续 exact-SHA A Review、merge 与 canonical ght complete 之后方可声明；本文当前仅为受审候选。

## 附录 A：A 定稿输入 → 本文覆盖对照

| A 材料（issuecomment-6092256674）决定 | 本文章节 |
| --- | --- |
| §1 8B magic `4e45415050020000`、`manifest_len=192`、`image_len`、16+192+image TBS、SHA-256 双用、DER 完整消费 | §2.1、§2.2 |
| §1 manifest 前 160B 复用 v1、NMF2、abi `0x00020000`、v2 caps、[58..59] 为零、原生 NEA1/32B/`format_version=1`/abi `0x00020000`/reserved0=0、装载量约束 | §3.1、§3.3、§2.3 |
| §1 [160..191] 扩展字段与全零 reserved、未知 profile/字段拒绝 | §3.2 |
| §1 能力 bit0..5、bit6..31 拒绝、profile 1 含 bit5、配额匹配、1576B/6144B 约束、声明 vs Host 逐项验证、caps=0x3f/2048/4096/6144 上界示例 | §4.1、§4.2 |
| §2 事件 40B 头 10×u32-le、kind/sequence/generation/flags 语义、FRAME=40+24×n（0..64）、1576B 上限 | §5.1 |
| §2 24B 记录、binary32 位编码、无指针、class name 唯一完整匹配、不编造索引/静默丢帧 | §5.2 |
| §2 flags bit0/bit1、`0xFFFFFFFF`、GAP 语义、四种可观察语义、>64 拒绝不截断 | §5.3 |
| §2 sequence/monotonic 会话内模 2³²、代次重查、`target_class_name` 32B 不静默截断 | §5.1、§5.4 |
| §3 ABI `0x00020000`、入口签名、v1 16B 表不变、48B 表 + 10 函数偏移、无前缀兼容、跨 ABI 结构规则与静态断言 | §6.1、§6.2 |
| §3 十个函数完整签名 | §6.3 |
| §3 返回码 0/1/2 与 -1..-10、UNAUTHORIZED/INCOMPATIBLE、失败不得当成功 | §6.4 |
| §3 model_meta 128B 布局、class_name 代次绑定/实际长度/NUL、INCOMPATIBLE 不截断 | §6.5 |
| §3 report_status 五枚举、MQTT 不冒充 2xx/exactly-once、report_submit Host 绑定 boot_id/report_seq、OK=平台接受 | §6.6 |
| §3 state blob 身份三元组、配额、revision=0、NOT_FOUND vs STORAGE_UNKNOWN、原子提交、失败保留、App 自管 schema、卸载/换钥保留不接管、重启不自启 | §6.7 |
| §3 should_stop 语义、有限等待、scrub 前提、BUSY、无抢占/隔离、特权风险 | §6.8 |
| §1/§4 旧 1024/4096 仅负例、新 2048/6144 正向量、全部摘要/DER/包哈希、OpenSSL 交叉证明、B 应转正式 tests | §10.1、§10.2、§10.3 |
| §4 反证与停止条件（64 框、6144B、PP_TYPE_OD=1、16B 表、一次入口 scrub 已核对；目标宿主假设未证；不改字段/静默降级须交 A） | §12、文件头证据锚点 |
| 历史归档（6092263046）244B TBS/DER 原始字节 | §10.2、`tests/spec-v2`（归档负例重建） |

本文与固定证据锚点（ne301 `app_host_abi.h` blob `9c13b87d`、`line_counting.h`/`pp.h`/`lc_delivery_queue.h`/`line_counting_config.h` @`de25a6f1`）已逐项核对，未发现与 A 决定实质冲突的编译器/资源/型号事实。
