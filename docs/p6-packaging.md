# P6 — .neapp v2 受信签名打包与跨版本离线验证（Issue #13）

本文说明 ne30x-app 的 `.neapp` **v2** 打包器、离线验真器、受支持的
ABI/配额/能力、签名输入、受控原生测试镜像的生成与离线复现方式、与
#12 正式黄金向量的独立性一致性证明、拒绝矩阵，以及本任务的**证据边界**。

**协议唯一权威**：

- v2：[docs/app-package-protocol-v2-draft.md](app-package-protocol-v2-draft.md)
  （#12 正式合并产物，历史文件名保留）与 `tests/spec-v2/**`（56+ 向量、
  OpenSSL 交叉验签、§2.3 判定序、能力位/信任库/loader 范围/tick 语义）。
- v1：[app-package-protocol-v1.md](app-package-protocol-v1.md)（P2/#6 基线，
  **本轮零改动**，其全部打包/校验行为与 hello-app V1/V2 回归保持不变）。

本文只是工具说明；不另建任何字节格式。v2 工具（`package/neapp_v2_format.py`
/ `neapp_pack_v2.py` / `neapp_verify_v2.py`）**分层复用** v1 共享格式模块
`package/neapp_format.py` 的全部共享原语（严格 DER/SPKI 解析、标识符字符集、
原生 32B 头解析、CRC-32、信任库、错误类），不建第二套平行签名系统。

## 1. v2 包格式摘要（细节以 v2 规范为准）

```text
偏移 0..7     magic   4E 45 41 50 50 02 00 00   ("NEAPP", 容器主版本 2, 2×0x00)
偏移 8..11    manifest_len  u32-le             v2 唯一合法值 192
偏移 12..15   image_len     u32-le             完整原生文件长度（≥ 32）
偏移 16..207  manifest 192B 定长：
              [0..159]   严格复用 v1 同位置编码，仅：
                         magic=NMF2；[58..59] 保留全零；
                         required_host_abi 必须 0x00020000（§3.1 格式不变量）；
                         required_host_caps = v2 能力掩码
              [160..191] run_profile（唯一合法值 1）/ event_max /
                         state_quota / report_max + [176..191] 保留全零
紧接 manifest 原生镜像原样字节（32B NEA1 头 + payload；abi_version=0x00020000、
              reserved0=0、format_version=1、header_size=32、CRC32、SHA-256 交叉）
文件末尾      恰好一个严格 DER ECDSA-Sig-Value（8–72B，完整消费，无尾段）

TBS = 文件 [0 : 16+192+image_len]；签名 = ECDSA secp256r1 (P-256) over
SHA-256(TBS)，严格 DER，不拒绝 high-S；幂等内容身份 = SHA-256(TBS)。
整包上限 2,097,432 B（16+192+2 MiB+72，§2.3）。
```

**验真判定序（§2.3，与 #12 `full_accept` 一致）**：
①有界结构（magic、两个长度、192B manifest 唯一编码、DER 结构与尾段完整消费）
→ ②Host 本地受信发行者映射（`publisher_id → SHA-256(SPKI DER)`，fail-closed
`PUBLISHER_UNTRUSTED`）→ ③对原样 TBS 的 ECDSA 验签 → ④原生头/摘要/CRC/
Thumb 入口/ABI 绑定交叉 → ⑤Host 策略（板型/PSRAM/ABI/能力子集/配额/loader
范围/实际执行区）。因此"签名段被改"与"已签 payload 被改"都得到确切
`SIGNATURE_INVALID`，不会被 `BAD_PACKAGE` 掩盖。

## 2. 工具与调用

| 文件 | 作用 |
| --- | --- |
| `package/neapp_v2_format.py` | v2 格式权威：容器/192B manifest 编解码、§2.3 判定序验真管线、能力位/配额/业务下限、Host 策略替身（复用 v1 原语） |
| `package/neapp_pack_v2.py` | v2 打包器：镜像 + 元数据 + 私钥 → `.neapp.v2` + 溯源 sidecar；写入前自验，任一约束违反即拒不出包 |
| `package/neapp_verify_v2.py` | v2 离线验真器：`.neapp.v2` + 信任库 JSON（+ 可选 Host 策略 JSON）→ PASS 或 §9 错误类 |
| `tools/make_v2_test_image.py` | 受控 v2-ABI 原生测试镜像生成器（确定性；默认字节 == #12 黄金原生镜像） |
| `tests/package-v2/v2_cases.py` | 59 项正/负/跨版本用例（真实 CLI 驱动，逐项 detail 归因断言） |
| `tests/package-v2/run_checks.sh` | 一键全流程（v1 回归 + #12 spec-v2 + v2 全套 → 证据） |

打包（v2，能力/配额为签名请求上界，§4.2）：

```bash
python3 package/neapp_pack_v2.py \
  --image tests/package-v2/work/img/lc-test-image.bin \
  --out lc-test-app-1.0.0.neapp.v2 \
  --key /path/to/dev-signer.pem \
  --publisher-id dev-publisher --app-id lc-test-app --version 1.0.0 \
  --host-caps 0x3f --event-max 2048 --state-quota 4096 --report-max 6144
```

受控测试原生镜像（符合 v2 ABI：NEA1 32B 头、`abi_version=0x00020000`、
`reserved0=0`；默认 payload `00207047` = Thumb `movs r0,#0; bx lr`）：

```bash
python3 tools/make_v2_test_image.py --out lc-test-image.bin
# 默认参数逐字节重建 #12 spec §10.1 黄金原生镜像（golden-tbs.bin 末 36B）
```

验真（离线）：

```bash
python3 package/neapp_verify_v2.py \
  --package lc-test-app-1.0.0.neapp.v2 --trust trust-dev.json [--policy host.json] \
  [--expect PASS|BAD_PACKAGE|SIGNATURE_INVALID|PUBLISHER_UNTRUSTED|\
            TARGET_INCOMPATIBLE|ABI_INCOMPATIBLE|RESOURCE_LIMIT]
```

信任库 JSON 与 v1 同格式（`{"version":1,"publishers":{...}}`）；公钥材料只来自
**本地配置**（离线替身对应设备内置信任锚），绝不采信包内自带公钥。可选
`--policy` 覆盖 Host 侧事实（board/ABI/`host_caps`=Host 实际提供能力/loader
基址与范围/装载区/执行区/事件缓冲/报告容量/状态配额/业务下限开关）——同为
本地配置，绝不来自包声明（§4.2 包声明 ≠ Host 授权）。

## 3. 受支持的 ABI / 板型 / 能力 / 配额（本轮证据基线）

| 项 | 值 | 依据 |
| --- | --- | --- |
| 容器主版本 | 2（magic `4e45415050020000`） | v2 §2.1 |
| manifest | NMF2，192B，前 160B 复用 v1 编码 | v2 §3.1 |
| `required_host_abi` | `0x00020000`（唯一合法；原生头 `abi_version` 必须相等） | v2 §3.1/§3.3/§8 M8 |
| 目标板型 / PSRAM | `0x00003010` / 64 MiB（继承 v1 §2.4 证据基线） | v1 §2.4 |
| 能力位 | bit0 `log`、bit1 `tick_ms`、bit2 `ai_events`、bit3 `report_submit`、bit4 `app_state`、bit5 `session_lifecycle`；**bit6..31 任一置位拒绝** | v2 §4.1 |
| run_profile | 唯一合法值 1（必须含 bit5） | v2 §3.2/§4.1 |
| 配额一致性 | bit2⇒`event_max>0`、bit3⇒`report_max>0`、bit4⇒`state_quota>0`，反向同样拒绝（不悄悄预留） | v2 §4.1 |
| 业务下限（64 框 line-crossing） | 声明 `ai_events` 时 `event_max ≥ 1576`（40+64×24）；声明 `report_submit` 时 `report_max ≥ 6144`（`LC_DQ_SLOT_CAPACITY`） | v2 §4.1/§8 M7 |
| Host 实际容量（默认策略替身） | 事件缓冲 2048 / 报告 6144 / 状态配额 4096；超出 → `RESOURCE_LIMIT` | v2 §9 |
| loader 范围 | `native_target_addr` 必须落在 Host **独立已知**的 `[0x93E00000, +2 MiB)`；装载临时量与驻留量分别验证 | v2 §3.3、v1 §2.3 |

行内示例 `caps=0x0000003f, 2048/4096/6144`（#12 §4.2 的 Line Crossing 兼容
profile）只是**签名请求上界**；Host 逐项验证不满足即整体拒绝，不部分成功。

## 4. 签名输入与密钥纪律（AC3）

- 唯一签名原文：`TBS = 文件[0 : 16+192+image_len]`；签名与幂等内容身份均用
  `SHA-256(TBS)`（§2.2）。不同但均合法的 DER **不构成版本冲突**——套件中
  `golden_low_s_variant_same_identity`（s→n-s 重编码）与
  `golden_replica_tbs_identity`（cryptography RFC-6979 与 #12 纯 Python
  RFC-6979 得到不同 k）都证明同一内容身份下不同合法 DER 均通过。
- 开发/测试签名身份由 `tests/package/gen_dev_key.py` **每轮测试时生成**
  （P-256），私钥只写入 `tests/package-v2/work/keys/`（gitignored、0600），
  绝不入仓、绝不打印。manifest/sidecar 只携带 `SHA-256(SPKI DER)` 指纹。
- d=1 是规范 §10.1 的**公开、非生产**测试钥；本套件用
  `cryptography` 从公开标量重构其 PEM/SPKI，并硬断言
  `SHA-256(SPKI)=5cd252fb…` 且与 #12 提交的 `test-publisher.spki.der`
  逐字节一致。
- 全部产物与文档标注**非生产可信根**；无生产密钥、无设备信任根写入。

## 5. 与 #12 黄金向量的独立一致性（AC3）

`tests/package-v2/v2_cases.py` 把 #12 已提交证据（`docs/evidence/spec-v2/`）
过**独立实现**（`package/` 工具链，`cryptography` 后端）复核：

| #12 钉定值 | 独立复核 |
| --- | --- |
| `SHA-256(TBS)=e14e2cce…` | 受控镜像（== 黄金原生镜像逐字节）经 `neapp_pack_v2.py` 打包，TBS 与 `golden-tbs.bin` **逐字节一致**，摘要相等 |
| 黄金包 `3766e8af…`（314B） | 提交的 `golden.neapp.v2` 过 `neapp_verify_v2.py` → PASS（哈希先行断言未漂移） |
| 钉定 70B DER | `cryptography` 验签 + OpenSSL `dgst -sha256 -verify` 双通道独立通过 |
| 归档负例 `f05ca613…`（M7） | 过 v2 验真 → `RESOURCE_LIMIT`，detail 归因 `event_max 1024` |
| v1 黄金 `9a212324…` | 结构/签名复核 + M2/M3 判别（见 §7） |

打包器自身 DER 与钉定 DER **不同但均合法**（RFC-6979 实现差异 → 不同 k），
这正是 §2.2 幂等身份语义的实证；套件记录该差异并双通道验证两个 DER。

## 6. 拒绝矩阵（AC2，59 项用例全绿）

全部用例断言 §9 错误类 **且** detail 子串归因（防止"碰巧在更早检查点被拒"）：

- **结构**：未知容器版本（magic=03/v1）、`manifest_len≠192`、`image_len<32`、
  溢出、整包/签名截断、DER 尾段不完整消费、第二 DER 对象、r=0、非最短长度。
- **manifest 唯一编码（重签仍拒）**：NMF1 混搭、[58..59]/[176..191] 保留非零、
  `required_host_abi=0x00010000`（M4：v2 容器声明 v1 ABI）。
- **签名覆盖**：native payload 翻转（DER 逐字节不动）→ `SIGNATURE_INVALID`；
  manifest caps/版本翻转（**权限/版本提升不可能绕过签名**）；DER 区翻转；
  错误签名钥。
- **信任映射**：未知 `publisher_id`、指纹与 Host 本地映射不一致（重签仍
  `PUBLISHER_UNTRUSTED`）。
- **原生交叉（摘要一致重签）**：原生头 ABI≠manifest ABI（M8，含
  hello-app V1 真实镜像作额外输入——不重建，仅消费 `d6eec431…` 历史字节；
  打包器同样拒绝 v1-ABI 镜像入 v2）、reserved0≠0、CRC 未同步、manifest 摘要
  未同步、长度矛盾、奇数入口。
- **策略（签名有效仍拒）**：未知能力位 bit6、profile 1 缺 bit5、未知
  profile、配额-能力双向不匹配（M9）、板型/PSRAM、能力子集反向
  fail-closed（M10：Host 缺 report_submit → `ABI_INCOMPATIBLE`）、
  业务下限 1576/6144（M7）、Host 容量上限、loader 范围越界、装载区不足、
  执行区超限。
- **跨版本判别**：v2 包过**未改动的 v1 验真器** → `BAD_PACKAGE`（M2，v1
  绝不解析 192B manifest）；v1 黄金过 v2 验真器 → `BAD_PACKAGE`；v1 golden
  caps⊆{log,tick_ms} 且 ABI 0x00010000（M3：v2 Host 仅按旧语义给 16B 表，
  无任何 v2 能力升级）；降级判别（同身份 2.0.0→1.0.0，版本三元组+不同
  SHA-256(TBS)）；内容冲突判别（同身份同版本不同镜像 → 不同内容身份）；
  幂等重打包（同输入 → 同 TBS/同包字节）。

## 7. 一键复现与证据

```bash
bash tests/package-v2/run_checks.sh
```

步骤：[1/8] **未改动** v1 回归 `tests/package/run_package_checks.sh`
（hello-app V1 逐字节复现 `d6eec431…` + spec_vectors 15 项 + generated_cases
33 项；其每轮产物快照为 `p6-v1-regression-artifacts.json`，P3 自有证据文件
恢复原状）→ [2/8] **未改动** `tests/spec-v2/run_all_tests.py`（73 向量，
提交证据逐字节不变）→ [3/8] 非生产身份（每轮 dev 钥 + 公开 d=1）→
[4/8] 受控镜像（== #12 黄金原生镜像断言）→ [5/8] d=1 黄金复刻包（TBS 逐字节
一致断言）→ [6/8] dev 包 1.0.0/2.0.0/alt → [7/8] 59 项 v2 用例 →
[8/8] 证据落盘。

证据（真实输出）：

- `docs/evidence/p6-package-checks.log` — 全程控制台输出；
- `docs/evidence/p6-package-artifacts.json` — 镜像/包哈希、验真报告、黄金
  一致性表、59 项用例逐项结果、密钥纪律声明；
- `docs/evidence/p6-v1-regression-artifacts.json` — v1 回归本轮快照。

## 8. 边界声明：模拟验真 ≠ 设备结果（AC4）

`neapp_verify_v2.py` 的 PASS 仅表示：结构合法、发行者在本地信任映射、签名对
TBS 有效、签名内容自洽、离线 Host 策略替身兼容。它**不**表示，本轮也**无任何
PASS**：

1. **STM32 安装/持续运行**：没有任何设备安装、启动或长会话运行该 v2 包；
2. **设备 PKA/mbedTLS 验签**：v2 包的设备端验签未测试（v1 §2.1 同款缺口）；
3. **真实 Host 容量**：2048/4096/6144 与 2 MiB 只是签名请求上界与实验基线，
   设备真实事件缓冲/报告槽/状态配额须由设备实现另行验证；
4. **AI 事件 wire 运行期语义**（§5/§6 的 `event_next`/`model_meta`/`tick_ms`
   回绕等）由 #12 规范套件离线钉定，无设备侧持续运行证明（#12 §12 全文适用）；
5. 断电/存储事务、协作式停止回收、沙箱隔离——均无本轮证据。

v2 ABI v2 函数表/调用面属设备承接任务（#12 §11）；本仓库 #11（Line Crossing
App 集成）不得因本工具的离线 PASS 而声称设备就绪。

---

# P6 v3 扩展 — .neapp v3 签名打包与离线验真（Issue #20）

本部分是 P6 的 **v3 扩展**（Issue #20），说明 `.neapp` **v3** 打包器、离线
验真器、受支持的 ABI/能力/配额、签名输入与 #19 黄金向量的**逐字节复现**、
拒绝矩阵与本部分的**证据边界**。上方 §1–§8（v1/v2，#13 基线）与本文互不
改动：v1/v2 工具行为逐字节冻结。

**协议唯一权威**：[docs/app-package-protocol-v3.md](app-package-protocol-v3.md)
（#19 正式合并产物，`6d3a9ccc`）与 `tests/spec-v3/**`（150 向量、OpenSSL
交叉验签、§2.3 判定序、§10 互操作矩阵）。v3 是**独立容器 major 3 + 独立
ABI major `0x00030000`**，不是 v2 的延伸；本部分只是消费已冻结 wire 的工具
说明，不另建任何字节格式。

## 9. v3 包格式摘要（细节以 v3 规范为准）

```text
偏移 0..7     magic   4E 45 41 50 50 03 00 00   ("NEAPP", 容器主版本 3, 2×0x00)
偏移 8..11    manifest_len  u32-le             v3 唯一合法值 192
偏移 12..15   image_len     u32-le             完整原生文件长度（≥ 32）
偏移 16..207  manifest 192B 定长（NMF3）：
              [0..159]    沿用 v2 同位置编码；[58..59] 保留全零；
                          required_host_abi 必须 0x00030000（§3.1 格式不变量）
              [160..175]  run_profile（唯一合法值 2）/ event_max /
                          state_quota / report_max
              [176..179]  control_max（声明 bit6 必须非零，且 ≥ 32 通用 wire 下界）
              [180..183]  snapshot_max（声明 bit7 必须非零）
              [184..191]  保留全零（任何非零拒绝）
紧接 manifest 原生镜像原样字节（32B NEA1 头 + payload；abi_version=0x00030000、
              reserved0=0、format_version=1、header_size=32、CRC32、SHA-256 交叉）
文件末尾      恰好一个严格 DER ECDSA-Sig-Value（8–72B，完整消费，无尾段）

TBS = 文件 [0 : 16+192+image_len]；签名 = ECDSA secp256r1 (P-256) over
SHA-256(TBS)，严格 DER，不拒绝 high-S；幂等内容身份 = SHA-256(TBS)。
整包上限 2,097,432 B（16+192+2 MiB+72，§2.3）。
```

**验真判定序（§2.3：结构 → 信任 → 签名 → 策略）**：①有界结构（v3 magic、
两个长度、192B NMF3 唯一编码、DER 结构与尾段完整消费；未知容器版本直接
拒绝，v1/v2 包**永不**被 v3 验证器解析）→ ②Host 本地受信发行者映射
（`publisher_id → SHA-256(SPKI DER)`，fail-closed `PUBLISHER_UNTRUSTED`；
包自带公钥/指纹**不得自注册信任**）→ ③对**原样 TBS** 的 ECDSA 验签
（Host 自有密钥）→ ④原生头/摘要/CRC/Thumb 入口/ABI 绑定交叉 → ⑤Host
策略（板型/PSRAM/ABI/能力位 bit8..31 拒绝/已知位 Host 不提供拒绝 §4.2/
profile 2 必含 bit5+bit6/配额-能力双向匹配含 bit6/bit7/`control_max ≥ 32`
通用 wire 下界/line-crossing-64 下限 1576/6144/Host 容量上限/loader 范围/
装载区/执行区）。因此"签名段被改"与"已签 payload 被改"都得到确切
`SIGNATURE_INVALID`，不会被 `BAD_PACKAGE` 掩盖。

## 10. v3 工具与调用

| 文件 | 作用 |
| --- | --- |
| `package/neapp_v3_format.py` | v3 格式权威：容器/192B NMF3 manifest 编解码、§2.3 判定序验真管线、能力位/配额/业务下限/控制 wire 下界、Host 策略替身（分层复用 v1 共享原语，同 v2 惯例） |
| `package/neapp_pack_v3.py` | v3 打包器：镜像 + 元数据 + 私钥 → `.neapp.v3` + 溯源 sidecar；写入前自验，任一约束违反即拒不出包 |
| `package/neapp_verify_v3.py` | v3 离线验真器：`.neapp.v3` + 信任库 JSON（+ 可选 Host 策略 JSON）→ PASS 或 §11 错误类 |
| `tests/package-v3/make_v3_test_image.py` | 受控 v3-ABI 原生测试镜像生成器（确定性；默认字节 == #19 黄金原生镜像） |
| `tests/package-v3/v3_cases.py` | 60+ 项正/负/跨版本用例（真实 CLI 驱动，逐项 detail 归因断言） |
| `tests/package-v3/run_checks.sh` | 一键全流程（冻结 v1/v2 回归 + spec-v2/spec-v3 套件 + v3 全套 → 证据） |

打包（v3；能力/配额为签名请求上界，§4.2 声明 ≠ Host 授权）：

```bash
python3 package/neapp_pack_v3.py \
  --image tests/package-v3/work/img/lc-v3-test-image.bin \
  --out lc-test-app-1.0.0.neapp.v3 \
  --key /path/to/dev-signer.pem \
  --publisher-id dev-publisher --app-id lc-test-app --version 1.0.0 \
  --host-caps 0xff --event-max 2048 --state-quota 4096 --report-max 6144 \
  --control-max 256 --snapshot-max 1024
```

受控测试原生镜像（NEA1 32B 头、`abi_version=0x00030000` 钉定、`reserved0=0`；
默认 payload `00207047` = Thumb `movs r0,#0; bx lr`；该工具拒绝其它 ABI 值，
v1/v2 镜像不可能被当作 v3 测试镜像）：

```bash
python3 tests/package-v3/make_v3_test_image.py --out lc-v3-test-image.bin
# 默认参数逐字节重建 #19 spec §12.1 黄金原生镜像
#（golden-tbs.bin 末 36B，SHA-256 aa8c3ef6…）
```

验真（离线）：

```bash
python3 package/neapp_verify_v3.py \
  --package lc-test-app-1.0.0.neapp.v3 --trust trust-dev.json [--policy host.json] \
  [--expect PASS|BAD_PACKAGE|SIGNATURE_INVALID|PUBLISHER_UNTRUSTED|\
            TARGET_INCOMPATIBLE|ABI_INCOMPATIBLE|RESOURCE_LIMIT]
```

信任库 JSON 与 v1/v2 同格式（`{"version":1,"publishers":{...}}`）；公钥材料
只来自**本地配置**（离线替身对应设备内置信任锚），绝不采信包内自带公钥。
可选 `--policy` 覆盖 Host 侧事实（board/ABI/`host_caps`=Host 实际提供能力/
loader 基址与范围/装载区/执行区/事件缓冲/报告容量/状态配额/**控制消息容量
`control_msg_bytes`/快照 RAM `snapshot_ram_bytes`**/业务下限开关）——同为
本地配置，绝不来自包声明（§4.2）。

## 11. v3 受支持的 ABI / 板型 / 能力 / 配额（本轮证据基线）

| 项 | 值 | 依据 |
| --- | --- | --- |
| 容器主版本 | 3（magic `4e45415050030000`） | v3 §2.1 |
| manifest | NMF3，192B，前 160B 沿用 v2 编码 | v3 §3.1 |
| `required_host_abi` | `0x00030000`（唯一合法；原生头 `abi_version` 必须相等） | v3 §3.1/§3.3/§10 M6 |
| 目标板型 / PSRAM | `0x00003010` / 64 MiB（继承 v1 §2.4 证据基线） | v1 §2.4 |
| 能力位 | bit0 `log`、bit1 `tick_ms`、bit2 `ai_events`、bit3 `report_submit`、bit4 `app_state`、bit5 `session_lifecycle`、bit6 `control_receive`、bit7 `business_snapshot`；**bit8..31 任一置位拒绝** | v3 §4.1 |
| run_profile | 唯一合法值 2（必须含 bit5+bit6；v2 的 1 在 v3 拒绝，旧 profile 不被误解释） | v3 §3.2/§4.1 |
| 配额一致性 | bit2⇒`event_max>0`、bit3⇒`report_max>0`、bit4⇒`state_quota>0`、**bit6⇒`control_max>0`、bit7⇒`snapshot_max>0`**，反向同样拒绝（不悄悄预留） | v3 §4.1 |
| 控制 wire 下界 | 声明 bit6 时 `control_max ≥ 32`（最小完整命令 `COUNTERS_RESET` 恰为 32B；业务候选尺寸不由本规范指定） | v3 §4.1/§13.11 |
| 业务下限（64 框 line-crossing） | 同时要求 bits2/3/4/5/6/7；声明 `ai_events` 时 `event_max ≥ 1576`；声明 `report_submit` 时 `report_max ≥ 6144` | v3 §4.1/§10 M11 |
| Host 实际容量（默认策略替身） | 事件缓冲 2048 / 报告 6144 / 状态配额 4096 / **控制消息 256 / 快照 RAM 1024**（§13.10 模拟参考值；设备实际值归 #55/#56）；超出 → `RESOURCE_LIMIT` | v3 §3.2/§10 M11 |
| loader 范围 | `native_target_addr` 必须落在 Host **独立已知**的 `[0x93E00000, +2 MiB)`；装载临时量与驻留量分别验证 | v3 §3.3、v1 §2.3 |

## 12. v3 签名输入、#19 黄金逐字节复现与密钥纪律（AC1/AC3）

- 唯一签名原文：`TBS = 文件[0 : 16+192+image_len]`；签名与幂等内容身份均用
  `SHA-256(TBS)`（§2.2）。低-S 重编码 DER 不改变内容身份（套件
  `golden_low_s_variant_same_identity` 实证）。
- **黄金逐字节复现（本轮核心证据）**：受控镜像（== #19 黄金原生镜像逐字节）
  经 `neapp_pack_v3.py` 以**规范自带 test-publisher 钥材料**（公开标量
  `d=1`，SPKI 91B，`SHA-256(SPKI)=5cd252fb…`，与 v1/v2 黄金同钥）重打包：

  | #19 钉定值 | 本轮复现 |
  | --- | --- |
  | `SHA-256(TBS)=d793a455…`（244B） | TBS 与 `docs/evidence/spec-v3/golden-tbs.bin` **逐字节一致** |
  | 固定严格 DER `30440220…bab50`（70B，RFC6979 d=1） | **逐字节相同**：打包器（`cryptography` `deterministic_signing=True`，RFC-6979）与 #19 纯 Python RFC-6979 对同一 d=1/同一 TBS 产生同一 k；OpenSSL `dgst -sha256 -verify` 独立返回 `Verified OK` |
  | 黄金包 `c74f7e46…`（314B） | **整包逐字节一致**（`SHA-256(package)=c74f7e46…` 精确复现） |

  因此 AC1 的"整包哈希复现"在相同钥（规范自带 d=1）与确定性编码下**成立**，
  无需任何文档例外说明。
- **公钥来源**：`docs/evidence/spec-v3/test-publisher.spki.der`（#19 已提交
  证据）＝公开标量 `d=1` 推导的 P-256 SPKI；每轮运行时重新从标量重构并
  硬断言与已提交工件逐字节一致。**d=1 是公开、不安全、非生产测试钥**
  （v3 §12 明示），**绝不能成为设备生产信任根**；所有产物、信任库 JSON 与
  溯源 sidecar 均带 NON-PRODUCTION 标注。
- 开发/测试签名身份由 `tests/package/gen_dev_key.py` **每轮测试时生成**
  （P-256），私钥只写入 `tests/package-v3/work/keys/`（gitignored、0600），
  绝不入仓、绝不打印；manifest/sidecar 只携带 `SHA-256(SPKI DER)` 指纹。
  无生产密钥、无设备信任根写入。
- v1/v2 黄金向量来源说明：`tests/package-v3/v3_cases.py` **只读引用**
  `docs/evidence/spec-v2/` 的 `golden.neapp.v2`（`3766e8af…`）与
  `v1-golden.neapp`（`9a212324…`）做跨版本判别（§10 M4/M5），不复制、不改写；
  来源为 #12/#6 已受审证据（本节即文档说明）。

## 13. v3 拒绝矩阵与跨版本判别（AC2）

`tests/package-v3/v3_cases.py` 全部用例断言 §11 错误类**且** detail 子串
归因（防止"碰巧在更早检查点被拒"）。分组摘要：

- **结构**：v2/v1 容器 magic 混入、`manifest_len=160/193`、`image_len<32`、
  溢出、整包/签名截断、DER 尾段不完整消费、第二 DER 对象、r=0、非最短长度。
- **manifest 唯一编码（重签仍拒）**：NMF2 混搭、[58..59]/[184..191] 保留
  非零、`required_host_abi=0x00020000`（M6：v3 容器声明 v2 ABI）。
- **签名覆盖**：native payload 翻转、manifest caps/`control_max`/版本翻转
  （权限/配额提升不可能绕过签名）、DER 区翻转、错误签名钥 → 全部
  `SIGNATURE_INVALID`。
- **信任映射**：未知 `publisher_id`、指纹与 Host 本地映射不一致（重签仍
  `PUBLISHER_UNTRUSTED`；包自带指纹不能自注册信任）。
- **原生交叉（摘要一致重签）**：原生头 ABI=0x00020000 ≠ manifest ABI（M6）、
  reserved0≠0、CRC 未同步、manifest 摘要未同步、长度矛盾、奇数入口。
- **策略（签名有效仍拒）**：未知能力位 bit8（M8）、profile 1（v2 值）在 v3
  （M9）、profile 2 缺 bit5/bit6、bit6 无 `control_max`、`snapshot_max` 无
  bit7、`control_max<32` 通用 wire 下界（M11）、`control_max`/`snapshot_max`
  超 Host 容量（M11）、业务下限 1576/6144（M11）、事件/状态超 Host 容量、
  板型/PSRAM、Host 缺 bit7 反向 fail-closed（M10）、执行区超限、loader 范围
  越界、装载区不足。
- **跨版本判别（§10 M2–M5，v2 保留位不得提权）**：v3 黄金过**未改动** v2
  验真器 → `BAD_PACKAGE`（M2，v2 绝不解析）；过**未改动** v1 验真器 →
  `BAD_PACKAGE`（M3）；#12 v2 黄金过 v3 验真器 → `BAD_PACKAGE`（M4，且
  断言 v2 黄金 caps⊆bits0..5/profile 1/ABI 0x00020000——v2 保留字节
  [176..191] 在任何 v3 判定域内都不产生 bit6/bit7）；#6 v1 黄金过 v3 验真器
  → `BAD_PACKAGE`（M5）。降级判别（同身份 2.0.0→1.0.0 版本三元组+不同内容
  身份）、内容冲突判别、幂等重打包（同输入 → 同 TBS/同包字节）。
- **hello-app 回归**：v1 回归（未改动）逐字节复现 hello-app V1
  `d6eec431…`（与 Issue #2 记录一致）并打包/验真 V1/V2；hello-app V1 镜像
  作为 v3 额外输入**不重建**直接消费 → v3 验真 `BAD_PACKAGE`（abi_version
  归因）、v3 打包器拒绝（exit 2，abi 归因）；v2-ABI 镜像同样被 v3 打包器
  拒绝。

## 14. 一键复现与证据（AC3/AC4）

```bash
bash tests/package-v3/run_checks.sh
```

步骤：[0/7] 预检 → [1/7] **未改动**冻结 v1/v2 包工具回归
`tests/package-v2/run_checks.sh`（内含 v1 回归 + hello-app 逐字节复现 + 59
项 v2 用例；本轮快照 captured，#13 拥有的已提交证据文件随后 **restore 原状**
，不被本轮 churn）→ [2/7] **未改动** `tests/spec-v2/run_all_tests.py`（73
向量）与 `tests/spec-v3/run_all_tests.py`（150 向量；两者提交证据必须
逐字节不变）→ [3/7] 非生产身份（每轮 dev 钥 + 公开 d=1）→ [4/7] 受控镜像
（== #19 黄金原生镜像断言）→ [5/7] d=1 黄金复刻包（TBS **与整包**逐字节
一致断言）→ [6/7] dev 包 1.0.0/2.0.0/alt → [7/7] v3 用例矩阵 + 证据落盘。

证据（真实输出）：

- `docs/evidence/p6-package-v3-checks.log` — 全程控制台输出；
- `docs/evidence/p6-package-v3-artifacts.json` — 镜像/包哈希、验真报告、
  黄金逐字节一致性表、v3 用例逐项结果、冻结回归快照、密钥纪律声明；
- v1/v2 证据文件（`p3-package-*`、`p6-package-*`、`spec-v2/`、`spec-v3/`）
  保持各自 Issue 的已受审字节不变。

本轮环境证据：Python 3.14.4 + `cryptography` 48.0.0、OpenSSL 3.6.2、
arm-none-eabi-gcc 15.2.1（仅冻结 v1 回归的 hello-app 重建需要）。

## 15. 边界声明：离线 PASS ≠ NE301 已准入/执行/热修改成功（AC4）

`neapp_verify_v3.py`（及打包器自验）的 PASS 仅表示：结构合法、发行者在本地
信任映射、签名对 TBS 有效、签名内容自洽、离线 Host 策略替身兼容。它**不**
表示，本轮也**无任何 PASS**：

1. **NE301 准入/安装/执行**：没有任何设备安装、启动或长会话运行该 v3 包；
   "离线验真 PASS"与"NE301 已准入/已执行/热修改成功"是两回事；
2. **设备端 v3 解析器与 PKA/mbedTLS 验签**：未实现、未测试（#55/#56 承接；
   v3 §14.1/§14.4 全文适用）；
3. **真实 Host 容量**：2048/4096/6144/256/1024 与 2 MiB 只是签名请求上界与
   §13.10 模拟参考值；设备真实事件缓冲、报告槽、状态配额、**控制消息容量
   与快照 RAM**、5s/10s 快照调度可承载性须由设备实现另行验证（#55/#56）；
4. **控制面运行期语义**：`control_next`/`control_reply`/`snapshot_publish`
   的会话交付、命令状态机、快照新鲜度由 #19 规范套件离线钉定，无设备侧
   持续运行证明；
5. **真实业务配置候选**：本工具不实现、不校验任何 Line Crossing 配置候选
   schema（归 App #21；#57 消费其受审公开 schema）；规范 §12.2 的
   `CONFIG_APPLY` 正向量是 opaque 传输向量，不得写成本工具证明了"真实配置
   可用性"；
6. 断电/存储事务、协作式停止回收、沙箱隔离、Line Crossing Web（#57）——
   均无本轮证据。

v3 ABI 60B 函数表/调用面属设备承接任务（#19 §5、#55/#56）；本仓库 #21
（Line Crossing App）不得因本工具的离线 PASS 而声称设备就绪。
