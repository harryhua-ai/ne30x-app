# NEUI UI-Sidecar v1 — 独立 UI 资产离线签名打包与严格验真（Issue #26 工具交付）

> **文件地位**：本文是 `ne30x-app` 对 [NE301 #79 §12 已冻结的 Sidecar v1 原始字节协议（2026-10-15）](https://github.com/harryhua-ai/ne301/issues/79) 的**机械化实现说明与工具手册**，覆盖 AC1（打包器）、AC2（独立验真器）、AC3（正反 golden 向量与安装语义判别）与 AC4（复现命令、故障矩阵、证据、回归）。**唯一 wire 权威是 NE301 #79 §12 原文**；本文不发明任何字节、上限或语义。本文不是 Host 安装器、HTTP 资源装载或真机写入的执行许可（[App #25](https://github.com/harryhua-ai/ne30x-app/issues/25)、[Host #83](https://github.com/harryhua-ai/ne301/issues/83)、[Host #84](https://github.com/harryhua-ai/ne301/issues/84) 均未 READY）。
>
> **签名域隔离**：Sidecar v1 的签名原文以独立 magic `NEUI 01 00 00 00` 开头，与原生 `.neapp` v1/v2/v3 的 `NEAPP` 域**绝不混同**：NEUI 包永远不被原生验证器解析，原生包永远不被 Sidecar 验证器解析（双向负例见 §6），并且**任何字节都不会被追加进冻结的原生 `.neapp` 容器**。信任体系复用已受审 v3 的 publisher SPKI / P-256 / 严格 DER 原语，但 Sidecar 的解析与判定是独立实现（`package/sidecar/neui_sidecar_format.py`）。
>
> **测试与证据**：全部正负向量由 [tests/sidecar/run_checks.sh](../tests/sidecar/run_checks.sh) 一键重建与核对；golden 工件与逐用例结果输出到 `docs/evidence/sidecar-v1/`。签名只用**公开、非生产** P-256 测试标量 `d=1`（`SHA-256(SPKI DER) = 5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3`，与 v1/v2/v3 黄金同钥）与临时测试密钥；**绝不引入、存储、输出或要求真实生产私钥**。

## 目录

- §1 wire 格式（冻结字节布局）
- §2 身份、信任与原生绑定
- §3 路径与记录规则
- §4 资源上限的真实含义
- §5 安装版本语义（幂等 / 冲突 / 降级 / 换原生）
- §6 验证判定序与错误类别
- §7 故障矩阵（AC2 负例 × 归因）
- §8 工具与一键复现
- §9 golden 向量
- §10 没有 PASS 的边界（如实标注）

## §1 wire 格式（NE301 #79 §12.1/§12.2 冻结；本文逐字段照抄）

全部整数 u16/u32 **little-endian**；禁止额外前后填充、第二个签名或自描述第二格式：

```text
offset   size    field
0        8       magic = 4E 45 55 49 01 00 00 00（ASCII "NEUI"，major 1，3 个零字节）
8        4       manifest_len_u32                 128..16384
12       4       asset_payload_len_u32            1..2097152
16       N       manifest（128B 固定块 + file_count 条有序记录，无 magic 前缀）
16+N     A       原样资产 payload 字节（按记录顺序拼接，无压缩、无填充）
16+N+A   8..72   恰好一个严格 DER ECDSA-Sig-Value；无其他尾段
```

**签名原文**：`TBS = 文件字节 [0 : 16 + manifest_len + asset_payload_len)`，即**未修改的头 + manifest + 全部资产字节**；签名算法唯一钉定 `SHA-256 + ECDSA P-256 + 严格 DER`（数学/DER 规则与 v3 相同：两个正整数 `1 <= r,s < n`、BER 非最短编码/负值/零值/越界/截断/附加字节/多 ASN.1 对象全部拒绝；**不要求 low-S**）。`ui_tbs_sha256 = SHA-256(TBS)` 是 Sidecar 的规范内容身份；同一 TBS 的另一个合法 DER **不构成新内容版本**。

128B manifest 固定块：

```text
offset  size  field
0       16    publisher_id          （v3 完全相同的小写 ASCII 标识符 + 右 NUL 填充规则）
16      32    app_id                （同上）
48      32    publisher_key_sha256  （Host 本地受信 SPKI DER 字节摘要）
80      32    native_tbs_sha256     （已验证原生 .neapp v3 的 SHA-256(TBS)）
112     2     sidecar_version_major_u16   （必须 >= 1）
114     2     sidecar_version_minor_u16
116     2     sidecar_version_patch_u16
118     2     file_count_u16        （1..64）
120     4     host_ui_abi_u32       （= 1，其它值拒绝）
124     4     reserved_u32          （= 0，非零拒绝）
128     ...   file_count 条记录，严格按路径原始 ASCII 字典序升序
```

每条记录恰为 `path_len_u16(1..160) + file_len_u32(1..1048576) + sha256_of_raw_asset[32] + path[path_len]`，`manifest_len = 128 + 各记录字节数的精确和`（不多一字节、无尾记录）；`asset_payload_len = Σ(file_len)` 且属于 `1..2097152`；`16 + manifest_len + asset_payload_len + DER` 的整体解析使用溢出安全的整数算术（本实现：先对每个 u32 做上界钳制，再做有界加法与截断检查，见 `neui_sidecar_format.py` stage 1）。**必须恰好存在一个根 `index.html`**：恰有一条路径恰为 `index.html` 的记录。`docs/index.html` 等嵌套同名文件只是每个段都匹配 `[A-Za-z0-9][A-Za-z0-9._-]*` 的普通合法路径，不构成第二个根 `index`，本工具不施加任何超出 §12 的额外拒绝（不收紧冻结 wire）。

## §2 身份、信任与原生绑定（§12.1/§12.3 冻结）

- **单一受信发行者**：`publisher_id` 必须与已安装 native 的 `publisher_id` 一致；`publisher_key_sha256` 是该发行者在 Host 本地可信映射（`publisher_id → SHA-256(SPKI DER)`，与 v1/v2/v3 同一 JSON 格式）中的指纹；Sidecar **必须**由该 SPKI 对应的 P-256 私钥签名。禁止自带公钥自授信、在线信任表或自行授权。打包器据此强制（§12.1 同一受信 SPKI 发行者同时签 Sidecar 与 native）：`--key` 的 SPKI SHA-256 指纹必须等于**已验证** native manifest 的 `publisher_key_sha256`，不匹配即拒绝且不产出 bundle/provenance；打包自验也直接用 `--native-trust` 信任库完成，不再自建以签名钥为锚的信任库。
- **原生绑定精确值**：`native_tbs_sha256 = SHA-256(原生 .neapp v3 的 TBS)`——**不是**含随机 DER 的整包 `package_sha256`。打包器要求先以 `--native-trust` 对 `--native-package` 做完整离线 v3 验签（intrinsic 层），只从**已验证**的原生 TBS 取该值。验证器在 `--native-package` 下核对 `publisher_id + app_id + publisher_key_sha256 + native_tbs_sha256` 四元组全部一致，并**如实区分信任级别**：给 `--native-trust` 时 native 先通过完整离线 v3 验签，报告 `native_binding_trusted=true`；不给时 native 字节只做结构解析与身份比对（**未验签**），报告 `native_binding_checked=true` 且 `native_binding_trusted=false`——这是独立的 untrusted byte-only 交叉核对，绝不表述为"受信 native 准入/验签"（报告 boundary 字段显式声明）。相同原生 TBS 的合法重签不被误判为不同 App 内容。
- Host（#83）仍必须以**自己的当前受信 install record / active session** 独立判定此身份；本离线工具的 `--native-package` 交叉核对只是证据工具，不是 Host 判定本身。

## §3 路径与记录规则（§12.2 冻结）

路径为相对、以 `/` 分隔的 POSIX 资产路径，1..160 ASCII 字节；每段匹配 `[A-Za-z0-9][A-Za-z0-9._-]*` 且不是 `.`/`..`；拒绝：前导/尾随 `/`、空段（`//`）、反斜杠、百分号转义、冒号、NUL、query（`?`）/fragment（`#`）、非 ASCII、绝对路径、重复路径与 ASCII 大小写折叠碰撞。打包端同样拒绝：符号链接（文件与目录，含逃逸资产根的链接目录）、非普通文件（FIFO 等）、资产根之外的任何输入。记录严格按**原始 ASCII 字节字典序升序**；payload 拼接必须按同一顺序；每资产实际 SHA-256 必须与记录一致——缺失/未列出/重复/截断/超限资产一律拒绝，**绝不静默重排伪造 manifest**。

## §4 资源上限的真实含义

`file_count 1..64`、`path_len <= 160`、`file_len 1..1,048,576`、`asset_payload_len 1..2,097,152`、`manifest_len <= 16,384` 是**打包输入的最大可接受值**（§12.3 Resource gate），用于让 #82 实测的 417 KiB 无压缩 UI 可装下——**不是** Host 承诺分配 2 MiB/8 MiB、**不是** 32 MiB 分区确有剩余空间的证明。Host 在提交前独立检查真实文件系统剩余量与保留额。

## §5 安装版本语义（§12.1/§12.3 冻结；`classify_install_transition`）

对同一原生身份（`publisher_id, app_id, publisher_key_sha256, native_tbs_sha256` 四元组）：

| 情形 | 判定 |
| --- | --- |
| `ui_tbs_sha256` 相同（任意合法 DER） | `IDEMPOTENT`（幂等，不是新版本） |
| 语义版本更高、`ui_tbs` 不同 | `UPGRADE`（唯一正常升级路径） |
| 语义版本相同、`ui_tbs` 不同 | `CONTENT_CONFLICT`（拒绝） |
| 语义版本更低 | `DOWNGRADE`（不是普通更新；授权的崩溃回滚到先前已提交可信快照是 #83 的独立行为） |
| 原生身份四元组任一不同 | `NATIVE_REBIND`（旧 Sidecar 绝不被新原生 TBS 继承，必须对新原生身份单独准入） |
| 无已安装前驱 | `FRESH_INSTALL` |

未知 metadata / 空间不足 / 掉电半写 ⇒ fail-closed（#83 语义）；本离线工具不实现暂存/激活/恢复。

## §6 验证判定序与错误类别

与 v3 相同的规范顺序 **结构 → 信任 → 签名 → 内容**（`neui_sidecar_format.verify_bundle`）：

1. 有界容器结构：NEUI v1 magic（未知版本拒绝、从不协商）、两个长度的钳制区间、有界加法的截断检查、DER 长度窗口 8..72（尾段必须被 DER 完整消费）。
2. 严格 DER 结构解码（完整消费，无 low-S 假设）。
3. manifest 严格解码：v3 标识符规则、`sidecar_version_major >= 1`、`file_count 1..64`、`host_ui_abi = 1`、`reserved = 0`、记录边界的精确定长、规范路径、严格升序、无重复/大小写折叠碰撞、恰一根 `index.html`（嵌套同名文件是普通合法路径，不额外拒绝）。
4. 本地信任映射（包自带指纹不能自授信）→ 不匹配即 `PUBLISHER_UNTRUSTED`。
5. 对原样 TBS 的 ECDSA P-256/SHA-256 验签 → 失败即 `SIGNATURE_INVALID`。
6. 签名内容交叉检查：`asset_payload_len == Σ(file_len)`、逐文件 SHA-256（恒时比较）；给了 `--native-package` 时再核对原生四元组（含"跨 App"归因），信任级别按 §2 报告（`native_binding_trusted` true=已验签 native / false=未验签 byte-only 比对）。

错误类别沿用 v1 §7 的离线子集：`BAD_PACKAGE`（结构/唯一编码/内部不一致/原生绑定不一致）、`PUBLISHER_UNTRUSTED`（不在本地映射或指纹不符）、`SIGNATURE_INVALID`（验签数学失败）。任何失败都不得冒充已受信 bundle；打包器在写出前用同一独立管线自验，任一拒绝即不出包。

## §7 故障矩阵（AC2；用例名见 `tests/sidecar/neui_cases.py`，逐条断言错误类 + detail 归因子串）

| 族 | 用例 | 期望 |
| --- | --- | --- |
| 篡改（DER 不动） | `tamper_payload_byte`、`tamper_manifest_version`、`tamper_manifest_native_tbs` | `SIGNATURE_INVALID` |
| 篡改（结构先行） | `tamper_manifest_major_structural`（version_major 翻转为 0） | `BAD_PACKAGE`（结构检查先于签名，规范序） |
| 替换/错签 | `wrong_signer_key`（临时密钥签真 TBS）、`tamper_der_byte` | `SIGNATURE_INVALID` |
| 未知发行者/公钥 | `unknown_publisher`（重签+自带指纹）、`publisher_fingerprint_mismatch` | `PUBLISHER_UNTRUSTED` |
| 错原生身份 | `wrong_native_identity`（对另一合法原生交叉核对）、`untrusted_native_byte_only_mismatch`（byte-only 未受信模式仍拒绝异身份字节） | `BAD_PACKAGE` (`native_tbs_sha256`) |
| 跨 App | `cross_app_app_id_mismatch`（重签、`app_id` 不符原生） | `BAD_PACKAGE` (`cross-App`) |
| 重放旧 build / 冲突 / 降级 | `classify_downgrade`、`classify_content_conflict`、`classify_native_rebind` | `DOWNGRADE` / `CONTENT_CONFLICT` / `NATIVE_REBIND`（§5） |
| 错版本 | `version_major_zero`（重签）、`magic_major2` | `BAD_PACKAGE` |
| 非规范路径/遍历 | `path_leading_slash`、`path_trailing_slash`、`path_dotdot_segment`、`path_dot_segment`、`path_backslash`、`path_percent`、`path_colon`、`path_query`、`path_fragment`、`path_non_ascii`、`path_empty_segment`、`path_hidden_dotfile`、`path_nul` | `BAD_PACKAGE` |
| 重复/乱序/碰撞 | `duplicate_paths`、`records_unsorted`、`casefold_collision`、`duplicate_root_index`（两条根 `index.html` 记录） | `BAD_PACKAGE` |
| index.html 规则 | `missing_index`、`nested_index_only`（只有嵌套同名、无根 index） | `BAD_PACKAGE` |
| 记录边界 | `manifest_extra_bytes`、`manifest_truncated_record`、`path_len_zero`、`path_len_161` | `BAD_PACKAGE` |
| 尺寸负值/超限（重签合法签名仍拒） | `file_len_zero`、`file_len_over_cap`、`file_count_zero`、`file_count_65`、`total_payload_over_cap` | `BAD_PACKAGE` |
| 整数溢出（溢出安全解析） | `manifest_len_u32max`、`asset_len_u32max`（另 `manifest_len_zero/127/16385`、`asset_len_zero/2097153`） | `BAD_PACKAGE` |
| 附加尾段 / DER 结构 | `der_trailing_byte`、`der_second_object`、`der_r_zero`、`truncate_der`、`truncate_header`、`truncate_body` | `BAD_PACKAGE` |
| 内容一致性 | `record_sha_mismatch`、`payload_wrong_order`、`payload_sum_mismatch` | `BAD_PACKAGE` |
| 域隔离（双向） | `native_v3_package_on_sidecar_verifier`、`sidecar_bundle_on_v3_verifier` | 双向 `BAD_PACKAGE`（对方 magic） |
| manifest 字段 | `host_ui_abi_2`、`reserved_nonzero`、`publisher_uppercase`、`app_id_bad_padding` | `BAD_PACKAGE` |
| 打包器 fail-closed | `pack_refusal_missing_index`、`pack_refusal_empty_file`、`pack_refusal_oversize_file`、`pack_refusal_total_over_cap`、`pack_refusal_too_many_files`、`pack_refusal_symlink_file`、`pack_refusal_symlink_dir_escape`、`pack_refusal_fifo`、`pack_refusal_version_major_zero`、`pack_refusal_native_not_v3`、`pack_refusal_native_signature_invalid`（只用**已验证**原生 TBS）、`pack_refusal_publisher_mismatch`、`pack_refusal_app_mismatch`、`pack_refusal_signer_key_not_native_publisher`（无关 P-256 钥：§12.1 同一发行者绑定，不产出 bundle/provenance） | 退出码 2，不产出 bundle |
| 正向（无 low-S 假设/幂等/合法嵌套路径） | `low_s_variant_same_identity`、`idempotent_repack_same_identity`、`golden_native_binding_accept`（`native_binding_trusted=true`）、`untrusted_native_byte_only_accept`（`native_binding_checked=true` 且 `native_binding_trusted=false`）、`nested_index_accept`、`pack_accept_nested_index`（根 index + 嵌套 `docs/index.html` 双工具 PASS） | `PASS` / 判别成立 |

## §8 工具与一键复现

| 文件 | 作用 |
| --- | --- |
| `package/sidecar/neui_sidecar_format.py` | Sidecar v1 格式权威 + 独立验真管线 + 安装转移判别（复用 v1/v3 的 DER/SPKI/标识符/信任库原语；Sidecar 解析与判定全部独立实现） |
| `package/sidecar/neui_pack_v1.py` | 打包器：资产树 + 元数据 + 私钥 + **已离线验证的原生 v3 包** → `.neui` + 溯源 sidecar；强制 `--key` 指纹 == native `publisher_key_sha256`（§12.1 同一发行者），写出前用 `--native-trust` 库自验，任一约束违反即拒不出包 |
| `package/sidecar/neui_verify_v1.py` | 离线验真器：`.neui` + 信任库 JSON（可选 `--native-package` 原生绑定交叉核对；给 `--native-trust` 则 native 先完整验签、`native_binding_trusted=true`，不给则为未验签 byte-only 比对、`native_binding_trusted=false`）→ PASS 或 §6 错误类 |
| `tools/sidecar/make_neui_fixture.py` | 确定性非生产 fixture 资产树（`base`/`alt` 变体；**不是**真实 counting UI，无产品主张） |
| `tests/sidecar/neui_cases.py` | 94 项正/负/判别用例（真实 CLI 驱动，逐项类 + 归因断言；产出 `docs/evidence/sidecar-v1/report.json|md`） |
| `tests/sidecar/run_checks.sh` | 一键全流程：先重跑 native v1/v2/v3 与 spec-v2/v3 全套回归（证据先验 clean、跑后逐字节还原），再跑 Sidecar 全套（§10 边界依然适用） |

依赖：`python3`（含 `cryptography`）、`openssl`（native 套件交叉验签）、`arm-none-eabi-gcc`（仅 native 回归需要构建 hello-app）、`git`。

```bash
sh tests/sidecar/run_checks.sh          # 全套：native 回归 + sidecar 全套 + 证据
python3 tests/sidecar/neui_cases.py \
    --work-dir /tmp/neui-work \
    --golden-dir docs/evidence/sidecar-v1   # 仅 sidecar 用例套
```

单次打包/验证示例（fixture 生成 → 打包 → 验真，全部离线）：

```bash
python3 tools/sidecar/make_neui_fixture.py --out-dir /tmp/neui --variant base
python3 package/sidecar/neui_pack_v1.py \
    --asset-root /tmp/neui/base --out /tmp/neui/out.neui \
    --key tests/sidecar/work/keys/d1-test-signer.pem \
    --publisher-id test-publisher --app-id line-crossing --version 1.0.0 \
    --native-package docs/evidence/spec-v3/golden.neapp.v3 \
    --native-trust tests/sidecar/work/trust-d1.json --sidecar none
python3 package/sidecar/neui_verify_v1.py \
    --bundle /tmp/neui/out.neui --trust tests/sidecar/work/trust-d1.json \
    --native-package docs/evidence/spec-v3/golden.neapp.v3 \
    --native-trust tests/sidecar/work/trust-d1.json
```

打包幂等性（AC1）：同内容两次打包的 `ui_tbs_sha256` 逐字节一致（`idempotent_repack_same_identity`）；在钉定工具链下 RFC-6979 使整包字节也一致（golden 复现），协议同时明确允许合法 ECDSA DER 非确定性（同一 TBS 的任何合法 DER 保持同一内容身份）。

## §9 golden 向量（`docs/evidence/sidecar-v1/`）

正向 golden 由**公开** d=1 测试密钥对确定性 base fixture 打包生成（native 绑定 `docs/evidence/spec-v3/golden.neapp.v3` 的已验证 TBS）：

| 可复核量 | 精确值 |
| --- | --- |
| bundle / TBS / DER 长度 | 968 / 896 / 72 B |
| `ui_tbs_sha256` | `aa8130ea20737d457bb6ace49871daa82e85338c7b2e2da656edcc9b7f3fe02f` |
| 整包 `SHA-256`（golden.neui） | `9ec5e44616e197dfa0b3d16a5f9b0f280b523883be2c1cddf4f363126e8f79d4` |
| 固定严格 DER（72B，RFC-6979 d=1，钉定工具链可复现） | `3046022100c6e9b567e1e33db227f7ed17b2fff38d98acc9577f688b43b9d7d9747e5038ae02210089412530ee5653dcf127e8c56968505f3a6aaa87b414a8528fbf5e412751fae9` |
| `publisher_id` / `app_id` / 版本 / `host_ui_abi` | `test-publisher` / `line-crossing` / `1.0.0` / 1 |
| `publisher_key_sha256` | `5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3` |
| `native_tbs_sha256` | `d793a455e3ccda715c8ee9ae95a718cf0fc2627c0ff20969f23e7ea9349b349e`（= 已受审 v3 golden TBS 244B 摘要） |
| 资产（4 文件，base fixture，sha256 见 report.json） | `assets/data.txt` 56B、`css/style.css` 68B、`index.html` 300B、`js/app.js` 129B（payload 553B，manifest 327B） |
| 重建 | `golden-tbs.bin` / `golden-sig.der` 与 golden.neui 的对应切片逐字节一致；每次 `run_checks.sh` 重建并断言 byte-identity |

该向量是**新的**合成非生产 fixture 正向量，**不是**真实 counting UI 的打包产物，**不是**设备/Host 解析器 PASS（§10）。#82 的 Ed25519 `sidecar-probe-v1` 与 tar.gz 试验材料未被用作生产格式。

## §10 没有 PASS 的边界（如实标注；AC4）

本 Issue 与本文**均无以下 PASS**，任何引用不得写成已证明：

1. **NE301 Host 验签/准入/安装**：#83 未实现；本离线 PASS 不等于 Host 能或会接受同一 wire（Host 必须独立核验并按其 install record 判定身份）。`--native-package` 不带 `--native-trust` 的交叉核对只是未验签 byte-only 比对（报告 `native_binding_trusted=false`），不构成受信 native 准入或验签；只有带 `--native-trust` 的核对（`native_binding_trusted=true`）才基于已验签 native。
2. **设备 LittleFS 空闲空间 / RAM**：§4 上限是打包输入最大值，不是板卡可安装承诺；真实 free bytes、GC、峰值 RAM 未知。
3. **双工件事务**：native + Sidecar 跨分区无已证实原子事务；暂存/激活/回滚/掉电恢复全部归 #83。
4. **摄像头 H264 / 视频 / 浏览器可信加载**：#84 未实现；浏览器 HTTP 传输完整性不在本工具范围内（#79 §8）。
5. **User 产品验收**：正式 UI 源仍是 `ne301/counting@de25a6f1`；本任务只用独立小 fixture，未从备份 `people-counting` 构造任何产品依据，也未交付 Sidecar 浏览器 UI（#25）。
6. **生产签发**：未签发任何生产包；未使用任何生产密钥；私有测试密钥只存在于 gitignored 的 `tests/sidecar/work/`（d=1 为公开规范标量）。
