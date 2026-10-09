# P3 — 可信 .neapp 签名打包与离线验真（Issue #6）

本文说明 ne30x-app 的 `.neapp` v1 打包器、离线验真器、受支持输入约束、
签名密钥纪律、hello-app V1→V2 可追溯替换证据，以及 P2 规范测试向量与
本仓库测试用例的逐一对应关系。

**协议唯一权威**：[docs/app-package-protocol-v1.md](app-package-protocol-v1.md)
（已集成 `ne30x-app/main` 的 P2 规范）。本文只是工具说明，不另建任何字节
格式；打包端与验真端共享同一实现模块 `package/neapp_format.py`，其正确性
不由"共用代码"自证，而由规范 §2.5 冻结向量的逐字节重建与预期判别证明
（见 §7）。

**边界声明（重要）**：本仓库的离线打包与离线验真**只证明生成与判别**。
PASS 不等于设备已完成安装、执行、断电恢复，也不等于设备端真实验签
（STM32/mbedTLS/PKA 属 P4 #29）。开发测试签名身份是**非生产可信根**，
不得用于任何真实发行。

## 1. 包格式摘要（细节以 P2 规范为准）

容器（§2.2）与 manifest（§2.3）的唯一 v1 编码：

```text
偏移 0..7    magic  4E 45 41 50 50 01 00 00   ("NEAPP", 容器主版本 1, 2×0x00)
偏移 8..11   manifest_len  u32-le             v1 唯一合法值 160
偏移 12..15  image_len     u32-le             ≥ 32（原生头），≤ 2,097,152
偏移 16..    manifest 160B 定长（NMF1 / publisher_id 16B / app_id 32B /
             版本 3×u16-le / 保留 2B×00 / board 0x00003010 / PSRAM 64 /
             ABI 0x00010000 / caps bit0=log bit1=tick_ms / 驻留量 /
             native_file_len / native_image_size / entry_offset /
             target_addr / native_file_sha256 / publisher_key_sha256）
紧接 manifest 原生镜像原样字节（32B NEA1 头 + payload，含 CRC32）
文件末尾     恰好一个严格 DER ECDSA-Sig-Value（8–72B，完整消费，无尾部）

TBS = 文件 [0 : 16+160+image_len]；签名 = ECDSA over secp256r1 (P-256)，
SHA-256(TBS)，严格 DER；v1 不因 high-S 拒绝。
幂等内容身份 = SHA-256(TBS)（不是整包摘要）。
整包上限 2,097,400 B。
```

## 2. 工具与调用

| 文件 | 作用 |
| --- | --- |
| `package/neapp_format.py` | 共享格式权威：全部 v1 常量、160B manifest 编解码、原生 32B 头解析、严格 DER/SPKI 解析、信任库、离线设备策略替身、`verify_package` 检查管线（§7.1 判定顺序） |
| `package/neapp_pack.py` | 打包器：镜像 + 元数据 + 私钥 → `.neapp` + 溯源 sidecar；写入前自验，任一约束违反即拒不出包 |
| `package/neapp_verify.py` | 离线验真器：`.neapp` + 信任库 JSON（+ 可选设备策略 JSON）→ PASS 或 §7 错误类 |
| `tests/package/gen_dev_key.py` | 每次测试生成非生产 P-256 开发签名身份（gitignored） |
| `tests/package/spec_vectors.py` | 逐字节重建 P2 §2.5 全部冻结向量并断言判别结果 |
| `tests/package/generated_cases.py` | 本地生成结构/DER/策略正负用例 |
| `tests/package/run_package_checks.sh` | 一键全流程（构建→打包→验真→全向量→证据） |

打包：

```bash
python3 package/neapp_pack.py \
  --image apps/hello-app/build/hello-app.bin \
  --out hello-app-v1.neapp \
  --key /path/to/dev-signer.pem \
  --publisher-id dev-publisher --app-id hello-app --version 1.0.0
```

验真：

```bash
python3 package/neapp_verify.py \
  --package hello-app-v1.neapp --trust trust-dev.json [--policy policy.json] \
  [--expect PASS|BAD_PACKAGE|SIGNATURE_INVALID|PUBLISHER_UNTRUSTED|\
            TARGET_INCOMPATIBLE|ABI_INCOMPATIBLE|RESOURCE_LIMIT]
```

信任库 JSON：`{"version":1,"publishers":{"<publisher_id>":{"spki_der_hex"|
"spki_der_file", "spki_sha256"}}}`。公钥材料只来自**本地配置**（离线替身
对应设备内置信任锚），绝不采信包内自带公钥（§4.1：不得自授信）。
可选 `--policy` 覆盖 board/PSRAM/ABI/caps/执行区大小（默认值即 §2.3/§2.4
实验基线：board `0x3010`、64 MiB、ABI `0x00010000`、caps 3、执行基址
`0x93E00000`、执行区 2 MiB）。

一键复现：

```bash
bash tests/package/run_package_checks.sh
```

## 3. 受支持输入约束

打包器接受的输入 = `tools/pack_app_image.py` 产出的原生镜像文件
（32B NEA1 头 + payload），且必须满足 v1 全部硬约束，否则拒绝打包：

- 原生头：`NEA1`、`header_size==32`（精确）、`format_version==1`、
  `abi_version==0x00010000`、`reserved0==0`、`entry_offset` 偶数且
  `< image_size`、`target_addr==0x93E00000`、payload CRC-32 匹配。
- 元数据：`publisher_id` 1–16B、`app_id` 1–32B，字符集 `[a-z0-9-]`、
  小写字母开头、字母/数字结尾；版本三段各 0–65535；caps 仅 bit0/bit1；
  board 仅 `0x3010`；PSRAM 仅 64（v1 证据只支持 64 MiB 板型）。
- 容量：`native_file_len ≤ 2,097,152`；`required_exec_region_bytes ≥
  image_size` 且 ≤ 2 MiB；整包 ≤ 2,097,400 B。

hello-app 镜像由既有流程构建（`make -C apps/hello-app clean all`，ABI 经
`tools/fetch_abi_header.sh` pinned 锁定；V2 用 `APP_VERSION=2`）。

## 4. 签名密钥纪律（AC3）

- 开发/测试签名身份由 `tests/package/gen_dev_key.py` 在**测试时**生成
  （P-256），私钥 PEM 只写入 `tests/package/work/keys/`（gitignored、
  0600），**绝不入仓、绝不打印**。
- manifest 只携带 `SHA-256(SPKI DER)` 身份指纹；溯源 sidecar 同样只含
  指纹与公开哈希。
- 全部产物与文档明确标注：**非生产可信根**（non-production trust root）。
  P2 §2.5 的公开测试钥（d=1）仅用于逐字节重建规范向量，同样非生产根。
- 溯源 sidecar（`*.provenance.json`，随包生成）：包/TBS/镜像 SHA-256、
  manifest 全字段、签名算法与确定性（RFC-6979）、签名者 SPKI 指纹、
  来源 commit。内容完全确定，无时间戳，两次 clean build 逐字节一致。

## 5. hello-app V1/V2 与可追溯替换证据（AC1/AC4）

- **V1**：`make -C apps/hello-app clean all`。本轮在 `main.c`/`Makefile`
  中加入了 V1/V2 变体开关（预处理后 V1 翻译单元与 Issue #2 完全一致），
  构建锚定既有源码与 Arm GNU 15.2.Rel1，重建结果与 Issue #2 历史记录
  **逐字节一致**：
  608 B，`sha256 d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03`
  （`tests/package/run_package_checks.sh` 步骤 [2/9][3/9] 硬断言）。
- **V2**：`make -C apps/hello-app clean all APP_VERSION=2`。源码单点变更
  （`HELLO_APP_VERSION=2`：banner `hello-app v2: …`、成功码 `0x4E46`），
  608 B，本次构建
  `sha256 e8526a1ab0500a49b23d09fabf2f3664823b55de99bef301fe816d39d5041bfd`。
  **登记为新的实验工件**：历史 v2（设备证据 `db1c6d60…`）的源码改动未入
  仓、原始 608B 不可得，本套件显式断言不冒充该哈希（P2 §2.6 要求）。
- **包层替换证据**（`generated_cases.py: v1_to_v2_traceable_replacement`）：
  同一 `publisher_id + app_id`，版本 `1.0.0 → 2.0.0`，包内容身份
  `SHA-256(TBS)` 与镜像 `SHA-256` 均不同——身份/版本/摘要三元证据满足
  §3.1 升级语义判定所需输入。
- **版本冲突/重放/降级策略证据**（AC3）：
  - 幂等：同镜像同元数据重打包 → `SHA-256(TBS)` 相同（确定性 RFC-6979
    下连包字节都一致）；不同合法 DER（high-S/low-S）共享同一内容身份。
  - 内容冲突判别：同身份同版本不同内容 → `SHA-256(TBS)` 不同
    （`v2-image-as-1.0.0` 包 vs V1 包），即设备侧
    `VERSION_CONTENT_CONFLICT` 分类的离线判别输入；降级判定同理由
    包内版本三元组 + 内容身份提供。设备侧状态与拒绝执行归 P4。

## 6. 离线验证 ≠ 设备结果

`neapp_verify.py` 的 PASS 仅表示：结构合法、发行者在本地信任映射、
签名对 TBS 有效、签名内容自洽、离线策略兼容。它**不**表示：

1. 设备已完成安装或曾执行该包；
2. 设备端（STM32/mbedTLS/PKA）验签行为一致；
3. 断电/提交失败后的旧版本/新版本完整性；
4. 签名代码无漏洞或沙箱隔离（无此机制）。

错误类的设备侧语义（`STORAGE_STATE_UNKNOWN`、`BUSY`、安装事务等）由
P2 §5/§7 与 P4 任务收敛；本工具只覆盖 §7 离线子集。

## 7. P2 规范向量 → 测试用例对应表

冻结向量（规范 §2.5）由 `tests/package/spec_vectors.py` **逐字节重建**，
每个重建包的 SHA-256 与规范发表值硬断言一致（`hash_matched_spec=true`），
再经 `package/neapp_verify.py --expect` 判别：

| P2 §2.5 向量（规范发表 SHA-256） | 期望 | 测试用例 | 结果 |
| --- | --- | --- | --- |
| `golden.neapp`（`9a212324…`，TBS `5035e651…`） | 通过 | `golden_accept` | PASS |
| 同 TBS low-S DER（s→n-s）（`99469a83…`） | 通过且内容身份不变 | `golden_low_s_accept` | PASS，`SHA-256(TBS)` 与 golden 相等 |
| `der_70byte_valid.neapp`（`2fcbeb5b…`） | 通过 | `der_70byte_valid_accept` | PASS |
| `der_tail_within_72byte_limit.neapp`（`ab839127…`，70B DER+`FF`，71B 段） | 拒绝（DER 完整消费） | `der_tail_within_72byte_limit` | BAD_PACKAGE |
| 原生头 `reserved0≠0`、摘要修正、重签（`585f5f61…`） | 正确签名仍须拒绝 | `native_reserved0_signed_reject` | BAD_PACKAGE |
| 72B DER 追加 1 字节（`4ceeff8e…`） | 拒绝（73B 越限） | `golden_der_73byte_reject` | BAD_PACKAGE |
| `manifest_uppercase_app_id`（`bee6d613…`） | BAD_PACKAGE | 同名 | BAD_PACKAGE |
| `manifest_reserved_nonzero`（`32529b60…`） | BAD_PACKAGE | 同名 | BAD_PACKAGE |
| `wrong_board_signed`（`a9e82949…`） | TARGET_INCOMPATIBLE | 同名 | TARGET_INCOMPATIBLE |
| `untrusted_key_fingerprint`（`45590d25…`） | PUBLISHER_UNTRUSTED | 同名 | PUBLISHER_UNTRUSTED |
| `native_header_size_33`（`97b2f926…`） | BAD_PACKAGE | 同名 | BAD_PACKAGE |
| `native_entry_offset_oob`（`9b4d74a6…`） | BAD_PACKAGE | 同名 | BAD_PACKAGE |
| `mismatched_manifest_native_len`（`f8cccc3c…`） | BAD_PACKAGE | 同名 | BAD_PACKAGE |
| "同一合法镜像/manifest 受信签名"正例要求 | 打包端正例 | `dev_v1_accept` / `dev_v2_accept`（dev 钥打包 + PASS） | PASS |
| "已签名内容被篡改 `d415350f…`"（规范只发表哈希，字节不可重建） | SIGNATURE_INVALID | 本地等价 `tamper_payload` / `tamper_manifest_version` | SIGNATURE_INVALID |
| "同 TBS 不同合法 DER `5af8dff5…`"（同上，字节不可重建） | 通过且同内容身份 | 等价性质由 `golden_accept`+`golden_low_s_accept` 覆盖（两个合法 DER、同一 `SHA-256(TBS)`、不同包哈希） | PASS |

规范 §2.3/§7.1 要求、由 `tests/package/generated_cases.py` 补充的本地
负例（全部 30 项见 `docs/evidence/p3-package-artifacts.json`）：

| 类别 | 用例（期望类） |
| --- | --- |
| 签名覆盖 | `tamper_payload`、`tamper_manifest_version`、`wrong_signer_key`（SIGNATURE_INVALID） |
| 容器结构 | `truncate_signature`、`truncate_whole_package`、`append_tail_byte`、`manifest_len_159`、`manifest_len_zero`、`image_len_below_header`、`image_len_overflow`、`magic_corrupted`（BAD_PACKAGE） |
| DER 编码 | `der_second_object`、`der_r_zero`、`der_nonminimal_length`（BAD_PACKAGE） |
| manifest 唯一编码（重签仍拒） | `app_id_nonzero_padding`、`app_id_embedded_nul`、`caps_unknown_bit_signed`、`abi_manifest_header_mismatch_signed`（BAD_PACKAGE） |
| 重签后策略拒绝 | `board_0x3011_signed`、`psram_32_signed`（TARGET_INCOMPATIBLE）；`abi_wrong_everywhere_signed`（ABI_INCOMPATIBLE）；`entry_odd_signed`（BAD_PACKAGE）；`exec_region_overcommit_signed`（RESOURCE_LIMIT）；`unknown_publisher`（PUBLISHER_UNTRUSTED） |
| 装载临时量 vs 运行驻留量 | `native_file_overrides_small_region`（golden 包，策略执行区 32B → RESOURCE_LIMIT：`native_file_len=36` 超装载预算，即使驻留声明仅 4B） |
| 版本/身份证据 | `repack_same_content_identity`、`v1_to_v2_traceable_replacement`、`version_content_conflict_discriminator` |

## 8. 证据与复现

```bash
bash tests/package/run_package_checks.sh    # 一键：[1/9]..[9/9]
bash tests/run_build_checks.sh              # 既有 #2 构建验收（回归）
```

- 结构化证据：`docs/evidence/p3-package-artifacts.json`
  （镜像/包哈希、验真报告、两组向量套件结果、密钥纪律声明）。
- 全流程控制台输出：`docs/evidence/p3-package-checks.log`。
- 每次运行重新生成 dev 身份，故 dev 包字节随运行变化（确定性 RFC-6979
  签名下同密钥重打包字节一致；密钥本身每轮更换）。规范冻结向量的哈希
  断言与运行无关，逐字节固定。
