# fs-manifests — LittleFS 内容级对照（Issue #2 AC3 整改证据，2026-10-08）

本目录由 `tools/fs_manifest.c`（只读挂载 littlefs、遍历整卷、逐文件输出
`path|size|sha256`）生成，用于证明：**pristine 备份中的原有文件在最终注入镜像中
逐一保留（内容哈希相同），仅新增 /apps/ 下 5 个测试文件**。

## 清单文件

| 文件 | 对应镜像 | 镜像 SHA256 | 规模 |
|---|---|---|---|
| [pristine_backup.manifest](pristine_backup.manifest) | `backup_littlefs.bin`（刷写前 pristine 全量备份，96MB） | `1a8b3c69003bb94c5509bbc9f299e24643eb68325dd241dc54c125dec8acf1cd` | 885 files / 25 dirs / 13,323,928 B |
| [injected_v2.manifest](injected_v2.manifest) | `lfs_injected_v2.img`（最终注入并整卷写入设备的镜像，96MB） | `45c6a4086ca1c49187bb4d1f4d7c58d60360edc26eec47199d778e882f6c43e1` | 890 files / 25 dirs / 13,326,968 B |
| [device_state_before_full_write.manifest](device_state_before_full_write.manifest) | `lfs_current.bin`（二次修复失败、固件静默格式化之后、整卷写入之前的设备状态快照，96MB） | `3edfff8b29aab3467ce90e00bf7cb9e9ee5af41b524135b2fbbdd4d8d65d75d2` | 11 files / 8 dirs / 167,377 B |
| [pristine_vs_injected.diff](pristine_vs_injected.diff) | 上述前两清单的 diff | — | 结论见下 |

`device_state_before_full_write.manifest` 是事故（首轮注入损坏 + 二次修复失败 +
静默格式化，见 device-evidence.md「事故记录」）后、最终整卷写入前的设备真实状态，
作为失败路径证据一并留存。

## 结论（pristine vs 最终注入镜像）

- **885 个原有文件逐一保留**：diff 中内容行（`path|size|sha256`）零删改——每个
  原有文件的路径、大小、内容 SHA256 与 pristine 备份完全一致（含 counting 演示
  数据：根目录 `/aicam.log*` 3 个日志文件、`/apps/apphost_test.bin` 与
  `/apps/apphost_corrupt.bin`、`/captures/data/…` 下 880 个抓拍 JPEG）。
- **仅新增 5 个测试文件**，全部位于 `/apps/`，均 608 B，哈希与 /tmp 构建产物一致：

| 新增文件 | SHA256 | 与构建产物一致性 |
|---|---|---|
| `/apps/hello_v1.bin` | `d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03` | == 构建 hello_v1.bin |
| `/apps/hello_v2.bin` | `db1c6d60b398cab11a276e15770fdcdf9d42b9c96b4de6ef2cc93c1ecdec8744` | == 构建 hello_v2.bin |
| `/apps/bad-crc32.bin` | `e2719ee39fba779681a72fe70276fd4740cbd37bca00092377d8c20a034611c6` | == bad/bad-crc32.bin |
| `/apps/bad-abi-version.bin` | `5d7b4c123e7b70eb03eb01cf2db624a5fd7f536c0e6bda9fb9faaf1e1a8d99d7` | == bad/bad-abi-version.bin |
| `/apps/bad-target-address.bin` | `77e94139c6ed7b938463ed5c17165f481a9f43e4030279a07460202c758390cf` | == bad/bad-target-address.bin |

## 生成方法（可复现）

工具源码：`tools/fs_manifest.c`（输入镜像只读读入内存，任何 prog/erase 请求即硬
错误；几何参数与设备一致：block_size=4096（pinned `Custom/Hal/storage.h:18`）、
read/prog/cache=1024（`storage.h:26`、`storage.c:488-493`）、lookahead=3072；
read/prog/cache 尺寸不影响 littlefs 落盘布局）。littlefs 源码取自 PoC Host 构建树
（与生成 `lfs_injected_v2.img` 的 lfstool 同源）。

```sh
cc -O2 -Wall \
  -I /tmp/ne301-host-build/Custom/Common/Lib/littlefs \
  -I /tmp/ne301-host-build/tests/app_host/lfstool/shim \
  -o /tmp/fs_manifest tools/fs_manifest.c \
  /tmp/ne301-host-build/Custom/Common/Lib/littlefs/lfs.c \
  /tmp/ne301-host-build/Custom/Common/Lib/littlefs/lfs_util.c

/tmp/fs_manifest /tmp/ne301-board-backup/backup_littlefs.bin  pristine_backup > pristine_backup.manifest
/tmp/fs_manifest /tmp/ne301-poc-evidence/lfs_injected_v2.img  final_injected  > injected_v2.manifest
/tmp/fs_manifest /tmp/ne301-poc-evidence/lfs_current.bin      pre_full_write  > device_state_before_full_write.manifest
diff pristine_backup.manifest injected_v2.manifest
```

两个输入镜像的 SHA256 均写在各自清单的 `# image_sha256=` 行（自校验），与
`/tmp/ne301-board-backup/BACKUP_SHA256.txt`（pristine）及本整改对
`/tmp/ne301-poc-evidence/` 的独立计算（注入镜像）一致。
