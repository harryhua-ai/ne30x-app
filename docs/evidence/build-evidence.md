# 构建证据 — hello-app 独立构建（Issue #2, AC1 + AC3 构建侧静态证据）

本文所有输出均为 2026-10-08 在 macOS (darwin 24.6.0, arm64) 上实际运行
`bash tests/run_build_checks.sh` 及相关命令的粘贴结果，非手写编造。

## 0. 环境与源码版本

```
$ git rev-parse HEAD            # 代码提交（apps/tools/tests 引入提交）
07724f1f98a3a4151c61b876861a7e0e64539975
$ git branch --show-current
agent/2/50117b15

$ arm-none-eabi-gcc --version | head -1
arm-none-eabi-gcc (Arm GNU Toolchain 15.2.Rel1 (Build arm-15.86)) 15.2.1 20251203
$ python3 --version
Python 3.14.4
```

ABI 权威：`harryhua-ai/ne301` `experiment/app-host-poc` pinned
`a5b4bf3dd25931d612680aff200e4e0ac8d8e64e`，头
`Custom/Common/Inc/app_host_abi.h`，sha256
`9337f684893cf2a06aea6f6f8c448708d91e8f9c6c86c24905ced8a7d5df23f4`。

## 1. 完整检查套件（bash tests/run_build_checks.sh，实际输出）

```
== [1/5] clean build (fetches pinned ABI header)
make: Entering directory '.../apps/hello-app'
rm -rf build
bash ../../tools/fetch_abi_header.sh build/cache/app_host_abi.h
fetch_abi_header: OK (local pinned checkout /tmp/ne301-pinned-ro) -> build/cache/app_host_abi.h
  pinned harryhua-ai/ne301@a5b4bf3dd25931d612680aff200e4e0ac8d8e64e:Custom/Common/Inc/app_host_abi.h
  sha256 9337f684893cf2a06aea6f6f8c448708d91e8f9c6c86c24905ced8a7d5df23f4
arm-none-eabi-gcc -mcpu=cortex-m55 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard -std=gnu11 -Os -Wall -Werror -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -Ibuild/cache -nostdlib -T hello_app.ld -Wl,--gc-sections -Wl,-Map,build/hello-app.map -o build/hello-app.elf main.c
arm-none-eabi-objcopy -O binary build/hello-app.elf build/hello-app.payload.bin
python3 ../../tools/pack_app_image.py \
	--elf build/hello-app.elf --payload build/hello-app.payload.bin --out build/hello-app.bin \
	--abi-header build/cache/app_host_abi.h --nm arm-none-eabi-nm --objcopy arm-none-eabi-objcopy \
	--exec-base 0x93E00000
packed build/hello-app.bin: header 32 B + payload 576 B = 608 B, entry_offset 0x50, crc32 0x1eb77cb6, abi 0x00010000, target 0x93e00000
   text	   data	    bss	    dec	    hex	filename
    576	      0	      0	    576	    240	build/hello-app.elf
hello-app: image ready -> build/hello-app.bin
make: Leaving directory '.../apps/hello-app'

== [2/5] validate packed image (must be VALID)
VALID: file=608 payload=576 target=0x93e00000 entry_offset=0x50 abi=0x00010000 crc32=0x1eb77cb6

== [3/5] reproducibility: rebuild from clean, require identical sha256
reproducible OK: sha256 d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03

== [4/5] generate corrupt-image fixtures
wrote .../build/bad-images/bad-magic.bin (expect rejection: magic, crc32 0x1eb77cb6)
wrote .../build/bad-images/bad-header-size.bin (expect rejection: header-size, crc32 0x1eb77cb6)
wrote .../build/bad-images/bad-format-version.bin (expect rejection: format-version, crc32 0x1eb77cb6)
wrote .../build/bad-images/bad-abi-version.bin (expect rejection: abi-version, crc32 0x1eb77cb6)
wrote .../build/bad-images/bad-target-address.bin (expect rejection: target-address, crc32 0x1eb77cb6)
wrote .../build/bad-images/bad-image-size.bin (expect rejection: image-size, crc32 0x1eb77cb6)
wrote .../build/bad-images/bad-entry-offset.bin (expect rejection: entry-offset, crc32 0x1eb77cb6)
wrote .../build/bad-images/bad-crc32.bin (expect rejection: crc32, crc32 0x33b5933b)

== [5/5] every fixture must be rejected for its expected reason
REJECTED as expected: abi-version (abi version mismatch) — .../bad-images/bad-abi-version.bin
REJECTED as expected: crc32 (crc mismatch) — .../bad-images/bad-crc32.bin
REJECTED as expected: entry-offset (entry offset invalid) — .../bad-images/bad-entry-offset.bin
REJECTED as expected: format-version (format version unsupported) — .../bad-images/bad-format-version.bin
REJECTED as expected: header-size (header size invalid) — .../bad-images/bad-header-size.bin
REJECTED as expected: image-size (image size out of bounds) — .../bad-images/bad-image-size.bin
REJECTED as expected: magic (bad magic) — .../bad-images/bad-magic.bin
REJECTED as expected: target-address (target address mismatch) — .../bad-images/bad-target-address.bin

== ALL BUILD CHECKS PASSED
image   .../apps/hello-app/build/hello-app.bin
sha256  d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03
size    608 bytes
```

（套件退出码 0；`.../` 为仓库根路径缩写。）

## 2. 产物尺寸与哈希

```
$ wc -c apps/hello-app/build/hello-app.bin apps/hello-app/build/hello-app.payload.bin
     608 apps/hello-app/build/hello-app.bin
     576 apps/hello-app/build/hello-app.payload.bin

$ shasum -a 256 apps/hello-app/build/hello-app.bin
d6eec431c6c17b84770263ce8e8a9d386f9e798d14024f4452f090c87c6e2d03  apps/hello-app/build/hello-app.bin
$ shasum -a 256 apps/hello-app/build/hello-app.elf
0d0e5c08eafd55bd3b8f8642b17af0d1a61b0bc8f97806fd7075e35cff4c7da7  apps/hello-app/build/hello-app.elf
$ shasum -a 256 apps/hello-app/build/hello-app.payload.bin
cc0269e71201d987e6e5837274f5d0f0d9b65d6cd5642bb8c3f084ba0cb01ef5  apps/hello-app/build/hello-app.payload.bin
```

## 3. 镜像头与符号复核

```
$ xxd -l 32 apps/hello-app/build/hello-app.bin
00000000: 4e45 4131 2000 0100 0000 0100 0000 e093  NEA1 ...........
00000010: 4002 0000 5000 0000 0000 0000 b67c b71e  @...P........|..
# magic=0x3141454E("NEA1") header_size=32 format=1 abi=0x00010000
# target=0x93E00000 image_size=0x240=576 entry_offset=0x50 reserved=0 crc32=0x1EB77CB6

$ arm-none-eabi-nm -g apps/hello-app/build/hello-app.elf
93e00050 T app_entry

$ arm-none-eabi-objdump -h apps/hello-app/build/hello-app.elf   # 摘录
  0 .text         00000240  93e00000  93e00000  00001000  2**2
  1 .data         00000000  93e00240  93e00240  00001240  2**0
  2 .bss          00000000  93e00240  93e00240  00000000  2**0
```

入口首指令为 Thumb `push {r4, r5, r6, lr}`（`b570`），防御检查编译结果：
`cmp r3, #15`（table_size < 16）、`cmp.w r1, #65536`（abi 精确比较）、
对 `[r0,#8]`/`[r0,#12]` 的 NULL 判断。busy wait 编译为 M55 硬件循环
（`dls`/`le`，2,000,000 次迭代）。

## 4. fetch_abi_header.sh 纯网络路径

禁用本地 pinned 检出后单独验证（重建缓存目录）：

```
$ rm -rf apps/hello-app/build/cache
$ NE301_PINNED_RO=/tmp/nonexistent bash tools/fetch_abi_header.sh \
    apps/hello-app/build/cache/app_host_abi.h
fetch_abi_header: OK (raw.githubusercontent.com) -> apps/hello-app/build/cache/app_host_abi.h
  pinned harryhua-ai/ne301@a5b4bf3dd25931d612680aff200e4e0ac8d8e64e:Custom/Common/Inc/app_host_abi.h
  sha256 9337f684893cf2a06aea6f6f8c448708d91e8f9c6c86c24905ced8a7d5df23f4
```

## 5. 覆盖的 AC 与边界

- **AC1（构建侧）**：可重复独立构建成立（步骤 [3/5] 两次 clean build 镜像
  sha256 一致）；ABI/板型/入口约束/产物尺寸/源码版本已在
  `docs/app-hello-poc.md` 明示；构建未编辑 ne301 工作树，未链接/复制任何
  平台私有实现（仅 pinned 单头经 fetch 脚本消费）。
- **AC3（构建侧静态证据）**：8 种坏镜像全部按 Host 同序拒绝码预期拒绝
  （步骤 [5/5]）；真机拒绝路径用例与预期设备日志对照见
  `docs/app-hello-poc.md` 第 7 节。**真机项（AC2/设备侧 AC3）未验证，
  由协调者在受权设备上执行。**
