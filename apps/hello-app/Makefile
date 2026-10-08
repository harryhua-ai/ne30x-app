# hello-app — standalone NE301 app-host PoC image build
#
# Standalone: needs only arm-none-eabi-gcc, python3 and network (or a pinned
# local checkout) for the ABI header fetch. `make clean all` from any shell.
#
# Compile ABI must stay identical to the pinned reference
# (ne301 experiment/app-host-poc@a5b4bf3 tests/app_host/testapp/Makefile).

# --- toolchain discovery: PATH first, then the local Arm GNU Toolchain install
CROSS ?= arm-none-eabi-
ifeq ($(shell command -v $(CROSS)gcc 2>/dev/null),)
  FOUND_GCC := $(shell find /Applications/ArmGNUToolchain -type f -name arm-none-eabi-gcc 2>/dev/null | head -n 1)
  ifneq ($(FOUND_GCC),)
    CROSS := $(dir $(FOUND_GCC))arm-none-eabi-
  endif
endif
CC       := $(CROSS)gcc
OBJCOPY  := $(CROSS)objcopy
NM       := $(CROSS)nm
SIZE     := $(CROSS)size
PYTHON   ?= python3

TOOLS_DIR := ../../tools
EXEC_BASE ?= 0x93E00000

BUILD_DIR  ?= build
ABI_HEADER := $(BUILD_DIR)/cache/app_host_abi.h
ELF        := $(BUILD_DIR)/hello-app.elf
PAYLOAD    := $(BUILD_DIR)/hello-app.payload.bin
IMAGE      := $(BUILD_DIR)/hello-app.bin

CFLAGS := -mcpu=cortex-m55 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard -std=gnu11 \
          -Os -Wall -Werror -ffunction-sections -fdata-sections \
          -ffreestanding -fno-builtin -I$(BUILD_DIR)/cache
LDFLAGS := -nostdlib -T hello_app.ld -Wl,--gc-sections \
           -Wl,-Map,$(BUILD_DIR)/hello-app.map

.PHONY: all clean dump

all: $(IMAGE)
	@$(SIZE) $(ELF)
	@echo "hello-app: image ready -> $(IMAGE)"

# The single authoritative ABI header; sha256-locked by the fetch script.
$(ABI_HEADER):
	bash $(TOOLS_DIR)/fetch_abi_header.sh $@

$(ELF): main.c hello_app.ld $(ABI_HEADER)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ main.c

$(PAYLOAD): $(ELF)
	$(OBJCOPY) -O binary $< $@

$(IMAGE): $(PAYLOAD) $(ABI_HEADER)
	$(PYTHON) $(TOOLS_DIR)/pack_app_image.py \
		--elf $(ELF) --payload $(PAYLOAD) --out $@ \
		--abi-header $(ABI_HEADER) --nm $(NM) --objcopy $(OBJCOPY) \
		--exec-base $(EXEC_BASE)

dump: $(ELF)
	@$(CROSS)objdump -d $(ELF)

clean:
	rm -rf $(BUILD_DIR)
