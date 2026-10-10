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

# --- build variant (P3 Issue #6): two independent image identities from one
# audited source.  APP_VERSION=1 (default) keeps the exact Issue #2 V1 build
# (same paths, same flags, same bytes).  APP_VERSION=2 builds the distinct
# V2 identity (new banner, 0x4E46 success code) into its own directory.
APP_VERSION ?= 1
ifeq ($(APP_VERSION),1)
BUILD_DIR       ?= build
IMAGE_NAME      := hello-app.bin
VERSION_CFLAGS  :=
else ifeq ($(APP_VERSION),2)
BUILD_DIR       ?= build-v2
IMAGE_NAME      := hello-app-v2.bin
VERSION_CFLAGS  := -DHELLO_APP_VERSION=2
else
$(error APP_VERSION must be 1 or 2)
endif

ABI_HEADER := $(BUILD_DIR)/cache/app_host_abi.h
ELF        := $(BUILD_DIR)/hello-app$(if $(filter-out 1,$(APP_VERSION)),-v$(APP_VERSION)).elf
PAYLOAD    := $(BUILD_DIR)/hello-app$(if $(filter-out 1,$(APP_VERSION)),-v$(APP_VERSION)).payload.bin
IMAGE      := $(BUILD_DIR)/$(IMAGE_NAME)

CFLAGS := -mcpu=cortex-m55 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard -std=gnu11 \
          -Os -Wall -Werror -ffunction-sections -fdata-sections \
          -ffreestanding -fno-builtin -I$(BUILD_DIR)/cache
LDFLAGS := -nostdlib -T hello_app.ld -Wl,--gc-sections \
           -Wl,-Map,$(BUILD_DIR)/hello-app$(if $(filter-out 1,$(APP_VERSION)),-v$(APP_VERSION)).map

.PHONY: all clean dump

all: $(IMAGE)
	@$(SIZE) $(ELF)
	@echo "hello-app: image ready -> $(IMAGE)"

# The single authoritative ABI header; sha256-locked by the fetch script.
$(ABI_HEADER):
	bash $(TOOLS_DIR)/fetch_abi_header.sh $@

$(ELF): main.c hello_app.ld $(ABI_HEADER)
	$(CC) $(CFLAGS) $(VERSION_CFLAGS) $(LDFLAGS) -o $@ main.c

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

# remove every variant's outputs (used before packaging runs)
cleanall:
	rm -rf build build-v2
