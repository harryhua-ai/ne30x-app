
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

APP_DIR   := ..
ROOT_DIR  := ../../..
APP_MK_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
BUILD     ?= build
ELF       := $(BUILD)/lc-line-crossing.elf
PAYLOAD   := $(BUILD)/lc-line-crossing.payload.bin
IMAGE     := $(BUILD)/lc-line-crossing.bin

EXEC_BASE ?= 0x93E00000

APP_ID       ?= line-crossing
PKG_VERSION  ?= $(V4_APP_VERSION)

CORE_SRCS := $(APP_DIR)/src/lc_tracker.c $(APP_DIR)/src/lc_line_cross.c

LC_ALLOC_FLAGS := -D'LC_MALLOC(sz)=lcapp_alloc(sz)' -D'LC_FREE(p)=lcapp_free(p)'

CFLAGS = -mcpu=cortex-m55 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard -std=gnu11 \
          -Os -Wall -Werror -ffunction-sections -fdata-sections \
          -ffreestanding -fno-builtin -DLC_APP_TARGET=1 \
          -DLC_APP_ID='"$(APP_ID)"' -DLC_APP_SW_VERSION='"$(PKG_VERSION)"' \
          $(LC_ALLOC_FLAGS) \
          -include $(APP_MK_DIR)lc_arena.h \
          -I$(APP_DIR)/include -I.
LDFLAGS := -nostdlib -T lc_app.ld -Wl,--gc-sections \
           -Wl,-Map,$(BUILD)/lc-line-crossing.map -lgcc

.DEFAULT_GOAL := all
.PHONY: all clean
all: elf-v4
clean:
	rm -rf $(BUILD)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/core_%.o: $(APP_DIR)/src/%.c $(wildcard $(APP_DIR)/include/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

V4_APP_VERSION ?= 4.2.14
V4_ELF := $(BUILD)/lc-line-crossing-v4.elf
V4_APP_SRCS := lc_app_entry_v4.c lc_bus.c lc_bus_config.c lc_stateblob.c \
               lc_ctrl.c lc_cfgcodec.c lc_json.c lc_arena.c lc_libc_mini.c \
               lc_lvn4.c
V4_OBJS := $(patsubst $(APP_DIR)/src/%.c,$(BUILD)/core_%.o,$(CORE_SRCS)) \
           $(patsubst %.c,$(BUILD)/v4_%.o,$(V4_APP_SRCS))

.PHONY: elf-v4 clean-v4

$(BUILD)/v4_%.o: PKG_VERSION = $(V4_APP_VERSION)

$(BUILD)/v4_%.o: %.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(V4_ELF): $(V4_OBJS) lc_app.ld
	$(CC) $(CFLAGS) -o $@ $(V4_OBJS) $(LDFLAGS)

elf-v4: $(V4_ELF)
	@echo "line-crossing-app: v4 ELF ready -> $(V4_ELF)"

clean-v4:
	rm -f $(V4_OBJS) $(V4_ELF)

V5_UI_DIR ?= $(ROOT_DIR)/tests/line-crossing-ui/.build/production
V5_OUT_DIR ?= $(BUILD)/pkg
V5_UI_VERSION ?= 1.2.17
# User-facing product version line (1.0.x): strictly monotonic. The internal Native/UI lines keep increasing independently and
# never decrease; they remain in provenance/diagnostics only.
V5_PRODUCT_VERSION ?= 1.0.3
V5_HOST_CAPS ?= 0x3ff
V5_EVENT_MAX ?= 1576
V5_STATE_QUOTA ?= 512
V5_REPORT_MAX ?= 6144
V5_CONTROL_MAX ?= 512
V5_SNAPSHOT_MAX ?= 1024
V5_LIVE_PUBLISH_MAX ?= 9008
V5_LIVE_TRACK_MAX ?= 64
# Simulated admission mask of a product-version-capable Host (base 0x3ff +
# CAP_PRODUCT_VERSION bit 0x400). Current Hosts (0x3ff) refuse the package.
V5_VERIFY_HOST_CAPS ?= 0x7ff
# Explicit provenance commit (set by package/release/build_neapp.sh); empty
# lets the packer detect the git HEAD of the checkout it runs in.
V5_SOURCE_COMMIT ?=

.PHONY: neapp-v5

neapp-v5: $(V4_ELF)
	mkdir -p $(V5_OUT_DIR)
	$(PYTHON) $(ROOT_DIR)/package/unsigned/neapp_pack_v5.py \
		--elf $(V4_ELF) --ui-assets $(V5_UI_DIR) \
		--out $(V5_OUT_DIR)/line-crossing-$(V5_PRODUCT_VERSION).neapp \
		--app-id $(APP_ID) --native-version $(V4_APP_VERSION) --ui-version $(V5_UI_VERSION) \
		--product-version $(V5_PRODUCT_VERSION) \
		$(if $(V5_SOURCE_COMMIT),--source-commit $(V5_SOURCE_COMMIT),) \
		--host-caps $(V5_HOST_CAPS) --event-max $(V5_EVENT_MAX) \
		--state-quota $(V5_STATE_QUOTA) --report-max $(V5_REPORT_MAX) \
		--control-max $(V5_CONTROL_MAX) --snapshot-max $(V5_SNAPSHOT_MAX) \
		--live-publish-max $(V5_LIVE_PUBLISH_MAX) --live-track-max $(V5_LIVE_TRACK_MAX)
	$(PYTHON) $(ROOT_DIR)/package/unsigned/neapp_verify_v5.py \
		--package $(V5_OUT_DIR)/line-crossing-$(V5_PRODUCT_VERSION).neapp \
		--host-caps-hex $(V5_VERIFY_HOST_CAPS) --compact

clean-v5:
	rm -rf $(V5_OUT_DIR)

.PHONY: print-v4_app_version print-v5_ui_version print-v5_product_version
print-v4_app_version:
	@echo $(V4_APP_VERSION)
print-v5_ui_version:
	@echo $(V5_UI_VERSION)
print-v5_product_version:
	@echo $(V5_PRODUCT_VERSION)
