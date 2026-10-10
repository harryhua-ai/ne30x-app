# line-crossing-app — native v2-ABI build + signed v2 package (Issue #11).
#
# Targets:
#   make image     -> build/lc-line-crossing.bin (32B NEA1 v2 header + payload)
#   make package   -> dev-key signed .neapp.v2 + neapp_verify_v2.py offline
#                     verify (keys/packages under tests/line-crossing-app/work/,
#                     gitignored; the signing identity is NON-PRODUCTION and
#                     generated per run by tests/package/gen_dev_key.py)
#   make clean
#
# Core library sources (../src, ../include) are compiled unmodified — the
# equivalence suite in tests/line-crossing remains the regression authority.

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

# --- v2 packaging inputs (spec §4.1 counting-compatible declaration) -------
PUBLISHER_ID ?= dev-publisher
APP_ID       ?= line-crossing
PKG_VERSION  ?= 1.0.0
HOST_CAPS    ?= 0x3f
EVENT_MAX    ?= 2048
STATE_QUOTA  ?= 4096
REPORT_MAX   ?= 6144

WORK := $(ROOT_DIR)/tests/line-crossing-app/work

CORE_SRCS := $(APP_DIR)/src/lc_tracker.c $(APP_DIR)/src/lc_line_cross.c
APP_SRCS  := lc_app_entry.c lc_bus.c lc_bus_config.c lc_stateblob.c lc_json.c lc_arena.c lc_libc_mini.c

# LC_MALLOC seam: the lc core allocates through this macro; on target it is
# the static arena allocator (no libc heap).
LC_ALLOC_FLAGS := -D'LC_MALLOC(sz)=lcapp_alloc(sz)' -D'LC_FREE(p)=lcapp_free(p)'

CFLAGS := -mcpu=cortex-m55 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard -std=gnu11 \
          -Os -Wall -Werror -ffunction-sections -fdata-sections \
          -ffreestanding -fno-builtin -DLC_APP_TARGET=1 \
          -DLC_APP_ID='"$(APP_ID)"' -DLC_APP_SW_VERSION='"$(PKG_VERSION)"' \
          $(LC_ALLOC_FLAGS) \
          -include $(APP_MK_DIR)lc_arena.h \
          -I$(APP_DIR)/include -I.
LDFLAGS := -nostdlib -T lc_app.ld -Wl,--gc-sections \
           -Wl,-Map,$(BUILD)/lc-line-crossing.map -lgcc

OBJS := $(patsubst $(APP_DIR)/src/%.c,$(BUILD)/core_%.o,$(CORE_SRCS)) \
        $(patsubst %.c,$(BUILD)/%.o,$(APP_SRCS))

.PHONY: all image package verify clean

all: image

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/core_%.o: $(APP_DIR)/src/%.c $(wildcard $(APP_DIR)/include/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(ELF): $(OBJS) lc_app.ld
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(PAYLOAD): $(ELF)
	$(OBJCOPY) -O binary $< $@

$(IMAGE): $(ELF) $(PAYLOAD)
	$(PYTHON) pack_v2_image.py --elf $(ELF) --payload $(PAYLOAD) --out $@ \
		--exec-base $(EXEC_BASE) --nm $(NM)
	@$(SIZE) $(ELF)

image: $(IMAGE)
	@echo "line-crossing-app: v2 image ready -> $(IMAGE)"

$(WORK)/keys/dev-signer.pem:
	$(PYTHON) $(ROOT_DIR)/tests/package/gen_dev_key.py \
		--out-dir $(WORK) --publisher-id $(PUBLISHER_ID)

package: $(IMAGE) $(WORK)/keys/dev-signer.pem
	mkdir -p $(WORK)/pkg
	$(PYTHON) $(ROOT_DIR)/package/neapp_pack_v2.py \
		--image $(IMAGE) --out $(WORK)/pkg/lc-line-crossing-$(PKG_VERSION).neapp.v2 \
		--key $(WORK)/keys/dev-signer.pem \
		--publisher-id $(PUBLISHER_ID) --app-id $(APP_ID) --version $(PKG_VERSION) \
		--host-caps $(HOST_CAPS) --event-max $(EVENT_MAX) \
		--state-quota $(STATE_QUOTA) --report-max $(REPORT_MAX)
	$(PYTHON) $(ROOT_DIR)/package/neapp_verify_v2.py \
		--package $(WORK)/pkg/lc-line-crossing-$(PKG_VERSION).neapp.v2 \
		--trust $(WORK)/trust-dev.json --expect PASS

clean:
	rm -rf $(BUILD)
