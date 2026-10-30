
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

V3_PKG_VERSION ?= 3.0.0
V3_HOST_CAPS   ?= 0xff
V3_EVENT_MAX   ?= 2048
V3_STATE_QUOTA ?= 4096
V3_REPORT_MAX  ?= 6144
V3_CONTROL_MAX ?= 256
V3_SNAPSHOT_MAX ?= 1024
V3_PUBLISHER_ID ?= dev-publisher

V3_WORK := $(ROOT_DIR)/tests/line-crossing-v3/work
V3_POLICY := $(ROOT_DIR)/tests/line-crossing-v3/host_policy_sim.json
V3_ELF := $(BUILD)/lc-line-crossing-v3.elf
V3_PAYLOAD := $(BUILD)/lc-line-crossing-v3.payload.bin
V3_IMAGE := $(BUILD)/lc-line-crossing-v3.bin

V3_APP_SRCS := lc_app_entry_v3.c lc_bus.c lc_bus_config.c lc_stateblob.c \
               lc_ctrl.c lc_cfgcodec.c lc_json.c lc_arena.c lc_libc_mini.c

V3_OBJS := $(patsubst $(APP_DIR)/src/%.c,$(BUILD)/core_%.o,$(CORE_SRCS)) \
           $(patsubst %.c,$(BUILD)/v3_%.o,$(V3_APP_SRCS))

.PHONY: image-v3 package-v3 clean-v3

$(BUILD)/v3_%.o: PKG_VERSION = $(V3_PKG_VERSION)

$(BUILD)/v3_%.o: %.c $(wildcard *.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(V3_ELF): $(V3_OBJS) lc_app.ld
	$(CC) $(CFLAGS) -o $@ $(V3_OBJS) $(LDFLAGS)

$(V3_PAYLOAD): $(V3_ELF)
	$(OBJCOPY) -O binary $< $@

$(V3_IMAGE): $(V3_ELF) $(V3_PAYLOAD) pack_v3_image.py
	$(PYTHON) pack_v3_image.py --elf $(V3_ELF) --payload $(V3_PAYLOAD) --out $@ \
		--exec-base $(EXEC_BASE) --nm $(NM)
	@$(SIZE) $(V3_ELF)

image-v3: $(V3_IMAGE)
	@echo "line-crossing-app: v3 image ready -> $(V3_IMAGE)"

$(V3_WORK)/keys/dev-signer.pem:
	$(PYTHON) $(ROOT_DIR)/tests/package/gen_dev_key.py \
		--out-dir $(V3_WORK) --publisher-id $(V3_PUBLISHER_ID)

package-v3: $(V3_IMAGE) $(V3_WORK)/keys/dev-signer.pem
	mkdir -p $(V3_WORK)/pkg
	$(PYTHON) $(ROOT_DIR)/package/neapp_pack_v3.py \
		--image $(V3_IMAGE) \
		--out $(V3_WORK)/pkg/lc-line-crossing-$(V3_PKG_VERSION).neapp.v3 \
		--key $(V3_WORK)/keys/dev-signer.pem \
		--publisher-id $(V3_PUBLISHER_ID) --app-id $(APP_ID) \
		--version $(V3_PKG_VERSION) \
		--host-caps $(V3_HOST_CAPS) --event-max $(V3_EVENT_MAX) \
		--state-quota $(V3_STATE_QUOTA) --report-max $(V3_REPORT_MAX) \
		--control-max $(V3_CONTROL_MAX) --snapshot-max $(V3_SNAPSHOT_MAX) \
		--host-policy $(V3_POLICY)
	$(PYTHON) $(ROOT_DIR)/package/neapp_verify_v3.py \
		--package $(V3_WORK)/pkg/lc-line-crossing-$(V3_PKG_VERSION).neapp.v3 \
		--trust $(V3_WORK)/trust-dev.json --policy $(V3_POLICY) --expect PASS

clean-v3:
	rm -f $(V3_OBJS) $(V3_ELF) $(V3_PAYLOAD) $(V3_IMAGE)

V4_APP_VERSION ?= 4.2.8
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
V5_UI_VERSION ?= 1.2.10
V5_HOST_CAPS ?= 0x3ff
V5_EVENT_MAX ?= 1576
V5_STATE_QUOTA ?= 512
V5_REPORT_MAX ?= 6144
V5_CONTROL_MAX ?= 512
V5_SNAPSHOT_MAX ?= 1024
V5_LIVE_PUBLISH_MAX ?= 9008
V5_LIVE_TRACK_MAX ?= 64

.PHONY: neapp-v5

neapp-v5: $(V4_ELF)
	mkdir -p $(V5_OUT_DIR)
	$(PYTHON) $(ROOT_DIR)/package/unsigned/neapp_pack_v5.py \
		--elf $(V4_ELF) --ui-assets $(V5_UI_DIR) \
		--out $(V5_OUT_DIR)/line-crossing-$(V4_APP_VERSION).neapp \
		--app-id $(APP_ID) --native-version $(V4_APP_VERSION) --ui-version $(V5_UI_VERSION) \
		--host-caps $(V5_HOST_CAPS) --event-max $(V5_EVENT_MAX) \
		--state-quota $(V5_STATE_QUOTA) --report-max $(V5_REPORT_MAX) \
		--control-max $(V5_CONTROL_MAX) --snapshot-max $(V5_SNAPSHOT_MAX) \
		--live-publish-max $(V5_LIVE_PUBLISH_MAX) --live-track-max $(V5_LIVE_TRACK_MAX)
	$(PYTHON) $(ROOT_DIR)/package/unsigned/neapp_verify_v5.py \
		--package $(V5_OUT_DIR)/line-crossing-$(V4_APP_VERSION).neapp --compact

clean-v5:
	rm -rf $(V5_OUT_DIR)

.PHONY: print-v4_app_version print-v5_ui_version
print-v4_app_version:
	@echo $(V4_APP_VERSION)
print-v5_ui_version:
	@echo $(V5_UI_VERSION)
