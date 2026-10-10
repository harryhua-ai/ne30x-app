# line-crossing core library (ported from ne301 counting@de25a6f1).
#
# Pure business core: target matching / track history / confirmed-loss
# retirement / line-crossing direction.  Host-compilable, no NE301
# platform dependencies (HAL / RTOS / AI / flash / network).
#
#   make            -> build/liblinecross.a
#   make clean      -> remove build artifacts
#
# Offline equivalence tests live in tests/line-crossing (run_tests.sh).

CC      ?= cc
CFLAGS  ?= -O2
WARN     = -Wall -Wextra -Werror -std=c11
INC      = -Iinclude

BUILD   := build
SRCS    := src/lc_tracker.c src/lc_line_cross.c
OBJS    := $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))
LIB     := $(BUILD)/liblinecross.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	ar rcs $@ $^

$(BUILD)/%.o: src/%.c include/lc_types.h include/lc_tracker.h include/lc_line_cross.h | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $(INC) -c $< -o $@

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
