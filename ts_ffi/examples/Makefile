# makefile for the ts_ffi examples

RUST_PROFILE := dev

ifeq ($(RUST_PROFILE),dev)
	RUST_PROFILE_DIR := debug
else
	RUST_PROFILE_DIR := $(RUST_PROFILE)
endif

CC := gcc

# the `l:libtailscalers.a` forces linkage to the static archive to make the executables easier to call
# (no need to futz with LD_LIBRARY_PATH with the dynamic lib)
CFLAGS := -Wall -Wextra -Werror -O2 -I.. -l:libtailscalers.a -lpthread -lm

# Windows targets the -gnu toolchain to make the build consistent (we can still use gcc rather than
# msvc), needs explicit linkage to certain Windows-specific system libraries, and produces
# .exe-suffixed binaries:
ifeq ($(OS),Windows_NT)
	RUST_TARGET := x86_64-pc-windows-gnu
	CFLAGS += -lntdll -luserenv -lbcrypt
	TARGET_SUFFIX := .exe
else
	TARGET_SUFFIX := .bin
endif

# If we have an explicit target set, this is usually because it's not our default target, and we
# need to specify a subdir in the build output dir. This approach can have false positives,
# unfortunately, but cargo doesn't make our lives easy here wrt. figuring out where the built
# artifacts actually went.
ifneq ($(RUST_TARGET),)
	RUST_TARGET_PATH := $(RUST_TARGET)/
	RUST_TARGET_FLAG := --target $(RUST_TARGET)
endif

CFLAGS += -L../../target/$(RUST_TARGET_PATH)$(RUST_PROFILE_DIR)/
TARGET_NAMES := udp_ping tcp_echo
TARGETS := $(patsubst %,%$(TARGET_SUFFIX),$(TARGET_NAMES))

# libtailscalers: let cargo handle build incrementality
.PHONY: all clean libtailscalers

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

$(TARGETS): %$(TARGET_SUFFIX): libtailscalers $(wildcard %/*.c)
	$(CC) -o $@ $(wildcard $*/*.c) $(CFLAGS)

libtailscalers:
	cargo build -p ts_ffi --profile $(RUST_PROFILE) $(RUST_TARGET_FLAG)
