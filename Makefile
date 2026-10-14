# Makefile for the Secure Vault kernel module
#
# Targets:
#   make          – build vault.ko
#   make clean    – remove all build artefacts
#   make load     – insmod the module (requires root / sudo)
#   make unload   – rmmod the module  (requires root / sudo)
#   make status   – show module info and /dev/vault permissions
#   make dmesg    – tail the kernel log

# Object file(s) that make up the module
obj-m += vault.o

# Path to the running kernel's build tree
KDIR := /lib/modules/$(shell uname -r)/build

# Working directory
PWD := $(shell pwd)

# ── Default target ──────────────────────────────────────────────────────
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# ── Clean ────────────────────────────────────────────────────────────────
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# ── Load the module ──────────────────────────────────────────────────────
load:
	sudo insmod vault.ko
	@echo "Module loaded. Device node:"
	@ls -l /dev/vault 2>/dev/null || echo "  /dev/vault not found – check dmesg"

# ── Unload the module ────────────────────────────────────────────────────
unload:
	sudo rmmod vault 2>/dev/null && echo "Module removed." || echo "Module not loaded."

# ── Status ───────────────────────────────────────────────────────────────
status:
	@echo "=== lsmod ==="
	@lsmod | grep vault || echo "  vault not loaded"
	@echo ""
	@echo "=== /dev/vault ==="
	@ls -l /dev/vault 2>/dev/null || echo "  not present"
	@echo ""
	@echo "=== /proc/devices ==="
	@grep vault /proc/devices 2>/dev/null || echo "  vault not in /proc/devices"

# ── Kernel log ───────────────────────────────────────────────────────────
dmesg:
	sudo dmesg | grep vault | tail -20

# ── Build GUI (requires GTK3) ────────────────────────────────────────────
gui:
	@which pkg-config >/dev/null 2>&1 || (echo "Install pkg-config: sudo apt install pkg-config" && exit 1)
	@pkg-config --exists gtk+-3.0 || (echo "Install GTK3: sudo apt install libgtk-3-dev" && exit 1)
	gcc $$(pkg-config --cflags gtk+-3.0) -Wall -o vault_gui vault_gui.c \
	    $$(pkg-config --libs gtk+-3.0)
	@echo "vault_gui built. Run: sudo ./vault_gui"

# ── Build user-space test tools ──────────────────────────────────────────
tools:
	gcc -Wall -o vault_test vault_test.c
	gcc -Wall -o vault_demo vault_demo.c
	@echo "vault_test and vault_demo built."

# ── Build everything ─────────────────────────────────────────────────────
full: all tools gui

.PHONY: all clean load unload status dmesg gui tools full
