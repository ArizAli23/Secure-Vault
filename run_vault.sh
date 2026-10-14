#!/bin/bash
# run_vault.sh – One-shot script to build, load, test, and clean up the
#                Secure Vault kernel module.
#
# Usage: sudo bash run_vault.sh
#
# The script performs these steps in order:
#   1. Check dependencies (kernel headers, gcc, make)
#   2. Build the kernel module (vault.ko) and user-space tools
#   3. Load the module with insmod
#   4. Set /dev/vault permissions so the current user can access it
#   5. Run the automated test suite
#   6. Run the quick demo with a sample secret
#   7. Show relevant kernel log output
#   8. Offer to unload the module
#
# Colours
RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
CYAN='\033[1;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fail()  { echo -e "${RED}[FAIL]${RESET}  $*"; exit 1; }

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║        Secure Vault – Automated Build & Test     ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── 0. Must run as root ────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    warn "Not running as root. Trying with sudo..."
    exec sudo bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || fail "Cannot cd to script directory"

# ── 1. Dependency check ───────────────────────────────────────────────
info "Checking dependencies..."

check_dep() {
    command -v "$1" &>/dev/null || {
        warn "$1 not found. Installing..."
        apt-get install -y "$2" &>/dev/null
    }
}

check_dep make    make
check_dep gcc     gcc
check_dep insmod  kmod

KHEADERS="/lib/modules/$(uname -r)/build"
if [ ! -d "$KHEADERS" ]; then
    warn "Kernel headers missing. Installing linux-headers-$(uname -r)..."
    apt-get install -y "linux-headers-$(uname -r)" &>/dev/null || \
        fail "Cannot install kernel headers. Run: sudo apt install linux-headers-$(uname -r)"
fi
ok "All dependencies present"

# ── 2. Build ──────────────────────────────────────────────────────────
info "Building kernel module..."
make clean &>/dev/null
make 2>&1 | tail -5
[ -f vault.ko ] || fail "Build failed: vault.ko not created"
ok "vault.ko built successfully"

info "Building user-space tools..."
gcc -Wall -o vault_test vault_test.c  || fail "vault_test compile error"
gcc -Wall -o vault_demo vault_demo.c  || fail "vault_demo compile error"
ok "vault_test and vault_demo compiled"

# ── 3. Unload any old instance ────────────────────────────────────────
if lsmod | grep -q "^vault "; then
    info "Previous vault module found, removing..."
    rmmod vault && ok "Old module removed" || warn "rmmod returned error (ignored)"
fi

# ── 4. Load ───────────────────────────────────────────────────────────
info "Loading vault.ko..."
insmod vault.ko || fail "insmod failed – check dmesg"
sleep 0.5
ok "Module loaded"

# ── 5. Device permissions ─────────────────────────────────────────────
if [ -e /dev/vault ]; then
    chmod 666 /dev/vault
    ok "/dev/vault exists ($(ls -l /dev/vault | awk '{print $5, $6, $7, $8, $9}'))"
else
    fail "/dev/vault was not created – check dmesg for errors"
fi

# ── 6. Automated tests ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════ Running Automated Test Suite ═══════════${RESET}"
./vault_test -a
TEST_EXIT=$?

# ── 7. Quick demo ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════ Running Quick Demo ══════════════════${RESET}"
./vault_demo "OS Project Secure Vault is working!"

# ── 8. Kernel log ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════ Kernel Log (vault) ══════════════════${RESET}"
dmesg | grep vault | tail -20

# ── 9. Summary ────────────────────────────────────────────────────────
echo ""
if [ $TEST_EXIT -eq 0 ]; then
    ok "All tests passed!"
else
    warn "Some tests failed – review output above"
fi

echo ""
read -r -p "Unload the module now? [y/N] " resp
if [[ "$resp" =~ ^[Yy]$ ]]; then
    rmmod vault && ok "Module unloaded" || warn "rmmod failed"
else
    info "Module left loaded. To remove: sudo rmmod vault"
fi

echo ""
info "Done. Output files in: $SCRIPT_DIR"
