# Secure Vault — Linux Encrypted Character Device Driver

A Linux Kernel Module that creates a virtual encrypted device at `/dev/vault`. Any data written to it is encrypted using XOR cipher and stored in kernel memory. Reading from it returns the original plaintext. Sensitive data never exists as plaintext inside the kernel buffer.

---

## Files

| File | Purpose |
|---|---|
| `vault.h` | Shared header — device constants and ioctl definitions |
| `vault.c` | Core kernel driver — encryption, read/write, ioctl handlers |
| `vault_gui.c` | GTK3 graphical interface for interacting with the vault |
| `vault_test.c` | Automated test suite — verifies all driver functionality |
| `vault_demo.c` | Simple demo program showing basic usage |
| `Makefile` | Build system |
| `run_vault.sh` | Script to compile, load the module, and set device permissions |

---

## Requirements

- Linux kernel 5.x or 6.x (tested on Ubuntu/Debian)
- GCC, make, and kernel headers installed
- GTK3 (only needed to compile the GUI)

---

## How to Use

**1. Build and load the driver**
```bash
sudo bash run_vault.sh
```

**2. Write data to the vault**
```bash
echo -n "your secret" > /dev/vault
```

**3. Read it back**
```bash
cat /dev/vault
```

**4. Run the test suite**
```bash
gcc -Wall -o vault_test vault_test.c
sudo ./vault_test
```

**5. Run the GUI**
```bash
gcc $(pkg-config --cflags gtk+-3.0) -Wall -o vault_gui vault_gui.c $(pkg-config --libs gtk+-3.0)
sudo ./vault_gui
```

**6. Unload the driver when done**
```bash
sudo rmmod vault
```

---

## What It Delivers

- Encrypted in-kernel storage via a character device — data is XOR-encrypted the moment it crosses into kernel space
- Standard Linux file interface — works with any program that can read/write files
- Dynamic key management via `ioctl` — change the encryption key at runtime without data loss
- Secure wipe — clears the buffer with a single ioctl call
- Concurrency safe — mutex-protected for simultaneous multi-process access

---
