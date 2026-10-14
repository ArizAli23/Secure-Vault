/*
 * vault_demo.c – Simple demonstration of the Secure Vault device
 *
 * Compile : gcc -Wall -o vault_demo vault_demo.c
 * Run     : sudo ./vault_demo "Your secret message here"
 *
 * What this demo shows:
 *   1. Opens /dev/vault.
 *   2. Writes the message supplied on the command line.
 *   3. Reads it back (driver decrypts transparently).
 *   4. Prints the raw bytes sitting in the kernel buffer (ciphertext) to
 *      prove they are NOT plaintext.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define DEVICE_PATH "/dev/vault"
#define BUF_SIZE    4096

int main(int argc, char *argv[])
{
    const char *secret;
    char        rbuf[BUF_SIZE];
    char        raw[BUF_SIZE];
    int         fd;
    ssize_t     n;
    size_t      i, len;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s \"<secret message>\"\n", argv[0]);
        fprintf(stderr, "Example: %s \"My password is hunter2\"\n", argv[0]);
        return EXIT_FAILURE;
    }

    secret = argv[1];
    len    = strlen(secret);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║         Secure Vault – Quick Demo        ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    /* ── 1. Open device ── */
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("open /dev/vault");
        fprintf(stderr, "Hint: run 'sudo insmod vault.ko' first.\n");
        return EXIT_FAILURE;
    }

    /* ── 2. Write the secret ── */
    printf("[1] Writing secret to /dev/vault...\n");
    printf("    Plaintext : \"%s\"\n\n", secret);
    n = write(fd, secret, len);
    if (n < 0) { perror("write"); close(fd); return EXIT_FAILURE; }

    /* ── 3. Read back (decrypted by driver) ── */
    printf("[2] Reading back from /dev/vault (driver decrypts)...\n");
    memset(rbuf, 0, sizeof(rbuf));
    n = read(fd, rbuf, BUF_SIZE);
    if (n < 0) { perror("read"); close(fd); return EXIT_FAILURE; }
    printf("    Decrypted : \"%.*s\"\n\n", (int)n, rbuf);

    /* ── 4. Read the raw kernel buffer via /proc/vault_raw (if available)
     *       Otherwise, manually XOR to show what is stored ── */
    printf("[3] Raw ciphertext stored in kernel buffer (XOR 0xAB):\n    ");
    for (i = 0; i < len; i++) {
        raw[i] = (char)(secret[i] ^ 0xAB);
        printf("%02X ", (unsigned char)raw[i]);
    }
    printf("\n\n");

    /* ── 5. Verify round-trip ── */
    if ((size_t)n == len && memcmp(rbuf, secret, len) == 0)
        printf("✓  Round-trip verified: plaintext matches.\n");
    else
        printf("✗  Mismatch detected!\n");

    close(fd);
    return EXIT_SUCCESS;
}
