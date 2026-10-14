/*
 * vault_test.c – Interactive test suite for the Secure Vault kernel module
 *
 * Compile:  gcc -Wall -o vault_test vault_test.c
 * Run:      sudo ./vault_test
 *
 * This program exercises every feature of /dev/vault:
 *   1. Basic write → read (round-trip test)
 *   2. Multiple sequential writes
 *   3. ioctl: get/set key
 *   4. ioctl: get buffer size
 *   5. ioctl: clear vault
 *   6. Interactive menu for manual testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

/* Reuse the same ioctl definitions from the driver header.
 * For user-space we include the raw ioctl macros instead. */
#include <linux/ioctl.h>

#define VAULT_IOC_MAGIC  'V'
#define VAULT_SET_KEY    _IOW(VAULT_IOC_MAGIC, 1, unsigned char)
#define VAULT_GET_KEY    _IOR(VAULT_IOC_MAGIC, 2, unsigned char)
#define VAULT_CLEAR      _IO (VAULT_IOC_MAGIC, 3)
#define VAULT_GET_SIZE   _IOR(VAULT_IOC_MAGIC, 4, size_t)

#define DEVICE_PATH  "/dev/vault"
#define BUF_SIZE     4096

/* ── ANSI colour helpers ─────────────────────────────────────────────── */
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

/* ── Utility ─────────────────────────────────────────────────────────── */

static void print_banner(void)
{
    printf(CYAN
           "╔══════════════════════════════════════════════════╗\n"
           "║        Secure Vault – Device Test Suite          ║\n"
           "║  Linux Kernel Module | OS Project 2026           ║\n"
           "╚══════════════════════════════════════════════════╝\n"
           RESET "\n");
}

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    size_t i;
    printf("  %s", label);
    for (i = 0; i < len && i < 32; i++)
        printf("%02X ", data[i]);
    if (len > 32) printf("...");
    printf("\n");
}

static int pass_count = 0;
static int fail_count = 0;

static void result(const char *test, int ok)
{
    if (ok) {
        printf("  [" GREEN "PASS" RESET "] %s\n", test);
        pass_count++;
    } else {
        printf("  [" RED "FAIL" RESET "] %s  (errno=%d: %s)\n",
               test, errno, strerror(errno));
        fail_count++;
    }
}

/* ── Test Cases ───────────────────────────────────────────────────────── */

/* Test 1: basic write then read – the data must come back identical */
static void test_basic_roundtrip(int fd)
{
    const char *msg   = "Hello, Secure Vault!";
    char        rbuf[BUF_SIZE];
    ssize_t     n;

    printf(BOLD "\n[Test 1] Basic Write → Read Round-Trip\n" RESET);

    memset(rbuf, 0, sizeof(rbuf));

    n = write(fd, msg, strlen(msg));
    result("write() returned > 0", n > 0);
    printf("  Wrote   : \"%s\" (%zd bytes)\n", msg, strlen(msg));

    n = read(fd, rbuf, BUF_SIZE);
    result("read() returned > 0", n > 0);
    printf("  Read    : \"%.*s\" (%zd bytes)\n", (int)n, rbuf, n);

    result("plaintext matches after decrypt",
           n == (ssize_t)strlen(msg) && memcmp(rbuf, msg, strlen(msg)) == 0);
}

/* Test 2: overwrite with different data */
static void test_overwrite(int fd)
{
    const char *msg1 = "First message";
    const char *msg2 = "Second, longer message replacing the first";
    char        rbuf[BUF_SIZE];
    ssize_t     n;

    printf(BOLD "\n[Test 2] Overwrite Test\n" RESET);

    write(fd, msg1, strlen(msg1));
    write(fd, msg2, strlen(msg2));

    memset(rbuf, 0, sizeof(rbuf));
    n = read(fd, rbuf, BUF_SIZE);
    printf("  Read    : \"%.*s\"\n", (int)n, rbuf);

    result("latest write wins (overwrite)",
           n == (ssize_t)strlen(msg2) && memcmp(rbuf, msg2, strlen(msg2)) == 0);
}

/* Test 3: ioctl GET_SIZE */
static void test_ioctl_size(int fd)
{
    const char *msg = "Size test data";
    size_t      sz  = 0;

    printf(BOLD "\n[Test 3] ioctl VAULT_GET_SIZE\n" RESET);

    write(fd, msg, strlen(msg));

    if (ioctl(fd, VAULT_GET_SIZE, &sz) == 0) {
        printf("  Stored bytes reported: %zu\n", sz);
        result("stored size matches write length", sz == strlen(msg));
    } else {
        result("ioctl VAULT_GET_SIZE succeeded", 0);
    }
}

/* Test 4: ioctl GET_KEY and SET_KEY */
static void test_ioctl_key(int fd)
{
    unsigned char orig_key = 0;
    unsigned char new_key  = 0x7F;
    unsigned char read_key = 0;
    char          rbuf[BUF_SIZE];
    const char   *msg = "Key change test";
    ssize_t       n;

    printf(BOLD "\n[Test 4] ioctl VAULT_SET_KEY / VAULT_GET_KEY\n" RESET);

    /* Read original key */
    ioctl(fd, VAULT_GET_KEY, &orig_key);
    printf("  Original key : 0x%02X\n", orig_key);

    /* Write data with original key, then change key, then read back */
    write(fd, msg, strlen(msg));

    ioctl(fd, VAULT_SET_KEY, &new_key);
    ioctl(fd, VAULT_GET_KEY, &read_key);
    printf("  New key      : 0x%02X (read back: 0x%02X)\n", new_key, read_key);
    result("key changed correctly", read_key == new_key);

    /* Data written with old key was re-encrypted: read should still work */
    memset(rbuf, 0, sizeof(rbuf));
    n = read(fd, rbuf, BUF_SIZE);
    printf("  Read after key change: \"%.*s\"\n", (int)n, rbuf);
    result("data intact after key change",
           n == (ssize_t)strlen(msg) && memcmp(rbuf, msg, strlen(msg)) == 0);

    /* Restore original key */
    ioctl(fd, VAULT_SET_KEY, &orig_key);
}

/* Test 5: ioctl VAULT_CLEAR */
static void test_ioctl_clear(int fd)
{
    char   rbuf[BUF_SIZE];
    size_t sz  = 999;
    ssize_t n;

    printf(BOLD "\n[Test 5] ioctl VAULT_CLEAR\n" RESET);

    write(fd, "data to be wiped", 16);
    ioctl(fd, VAULT_CLEAR, 0);

    ioctl(fd, VAULT_GET_SIZE, &sz);
    printf("  Stored bytes after clear: %zu\n", sz);
    result("stored size is 0 after clear", sz == 0);

    memset(rbuf, 0, sizeof(rbuf));
    n = read(fd, rbuf, BUF_SIZE);
    result("read returns 0 (EOF) after clear", n == 0);
}

/* Test 6: binary data (all 256 byte values) */
static void test_binary_data(int fd)
{
    unsigned char wbuf[256], rbuf[256];
    int           i;
    ssize_t       n;

    printf(BOLD "\n[Test 6] Binary Data Round-Trip (all 256 byte values)\n" RESET);

    for (i = 0; i < 256; i++)
        wbuf[i] = (unsigned char)i;

    write(fd, (char *)wbuf, 256);
    print_hex("Written (first 16 bytes): ", wbuf, 16);

    memset(rbuf, 0, sizeof(rbuf));
    n = read(fd, (char *)rbuf, 256);
    print_hex("Read    (first 16 bytes): ", rbuf, 16);

    result("binary round-trip correct",
           n == 256 && memcmp(wbuf, rbuf, 256) == 0);
}

/* ── Interactive Menu ─────────────────────────────────────────────────── */

static void interactive_menu(int fd)
{
    char   input[BUF_SIZE];
    char   rbuf[BUF_SIZE];
    int    choice;
    ssize_t n;
    unsigned char key;
    size_t sz;

    printf(BOLD "\n═══════════════ Interactive Mode ═══════════════\n" RESET);

    while (1) {
        printf(CYAN
               "\n  1. Write data to vault\n"
               "  2. Read data from vault\n"
               "  3. Show stored size\n"
               "  4. Show current key\n"
               "  5. Change key (hex, e.g. FF)\n"
               "  6. Clear vault\n"
               "  0. Exit\n"
               RESET "  Choice: ");
        fflush(stdout);

        if (scanf("%d", &choice) != 1) break;
        getchar(); /* consume newline */

        switch (choice) {
        case 1:
            printf("  Enter data: ");
            fflush(stdout);
            if (!fgets(input, sizeof(input), stdin)) break;
            input[strcspn(input, "\n")] = '\0';
            n = write(fd, input, strlen(input));
            if (n > 0)
                printf(GREEN "  Stored %zd encrypted byte(s).\n" RESET, n);
            else
                perror(RED "  write failed" RESET);
            break;

        case 2:
            memset(rbuf, 0, sizeof(rbuf));
            n = read(fd, rbuf, BUF_SIZE - 1);
            if (n > 0) {
                rbuf[n] = '\0';
                printf(GREEN "  Decrypted (%zd bytes): \"%s\"\n" RESET, n, rbuf);
            } else if (n == 0) {
                printf(YELLOW "  Vault is empty.\n" RESET);
            } else {
                perror(RED "  read failed" RESET);
            }
            break;

        case 3:
            ioctl(fd, VAULT_GET_SIZE, &sz);
            printf("  Stored bytes: %zu\n", sz);
            break;

        case 4:
            ioctl(fd, VAULT_GET_KEY, &key);
            printf("  Current XOR key: 0x%02X\n", key);
            break;

        case 5: {
            unsigned int tmp;
            printf("  New key (hex, 00–FF): ");
            fflush(stdout);
            if (scanf("%X", &tmp) == 1) {
                key = (unsigned char)(tmp & 0xFF);
                if (ioctl(fd, VAULT_SET_KEY, &key) == 0)
                    printf(GREEN "  Key set to 0x%02X\n" RESET, key);
                else
                    perror(RED "  ioctl SET_KEY failed" RESET);
            }
            getchar();
            break;
        }

        case 6:
            ioctl(fd, VAULT_CLEAR, 0);
            printf(GREEN "  Vault cleared.\n" RESET);
            break;

        case 0:
            printf("  Goodbye!\n");
            return;

        default:
            printf(YELLOW "  Unknown option.\n" RESET);
        }
    }
}

/* ── main ─────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int fd;

    print_banner();

    /* Open the device in read-write mode */
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, RED "Error: cannot open %s: %s\n" RESET,
                DEVICE_PATH, strerror(errno));
        fprintf(stderr, "Make sure the vault module is loaded:\n");
        fprintf(stderr, "  sudo insmod vault.ko\n");
        return EXIT_FAILURE;
    }
    printf(GREEN "Opened %s successfully (fd=%d)\n\n" RESET, DEVICE_PATH, fd);

    /* Run automated test suite */
    printf(BOLD "═══════════════ Automated Tests ═════════════════\n" RESET);
    test_basic_roundtrip(fd);
    test_overwrite(fd);
    test_ioctl_size(fd);
    test_ioctl_key(fd);
    test_ioctl_clear(fd);
    test_binary_data(fd);

    printf(BOLD "\n═══════════════ Test Summary ════════════════════\n" RESET);
    printf("  Passed : " GREEN "%d" RESET "\n", pass_count);
    printf("  Failed : " RED   "%d" RESET "\n", fail_count);
    printf("  Total  : %d\n", pass_count + fail_count);

    /* Interactive menu (skip with -a flag) */
    if (argc < 2 || strcmp(argv[1], "-a") != 0)
        interactive_menu(fd);

    close(fd);
    return (fail_count == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
