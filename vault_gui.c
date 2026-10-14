
#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>

/* ── ioctl definitions (mirror of vault.h) ─────────────────────────── */
#define VAULT_IOC_MAGIC  'V'
#define VAULT_SET_KEY    _IOW(VAULT_IOC_MAGIC, 1, unsigned char)
#define VAULT_GET_KEY    _IOR(VAULT_IOC_MAGIC, 2, unsigned char)
#define VAULT_CLEAR      _IO (VAULT_IOC_MAGIC, 3)
#define VAULT_GET_SIZE   _IOR(VAULT_IOC_MAGIC, 4, size_t)

#define DEVICE_PATH  "/dev/vault"
#define BUF_SIZE     4096

/* ── CSS Theme ─────────────────────────────────────────────────────── */
static const char *CSS = ""
"window {"
"  background-color: #0d1117;"
"}"
"* {"
"  font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;"
"  color: #e6edf3;"
"}"
".title-bar {"
"  background-color: #161b22;"
"  border-bottom: 1px solid #30363d;"
"  padding: 12px 20px;"
"}"
".title-label {"
"  font-size: 18px;"
"  font-weight: bold;"
"  color: #58a6ff;"
"  letter-spacing: 2px;"
"}"
".subtitle-label {"
"  font-size: 11px;"
"  color: #8b949e;"
"  letter-spacing: 1px;"
"}"
".panel {"
"  background-color: #161b22;"
"  border: 1px solid #30363d;"
"  border-radius: 6px;"
"  padding: 16px;"
"  margin: 6px;"
"}"
".panel-title {"
"  font-size: 12px;"
"  font-weight: bold;"
"  color: #8b949e;"
"  letter-spacing: 2px;"
"  text-transform: uppercase;"
"  margin-bottom: 8px;"
"}"
"textview {"
"  background-color: #0d1117;"
"  color: #e6edf3;"
"  font-size: 13px;"
"  border: 1px solid #30363d;"
"  border-radius: 4px;"
"  padding: 8px;"
"}"
"textview text {"
"  background-color: #0d1117;"
"  color: #e6edf3;"
"}"
".hex-view text {"
"  background-color: #0d1117;"
"  color: #3fb950;"
"  font-size: 12px;"
"}"
".log-view text {"
"  background-color: #0d1117;"
"  color: #8b949e;"
"  font-size: 11px;"
"}"
"button {"
"  background-color: #21262d;"
"  border: 1px solid #30363d;"
"  border-radius: 6px;"
"  padding: 8px 16px;"
"  color: #e6edf3;"
"  font-size: 13px;"
"}"
"button:hover {"
"  background-color: #30363d;"
"  border-color: #58a6ff;"
"}"
".btn-primary {"
"  background-color: #1f6feb;"
"  border-color: #1f6feb;"
"  color: #ffffff;"
"  font-weight: bold;"
"}"
".btn-primary:hover {"
"  background-color: #388bfd;"
"  border-color: #388bfd;"
"}"
".btn-danger {"
"  background-color: #da3633;"
"  border-color: #da3633;"
"  color: #ffffff;"
"  font-weight: bold;"
"}"
".btn-danger:hover {"
"  background-color: #f85149;"
"  border-color: #f85149;"
"}"
".btn-success {"
"  background-color: #238636;"
"  border-color: #238636;"
"  color: #ffffff;"
"  font-weight: bold;"
"}"
".btn-success:hover {"
"  background-color: #2ea043;"
"  border-color: #2ea043;"
"}"
"entry {"
"  background-color: #0d1117;"
"  border: 1px solid #30363d;"
"  border-radius: 6px;"
"  color: #e6edf3;"
"  padding: 6px 10px;"
"  font-size: 13px;"
"}"
"entry:focus {"
"  border-color: #58a6ff;"
"  box-shadow: 0 0 0 3px rgba(31,111,235,0.3);"
"}"
"scale {"
"  color: #58a6ff;"
"}"
"scale trough {"
"  background-color: #21262d;"
"  border-radius: 4px;"
"}"
"scale highlight {"
"  background-color: #1f6feb;"
"  border-radius: 4px;"
"}"
".status-bar {"
"  background-color: #161b22;"
"  border-top: 1px solid #30363d;"
"  padding: 6px 16px;"
"}"
".status-ok {"
"  color: #3fb950;"
"  font-size: 12px;"
"}"
".status-err {"
"  color: #f85149;"
"  font-size: 12px;"
"}"
".key-label {"
"  color: #d2a8ff;"
"  font-size: 14px;"
"  font-weight: bold;"
"}"
".stored-label {"
"  color: #ffa657;"
"  font-size: 13px;"
"}"
"separator {"
"  background-color: #30363d;"
"  margin: 4px 0;"
"}"
".badge {"
"  background-color: #21262d;"
"  border: 1px solid #30363d;"
"  border-radius: 12px;"
"  padding: 2px 10px;"
"  font-size: 11px;"
"  color: #8b949e;"
"}";

/* ── App State ─────────────────────────────────────────────────────── */
typedef struct {
    /* Window widgets */
    GtkWidget *window;
    GtkWidget *status_label;
    GtkWidget *device_status_label;
    GtkWidget *key_display_label;
    GtkWidget *stored_size_label;

    /* Input / output */
    GtkTextBuffer *input_buf;
    GtkTextBuffer *output_buf;
    GtkTextBuffer *hex_buf;
    GtkTextBuffer *log_buf;

    /* Key control */
    GtkWidget *key_scale;
    GtkWidget *key_entry;

    /* Device state */
    int   fd;
    unsigned char current_key;
    size_t stored_bytes;
    gboolean device_open;
} VaultApp;

static VaultApp app;

/* ── Helpers ──────────────────────────────────────────────────────── */

static void set_status(const char *msg, gboolean is_error)
{
    gtk_label_set_text(GTK_LABEL(app.status_label), msg);
    GtkStyleContext *ctx = gtk_widget_get_style_context(app.status_label);
    if (is_error) {
        gtk_style_context_remove_class(ctx, "status-ok");
        gtk_style_context_add_class(ctx, "status-err");
    } else {
        gtk_style_context_remove_class(ctx, "status-err");
        gtk_style_context_add_class(ctx, "status-ok");
    }
}

static void update_device_info(void)
{
    char key_str[32], size_str[64], dev_str[64];

    if (!app.device_open) {
        gtk_label_set_text(GTK_LABEL(app.device_status_label), "⬤  DISCONNECTED");
        GtkStyleContext *ctx = gtk_widget_get_style_context(app.device_status_label);
        gtk_style_context_remove_class(ctx, "status-ok");
        gtk_style_context_add_class(ctx, "status-err");
        return;
    }

    /* Query current key */
    ioctl(app.fd, VAULT_GET_KEY, &app.current_key);
    snprintf(key_str, sizeof(key_str), "KEY: 0x%02X", app.current_key);
    gtk_label_set_text(GTK_LABEL(app.key_display_label), key_str);

    /* Query stored size */
    ioctl(app.fd, VAULT_GET_SIZE, &app.stored_bytes);
    snprintf(size_str, sizeof(size_str), "%zu byte%s stored",
             app.stored_bytes, app.stored_bytes == 1 ? "" : "s");
    gtk_label_set_text(GTK_LABEL(app.stored_size_label), size_str);

    snprintf(dev_str, sizeof(dev_str), "⬤  %s  (fd=%d)", DEVICE_PATH, app.fd);
    gtk_label_set_text(GTK_LABEL(app.device_status_label), dev_str);
    GtkStyleContext *ctx = gtk_widget_get_style_context(app.device_status_label);
    gtk_style_context_remove_class(ctx, "status-err");
    gtk_style_context_add_class(ctx, "status-ok");

    /* Sync key slider */
    g_signal_handlers_block_by_func(app.key_scale, NULL, NULL);
    gtk_range_set_value(GTK_RANGE(app.key_scale), (double)app.current_key);
    g_signal_handlers_unblock_by_func(app.key_scale, NULL, NULL);

    char hex_key[8];
    snprintf(hex_key, sizeof(hex_key), "%02X", app.current_key);
    gtk_entry_set_text(GTK_ENTRY(app.key_entry), hex_key);
}

static void append_log(const char *msg)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(app.log_buf, &end);
    gtk_text_buffer_insert(app.log_buf, &end, msg, -1);
    gtk_text_buffer_insert(app.log_buf, &end, "\n", -1);
}

static void build_hex_view(const unsigned char *data, size_t len)
{
    char line[80];
    char hex_part[50], ascii_part[20];
    GString *out = g_string_new("  OFFSET   00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII\n"
                                 "  ────────  ──────────────────────  ────────────────────────   ────────────────\n");

    size_t i, j;
    for (i = 0; i < len && i < 256; i += 16) {
        memset(hex_part,   ' ', sizeof(hex_part));
        memset(ascii_part, '.', sizeof(ascii_part));
        hex_part[48]   = '\0';
        ascii_part[16] = '\0';

        for (j = 0; j < 16 && (i + j) < len; j++) {
            unsigned char b = data[i + j];
            snprintf(line, 4, "%02X ", b);
            memcpy(hex_part + j * 3 + (j >= 8 ? 1 : 0), line, 3);
            ascii_part[j] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
        }
        hex_part[48]   = '\0';
        ascii_part[16] = '\0';

        snprintf(line, sizeof(line), "  %06zX    %-49s  %s\n", i, hex_part, ascii_part);
        g_string_append(out, line);
    }
    if (len > 256)
        g_string_append_printf(out, "  ... (%zu more bytes)\n", len - 256);
    if (len == 0)
        g_string_append(out, "\n  (vault is empty)\n");

    gtk_text_buffer_set_text(app.hex_buf, out->str, -1);
    g_string_free(out, TRUE);
}

static void refresh_hex_view(void)
{
    if (!app.device_open || app.stored_bytes == 0) {
        build_hex_view(NULL, 0);
        return;
    }
    /* Re-open device for raw read, then decrypt manually to show cipher */
    /* We show stored_bytes of zeros XOR key to approximate ciphertext   */
    /* Real driver: read decrypts, so we reconstruct ciphertext display  */
    unsigned char tmp[BUF_SIZE];
    ssize_t n = read(app.fd, (char *)tmp, sizeof(tmp));
    if (n > 0) {
        /* Re-encrypt to show what sits in kernel buffer */
        size_t k;
        for (k = 0; k < (size_t)n; k++)
            tmp[k] ^= app.current_key;
        build_hex_view(tmp, (size_t)n);
    }
}

/* ── Button Callbacks ─────────────────────────────────────────────── */

static void on_connect_clicked(GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;

    if (app.device_open) {
        close(app.fd);
        app.device_open = FALSE;
        set_status("Disconnected from /dev/vault", FALSE);
        update_device_info();
        append_log("[INFO] Disconnected from /dev/vault");
        return;
    }

    app.fd = open(DEVICE_PATH, O_RDWR);
    if (app.fd < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Cannot open %s: %s", DEVICE_PATH, strerror(errno));
        set_status(msg, TRUE);
        append_log(msg);

        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(app.window),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE,
            "Cannot open /dev/vault\n\n"
            "Make sure the module is loaded:\n"
            "  sudo insmod vault.ko\n\n"
            "And permissions are set:\n"
            "  sudo chmod 666 /dev/vault");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    app.device_open = TRUE;
    set_status("Connected to /dev/vault", FALSE);
    append_log("[OK] Connected to /dev/vault");
    update_device_info();
    refresh_hex_view();
}

static void on_write_clicked(GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;

    if (!app.device_open) {
        set_status("Not connected — open /dev/vault first", TRUE);
        return;
    }

    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(app.input_buf, &start, &end);
    gchar *text = gtk_text_buffer_get_text(app.input_buf, &start, &end, FALSE);

    if (!text || strlen(text) == 0) {
        set_status("Nothing to write — input is empty", TRUE);
        g_free(text);
        return;
    }

    ssize_t n = write(app.fd, text, strlen(text));
    if (n < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Write failed: %s", strerror(errno));
        set_status(msg, TRUE);
        append_log(msg);
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "Encrypted & stored %zd byte(s)", n);
        set_status(msg, FALSE);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg),
                 "[WRITE] %zd bytes encrypted with key 0x%02X → /dev/vault",
                 n, app.current_key);
        append_log(log_msg);
    }

    g_free(text);
    update_device_info();
    refresh_hex_view();
}

static void on_read_clicked(GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;

    if (!app.device_open) {
        set_status("Not connected — open /dev/vault first", TRUE);
        return;
    }

    char rbuf[BUF_SIZE + 1];
    memset(rbuf, 0, sizeof(rbuf));
    ssize_t n = read(app.fd, rbuf, BUF_SIZE);

    if (n < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Read failed: %s", strerror(errno));
        set_status(msg, TRUE);
        append_log(msg);
    } else if (n == 0) {
        gtk_text_buffer_set_text(app.output_buf, "(vault is empty)", -1);
        set_status("Vault is empty", FALSE);
        append_log("[READ] Vault is empty");
    } else {
        rbuf[n] = '\0';
        gtk_text_buffer_set_text(app.output_buf, rbuf, -1);
        char msg[128];
        snprintf(msg, sizeof(msg), "Decrypted %zd byte(s) from vault", n);
        set_status(msg, FALSE);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg),
                 "[READ] %zd bytes decrypted with key 0x%02X ← /dev/vault", n, app.current_key);
        append_log(log_msg);
    }

    update_device_info();
}

static void on_clear_clicked(GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;

    if (!app.device_open) {
        set_status("Not connected", TRUE);
        return;
    }

    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(app.window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_YES_NO,
        "Securely wipe the vault buffer?\n\nThis will zero all %zu stored byte(s).",
        app.stored_bytes);
    gint resp = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);

    if (resp != GTK_RESPONSE_YES) return;

    ioctl(app.fd, VAULT_CLEAR, 0);
    gtk_text_buffer_set_text(app.output_buf, "", -1);
    set_status("Vault cleared — buffer securely wiped", FALSE);
    append_log("[CLEAR] Vault buffer securely wiped (memset 0)");
    update_device_info();
    build_hex_view(NULL, 0);
}

static void on_key_scale_changed(GtkRange *range, gpointer data)
{
    (void)data;
    if (!app.device_open) return;

    unsigned char new_key = (unsigned char)(int)gtk_range_get_value(range);
    ioctl(app.fd, VAULT_SET_KEY, &new_key);

    char hex[8];
    snprintf(hex, sizeof(hex), "%02X", new_key);
    gtk_entry_set_text(GTK_ENTRY(app.key_entry), hex);

    char log_msg[64];
    snprintf(log_msg, sizeof(log_msg), "[KEY] Changed to 0x%02X", new_key);
    append_log(log_msg);
    update_device_info();
    refresh_hex_view();
}

static void on_key_entry_activate(GtkEntry *entry, gpointer data)
{
    (void)data;
    if (!app.device_open) return;

    const char *text = gtk_entry_get_text(entry);
    unsigned int val;
    if (sscanf(text, "%X", &val) == 1) {
        unsigned char new_key = (unsigned char)(val & 0xFF);
        ioctl(app.fd, VAULT_SET_KEY, &new_key);
        gtk_range_set_value(GTK_RANGE(app.key_scale), (double)new_key);

        char log_msg[64];
        snprintf(log_msg, sizeof(log_msg), "[KEY] Set to 0x%02X via manual input", new_key);
        append_log(log_msg);
        update_device_info();
        refresh_hex_view();
    } else {
        set_status("Invalid hex key — enter 00 to FF", TRUE);
    }
}

static void on_refresh_log_clicked(GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;
    FILE *fp = popen("dmesg 2>/dev/null | grep vault | tail -30", "r");
    if (!fp) {
        append_log("[ERROR] Cannot run dmesg");
        return;
    }
    gtk_text_buffer_set_text(app.log_buf, "── dmesg | grep vault ──\n", -1);
    char line[512];
    while (fgets(line, sizeof(line), fp))
        append_log(line[0] == '\n' ? "" : line);
    pclose(fp);
    append_log("────────────────────────");
}

static void on_clear_input_clicked(GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;
    gtk_text_buffer_set_text(app.input_buf, "", -1);
}

/* ── Build UI ─────────────────────────────────────────────────────── */

static GtkWidget *make_scrolled_textview(GtkTextBuffer **buf_out,
                                          const char *css_class,
                                          int min_h)
{
    GtkWidget *tv  = gtk_text_view_new();
    GtkWidget *sw  = gtk_scrolled_window_new(NULL, NULL);
    *buf_out = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv));
    gtk_text_view_set_editable(GTK_TEXT_VIEW(tv), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(tv), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tv), GTK_WRAP_WORD_CHAR);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    if (css_class)
        gtk_style_context_add_class(gtk_widget_get_style_context(tv), css_class);
    gtk_container_add(GTK_CONTAINER(sw), tv);
    gtk_widget_set_size_request(sw, -1, min_h);
    return sw;
}

static GtkWidget *make_panel(const char *title, GtkWidget *content)
{
    GtkWidget *box   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *label = gtk_label_new(title);
    gtk_style_context_add_class(gtk_widget_get_style_context(box),   "panel");
    gtk_style_context_add_class(gtk_widget_get_style_context(label), "panel-title");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_box_pack_start(GTK_BOX(box), label,   FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), content, TRUE,  TRUE,  0);
    return box;
}

static void build_ui(void)
{
    /* Window */
    app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app.window), "Secure Vault — Kernel Device Manager");
    gtk_window_set_default_size(GTK_WINDOW(app.window), 1100, 820);
    gtk_window_set_resizable(GTK_WINDOW(app.window), TRUE);
    g_signal_connect(app.window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    /* Apply CSS */
    GtkCssProvider *css_prov = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css_prov, CSS, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css_prov),
        GTK_STYLE_PROVIDER_PRIORITY_USER);

    /* Root vbox */
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(app.window), root);

    /* ── Title Bar ── */
    GtkWidget *title_bar  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *title_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title_lbl  = gtk_label_new("⬡  SECURE VAULT");
    GtkWidget *sub_lbl    = gtk_label_new("VIRTUAL ENCRYPTED CHARACTER DEVICE DRIVER  •  LINUX KERNEL MODULE");
    gtk_style_context_add_class(gtk_widget_get_style_context(title_bar),  "title-bar");
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl),  "title-label");
    gtk_style_context_add_class(gtk_widget_get_style_context(sub_lbl),    "subtitle-label");
    gtk_label_set_xalign(GTK_LABEL(title_lbl), 0.0);
    gtk_label_set_xalign(GTK_LABEL(sub_lbl),   0.0);
    gtk_box_pack_start(GTK_BOX(title_vbox), title_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(title_vbox), sub_lbl,   FALSE, FALSE, 0);

    /* Connect button in title bar */
    GtkWidget *connect_btn = gtk_button_new_with_label("⬡  Connect  /dev/vault");
    gtk_style_context_add_class(gtk_widget_get_style_context(connect_btn), "btn-primary");
    g_signal_connect(connect_btn, "clicked", G_CALLBACK(on_connect_clicked), NULL);

    app.device_status_label = gtk_label_new("⬤  DISCONNECTED");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.device_status_label), "status-err");

    gtk_box_pack_start(GTK_BOX(title_bar), title_vbox,             TRUE,  TRUE,  0);
    gtk_box_pack_end  (GTK_BOX(title_bar), connect_btn,            FALSE, FALSE, 0);
    gtk_box_pack_end  (GTK_BOX(title_bar), app.device_status_label, FALSE, FALSE, 12);
    gtk_box_pack_start(GTK_BOX(root), title_bar, FALSE, FALSE, 0);

    /* ── Main content area: left col + right col ── */
    GtkWidget *hpaned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(hpaned), 560);
    gtk_box_pack_start(GTK_BOX(root), hpaned, TRUE, TRUE, 0);

    /* ════ LEFT COLUMN ════ */
    GtkWidget *left_col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* — Info strip — */
    GtkWidget *info_strip = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
    gtk_widget_set_margin_start(info_strip, 6);
    gtk_widget_set_margin_end  (info_strip, 6);
    gtk_widget_set_margin_top  (info_strip, 8);

    app.key_display_label  = gtk_label_new("KEY: —");
    app.stored_size_label  = gtk_label_new("0 bytes stored");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.key_display_label), "key-label");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.stored_size_label), "stored-label");
    gtk_box_pack_start(GTK_BOX(info_strip), app.key_display_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(info_strip), app.stored_size_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(left_col), info_strip, FALSE, FALSE, 0);

    /* — Input panel — */
    GtkWidget *input_tv_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkTextBuffer *in_buf;
    GtkWidget *in_sv = make_scrolled_textview(&in_buf, NULL, 130);
    app.input_buf = in_buf;
    gtk_text_view_set_editable(GTK_TEXT_VIEW(gtk_bin_get_child(GTK_BIN(in_sv))), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(gtk_bin_get_child(GTK_BIN(in_sv))),
                                GTK_WRAP_WORD_CHAR);

    GtkWidget *write_hbox  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *write_btn   = gtk_button_new_with_label("⬆  Encrypt & Write");
    GtkWidget *clear_in_btn = gtk_button_new_with_label("✕ Clear");
    gtk_style_context_add_class(gtk_widget_get_style_context(write_btn), "btn-primary");
    g_signal_connect(write_btn,    "clicked", G_CALLBACK(on_write_clicked),       NULL);
    g_signal_connect(clear_in_btn, "clicked", G_CALLBACK(on_clear_input_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(write_hbox), write_btn,    TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(write_hbox), clear_in_btn, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(input_tv_box), in_sv,      TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(input_tv_box), write_hbox, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(left_col), make_panel("PLAINTEXT INPUT", input_tv_box), TRUE, TRUE, 0);

    /* — Output panel — */
    GtkWidget *output_tv_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *out_sv = make_scrolled_textview(&app.output_buf, NULL, 130);
    GtkWidget *read_btn = gtk_button_new_with_label("⬇  Decrypt & Read");
    gtk_style_context_add_class(gtk_widget_get_style_context(read_btn), "btn-success");
    g_signal_connect(read_btn, "clicked", G_CALLBACK(on_read_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(output_tv_box), out_sv,   TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(output_tv_box), read_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(left_col), make_panel("DECRYPTED OUTPUT", output_tv_box), TRUE, TRUE, 0);

    /* — Key control panel — */
    GtkWidget *key_box  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *key_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *key_lbl  = gtk_label_new("XOR Key (0x00 – 0xFF):");

    app.key_scale = gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL, 0, 255, 1);
    gtk_range_set_value(GTK_RANGE(app.key_scale), 0xAB);
    gtk_scale_set_draw_value(GTK_SCALE(app.key_scale), FALSE);
    g_signal_connect(app.key_scale, "value-changed", G_CALLBACK(on_key_scale_changed), NULL);

    GtkWidget *key_entry_lbl = gtk_label_new("Hex:");
    app.key_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app.key_entry), "AB");
    gtk_entry_set_max_length(GTK_ENTRY(app.key_entry), 2);
    gtk_widget_set_size_request(app.key_entry, 60, -1);
    g_signal_connect(app.key_entry, "activate", G_CALLBACK(on_key_entry_activate), NULL);

    GtkWidget *clear_btn = gtk_button_new_with_label("⬡ Wipe Vault");
    gtk_style_context_add_class(gtk_widget_get_style_context(clear_btn), "btn-danger");
    g_signal_connect(clear_btn, "clicked", G_CALLBACK(on_clear_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(key_hbox), key_entry_lbl, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(key_hbox), app.key_entry, FALSE, FALSE, 0);
    gtk_box_pack_end  (GTK_BOX(key_hbox), clear_btn,     FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(key_box), key_lbl,      FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(key_box), app.key_scale, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(key_box), key_hbox,     FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(left_col), make_panel("ENCRYPTION KEY CONTROL", key_box), FALSE, FALSE, 0);

    /* ════ RIGHT COLUMN ════ */
    GtkWidget *right_col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* — Hex viewer — */
    GtkWidget *hex_sw = make_scrolled_textview(&app.hex_buf, "hex-view", 200);
    build_hex_view(NULL, 0);
    gtk_box_pack_start(GTK_BOX(right_col), make_panel("KERNEL BUFFER  (CIPHERTEXT — NEVER PLAINTEXT)", hex_sw), TRUE, TRUE, 0);

    /* — Kernel log — */
    GtkWidget *log_tv_box   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *log_sw       = make_scrolled_textview(&app.log_buf, "log-view", 160);
    GtkWidget *refresh_btn  = gtk_button_new_with_label("↻  Refresh dmesg");
    g_signal_connect(refresh_btn, "clicked", G_CALLBACK(on_refresh_log_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(log_tv_box), log_sw,      TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(log_tv_box), refresh_btn, FALSE, FALSE, 0);
    append_log("[ Secure Vault GUI started ]");
    append_log("[ Click 'Connect' to open /dev/vault ]");
    gtk_box_pack_start(GTK_BOX(right_col), make_panel("KERNEL LOG  (dmesg | grep vault)", log_tv_box), TRUE, TRUE, 0);

    /* Pack columns into paned */
    gtk_paned_add1(GTK_PANED(hpaned), left_col);
    gtk_paned_add2(GTK_PANED(hpaned), right_col);

    /* ── Status Bar ── */
    GtkWidget *status_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_style_context_add_class(gtk_widget_get_style_context(status_bar), "status-bar");
    GtkWidget *status_icon = gtk_label_new("⬡");
    app.status_label = gtk_label_new("Ready — click 'Connect' to open /dev/vault");
    gtk_style_context_add_class(gtk_widget_get_style_context(app.status_label), "status-ok");
    gtk_label_set_xalign(GTK_LABEL(app.status_label), 0.0);
    gtk_box_pack_start(GTK_BOX(status_bar), status_icon,     FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(status_bar), app.status_label, TRUE,  TRUE,  0);

    GtkWidget *authors = gtk_label_new("Rehan 24K-0707  •  Abdullah 24K-0691  •  Ariz 24K-1044");
    gtk_style_context_add_class(gtk_widget_get_style_context(authors), "subtitle-label");
    gtk_box_pack_end(GTK_BOX(status_bar), authors, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(root), status_bar, FALSE, FALSE, 0);

    gtk_widget_show_all(app.window);
}

/* ── main ─────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    memset(&app, 0, sizeof(app));
    app.fd           = -1;
    app.device_open  = FALSE;
    app.current_key  = 0xAB;

    gtk_init(&argc, &argv);
    build_ui();
    gtk_main();

    if (app.device_open)
        close(app.fd);
    return 0;
}
