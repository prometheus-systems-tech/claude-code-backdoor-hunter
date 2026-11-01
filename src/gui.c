/*
 * Copyright (c) 2026 Ross WD Cameron <rwd.cameron@prometheus-systems.co.za>
 * Licensed under the GNU General Public License, version 2.
 *
 * GTK 4 front end for the hunter checker. Runs the read-only checker, streams its
 * output into a window and shows the result. All detection logic lives in hunter.c.
 */

#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define APP_ID "org.backdoorhunter.Gui"
#ifdef _WIN32
#define HUNTER_NAME "hunter.exe"
#else
#define HUNTER_NAME "hunter"
#endif

typedef struct {
    GtkWidget *win, *run_btn, *stop_btn, *save_btn, *root_check, *sshd_check, *progress, *result;
    GtkTextBuffer *buf;
    GtkWidget *view;
    GSubprocess *proc;
    GDataInputStream *in;
    gboolean running;
    char *hunter;
    char *self_dir;
    GtkFileChooserNative *chooser;
} Ui;

static Ui ui;

/* ------------------------------------------------------------ helpers */

static void set_result(const char *text, const char *colour)
{
    char *m = g_markup_printf_escaped("<span foreground=\"%s\" weight=\"bold\">%s</span>", colour, text);
    gtk_label_set_markup(GTK_LABEL(ui.result), m);
    g_free(m);
}

static void append(const char *line, const char *tag)
{
    GtkTextIter end;
    GtkTextMark *mark;
    gtk_text_buffer_get_end_iter(ui.buf, &end);
    if (tag) gtk_text_buffer_insert_with_tags_by_name(ui.buf, &end, line, -1, tag, NULL);
    else gtk_text_buffer_insert(ui.buf, &end, line, -1);
    gtk_text_buffer_insert(ui.buf, &end, "\n", 1);
    gtk_text_buffer_get_end_iter(ui.buf, &end);
    mark = gtk_text_buffer_create_mark(ui.buf, NULL, &end, FALSE);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(ui.view), mark, 0.0, FALSE, 0.0, 0.0);
    gtk_text_buffer_delete_mark(ui.buf, mark);
}

/* Find the checker next to this executable, in a libexec layout, or in ./build. */
static char *locate_hunter(const char *argv0)
{
    char *exe = NULL, *dir, *cand;
    const char *env = g_getenv("HUNTER_BIN");
    if (env && g_file_test(env, G_FILE_TEST_IS_EXECUTABLE)) return g_strdup(env);
#ifdef __linux__
    exe = g_file_read_link("/proc/self/exe", NULL);
#endif
    if (!exe) {
        char *found = g_strrstr(argv0, G_DIR_SEPARATOR_S) ? g_strdup(argv0) : g_find_program_in_path(argv0);
#ifdef G_OS_UNIX
        char real[4096];
        exe = found && realpath(found, real) ? g_strdup(real) : NULL;
#else
        exe = found ? g_canonicalize_filename(found, NULL) : NULL;
#endif
        g_free(found);
    }
    if (!exe) return NULL;
    dir = g_path_get_dirname(exe);
    ui.self_dir = g_strdup(dir);
    g_free(exe);
    cand = g_build_filename(dir, HUNTER_NAME, NULL);
    if (!g_file_test(cand, G_FILE_TEST_IS_EXECUTABLE)) {
        g_free(cand);
        cand = g_build_filename(dir, "..", "libexec", "claude-code-backdoor-hunter", HUNTER_NAME, NULL);
        if (!g_file_test(cand, G_FILE_TEST_IS_EXECUTABLE)) { g_free(cand); cand = NULL; }
    }
    g_free(dir);
    return cand;
}

/* ------------------------------------------------------------ run handling */

static void read_next(void);

static void on_done(int rc)
{
    ui.running = FALSE;
    g_clear_object(&ui.in);
    g_clear_object(&ui.proc);
    gtk_widget_set_sensitive(ui.run_btn, TRUE);
    gtk_widget_set_sensitive(ui.stop_btn, FALSE);
    gtk_widget_set_sensitive(ui.save_btn, TRUE);
    if (rc == 0 || rc == 1 || rc == 2) {
        static const char *text[] = {
            "No indicators found.",
            "Indicators of compromise found. Isolate the machine, remove the key and persistence, rotate credentials.",
            "No definite indicators, but [?] items need manual review."};
        static const char *colour[] = {"#26a269", "#c01c28", "#e5a50a"};
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ui.progress), 1.0);
        gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui.progress), "Done");
        set_result(text[rc], colour[rc]);
    } else {
        char *t = g_strdup_printf("Check stopped or failed (exit code %d).", rc);
        gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui.progress), "Stopped");
        set_result(t, "#c01c28");
        g_free(t);
    }
}

static void on_wait(GObject *src, GAsyncResult *res, gpointer data)
{
    int rc = -1;
    (void)data;
    if (g_subprocess_wait_finish(G_SUBPROCESS(src), res, NULL) && g_subprocess_get_if_exited(G_SUBPROCESS(src)))
        rc = g_subprocess_get_exit_status(G_SUBPROCESS(src));
    on_done(rc);
}

static void handle_line(const char *line)
{
    const char *tag = NULL;
    if (line[0] == '[' && (line[1] == '#' || line[1] == '-')) {
        const char *p = strstr(line, "] ");
        int step, total;
        if (p && sscanf(p + 2, "%d/%d", &step, &total) == 2 && total > 0) {
            char t[32];
            g_snprintf(t, sizeof t, "%d/%d", step, total);
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ui.progress), (double)step / total);
            gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui.progress), t);
            return;
        }
    }
    if (g_str_has_prefix(line, "[!]")) tag = "bad";
    else if (g_str_has_prefix(line, "[?]")) tag = "review";
    else if (g_str_has_prefix(line, "[ok]")) tag = "ok";
    else if (g_str_has_prefix(line, "==")) tag = "head";
    append(line, tag);
}

static void on_line(GObject *src, GAsyncResult *res, gpointer data)
{
    gsize len = 0;
    char *line = g_data_input_stream_read_line_finish(G_DATA_INPUT_STREAM(src), res, &len, NULL);
    (void)data;
    if (!line) {
        if (ui.proc) g_subprocess_wait_async(ui.proc, NULL, on_wait, NULL);
        return;
    }
    {
        char *valid = g_utf8_make_valid(line, -1);
        handle_line(valid);
        g_free(valid);
    }
    g_free(line);
    read_next();
}

static void read_next(void)
{
    if (ui.in) g_data_input_stream_read_line_async(ui.in, G_PRIORITY_DEFAULT, NULL, on_line, NULL);
}

static void on_run(GtkButton *b, gpointer d)
{
    GPtrArray *argv;
    GError *err = NULL;
    (void)b; (void)d;
    if (ui.running) return;

    gtk_text_buffer_set_text(ui.buf, "", 0);
    gtk_label_set_text(GTK_LABEL(ui.result), "");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ui.progress), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui.progress), "Starting...");
    gtk_widget_set_sensitive(ui.run_btn, FALSE);
    gtk_widget_set_sensitive(ui.save_btn, FALSE);
    gtk_widget_set_sensitive(ui.stop_btn, TRUE);
    ui.running = TRUE;

    argv = g_ptr_array_new_with_free_func(g_free);
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ui.root_check)) && gtk_widget_get_sensitive(ui.root_check)) {
        g_ptr_array_add(argv, g_strdup("pkexec"));
        g_ptr_array_add(argv, g_strdup("env"));
        g_ptr_array_add(argv, g_strdup_printf("HOME=%s", g_get_home_dir()));
    }
    g_ptr_array_add(argv, g_strdup(ui.hunter));
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ui.sshd_check)))
        g_ptr_array_add(argv, g_strdup("--sshd-ok"));
    g_ptr_array_add(argv, NULL);

    ui.proc = g_subprocess_newv((const gchar *const *)argv->pdata,
                                G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_MERGE, &err);
    g_ptr_array_free(argv, TRUE);
    if (!ui.proc) {
        char *m = g_strdup_printf("Failed to start: %s", err->message);
        append(m, "bad");
        g_free(m);
        g_error_free(err);
        on_done(-1);
        return;
    }
    ui.in = g_data_input_stream_new(g_subprocess_get_stdout_pipe(ui.proc));
    read_next();
}

static void on_stop(GtkButton *b, gpointer d)
{
    (void)b; (void)d;
    if (!ui.proc) return;
#ifdef G_OS_UNIX
    g_subprocess_send_signal(ui.proc, SIGTERM);
#else
    g_subprocess_force_exit(ui.proc);
#endif
}

/* ------------------------------------------------------------ save report */

static void on_save_response(GtkNativeDialog *dlg, int response, gpointer d)
{
    (void)d;
    if (response == GTK_RESPONSE_ACCEPT) {
        GFile *f = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dlg));
        GtkTextIter s, e;
        char *text, *path;
        gtk_text_buffer_get_bounds(ui.buf, &s, &e);
        text = gtk_text_buffer_get_text(ui.buf, &s, &e, FALSE);
        path = g_file_get_path(f);
        if (!g_file_set_contents(path, text, -1, NULL)) {
            char *m = g_strdup_printf("Could not save report to %s", path);
            set_result(m, "#c01c28");
            g_free(m);
        }
        g_free(path);
        g_free(text);
        g_object_unref(f);
    }
    g_clear_object(&ui.chooser);
}

static void on_save(GtkButton *b, gpointer d)
{
    (void)b; (void)d;
    ui.chooser = gtk_file_chooser_native_new("Save report", GTK_WINDOW(ui.win), GTK_FILE_CHOOSER_ACTION_SAVE,
                                             "Save", "Cancel");
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(ui.chooser), "backdoor-check-report.txt");
    g_signal_connect(ui.chooser, "response", G_CALLBACK(on_save_response), NULL);
    gtk_native_dialog_show(GTK_NATIVE_DIALOG(ui.chooser));
}

/* ------------------------------------------------------------ window */

static void activate(GtkApplication *app, gpointer d)
{
    GtkWidget *box, *bar, *scroll;
    GtkTextTagTable *tt;
    (void)d;

    if (gtk_application_get_active_window(app)) {
        gtk_window_present(gtk_application_get_active_window(app));
        return;
    }
    if (ui.self_dir) {
        char *pk = g_build_filename(ui.self_dir, "..", "packaging", NULL);
        gtk_icon_theme_add_search_path(gtk_icon_theme_get_for_display(gdk_display_get_default()), pk);
        g_free(pk);
    }

    ui.win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(ui.win), "Claude Code Backdoor Hunter");
    gtk_window_set_icon_name(GTK_WINDOW(ui.win), APP_ID);
    gtk_window_set_default_size(GTK_WINDOW(ui.win), 900, 650);

    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(box, 10);
    gtk_widget_set_margin_bottom(box, 10);
    gtk_widget_set_margin_start(box, 10);
    gtk_widget_set_margin_end(box, 10);
    gtk_window_set_child(GTK_WINDOW(ui.win), box);

    bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    ui.run_btn = gtk_button_new_with_label("Run check");
    gtk_widget_add_css_class(ui.run_btn, "suggested-action");
    g_signal_connect(ui.run_btn, "clicked", G_CALLBACK(on_run), NULL);
    ui.stop_btn = gtk_button_new_with_label("Stop");
    gtk_widget_set_sensitive(ui.stop_btn, FALSE);
    g_signal_connect(ui.stop_btn, "clicked", G_CALLBACK(on_stop), NULL);
    ui.save_btn = gtk_button_new_with_label("Save report...");
    gtk_widget_set_sensitive(ui.save_btn, FALSE);
    g_signal_connect(ui.save_btn, "clicked", G_CALLBACK(on_save), NULL);
    gtk_box_append(GTK_BOX(bar), ui.run_btn);
    gtk_box_append(GTK_BOX(bar), ui.stop_btn);
    gtk_box_append(GTK_BOX(bar), ui.save_btn);

    ui.sshd_check = gtk_check_button_new_with_label("SSH server is expected to run");
    gtk_widget_set_tooltip_text(ui.sshd_check,
        "Tick this if you run sshd on purpose. A running sshd is then reported as OK instead of needing review.");
    gtk_box_append(GTK_BOX(bar), ui.sshd_check);
    ui.root_check = gtk_check_button_new_with_label("Run with administrator rights");
#ifdef __linux__
    {
        char *pk = g_find_program_in_path("pkexec");
        gtk_widget_set_tooltip_text(ui.root_check,
            "Uses pkexec so root-only files and logs can be read. Your own home directory is still checked.");
        if (!pk) gtk_widget_set_sensitive(ui.root_check, FALSE);
        g_free(pk);
    }
#else
    gtk_widget_set_sensitive(ui.root_check, FALSE);
    gtk_widget_set_tooltip_text(ui.root_check, "Needs Linux with pkexec (polkit). Run the GUI with sudo instead.");
#endif
    gtk_widget_set_hexpand(ui.root_check, TRUE);
    gtk_widget_set_halign(ui.root_check, GTK_ALIGN_END);
    gtk_box_append(GTK_BOX(bar), ui.root_check);
    gtk_box_append(GTK_BOX(box), bar);

    ui.progress = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(ui.progress), TRUE);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui.progress), "Idle");
    gtk_box_append(GTK_BOX(box), ui.progress);

    ui.result = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(ui.result), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(ui.result), TRUE);
    gtk_box_append(GTK_BOX(box), ui.result);

    ui.buf = gtk_text_buffer_new(NULL);
    tt = gtk_text_buffer_get_tag_table(ui.buf);
    (void)tt;
    gtk_text_buffer_create_tag(ui.buf, "bad", "foreground", "#c01c28", "weight", PANGO_WEIGHT_BOLD, NULL);
    gtk_text_buffer_create_tag(ui.buf, "review", "foreground", "#b8730a", NULL);
    gtk_text_buffer_create_tag(ui.buf, "ok", "foreground", "#26a269", NULL);
    gtk_text_buffer_create_tag(ui.buf, "head", "weight", PANGO_WEIGHT_BOLD, NULL);
    ui.view = gtk_text_view_new_with_buffer(ui.buf);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(ui.view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(ui.view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(ui.view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ui.view), GTK_WRAP_WORD_CHAR);
    scroll = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), ui.view);
    gtk_box_append(GTK_BOX(box), scroll);

    if (!ui.hunter) {
        gtk_widget_set_sensitive(ui.run_btn, FALSE);
        set_result("Cannot find the hunter checker next to this program (set HUNTER_BIN to override).", "#c01c28");
    }
    gtk_window_present(GTK_WINDOW(ui.win));
}

int main(int argc, char **argv)
{
    GtkApplication *app;
    int rc;
    ui.hunter = locate_hunter(argv[0]);
    app = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    rc = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return rc;
}
