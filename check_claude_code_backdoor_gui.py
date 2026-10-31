#!/usr/bin/env python3
"""GTK 4 front end for check_claude_code_backdoor.sh.

Runs the read-only checker, streams its output into a window and shows the
result. All detection logic stays in the shell script; this is only a viewer.
"""

import os
import re
import shutil
import subprocess
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk, Pango  # noqa: E402

APP_ID = "org.backdoorhunter.Gui"
SCRIPT = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "check_claude_code_backdoor.sh"
)
PROGRESS_RE = re.compile(r"^\[[#-]+\] (\d+)/(\d+)")

RESULTS = {
    0: ("No indicators found.", "#26a269"),
    1: ("Indicators of compromise found. Isolate the machine, remove the key and persistence, rotate credentials.", "#c01c28"),
    2: ("No definite indicators, but [?] items need manual review.", "#e5a50a"),
}


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Claude Code Backdoor Hunter")
        self.set_default_size(900, 650)
        self.proc = None
        self.running = False

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        for side in ("top", "bottom", "start", "end"):
            getattr(box, f"set_margin_{side}")(10)
        self.set_child(box)

        # Controls
        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.run_btn = Gtk.Button(label="Run check")
        self.run_btn.add_css_class("suggested-action")
        self.run_btn.connect("clicked", self.on_run)
        self.stop_btn = Gtk.Button(label="Stop")
        self.stop_btn.set_sensitive(False)
        self.stop_btn.connect("clicked", self.on_stop)
        self.save_btn = Gtk.Button(label="Save report...")
        self.save_btn.set_sensitive(False)
        self.save_btn.connect("clicked", self.on_save)
        bar.append(self.run_btn)
        bar.append(self.stop_btn)
        bar.append(self.save_btn)

        self.root_check = Gtk.CheckButton(label="Run with administrator rights")
        self.root_check.set_tooltip_text(
            "Uses pkexec so root-only files and logs can be read. Your own home directory is still checked."
        )
        if not (sys.platform.startswith("linux") and shutil.which("pkexec")):
            self.root_check.set_sensitive(False)
            self.root_check.set_tooltip_text("Needs Linux with pkexec (polkit). Run the GUI with sudo instead.")
        self.root_check.set_hexpand(True)
        self.root_check.set_halign(Gtk.Align.END)
        bar.append(self.root_check)
        box.append(bar)

        # Progress and result
        self.progress = Gtk.ProgressBar()
        self.progress.set_show_text(True)
        self.progress.set_text("Idle")
        box.append(self.progress)

        self.result = Gtk.Label(xalign=0)
        self.result.set_wrap(True)
        box.append(self.result)

        # Output
        self.buf = Gtk.TextBuffer()
        self.tags = {
            "bad": self.buf.create_tag("bad", foreground="#c01c28", weight=Pango.Weight.BOLD),
            "review": self.buf.create_tag("review", foreground="#b8730a"),
            "ok": self.buf.create_tag("ok", foreground="#26a269"),
            "head": self.buf.create_tag("head", weight=Pango.Weight.BOLD),
        }
        self.view = Gtk.TextView(buffer=self.buf)
        self.view.set_editable(False)
        self.view.set_cursor_visible(False)
        self.view.set_monospace(True)
        self.view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_child(self.view)
        box.append(scroll)

        if not os.path.isfile(SCRIPT):
            self.run_btn.set_sensitive(False)
            self.set_result(f"Cannot find {SCRIPT}", "#c01c28")

    # ----------------------------------------------------------- helpers
    def set_result(self, text, colour):
        self.result.set_markup(
            f'<span foreground="{colour}" weight="bold">{GLib.markup_escape_text(text)}</span>'
        )

    def append(self, text, tag=None):
        end = self.buf.get_end_iter()
        if tag:
            self.buf.insert_with_tags(end, text, self.tags[tag])
        else:
            self.buf.insert(end, text)
        mark = self.buf.create_mark(None, self.buf.get_end_iter(), False)
        self.view.scroll_to_mark(mark, 0.0, False, 0.0, 0.0)
        self.buf.delete_mark(mark)

    # ----------------------------------------------------------- actions
    def on_run(self, _btn):
        if self.running:
            return
        self.buf.set_text("")
        self.result.set_text("")
        self.progress.set_fraction(0.0)
        self.progress.set_text("Starting...")
        self.run_btn.set_sensitive(False)
        self.save_btn.set_sensitive(False)
        self.stop_btn.set_sensitive(True)
        self.running = True

        cmd = ["/bin/sh", SCRIPT]
        if self.root_check.get_active() and self.root_check.get_sensitive():
            cmd = ["pkexec", "env", f"HOME={os.path.expanduser('~')}"] + cmd
        threading.Thread(target=self.worker, args=(cmd,), daemon=True).start()

    def on_stop(self, _btn):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def on_save(self, _btn):
        chooser = Gtk.FileChooserNative(
            title="Save report",
            transient_for=self,
            action=Gtk.FileChooserAction.SAVE,
            accept_label="Save",
        )
        chooser.set_current_name("backdoor-check-report.txt")
        chooser.connect("response", self.on_save_response)
        self._chooser = chooser  # keep a reference alive
        chooser.show()

    def on_save_response(self, chooser, response):
        if response == Gtk.ResponseType.ACCEPT:
            path = chooser.get_file().get_path()
            text = self.buf.get_text(self.buf.get_start_iter(), self.buf.get_end_iter(), False)
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
            except OSError as exc:
                self.set_result(f"Could not save report: {exc}", "#c01c28")

    # ----------------------------------------------------------- worker
    def worker(self, cmd):
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                bufsize=1,
            )
            for line in self.proc.stdout:
                GLib.idle_add(self.on_line, line)
            rc = self.proc.wait()
        except OSError as exc:
            GLib.idle_add(self.on_line, f"Failed to start: {exc}\n")
            rc = -1
        GLib.idle_add(self.on_done, rc)

    def on_line(self, line):
        m = PROGRESS_RE.match(line)
        if m:
            step, total = int(m.group(1)), int(m.group(2))
            self.progress.set_fraction(step / total)
            self.progress.set_text(f"{step}/{total}")
            return False
        if line.startswith("[!]"):
            tag = "bad"
        elif line.startswith("[?]"):
            tag = "review"
        elif line.startswith("[ok]"):
            tag = "ok"
        elif line.startswith("=="):
            tag = "head"
        else:
            tag = None
        self.append(line, tag)
        return False

    def on_done(self, rc):
        self.running = False
        self.proc = None
        self.run_btn.set_sensitive(True)
        self.stop_btn.set_sensitive(False)
        self.save_btn.set_sensitive(True)
        if rc in RESULTS:
            text, colour = RESULTS[rc]
            self.progress.set_fraction(1.0)
            self.progress.set_text("Done")
        else:
            text, colour = f"Check stopped or failed (exit code {rc}).", "#c01c28"
            self.progress.set_text("Stopped")
        self.set_result(text, colour)
        return False


class App(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)

    def do_activate(self):
        win = self.props.active_window or MainWindow(self)
        win.present()


if __name__ == "__main__":
    sys.exit(App().run(sys.argv))
