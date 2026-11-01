#!/usr/bin/env python3
"""Assemble the Windows runtime tree for hunter-gui.exe (build tooling only).

Usage: stage.py SYSROOT_UCRT64 STAGE_DIR HUNTER_EXE HUNTER_GUI_EXE [WINE_CMD ...]

Copies the two executables plus only the DLLs they need (resolved recursively
with objdump), the GDK-Pixbuf loaders, Adwaita and hicolor icons, and the
compiled GSettings schemas into STAGE_DIR/{bin,lib,share}. The pixbuf loader
cache is generated under Wine and rewritten to relative paths.
"""
import os
import re
import shutil
import subprocess
import sys


def imports(path):
    out = subprocess.run(["objdump", "-p", path], capture_output=True, text=True, check=True).stdout
    return re.findall(r"DLL Name: (\S+)", out)


def main():
    sysroot, stage, hunter, gui = sys.argv[1:5]
    wine = sys.argv[5:]
    src_bin = os.path.join(sysroot, "bin")
    have = {f.lower(): f for f in os.listdir(src_bin) if f.lower().endswith(".dll")}

    shutil.rmtree(stage, ignore_errors=True)
    for d in ("bin", "lib", "share"):
        os.makedirs(os.path.join(stage, d))
    shutil.copy(hunter, os.path.join(stage, "bin"))
    shutil.copy(gui, os.path.join(stage, "bin"))

    pix_src = os.path.join(sysroot, "lib", "gdk-pixbuf-2.0", "2.10.0", "loaders")
    pix_dst = os.path.join(stage, "lib", "gdk-pixbuf-2.0", "2.10.0", "loaders")
    os.makedirs(pix_dst)
    loaders = [f for f in os.listdir(pix_src) if f.endswith(".dll")]
    for f in loaders:
        shutil.copy(os.path.join(pix_src, f), pix_dst)

    todo = [gui] + [os.path.join(pix_dst, f) for f in loaders]
    done = set()
    while todo:
        cur = todo.pop()
        for dll in imports(cur):
            real = have.get(dll.lower())
            if real and real not in done:
                done.add(real)
                shutil.copy(os.path.join(src_bin, real), os.path.join(stage, "bin"))
                todo.append(os.path.join(src_bin, real))
    print("copied %d DLLs" % len(done))

    # Icons and schemas.
    for theme in ("Adwaita", "hicolor"):
        shutil.copytree(os.path.join(sysroot, "share", "icons", theme),
                        os.path.join(stage, "share", "icons", theme))
    sch = os.path.join(stage, "share", "glib-2.0", "schemas")
    shutil.copytree(os.path.join(sysroot, "share", "glib-2.0", "schemas"), sch)
    subprocess.run(["glib-compile-schemas", sch], check=True)

    # Pixbuf loader cache with prefix-relative paths.
    qry = os.path.join(src_bin, "gdk-pixbuf-query-loaders.exe")
    mods = [os.path.join(pix_dst, f) for f in loaders]
    txt = subprocess.run(wine + [qry] + mods, capture_output=True, text=True, check=True).stdout
    keep = []
    for ln in txt.splitlines():
        if ln.startswith('"') and ln.endswith('.dll"'):
            ln = '"lib\\\\gdk-pixbuf-2.0\\\\2.10.0\\\\loaders\\\\%s"' % os.path.basename(ln.strip('"'))
        if not re.match(r"^[0-9a-f]{4}:", ln):
            keep.append(ln)
    cache = os.path.join(stage, "lib", "gdk-pixbuf-2.0", "2.10.0", "loaders.cache")
    with open(cache, "w", newline="\n") as f:
        f.write("\n".join(keep) + "\n")
    print("stage ready: %s" % stage)


if __name__ == "__main__":
    main()
