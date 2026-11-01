#!/usr/bin/env python3
"""Download GTK4 and all of its dependencies for Windows (MSYS2 UCRT64) and
unpack them into a sysroot, so gui.c can be cross-compiled from Linux.

Usage: fetch_gtk4.py SYSROOT [extra-package ...]
Needs: curl, tar, zstd on PATH.
"""
import os
import re
import subprocess
import sys
import tempfile

BASE = "https://mirror.msys2.org/mingw/ucrt64"
PFX = "mingw-w64-ucrt-x86_64-"
ROOTS = ["gtk4", "adwaita-icon-theme", "hicolor-icon-theme", "librsvg", "gdk-pixbuf2"]


def sh(*a):
    subprocess.run(a, check=True)


def parse(path):
    out, key = {}, None
    with open(path, encoding="utf-8") as f:
        for ln in f.read().splitlines():
            m = re.fullmatch(r"%(\w+)%", ln)
            if m:
                key = m.group(1)
                out[key] = []
            elif ln and key:
                out[key].append(ln)
    return out


def main():
    root = os.path.abspath(sys.argv[1])
    extra = sys.argv[2:]
    tmp = tempfile.mkdtemp()
    dbf = os.path.join(tmp, "ucrt64.db")
    sh("curl", "-fsSL", "-o", dbf, BASE + "/ucrt64.db")
    dbdir = os.path.join(tmp, "db")
    os.makedirs(dbdir)
    sh("tar", "-xf", dbf, "-C", dbdir)

    pk, prov = {}, {}
    for d in os.listdir(dbdir):
        desc = parse(os.path.join(dbdir, d, "desc"))
        deps = desc.get("DEPENDS", [])
        name = desc["NAME"][0]
        pk[name] = (desc["FILENAME"][0], deps)
        prov[name] = name
        for p in desc.get("PROVIDES", []):
            prov.setdefault(re.split(r"[<>=]", p)[0], name)

    todo = [PFX + r for r in ROOTS + extra]
    seen = set()
    while todo:
        n = todo.pop()
        n = prov.get(re.split(r"[<>=]", n)[0], None)
        if not n or n in seen:
            continue
        seen.add(n)
        for d in pk[n][1]:
            todo.append(re.split(r"[<>=]", d)[0])

    os.makedirs(root, exist_ok=True)
    cache = os.path.join(root, ".cache")
    os.makedirs(cache, exist_ok=True)
    for n in sorted(seen):
        fn = pk[n][0]
        dst = os.path.join(cache, fn)
        if not os.path.exists(dst):
            sh("curl", "-fsSL", "-o", dst, BASE + "/" + fn)
        sh("tar", "--zstd", "-xf", dst, "-C", root, "--exclude=.PKGINFO",
           "--exclude=.BUILDINFO", "--exclude=.MTREE", "--exclude=.INSTALL")
    print("unpacked %d packages into %s" % (len(seen), root))


if __name__ == "__main__":
    main()
