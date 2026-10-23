#!/usr/bin/env python3
"""Every name a manual page could have on the reference machine, for `man` (2026-10-14).

The relay answers `man NAME...` in code only when no NAME can be a page there: then the
real man-db 2.13.1 prints `No manual entry for NAME` for each and exits 16 (recorded in
the arm64 userland, offline/debian13-arm64). Which pages the machine has is not
recorded, so the list errs on the safe side: every page name in **any** Debian 13
package (not only the installed ones), in Raspberry Pi's archive and in the Docker
packages Ground Truth installed, lower case (man-db ignores case by default). A name on
the list goes to the model, as before; only a name no package anywhere has a page for
gets the code answer.

Sources (offline/man-index/, git-ignored, refetchable):
  curl -sSL -o offline/man-index/Contents-arm64-trixie.gz \\
    http://snapshot.debian.org/archive/debian/20260406T000000Z/dists/trixie/main/Contents-arm64.gz
  curl -sSL -o offline/man-index/Contents-all-trixie.gz \\
    http://snapshot.debian.org/archive/debian/20260406T000000Z/dists/trixie/main/Contents-all.gz
  curl -sSL -o offline/man-index/Contents-arm64-rpi.gz \\
    http://archive.raspberrypi.com/debian/dists/trixie/main/Contents-arm64.gz
and the packages in offline/docker-gt/ (their own file lists).

Run: python3 tools/build_man_names.py      (writes honeypot/man_names.txt.gz)
"""
from __future__ import annotations
import gzip
import io
import pathlib
import re
import sys
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = ROOT / "offline" / "man-index"
OUT = ROOT / "honeypot" / "man_names.txt.gz"
PAGE = re.compile(r"^(?:\./)?usr/share/man/(?:[^/]+/)?man[^/]+/([^/\s]+)")


def name_of(file: str) -> str | None:
    base = re.sub(r"\.(gz|bz2|xz|zst|lzma|Z)$", "", file)
    m = re.match(r"^(.+)\.([0-9n][^.]*|l)$", base)
    return m.group(1).lower() if m else None


def deb_files(path: pathlib.Path) -> list[str]:
    """The file list of a .deb (an ar archive with a data.tar.*), without dpkg."""
    raw = path.read_bytes()
    assert raw[:8] == b"!<arch>\n", path
    i = 8
    while i < len(raw):
        name, size = raw[i:i + 16].decode().strip(), int(raw[i + 48:i + 58].decode())
        body = raw[i + 60:i + 60 + size]
        if name.startswith("data.tar"):
            with tarfile.open(fileobj=io.BytesIO(body)) as t:
                return t.getnames()
        i += 60 + size + (size % 2)
    return []


def main() -> int:
    names: set[str] = set()
    for f in sorted(INDEX.glob("Contents-*.gz")):
        n0 = len(names)
        with gzip.open(f, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = PAGE.match(line)
                if m and (n := name_of(m.group(1))):
                    names.add(n)
        print(f"{f.name}: {len(names) - n0} new names")
    if len(names) < 50_000:
        sys.exit(f"only {len(names)} names: an index is missing or broken (see the docstring)")
    for deb in sorted((ROOT / "offline" / "docker-gt").glob("*.deb")):
        n0 = len(names)
        for path in deb_files(deb):
            m = PAGE.match(path)
            if m and (n := name_of(m.group(1))):
                names.add(n)
        print(f"{deb.name}: {len(names) - n0} new names")
    with gzip.open(OUT, "wt", encoding="utf-8", compresslevel=9) as fh:
        fh.write("\n".join(sorted(names)) + "\n")
    print(f"{len(names)} names -> {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
