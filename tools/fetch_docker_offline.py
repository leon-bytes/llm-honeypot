#!/usr/bin/env python3
"""Stage Docker CE and its dependencies as arm64 .deb files for Ground Truth Pi.

The lab has no internet (hard rule 2), so everything apt would normally download
has to be fetched here on the dev machine and copied in. Ground Truth runs Raspberry
Pi OS Lite 64-bit = Debian 13 trixie, arm64.

The user chose to install Recommends, matching what a normal `apt install` does
on a machine with a network. apt cannot fetch those on Ground Truth, so the
recommended packages are staged too.

Which packages are actually needed depends on what Ground Truth already has, so
this works from a real inventory rather than guesswork:

    ssh lab-gt "dpkg-query -W -f='\\${binary:Package}\\t\\${Version}\\t\\${db:Status-Status}\\n'" \\
        > offline/gt-installed.txt

That is a read-only command as the `pi` user and needs no sudo. Without the
inventory the script still runs, but stages the full closure (much larger).

Usage:
    python3 tools/fetch_docker_offline.py                   # resolve + download
    python3 tools/fetch_docker_offline.py --dry-run         # resolve only
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import pathlib
import re
import sys
import urllib.request

SUITE = "trixie"
ARCH = "arm64"

# Docker's own repo, plus Debian's for the dependencies and recommends.
SOURCES = [
    ("docker", f"https://download.docker.com/linux/debian/dists/{SUITE}/stable/binary-{ARCH}/Packages.gz",
     "https://download.docker.com/linux/debian/"),
    ("debian-main", f"https://deb.debian.org/debian/dists/{SUITE}/main/binary-{ARCH}/Packages.gz",
     "https://deb.debian.org/debian/"),
    ("debian-updates", f"https://deb.debian.org/debian/dists/{SUITE}-updates/main/binary-{ARCH}/Packages.gz",
     "https://deb.debian.org/debian/"),
    ("debian-security", f"https://deb.debian.org/debian-security/dists/{SUITE}-security/main/binary-{ARCH}/Packages.gz",
     "https://deb.debian.org/debian-security/"),
]

ROOTS = [
    "docker-ce",
    "docker-ce-cli",
    "containerd.io",
    "docker-buildx-plugin",
    "docker-compose-plugin",
    "docker-ce-rootless-extras",
]


# --------------------------------------------------------------------------
# dpkg version comparison (needed both to pick the newest candidate from an
# index holding many versions, and to tell whether what Ground Truth already
# has satisfies a constraint like "libseccomp2 (>= 2.6.0)").
# --------------------------------------------------------------------------

def _order(c: str) -> int:
    """dpkg's character collation: '~' sorts before everything, then letters,
    then everything else."""
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        # non-digit run, compared by dpkg collation
        first = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        # digit run, compared numerically
        si, sj = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        na = int(a[si:i] or 0)
        nb = int(b[sj:j] or 0)
        if na != nb:
            return -1 if na < nb else 1
        if first:
            break
    return 0


def version_cmp(v1: str, v2: str) -> int:
    """Return -1/0/1 comparing two Debian version strings."""
    def split(v):
        epoch, _, rest = v.partition(":")
        if not _ or not epoch.isdigit():
            epoch, rest = "0", v
        upstream, _, revision = rest.rpartition("-")
        if not _:
            upstream, revision = rest, ""
        return int(epoch), upstream, revision

    e1, u1, r1 = split(v1)
    e2, u2, r2 = split(v2)
    if e1 != e2:
        return -1 if e1 < e2 else 1
    c = _cmp_part(u1, u2)
    if c:
        return c
    return _cmp_part(r1, r2)


def satisfies(installed: str, op: str, wanted: str) -> bool:
    c = version_cmp(installed, wanted)
    return {">=": c >= 0, ">>": c > 0, "<=": c <= 0, "<<": c < 0,
            "=": c == 0}.get(op, True)


# --------------------------------------------------------------------------
# Index parsing
# --------------------------------------------------------------------------

FIELD = re.compile(r"^([A-Za-z0-9][A-Za-z0-9-]*): ?(.*)$")


def fetch_index(url: str) -> str:
    print(f"  fetching {url}")
    with urllib.request.urlopen(url, timeout=120) as r:
        return gzip.decompress(r.read()).decode("utf-8", "replace")


def parse_index(text: str, origin: str, base: str, index: dict, provides: dict):
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        f, key = {}, None
        for line in block.split("\n"):
            m = FIELD.match(line)
            if m:
                key = m.group(1)
                f[key] = m.group(2)
            elif key and line.startswith((" ", "\t")):
                continue          # continuation of a multi-line field; not needed
        name, ver = f.get("Package"), f.get("Version")
        if not name or not ver or f.get("Architecture") not in (ARCH, "all"):
            continue
        f["_origin"], f["_base"] = origin, base
        prev = index.get(name)
        # Keep the newest version; Docker's index lists many.
        if prev is None or version_cmp(ver, prev["Version"]) > 0:
            index[name] = f
        for p in (f.get("Provides") or "").split(","):
            p = p.strip().split(" ")[0].split("(")[0].strip()
            if p:
                provides.setdefault(p, set()).add(name)


def parse_relations(field: str):
    """Parse a Depends/Recommends field into [[(name, op, ver), ...alternatives]]."""
    out = []
    for group in (field or "").split(","):
        group = group.strip()
        if not group:
            continue
        alts = []
        for alt in group.split("|"):
            alt = alt.strip()
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9+.\-]*)(?::[A-Za-z0-9]+)?"
                         r"(?:\s*\(\s*(<<|<=|=|>=|>>|<|>)\s*([^)]+)\))?", alt)
            if not m:
                continue
            op = m.group(2) or ""
            op = {"<": "<<", ">": ">>"}.get(op, op)
            alts.append((m.group(1), op, (m.group(3) or "").strip()))
        if alts:
            out.append(alts)
    return out


def load_inventory(path: pathlib.Path):
    """name -> version for packages in state 'installed' on Ground Truth."""
    inv = {}
    if not path.exists():
        return inv
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 3 and parts[2].strip() != "installed":
            continue                              # config-files, half-installed, etc.
        if len(parts) < 2:
            continue
        # dpkg-query prints multi-arch packages as "libc6:arm64"; dependency
        # fields say plain "libc6", so drop the architecture qualifier.
        inv[parts[0].strip().split(":")[0]] = parts[1].strip()
    return inv


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------

def resolve(index, provides, inventory, rec_depth):
    """Closure of ROOTS over Depends (recursive) and Recommends (to rec_depth).

    Recommends are followed only `rec_depth` levels deep from the roots. apt
    would follow them all the way down; bounding it keeps the staged set
    predictable and reviewable, while still covering git/pigz/apparmor and the
    rest of docker-ce's recommends.
    """
    need, seen, missing, skipped = {}, set(), [], []
    queue = [(r, 0, True) for r in ROOTS]

    def have(name, op, ver):
        if name not in inventory:
            return False
        return satisfies(inventory[name], op, ver) if op else True

    while queue:
        name, depth, is_root = queue.pop(0)
        if (name, depth) in seen:
            continue
        seen.add((name, depth))

        entry = index.get(name)
        if entry is None:
            if name in provides:                  # virtual package
                real = sorted(provides[name])
                if any(r in inventory for r in real):
                    continue
                name = real[0]
                entry = index.get(name)
            if entry is None:
                missing.append(name)
                continue

        # Already on Ground Truth at a good enough version, and not a root.
        if not is_root and name in inventory:
            skipped.append(f"{name} (installed {inventory[name]})")
            continue

        need[name] = entry

        for group in parse_relations(entry.get("Depends")):
            chosen = None
            for cand in group:
                if have(*cand):                   # satisfied already
                    chosen = None
                    break
                if cand[0] in index or cand[0] in provides:
                    chosen = chosen or cand
            if chosen:
                queue.append((chosen[0], depth, False))

        if depth < rec_depth:
            for group in parse_relations(entry.get("Recommends")):
                for cand in group:
                    if have(*cand):
                        break
                    if cand[0] in index or cand[0] in provides:
                        queue.append((cand[0], depth + 1, False))
                        break

    return need, missing, skipped


# --------------------------------------------------------------------------

def download(entry, outdir: pathlib.Path) -> pathlib.Path:
    url = entry["_base"] + entry["Filename"]
    dest = outdir / pathlib.PurePosixPath(entry["Filename"]).name
    want = entry.get("SHA256")
    if dest.exists() and want:
        if hashlib.sha256(dest.read_bytes()).hexdigest() == want:
            print(f"  = {dest.name} (already staged, checksum OK)")
            return dest
    print(f"  + {dest.name} ({int(entry.get('Size', 0)) / 1e6:.1f} MB)")
    with urllib.request.urlopen(url, timeout=300) as r:
        data = r.read()
    if want:
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            raise SystemExit(f"CHECKSUM MISMATCH for {dest.name}\n  want {want}\n  got  {got}")
    dest.write_bytes(data)
    return dest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", default="offline/gt-installed.txt",
                    help="dpkg-query dump from Ground Truth (read-only to collect)")
    ap.add_argument("--outdir", default="offline/docker-gt")
    ap.add_argument("--recommends-depth", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true", help="resolve and report, download nothing")
    args = ap.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    inv_path = (root / args.inventory) if not pathlib.Path(args.inventory).is_absolute() \
        else pathlib.Path(args.inventory)
    outdir = (root / args.outdir) if not pathlib.Path(args.outdir).is_absolute() \
        else pathlib.Path(args.outdir)

    inventory = load_inventory(inv_path)
    if inventory:
        print(f"[inventory] {len(inventory)} packages already on Ground Truth ({inv_path})")
    else:
        print(f"[inventory] NONE found at {inv_path} - staging the full closure.\n"
              f"            Collect it read-only with:\n"
              f"            ssh lab-gt \"dpkg-query -W -f='\\${{binary:Package}}\\t"
              f"\\${{Version}}\\t\\${{db:Status-Status}}\\n'\" > {args.inventory}")

    print("[indexes]")
    index, provides = {}, {}
    for origin, url, base in SOURCES:
        try:
            parse_index(fetch_index(url), origin, base, index, provides)
        except Exception as e:
            print(f"  ! {origin} unavailable ({e}) - continuing")
    print(f"[indexes] {len(index)} packages known")

    need, missing, skipped = resolve(index, provides, inventory, args.recommends_depth)

    print(f"\n[resolved] {len(need)} packages to stage:")
    total = 0
    for name in sorted(need):
        e = need[name]
        size = int(e.get("Size", 0))
        total += size
        print(f"  {name:<34} {e['Version']:<32} {size/1e6:7.1f} MB  [{e['_origin']}]")
    print(f"[resolved] total {total/1e6:.1f} MB")
    if skipped:
        print(f"\n[already on Ground Truth] {len(skipped)} skipped: {', '.join(sorted(skipped)[:12])}"
              + (" ..." if len(skipped) > 12 else ""))
    if missing:
        print(f"\n[WARNING] not found in any index: {', '.join(sorted(set(missing)))}")

    if args.dry_run:
        print("\n[dry-run] nothing downloaded")
        return

    outdir.mkdir(parents=True, exist_ok=True)
    print(f"\n[download] -> {outdir}")
    lines = []
    for name in sorted(need):
        e = need[name]
        p = download(e, outdir)
        lines.append(f"{name}\t{e['Version']}\t{p.name}\t{p.stat().st_size}\t"
                     f"{hashlib.sha256(p.read_bytes()).hexdigest()}\t{e['_origin']}")

    manifest = outdir / "MANIFEST.txt"
    manifest.write_text(
        f"# Docker CE staged for Ground Truth Pi ({SUITE}/{ARCH})\n"
        f"# Recommends included (user's choice); recommends-depth={args.recommends_depth}\n"
        f"# inventory: {inv_path if inventory else 'NONE - full closure'}\n"
        f"# package\tversion\tfile\tbytes\tsha256\torigin\n" + "\n".join(lines) + "\n",
        encoding="utf-8")
    print(f"[download] {len(lines)} packages staged; wrote {manifest}")


if __name__ == "__main__":
    main()
