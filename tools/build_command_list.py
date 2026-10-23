#!/usr/bin/env python3
"""Build the list of commands that exist on Ground Truth, for the relay's
`command not found` (honeypot/commands.json).

Nothing here touches Ground Truth. The inputs are its package inventory and public
package indexes:
  - offline/gt-installed.txt          packages before the Docker setup (2026-09-27)
  - offline/docker-gt/MANIFEST.txt    packages scripts/gt_setup.sh added
  - Debian trixie Contents-{arm64,all} (main, contrib, non-free, non-free-firmware)
    and Raspberry Pi's trixie Contents-arm64: which files each package installs
  - the Docker CE .debs in offline/docker-gt (docker.com publishes no Contents)
  - ALTERNATIVES below: links that package scripts create at install time, which no
    index lists
  - bash 5.2's builtins and keywords

When the indexes disagree, a command is included: listing a command the machine
lacks only sends it to the model, while calling a real command "not found" is an
obvious tell.

Run (the dev machine, internet needed once for --fetch):
  .venv/bin/python tools/build_command_list.py --fetch
  .venv/bin/python tools/build_command_list.py
"""
from __future__ import annotations
import argparse
import gzip
import io
import json
import pathlib
import re
import sys
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = ROOT / "offline" / "pkg-index"
OUT = ROOT / "honeypot" / "commands.json"

DEBIAN = "https://deb.debian.org/debian/dists/trixie"
RPI = "http://archive.raspberrypi.com/debian/dists/trixie"
SOURCES = {f"debian-{c}-{a}.gz": f"{DEBIAN}/{c}/Contents-{a}.gz"
           for c in ("main", "contrib", "non-free", "non-free-firmware")
           for a in ("arm64", "all")}
SOURCES["rpi-main-arm64.gz"] = f"{RPI}/main/Contents-arm64.gz"

# root's PATH on Ground Truth (gt43 n=22), searched in this order. Trixie has merged
# /usr: /bin and /sbin are links to /usr/bin and /usr/sbin.
PATH = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
MERGED = {"bin": "usr/bin", "sbin": "usr/sbin"}

# Links made by update-alternatives in package scripts: {provider package: [(dir, name)]}.
# Only those whose provider is installed are used.
ALTERNATIVES = {
    "mawk": [("usr/bin", n) for n in ("awk", "nawk")],
    "vim-tiny": [("usr/bin", n) for n in ("vi", "view", "ex", "rview", "editor")],
    "nano": [("usr/bin", n) for n in ("editor", "pico")],
    "less": [("usr/bin", "pager")],
    "tar": [("usr/sbin", "rmt")],
    "debianutils": [("usr/bin", "which")],
    "gcc": [("usr/bin", n) for n in ("cc", "c89", "c99")],
    "g++": [("usr/bin", "c++")],
    "openssh-client": [("usr/bin", n) for n in ("rsh", "rlogin", "rcp")],
    "netcat-openbsd": [("usr/bin", n) for n in ("nc", "netcat")],
    "netcat-traditional": [("usr/bin", n) for n in ("nc", "netcat")],
    "inetutils-telnet": [("usr/bin", "telnet")],
    "traceroute": [("usr/bin", n) for n in ("traceroute", "traceroute6")],
    "bsdextrautils": [("usr/bin", "write")],
    "rename": [("usr/bin", "rename")],
    "cpio": [("usr/bin", "mt")],
    "xz-utils": [("usr/bin", n) for n in ("lzma", "unlzma", "lzcat", "lzmore", "lzless",
                                          "lzdiff", "lzcmp", "lzgrep", "lzegrep", "lzfgrep")],
    "iptables": [("usr/sbin", n) for n in (
        "iptables", "iptables-save", "iptables-restore", "ip6tables", "ip6tables-save",
        "ip6tables-restore", "arptables", "arptables-save", "arptables-restore",
        "ebtables", "ebtables-save", "ebtables-restore")],
}

BUILTINS = sorted("""
. : [ alias bg bind break builtin caller cd command compgen complete compopt continue
declare dirs disown echo enable eval exec exit export false fc fg getopts hash help
history jobs kill let local logout mapfile popd printf pushd pwd read readarray
readonly return set shift shopt source suspend test times trap true type typeset
ulimit umask unalias unset wait
""".split())
KEYWORDS = sorted("! [[ ]] case do done elif else esac fi for function if in select "
                  "then time until while { } coproc".split())


def fetch() -> None:
    INDEX.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        with urllib.request.urlopen(url, timeout=120) as r:
            (INDEX / name).write_bytes(r.read())
        print("fetched", name)


def installed() -> dict[str, str]:
    pkgs = {}
    for line in (ROOT / "offline" / "gt-installed.txt").read_text().splitlines():
        name, version, state = line.split("\t")[:3]
        if state == "installed":
            pkgs[name.split(":")[0]] = version
    for line in (ROOT / "offline" / "docker-gt" / "MANIFEST.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            name, version = line.split("\t")[:2]
            pkgs[name] = version
    return pkgs


def path_files(path: str) -> tuple[str, str] | None:
    """'usr/bin/ls' -> ('usr/bin', 'ls') if the file is directly in a PATH directory."""
    d, _, name = path.rpartition("/")
    d = MERGED.get(d, d)
    if "/" + d in PATH and name:
        return d, name
    return None


def from_contents(pkgs: set[str]) -> dict[tuple[str, str], set[str]]:
    found: dict[tuple[str, str], set[str]] = {}
    want = re.compile(r"^(usr/)?(local/)?s?bin/[^/\s]+\s")
    for name in SOURCES:
        with gzip.open(INDEX / name, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not want.match(line):
                    continue
                path, _, owners = line.rstrip("\n").rpartition(" ")
                pf = path_files(path.strip())
                if not pf:
                    continue
                for o in owners.split(","):
                    pkg = o.rsplit("/", 1)[-1]
                    if pkg in pkgs:
                        found.setdefault(pf, set()).add(pkg)
    return found


def deb_files(deb: pathlib.Path) -> list[str]:
    """File paths inside a .deb (an ar archive holding data.tar.*)."""
    raw = deb.read_bytes()
    assert raw[:8] == b"!<arch>\n", deb
    i = 8
    while i < len(raw):
        name = raw[i:i + 16].decode().strip().rstrip("/")
        size = int(raw[i + 48:i + 58].decode().strip())
        body = raw[i + 60:i + 60 + size]
        if name.startswith("data.tar"):
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as t:
                return [m.name.removeprefix("./") for m in t.getmembers() if not m.isdir()]
        i += 60 + size + (size % 2)
    raise ValueError(f"no data.tar in {deb}")


def build() -> dict:
    pkgs = installed()
    found = from_contents(set(pkgs))
    manifest = (ROOT / "offline" / "docker-gt" / "MANIFEST.txt").read_text().splitlines()
    for line in manifest:
        if line and not line.startswith("#") and line.split("\t")[5] == "docker":
            pkg, _, deb = line.split("\t")[:3]
            for path in deb_files(ROOT / "offline" / "docker-gt" / deb):
                pf = path_files(path)
                if pf:
                    found.setdefault(pf, set()).add(pkg)
    for pkg, links in ALTERNATIVES.items():
        if pkg in pkgs:
            for pf in links:
                found.setdefault(pf, set()).add(pkg + " (alternative)")

    commands: dict[str, str] = {}
    for d in PATH:
        for (fd, name), _ in sorted(found.items()):
            if "/" + fd == d and name not in commands:
                commands[name] = d
    return {
        "_comment": "Commands on Ground Truth's PATH, from its package inventory and public "
                    "package indexes; built by tools/build_command_list.py. Directory is "
                    "the first one on root's PATH that holds it.",
        "packages": len(pkgs),
        "builtins": BUILTINS,
        "keywords": KEYWORDS,
        "path": dict(sorted(commands.items())),
        "owners": {f"/{d}/{n}": sorted(p) for (d, n), p in sorted(found.items())},
    }


def check(data: dict) -> list[str]:
    """Compare with what Ground Truth itself answered (corpus, not the 43)."""
    corpus = {e["n"]: e for e in json.load(open(ROOT / "corpus284_lab_2026-09.json"))}
    problems = []
    usr_bin = {k.removeprefix("/usr/bin/") for k in data["owners"] if k.startswith("/usr/bin/")}
    for name in corpus[109]["output"].splitlines():          # ls /usr/bin | head -40
        if name not in usr_bin:
            problems.append(f"n=109 lists /usr/bin/{name}, missing here")
    first40 = corpus[109]["output"].splitlines()
    last = first40[-1]
    key = lambda s: (re.sub(r"[^0-9a-z]", "", s.lower()), s)      # en_GB-like order
    extra = [n for n in usr_bin if key(n) <= key(last) and n not in first40]
    if extra:
        problems.append(f"names that would sort into n=109's first 40 but are not there: "
                        f"{sorted(extra)}")
    for n, cmd in ((237, "ls"), (238, "bash"), (240, "python3")):
        want = corpus[n]["output"].split()[-1]
        got = f"{data['path'].get(cmd, '?')}/{cmd}"
        if got != want:
            problems.append(f"n={n} says {want}, here {got}")
    if "cd" not in data["builtins"]:
        problems.append("n=236: cd must be a builtin")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fetch", action="store_true", help="download the package indexes")
    args = ap.parse_args()
    if args.fetch:
        fetch()
    data = build()
    problems = check(data)
    for p in problems:
        print("CHECK:", p)
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    print(f"{len(data['path'])} commands on PATH from {data['packages']} packages -> "
          f"{OUT.relative_to(ROOT)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
