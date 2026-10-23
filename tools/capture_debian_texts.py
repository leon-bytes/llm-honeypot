#!/usr/bin/env python3
"""Record exact error, usage, version and help texts from a Debian 13 arm64 userland.

A second source of fine-tuning data next to the corpus (tools/build_training_data.py,
source "debian"): what `ls /nonexistent`, `cp`, `ps --nosuchoption` or `grep --version`
print is the same on every Debian 13 with the same package versions, so it can be taken
from a container instead of from Ground Truth, which stays closed. The commands are in
tools/debian_text_commands.txt.

How it runs (the dev machine is x86_64 and there is no sudo, so no binfmt emulation):
the arm64 root file system of an official Debian image is unpacked into
offline/debian13-arm64/rootfs and each command is run in it with proot (a user-space
chroot) and qemu-aarch64 (user-mode emulation). Nothing needs root, nothing touches the
lab. The one-time setup is in offline/debian13-arm64/README.md.

Each command runs as Ground Truth's root would run it: `bash -c`, HOME=/root, root's
PATH, LANG=en_GB.UTF-8, in /root, no input. bash words its own errors `bash: line 1: `
under `-c` and `-bash: ` in a login shell (measured on Ground Truth 2026-10-01, the
relay's exec mode); the recorded text is converted to the login-shell form.

What keeps the texts honest:
  - A command is kept only if every program in it comes from a package that Ground Truth
    has in exactly the same version (offline/gt-installed.txt). A program the container
    lacks, or has in another version, drops the command; the reason goes in the
    manifest. A container can never tell us that Ground Truth lacks a program.
  - Before anything is recorded, commands that Ground Truth itself answered in the
    corpus are run in the container and must come back byte for byte.
  - Afterwards /root and /tmp in the container must hold no new file.

Output (tracked in git; it contains nothing from Ground Truth):
  offline/debian13-arm64/texts.json            n, command, output, exit_code, packages
  offline/debian13-arm64/texts.manifest.json   image, tools, checks, every dropped command

Run: .venv/bin/python tools/capture_debian_texts.py [--limit N]
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BOX = ROOT / "offline" / "debian13-arm64"
ROOTFS, PROOT, QEMU = BOX / "rootfs", BOX / "proot", BOX / "qemu-aarch64-static"
COMMANDS = ROOT / "tools" / "debian_text_commands.txt"

# Root's environment in a login shell on Ground Truth (gt43 `env`), without what belongs
# to one SSH session.
ENV = {"SHELL": "/bin/bash", "PWD": "/root", "LOGNAME": "root", "HOME": "/root",
       "LANG": "en_GB.UTF-8", "TERM": "xterm", "USER": "root", "SHLVL": "0",
       "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

# Corpus answers that do not depend on the machine: the container must give the same.
VALIDATE = (310, 311, 312, 313, 315, 316, 317, 205)

TIMEOUT_S = 30
MAX_LINES = 80       # a usage text is shorter; a longer answer is a listing of the container


def in_box(argv: list[str], timeout: int = TIMEOUT_S) -> tuple[str, int]:
    """Run argv in the arm64 userland; (stdout and stderr as one text, exit status)."""
    cmd = [str(PROOT), "-0", "-q", str(QEMU), "-r", str(ROOTFS), "-b", "/dev", "-b", "/proc",
           "-b", "/sys", "-w", "/root", "/usr/bin/env", "-i",
           *[f"{k}={v}" for k, v in ENV.items()], *argv]
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "[timeout]", -1
    return p.stdout.decode("utf-8", errors="replace"), p.returncode


def run_command(command: str) -> tuple[str, int]:
    # Started as `bash`, found on PATH, so its errors begin `bash: line 1: ` exactly as
    # in Ground Truth's exec mode; started as /bin/bash they would begin `/bin/bash:`.
    out, code = in_box(["bash", "-c", command])
    out = re.sub(r"(?m)^bash: line 1: ", "-bash: ", out)        # the login shell's wording
    return out.removesuffix("\n"), code


def programs(command: str) -> list[str]:
    """The program names a command line starts: the first word of each pipeline part."""
    names = []
    for part in re.split(r"\|\||&&|[|;]", command):
        words = part.strip().split()
        while words and re.fullmatch(r"\w+=\S*", words[0]):
            words = words[1:]
        if words:
            names.append(words[0])
    return names


def resolve(names: list[str]) -> dict[str, str]:
    """name -> the Debian package it comes from in the container ('' if it is not there).
    A bash builtin or keyword is bash's."""
    script = r'''
for w in "$@"; do
  t=$(type -t -- "$w" 2>/dev/null)
  case "$t" in
    builtin|keyword) echo "$w bash";;
    file) p=$(readlink -f "$(type -P -- "$w")")
          pkg=$(dpkg -S "$p" 2>/dev/null | head -1 | cut -d: -f1)
          [ -z "$pkg" ] && pkg=$(dpkg -S "${p#/usr}" 2>/dev/null | head -1 | cut -d: -f1)
          echo "$w $pkg";;
    *) echo "$w";;
  esac
done'''
    out, _ = in_box(["/bin/bash", "-c", script, "resolve", *names], timeout=600)
    found = {}
    for line in out.splitlines():
        parts = line.split()
        if parts:
            found[parts[0]] = parts[1] if len(parts) > 1 else ""
    for name in names:
        # A program named by its path (`/etc/passwd`, `./run.sh`) that is not a program:
        # the text comes from bash, which tried to start it.
        if "/" in name and not found.get(name):
            found[name] = "bash"
    return found


def versions() -> tuple[dict, dict]:
    out, _ = in_box(["dpkg-query", "-W", "-f", "${Package} ${Version}\n"], timeout=120)
    box = dict(l.split() for l in out.splitlines() if len(l.split()) == 2)
    gt = {}
    for line in open(ROOT / "offline" / "gt-installed.txt"):
        p = line.split()
        if len(p) >= 2:
            gt[p[0].split(":")[0]] = p[1]
    return box, gt


def listing() -> str:
    return in_box(["/bin/sh", "-c", "ls -A /root /tmp"])[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--limit", type=int, help="only the first N commands (for a trial run)")
    args = ap.parse_args()
    for need in (ROOTFS, PROOT, QEMU):
        if not need.exists():
            sys.exit(f"missing {need}: set the userland up first, see "
                     f"offline/debian13-arm64/README.md")

    arch, _ = in_box(["uname", "-m"])
    debian = (ROOTFS / "etc" / "debian_version").read_text().strip()
    if arch.strip() != "aarch64":
        sys.exit(f"the userland answers `uname -m` with {arch!r}, not aarch64")

    # 1. The container must repeat what Ground Truth itself recorded.
    corpus = {e["n"]: e for e in json.load(open(ROOT / "corpus284_lab_2026-09.json"))}
    checks = []
    for n in VALIDATE:
        want = corpus[n]
        got, code = run_command(want["command"])
        ok = got == want["output"] and code == want["exit_code"]
        checks.append({"corpus_n": n, "command": want["command"], "same": ok})
        print(f"  check corpus n={n:<4} {'same' if ok else 'DIFFERENT':<10} {want['command']}")
        if not ok:
            print(f"      Ground Truth: {want['output']!r} (exit {want['exit_code']})\n"
                  f"      container:    {got!r} (exit {code})")
    if not all(c["same"] for c in checks):
        sys.exit("the container does not repeat Ground Truth's own answers: nothing recorded")

    # 2. Which commands may be recorded at all.
    commands = [l.strip() for l in COMMANDS.read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    if args.limit:
        commands = commands[:args.limit]
    box, gt = versions()
    where = resolve(sorted({p for c in commands for p in programs(c)}))
    before = listing()
    kept, dropped = [], {}
    for i, command in enumerate(commands, 1):
        pkgs, reason = {}, None
        for prog in programs(command):
            pkg = where.get(prog, "")
            if not pkg:
                reason = f"{prog}: not in the container"
            elif pkg not in gt:
                reason = f"{prog}: package {pkg} is not on Ground Truth"
            elif gt[pkg] != box.get(pkg):
                reason = f"{prog}: {pkg} {box.get(pkg)} here, {gt[pkg]} on Ground Truth"
            if reason:
                break
            pkgs[pkg] = gt[pkg]
        if reason is None:
            out, code = run_command(command)
            if code == -1:
                reason = "timed out (waits for input?)"
            elif re.search(r"(?m)^bash: (-c: )?line \d+:", out) or "bash: -c:" in out:
                reason = "bash reports this differently under -c (a syntax error)"
            elif "command not found" in out:
                reason = "command not found: the container cannot speak for Ground Truth"
            elif "does not have a stable CLI interface" in out:
                reason = "apt's warning for output that is not a terminal"
            elif len(out.splitlines()) > MAX_LINES:
                reason = f"more than {MAX_LINES} lines: not a fixed text"
        if reason:
            dropped[command] = reason
            continue
        kept.append({"n": f"d{i}", "command": command, "output": out, "exit_code": code,
                     "packages": pkgs})
        if i % 50 == 0:
            print(f"  {i}/{len(commands)} run, {len(kept)} kept")
    after = listing()
    if after != before:
        sys.exit(f"a command changed files in the container:\nbefore:\n{before}\nafter:\n{after}")

    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = {
        "recorded": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "userland": {"debian_version": debian, "arch": arch.strip(),
                     "image": (BOX / "IMAGE").read_text().strip() if (BOX / "IMAGE").exists()
                     else "see README.md",
                     "packages_same_as_ground_truth":
                         sum(1 for p in box if gt.get(p) == box[p]),
                     "packages": len(box)},
        "tools": {"proot_sha256": digest(PROOT), "qemu_aarch64_static_sha256": digest(QEMU)},
        "environment": ENV,
        "checks_against_the_corpus": checks,
        "commands": len(commands), "kept": len(kept), "dropped": dropped,
    }
    (BOX / "texts.json").write_text(json.dumps(kept, indent=1, ensure_ascii=False) + "\n")
    (BOX / "texts.manifest.json").write_text(json.dumps(manifest, indent=1,
                                                        ensure_ascii=False) + "\n")
    print(f"\n{len(kept)} of {len(commands)} commands recorded, {len(dropped)} dropped "
          f"-> {BOX / 'texts.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
