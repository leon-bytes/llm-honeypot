#!/usr/bin/env python3
"""
compare_captures.py - diff a re-recorded capture against the committed one and
group every changed answer by cause.

The point: after any change to Ground Truth the capture is re-run, and every
answer that moved has to be explained before the data is trusted. Anything this
script cannot attribute to a known cause is printed under UNEXPLAINED, which is
the list a human then has to look at.

    .venv/bin/python tools/compare_captures.py            # vs HEAD
    .venv/bin/python tools/compare_captures.py --rev HEAD~1

CAREFUL WITH THE BASELINE: the default compares the working tree against HEAD,
which is what you want *before* committing a re-capture. Once the new files are
committed there is nothing left to see, and the honest comparison is against the
commit before them - `--rev HEAD~1`, or whatever revision holds the previous
recording. An empty report does not mean nothing changed; it may mean you are
comparing a file with itself.

Read-only. Touches no lab host; it compares local files with `git show`.
"""
from __future__ import annotations
import argparse, difflib, json, re, subprocess, sys

FILES = ["gt43_lab_2026-09.json",
         "corpus284_lab_2026-09.json",
         "gt_docker_shell_2026-09.json"]

# Ordered: the first rule that matches a changed entry claims it. Each is
# (label, command-predicate or None, output-predicate or None).
CAUSES = [
    ("Phase 2 Docker API traces (deliberate)",
     lambda c: any(k in c for k in ("journalctl", "dmesg")),
     lambda a, b: any(k in (a + b) for k in
                      ("images/create", "sbJoin", "signal 15", "task-delete",
                       "moby", "libcontainerd", "registry-1.docker.io"))),

    ("/root-clean.tar.gz deleted (2026-09-27 22:12:30)",
     None,
     lambda a, b: "root-clean.tar.gz" in a and "root-clean.tar.gz" not in b),

    ("/home/pi/.bash_history trimmed (2026-09-27 22:51)",
     lambda c: "/home/pi" in c or "home/pi" in c,
     None),

    ("clock / uptime / boot-relative",
     lambda c: any(k in c for k in
                   ("uptime", "/proc/uptime", "date", "who", "last", "top -bn1",
                    "loadavg", "hostnamectl", "timedatectl", "systemd-analyze",
                    "stat ", "vmstat", "free")),
     None),

    ("PIDs / session ids / per-run identifiers",
     lambda c: any(k in c for k in
                   ("ps -aux", "ps aux", "echo $$", "ss -tulnp", "netstat",
                    "pstree", "systemctl", "pgrep", "lsof", "/proc/self",
                    "env", "printenv", "id -u", "w ")),
     None),

    ("sensors / counters / memory",
     lambda c: any(k in c for k in
                   ("vcgencmd", "temp", "meminfo", "free -m", "free -h",
                    "/proc/stat", "/proc/interrupts", "/proc/diskstats",
                    "ifconfig", "ip -s", "df", "du ")),
     None),

    ("container / docker state",
     lambda c: "docker" in c,
     None),
]


def classify(cmd, a, b):
    for label, cpred, opred in CAUSES:
        if cpred and not cpred(cmd):
            continue
        if opred and not opred(a, b):
            continue
        if cpred is None and opred is None:
            continue
        return label
    return "UNEXPLAINED"


def short_diff(a, b, n=6):
    d = [l for l in difflib.unified_diff(a.split("\n"), b.split("\n"),
                                         lineterm="", n=0)
         if l[:1] in "+-" and not l.startswith(("---", "+++"))]
    out = d[:n]
    if len(d) > n:
        out.append(f"   ... {len(d)-n} more changed line(s)")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--full", action="append", default=[],
                    help="show the whole diff for this n (repeatable, as file:n)")
    args = ap.parse_args()

    grand = {}
    for f in FILES:
        raw = subprocess.run(["git", "show", f"{args.rev}:{f}"],
                             capture_output=True, text=True)
        if raw.returncode:
            print(f"[compare] cannot read {args.rev}:{f} - {raw.stderr.strip()}")
            continue
        old = {r["n"]: r for r in json.loads(raw.stdout)}
        new = {r["n"]: r for r in json.load(open(f))}

        print(f"\n{'='*78}\n{f}   {len(old)} -> {len(new)} entries\n{'='*78}")
        if set(old) != set(new):
            print(f"  !! entry numbers differ: only-old {sorted(set(old)-set(new))}, "
                  f"only-new {sorted(set(new)-set(old))}")

        buckets = {}
        for k in sorted(set(old) & set(new)):
            o, n = old[k], new[k]
            if o["output"] == n["output"] and o["exit_code"] == n["exit_code"]:
                continue
            label = classify(o["command"], o["output"], n["output"])
            buckets.setdefault(label, []).append((k, o, n))

        tot = sum(len(v) for v in buckets.values())
        print(f"  {tot} of {len(new)} answers changed\n")
        # UNEXPLAINED last, so it is the thing left on screen.
        order = sorted(buckets, key=lambda l: (l == "UNEXPLAINED", l))
        for label in order:
            rows = buckets[label]
            print(f"  --- {label}  ({len(rows)}) " + "-" * max(0, 50 - len(label)))
            for k, o, n in rows:
                ec = "" if o["exit_code"] == n["exit_code"] else \
                     f"   exit {o['exit_code']} -> {n['exit_code']}"
                print(f"   n={k:<4} {o['command'][:62]}{ec}")
                if label == "UNEXPLAINED" or f"{f}:{k}" in args.full:
                    for l in short_diff(o["output"], n["output"],
                                        99 if f"{f}:{k}" in args.full else 8):
                        print(f"        {l[:150]}")
            print()
        grand[f] = buckets

        # Timings: the regression this re-recording exists to prevent.
        slow = [(r["n"], r["command"], r["elapsed_ms"]) for r in new.values()
                if r["elapsed_ms"] > 5000]
        nz = [r for r in new.values() if r["exit_code"] not in (0, -1)]
        print(f"  timings: slowest {max(r['elapsed_ms'] for r in new.values()):.0f} ms, "
              f"median {sorted(r['elapsed_ms'] for r in new.values())[len(new)//2]:.0f} ms, "
              f"{len(nz)} nonzero-exit entries")
        if nz:
            print(f"  slowest nonzero-exit: "
                  f"{max(r['elapsed_ms'] for r in nz):.0f} ms "
                  f"(the old sentinel bug showed ~20,600 ms here)")
        for n_, c, ms in slow:
            print(f"    slow: n={n_} {ms:.0f} ms  {c[:60]}")

    unexp = sum(len(b.get("UNEXPLAINED", [])) for b in grand.values())
    print(f"\n{'='*78}")
    print(f"UNEXPLAINED TOTAL: {unexp}")
    print('='*78)
    return 1 if unexp else 0


if __name__ == "__main__":
    sys.exit(main())
