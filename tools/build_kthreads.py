#!/usr/bin/env python3
"""Build honeypot/kthreads.json: the simulated machine's kernel threads.

Source: CAPTURED MACHINE STATE. Ground Truth's kernel threads (PID, parent PID, state,
nice, real-time priority, name), read 2026-10-02 20:49 with one non-interactive
`ssh lab-gt` as pi (offline/gt-kthreads-20261002.txt; logged in docs/gt-changes.md),
about 4 days after its last boot. Approved by the user on the grounds that the 43's
`ps -aux` (n=14) and `top -bn1` (n=36) are not gradable as text (PIDs and times
change every run), so the capture cannot inflate a score. The paper reports these
threads as captured state, not imitation.

The capture is cross-checked against the corpus (n=180, PIDs 2-21 at 11 minutes).
Runtime workers keep their captured PIDs: procs.py shows a thread only once the
honeypot's own PID counter (machine.pid_floor) has passed it.

Run: python3 tools/build_kthreads.py
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
CAPTURE = ROOT / "offline" / "gt-kthreads-20261002.txt"
corpus = {e["n"]: e for e in json.load(open(ROOT / "corpus284_lab_2026-09.json"))}

threads = []
for line in CAPTURE.read_text().splitlines()[1:]:
    pid, ppid, stat, ni, rtprio, comm = line.split(None, 5)
    rt = None if rtprio == "-" else int(rtprio)
    nice = 0 if ni == "-" else int(ni)
    pr = ("rt" if rt == 99 else str(-1 - rt)) if rt else str(20 + nice)
    threads.append({"pid": int(pid), "comm": comm, "stat": stat, "ni": nice, "pr": pr,
                    "source": "gt-captured-2026-10-02"})

# Cross-check: every thread the corpus shows at 11 minutes that still exists has the
# same PID and name (runtime workers like kworker/0:1-events come and go).
by_pid = {t["pid"]: t["comm"] for t in threads}
for line in corpus[180]["output"].splitlines()[2:]:
    pid, name = line.split(None, 1)
    if int(pid) in by_pid:
        assert by_pid[int(pid)] == name, (pid, name, by_pid[int(pid)])

doc = {"_comment": "Ground Truth's kernel threads: captured machine state (see "
                   "tools/build_kthreads.py). Not imitation; the paper says so.",
       "captured": "2026-10-02T20:49-04:00",
       "threads": threads}
(ROOT / "honeypot" / "kthreads.json").write_text(json.dumps(doc, indent=1) + "\n")
print(f"{len(threads)} kernel threads from the capture; corpus PIDs 2-21 agree")
