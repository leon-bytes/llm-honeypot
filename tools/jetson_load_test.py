#!/usr/bin/env python3
"""A careful load test of the model nodes, shaped like a class session.

Why: on 2026-10-06 and 2026-10-08 both Jetsons went down after about 50 model answers
(docs/jetson-stability.md). The cause found was llama-server's prompt cache filling the
memory. This test shows whether a fix holds, and stops by itself before a node is in
danger.

What it does: it plays students at the honeypot, through the relay, the way Cowrie
will: a login, then commands with pauses in between, then a logout. The commands are
corpus commands the MODEL answers (never the 43 test commands, and nothing that
creates files). After every few answers it looks at each Jetson over SSH, read-only:
memory still available, the hottest temperature, llama-server's memory, and the size
of the prompt cache from its log. It stops at once if a node has less memory than
--stop-below-mb, is hotter than --stop-above-c, or stops answering.

Stages (run them in this order, one at a time, and read the result before the next):
  1  60 answers, one student, 8 s between commands        just past where they died
  2  300 answers, one student, 8 s between commands        about a class session
  3  200 answers, no pause                                 a script, not a person
  4  2 students at once, 150 answers each, 5 s pauses      if two ever get in together

DO NOT run stages 2 to 4 before scripts/jetson_keep_logs.sh has been applied on both
Jetsons: if a node does go down, that is what leaves the evidence.

  .venv/bin/python tools/jetson_load_test.py --stage 1 --dry-run     # shows the plan only
  .venv/bin/python tools/jetson_load_test.py --stage 1

Needs the tunnel to the relay (TASKS.md): ssh -M -S $HOME/.orch.sock -f -N -L
18000:127.0.0.1:8000 lab-orch. Writes res_loadtest_stage<N>_<time>.json (git-ignored).
"""
from __future__ import annotations
import argparse
import datetime
import json
import pathlib
import random
import re
import subprocess
import sys
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))
from relay_client import Client          # noqa: E402
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

STAGES = {1: dict(students=1, answers=60, pause=8.0),
          2: dict(students=1, answers=300, pause=8.0),
          3: dict(students=1, answers=200, pause=0.0),
          4: dict(students=2, answers=150, pause=5.0)}
# The serving nodes are the relay's backends (honeypot/config.json): Jetson N is
# 10.77.10.3N and the alias lab-jN. Read from the config so that Jetsons 2 and 3 are
# watched as soon as the config names them.
def serving_nodes() -> dict[str, str]:
    cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
    out = {}
    for b in cfg["backends"]:
        m = re.search(r"//10\.77\.10\.3(\d):", b["base_url"])
        if m:
            out[b["name"]] = f"lab-j{m.group(1)}"
    return out


NODES = serving_nodes()
CHECK = ("awk '/^MemAvailable/ {printf \"avail=%d \", $2/1024}' /proc/meminfo; "
         "printf 'hot=%d ' $(( $(cat /sys/devices/virtual/thermal/thermal_zone*/temp 2>/dev/null "
         "| sort -n | tail -1) / 1000 )); "
         "ps -C llama-server -o rss= | awk '{s+=$1} END {printf \"rss=%d \", s/1024}'; "
         # the newest line counts: with the cache switched off the server prints no
         # "cache state" at all, and an older one from before the switch would mislead
         "grep -a 'cache state\\|prompt cache is' /var/log/syslog | tail -1 "
         "| sed -E 's/.*cache state: ([0-9]+) prompts, ([0-9.]+) MiB.*/cache=\\2/; "
         "s/.*prompt cache is disabled.*/cache=0/; s/.*prompt cache is enabled.*/cache=0/'")


def commands() -> list[str]:
    """Corpus commands the relay sends to the model, that change nothing."""
    from honeypot.relay import Relay
    import tempfile
    corpus = json.load(open(ROOT / "corpus284_lab_2026-09.json"))
    tests = {e["command"] for e in json.load(open(ROOT / "gt43_lab_2026-09.json"))}
    cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
    tmp = tempfile.mkdtemp()
    cfg["state_dir"], cfg["log"] = tmp + "/s", tmp + "/r.jsonl"

    class Stand:
        backends = []

        def complete(self, sid, messages, role="state"):
            return "x", {}
    relay = Relay(cfg, str(ROOT / "honeypot"), pool=Stand())
    keep = []
    for e in corpus:
        cmd = e["command"]
        if cmd in tests or re.search(r"\b(touch|mkdir|rm|mv|cp|chmod|tee|dd|kill|export)\b|>", cmd):
            continue
        sid = f"lt-{e['n']}"
        relay.handle({"user": sid, "messages": [{"role": "user", "content": ""}],
                      "honeypot": {"event": "login", "mode": "normal"}})
        _, resp = relay.handle({"user": sid, "messages": [{"role": "user", "content": cmd}],
                                "honeypot": {"event": "command"}})
        if resp["honeypot"]["source"] == "model":
            keep.append(cmd)
        relay.handle({"user": sid, "messages": [{"role": "user", "content": ""}],
                      "honeypot": {"event": "logout"}})
    relay._log.close()
    return keep


def look(host: str) -> dict:
    """One read-only look at a Jetson. {} if it does not answer."""
    try:
        out = subprocess.run(["ssh", "-o", "ConnectTimeout=6", "-o", "BatchMode=yes", host, CHECK],
                             capture_output=True, text=True, timeout=20).stdout
    except subprocess.TimeoutExpired:
        return {}
    return {k: float(v) for k, v in re.findall(r"(\w+)=([\d.]+)", out)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--stage", type=int, choices=sorted(STAGES), required=True)
    ap.add_argument("--url", default="http://127.0.0.1:18000")
    ap.add_argument("--check-every", type=int, default=5, help="look at the Jetsons every N answers")
    ap.add_argument("--stop-below-mb", type=int, default=1500,
                    help="stop if a Jetson has less memory available than this")
    ap.add_argument("--stop-above-c", type=int, default=90, help="stop if a Jetson is hotter than this")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true", help="show the plan, send nothing")
    args = ap.parse_args()
    st = STAGES[args.stage]
    pool = commands()
    rng = random.Random(args.seed)
    print(f"stage {args.stage}: {st['students']} student(s), {st['answers']} model answers each, "
          f"{st['pause']} s between commands; {len(pool)} different commands to draw from")
    print(f"stops if a Jetson has under {args.stop_below_mb} MB available, is over "
          f"{args.stop_above_c} C, or does not answer")
    if args.dry_run:
        print("first ten commands:", [rng.choice(pool) for _ in range(10)])
        print("dry run: nothing sent")
        return 0

    start = {name: look(host) for name, host in NODES.items()}
    print("before:", start)
    if not all(start.values()):
        print("a Jetson does not answer: not starting")
        return 1
    client = Client(args.url, SITE.lab_jump, mode="normal")
    rows, stop = [], threading.Event()
    lock = threading.Lock()

    def student(k: int) -> None:
        r = random.Random(args.seed * 100 + k)
        done = 0
        while done < st["answers"] and not stop.is_set():
            sid = f"loadtest-{uuid.uuid4().hex[:8]}"
            client.send(sid, event="login")
            for _ in range(r.randint(6, 14)):                 # commands per login
                if done >= st["answers"] or stop.is_set():
                    break
                cmd = r.choice(pool)
                text, ext, ms = client.send(sid, cmd)
                done += 1
                with lock:
                    rows.append({"t": time.time(), "student": k, "command": cmd, "ms": ms,
                                 "source": ext["source"], "chars": len(text)})
                    n = len(rows)
                if ext["source"] == "fallback":
                    print(f"   answer {n}: FALLBACK (no Jetson answered): {cmd}")
                if n % args.check_every == 0:
                    seen = {name: look(host) for name, host in NODES.items()}
                    with lock:
                        rows[-1]["nodes"] = seen
                    line = "  ".join(f"{name}: " + (" ".join(f"{k}={v:g}" for k, v in s.items())
                                                    if s else "NO ANSWER") for name, s in seen.items())
                    print(f"   after {n:4} answers  last {ms:6} ms   {line}", flush=True)
                    for name, s in seen.items():
                        if not s or s.get("avail", 1e9) < args.stop_below_mb \
                                or s.get("hot", 0) > args.stop_above_c:
                            print(f"STOP: {name} " + ("does not answer" if not s else str(s)))
                            stop.set()
                time.sleep(st["pause"] * r.uniform(0.5, 1.5))
            client.send(sid, event="logout")

    threads = [threading.Thread(target=student, args=(k,)) for k in range(st["students"])]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    end = {name: look(host) for name, host in NODES.items()}
    ms = sorted(r["ms"] for r in rows)
    out = ROOT / f"res_loadtest_stage{args.stage}_{datetime.datetime.now():%Y%m%d-%H%M}.json"
    out.write_text(json.dumps({"stage": args.stage, "plan": st, "before": start, "after": end,
                               "stopped_early": stop.is_set(), "answers": rows}, indent=1))
    print(f"\n{len(rows)} answers" + (" (STOPPED EARLY)" if stop.is_set() else "")
          + f"; median {ms[len(ms) // 2] if ms else 0} ms, slowest {ms[-1] if ms else 0} ms; "
          f"fallbacks {sum(r['source'] == 'fallback' for r in rows)}")
    for name in NODES:
        a, b = start[name], end.get(name) or {}
        print(f"  {name}: available {a.get('avail', 0):.0f} -> {b.get('avail', 0):.0f} MB, "
              f"prompt cache {a.get('cache', 0):.0f} -> {b.get('cache', 0):.0f} MiB, "
              f"hottest {b.get('hot', 0):.0f} C")
    print(f"saved to {out}")
    return 1 if stop.is_set() else 0


if __name__ == "__main__":
    sys.exit(main())
