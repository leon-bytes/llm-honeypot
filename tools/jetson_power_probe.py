#!/usr/bin/env python3
"""What one model node draws and how hot it runs while it answers: a measurement, not a
load test.

Why: Jetson 1 froze on 2026-10-13 under answers without pauses with its memory flat
(docs/jetson-stability.md). The kernel said nothing before it stopped, so the cause has
to be measured from outside: the board's own power monitor (voltage and current at the
module's input), its over-current counters, temperature and fan.

What it does: it starts a reader on the node over SSH (read-only: files under /sys, five
times a second, no sudo) and meanwhile asks that node's model for a few answers, PACED,
with the prompts the relay would send for corpus commands. It asks the node directly,
not through the relay, so the relay's log and state are not touched and any node can be
measured, the spare too.

  .venv/bin/python tools/jetson_power_probe.py --node lab-j1 --answers 12 --pause 12

Writes res_powerprobe_<node>_<time>.json (git-ignored) and prints a summary. Never run
it without --pause (8 s at least): a node has frozen under back-to-back answers.
"""
from __future__ import annotations
import argparse
import datetime
import json
import pathlib
import random
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

# One line per sample: time, VDD_IN mV and mA, the other two rails' mA, the three
# over-current counters, the hottest zone, fan pwm and rpm, GPU load (0..1000).
READER = r'''
ina=$(for h in /sys/class/hwmon/hwmon*; do [ "$(cat $h/name 2>/dev/null)" = ina3221 ] && echo $h; done | head -1)
oc=$(dirname $(find /sys/devices -name oc3_event_cnt 2>/dev/null | head -1))
fan=$(for h in /sys/class/hwmon/hwmon*; do [ -e $h/pwm1 ] && echo $h; done | head -1)
tach=$(for h in /sys/class/hwmon/hwmon*; do [ -e $h/rpm ] && echo $h; done | head -1)
gpu=$(ls /sys/devices/platform/gpu.0/load /sys/devices/platform/bus@0/17000000.gpu/load /sys/devices/gpu.0/load 2>/dev/null | head -1)
echo "limits crit=$(cat $ina/curr1_crit) max=$(cat $ina/curr1_max) mode=$(nvpmodel -q 2>/dev/null | head -1)"
end=$(( $(date +%s) + SECONDS_TO_RUN ))
while [ $(date +%s) -lt $end ]; do
  hot=$(cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | sort -n | tail -1)
  echo "$(date +%s.%N | cut -c1-14) $(cat $ina/in1_input) $(cat $ina/curr1_input) $(cat $ina/curr2_input) $(cat $ina/curr3_input) $(cat $oc/oc1_event_cnt) $(cat $oc/oc2_event_cnt) $(cat $oc/oc3_event_cnt) $hot $(cat $fan/pwm1 2>/dev/null) $(cat $tach/rpm 2>/dev/null) $(cat $gpu 2>/dev/null)"
  sleep 0.15
done
'''


def prompts(n: int, seed: int) -> list[list[dict]]:
    """The messages the relay sends for corpus commands the model answers."""
    from honeypot.relay import Relay

    class Catch:
        backends = []

        def __init__(self):
            self.calls = []

        def complete(self, sid, messages, role="state"):
            self.calls.append(messages)
            return "x", {}

    cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
    tmp = tempfile.mkdtemp()
    cfg["state_dir"], cfg["log"] = tmp + "/state", tmp + "/relay.jsonl"
    pool = Catch()
    relay = Relay(cfg, str(ROOT / "honeypot"), pool=pool)
    body = {"model": "x", "user": "probe", "messages": [{"role": "user", "content": ""}],
            "honeypot": {"event": "login", "username": "root", "src_ip": SITE.lab_jump}}
    relay.handle(body)
    corpus = json.load(open(ROOT / "corpus284_lab_2026-09.json"))
    random.Random(seed).shuffle(corpus)
    for e in corpus:
        if len(pool.calls) >= n:
            break
        if any(w in e["command"] for w in (">", "touch", "mkdir", "rm ", "cd ", "export")):
            continue
        body["honeypot"], body["messages"] = {"event": "command"}, [
            {"role": "user", "content": e["command"]}]
        relay.handle(body)
    return pool.calls[:n]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--node", required=True, help="SSH alias of the Jetson, e.g. lab-j1")
    ap.add_argument("--answers", type=int, default=12)
    ap.add_argument("--pause", type=float, default=12.0, help="seconds between answers (8 at least)")
    ap.add_argument("--model", default="qwen2.5:3b-instruct-q4_K_M")
    ap.add_argument("--port", type=int, default=21434, help="local end of the tunnel")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    if args.pause < 8:
        ap.error("--pause below 8 s is not allowed: a node froze under answers without pauses")

    msgs = prompts(args.answers, args.seed)
    seconds = int(len(msgs) * (args.pause + 12) + 20)
    tunnel = subprocess.Popen(["ssh", "-o", "ExitOnForwardFailure=yes", "-N", "-L",
                               f"{args.port}:127.0.0.1:11434", args.node])
    reader = subprocess.Popen(["ssh", args.node, "bash -s"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    reader.stdin.write(READER.replace("SECONDS_TO_RUN", str(seconds)))
    reader.stdin.close()
    time.sleep(8)                       # a few idle samples first
    answers = []
    try:
        for i, m in enumerate(msgs, 1):
            body = json.dumps({"model": args.model, "messages": m, "temperature": 0,
                               "max_tokens": 700, "stream": False}).encode()
            t0 = time.time()
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{args.port}/v1/chat/completions",
                                             body, {"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    usage = json.load(r).get("usage", {})
                ok = True
            except Exception as e:          # a node that stops answering ends the probe
                usage, ok = {"error": str(e)}, False
            t1 = time.time()
            answers.append({"start": t0, "end": t1, "ok": ok, **usage})
            print(f"  answer {i:2d}/{len(msgs)}: {t1 - t0:5.1f} s  {usage}", flush=True)
            if not ok:
                break
            time.sleep(args.pause)
    finally:
        tunnel.terminate()
    time.sleep(3)
    reader.terminate()
    lines = reader.stdout.read().splitlines()
    limits = lines[0] if lines and lines[0].startswith("limits") else ""
    cols = ("t", "mv", "ma", "ma_cpu_gpu", "ma_soc", "oc1", "oc2", "oc3", "hot", "pwm", "rpm", "gpu")
    rows = []
    for ln in lines[1:]:
        f = ln.split()
        if len(f) >= 9:
            rows.append(dict(zip(cols, [float(x) for x in f])))
    out = ROOT / f"res_powerprobe_{args.node}_{datetime.datetime.now():%Y%m%d-%H%M}.json"
    json.dump({"node": args.node, "limits": limits, "pause": args.pause, "answers": answers,
               "samples": rows}, open(out, "w"))
    if not rows:
        print("no samples came back")
        return 1

    def busy(r):
        return any(a["start"] <= r["t"] <= a["end"] for a in answers)
    work, idle = [r for r in rows if busy(r)], [r for r in rows if not busy(r)]
    watts = lambda r: r["mv"] * r["ma"] / 1e6                      # noqa: E731
    print(f"\n{args.node}: {limits}")
    print(f"  samples: {len(rows)} ({len(work)} while answering), answers: {len(answers)}, "
          f"median {statistics.median(a['end'] - a['start'] for a in answers):.1f} s")
    for name, part in (("idle", idle), ("answering", work)):
        if part:
            print(f"  {name:10} input {min(r['mv'] for r in part):.0f} to {max(r['mv'] for r in part):.0f} mV, "
                  f"current up to {max(r['ma'] for r in part):.0f} mA, "
                  f"power median {statistics.median(map(watts, part)):.1f} W, peak {max(map(watts, part)):.1f} W, "
                  f"hottest {max(r['hot'] for r in part) / 1000:.0f} C")
    for k, what in (("oc1", "under-voltage"), ("oc2", "average over-current"), ("oc3", "peak over-current")):
        print(f"  {what} events during the probe: {int(rows[-1][k] - rows[0][k])} (counter now {int(rows[-1][k])})")
    if "rpm" in rows[-1]:
        print(f"  fan: pwm {min(r.get('pwm', 0) for r in rows):.0f} to {max(r.get('pwm', 0) for r in rows):.0f} of 255, "
              f"up to {max(r.get('rpm', 0) for r in rows):.0f} rpm")
    print(f"  written: {out.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
