#!/usr/bin/env python3
"""
run_unmask_probes.py - the LLM-unmasking probe set (tools/unmask_probes.json) through the
deployed relay, paced, one fresh login per probe. A teammate's question (2026-10-16): how well
does the honeypot resist probes meant to reveal that it is an LLM?

For each probe it records the honeypot's answer, which tier answered (code / model), the
exit code, and the time the command request took (the latency tell). A `repeat` probe is
sent in two fresh sessions so a real machine's determinism can be checked. Model-answered
probes are paced (--pause, default 15 s) because the nodes freeze without pauses
(docs/jetson-stability.md). Nothing is changed on any machine.

  # open a tunnel to the deployed relay first, e.g.:
  #   ssh -fN -L 18000:127.0.0.1:8000 lab-orch
  python3 tools/run_unmask_probes.py --url http://127.0.0.1:18000 --label build-1016

Run it on a relay with a clean file state and while nobody else is on the honeypot, like
the other measurements; not during a measurement run. Classify each answer afterwards as
PASS (indistinguishable from a real machine) or TELL. Writes res_unmask_<label>_<date>.json.
"""
from __future__ import annotations
import argparse
import datetime
import json
import pathlib
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from relay_client import Client, refuse_class_build, require_mode       # noqa: E402
from honeypot.site import SITE                                          # noqa: E402  (site.local.json)

TIER = {"builtin": "code", "cache": "replay", "model": "model", "fallback": "fallback"}


def one(c: Client, cmd: str, setup, pause: float) -> dict:
    """One probe in a fresh session: optional setup lines, then the probe. Returns the
    probe's answer with its tier, exit and the request time."""
    sid = f"probe-{uuid.uuid4().hex[:8]}"
    c.send(sid, event="login")
    for line in setup or []:
        _, ext, _ = c.send(sid, line)
        if TIER.get(ext["source"]) == "model":
            time.sleep(pause)
    text, ext, ms = c.send(sid, cmd)
    c.send(sid, event="logout")
    tier = TIER.get(ext["source"], ext["source"])
    if tier == "model":
        time.sleep(pause)
    return {"output": text, "tier": tier, "exit_code": ext["exit_code"], "elapsed_ms": ms}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default="http://127.0.0.1:18000")
    ap.add_argument("--label", required=True)
    ap.add_argument("--probes", default="tools/unmask_probes.json")
    ap.add_argument("--src-ip", default=SITE.lab_jump)
    ap.add_argument("--pause", type=float, default=15.0,
                    help="seconds after each model answer (the nodes need it)")
    ap.add_argument("--cols", type=int, default=200,
                    help="the terminal width sent at login: 200, the width the reference "
                         "machine's probes were recorded at (capture_session_v3.py), so a "
                         "width-dependent answer (help's table) is compared like for like")
    ap.add_argument("--out")
    args = ap.parse_args()
    out = args.out or f"res_unmask_{args.label}_{datetime.date.today().isoformat()}.json"

    refuse_class_build(args.url)
    require_mode(args.url, "normal")
    c = Client(args.url, args.src_ip)
    c.cols, c.rows = args.cols, 24
    probes = json.load(open(pathlib.Path(args.probes)))["probes"]

    results = []
    for i, p in enumerate(probes, 1):
        r = one(c, p["cmd"], p.get("setup"), args.pause)
        entry = {**{k: p[k] for k in ("id", "cat", "cmd", "reach", "real") if k in p},
                 "got": r["output"], "tier": r["tier"], "exit_code": r["exit_code"],
                 "elapsed_ms": r["elapsed_ms"]}
        if p.get("repeat"):
            r2 = one(c, p["cmd"], p.get("setup"), args.pause)
            entry["got_repeat"] = r2["output"]
            entry["identical_on_repeat"] = r2["output"] == r["output"]
            entry["elapsed_ms_repeat"] = r2["elapsed_ms"]
        results.append(entry)
        flag = "" if r["output"] else " (empty)"
        rep = "" if not p.get("repeat") else (" repeat=SAME" if entry["identical_on_repeat"] else " repeat=DIFFERS")
        print(f"[{i:2}/{len(probes)}] {p['id']:16} {r['tier']:5} {r['elapsed_ms']:6} ms{rep}{flag}", flush=True)

    code = [e for e in results if e["tier"] == "code"]
    model = [e for e in results if e["tier"] == "model"]

    def med(xs):
        xs = sorted(xs)
        return xs[len(xs) // 2] if xs else None
    summary = {
        "probes": len(results),
        "answered_by_code": len(code), "answered_by_model": len(model),
        "code_median_ms": med([e["elapsed_ms"] for e in code]),
        "model_median_ms": med([e["elapsed_ms"] for e in model]),
        "repeats_that_differ": [e["id"] for e in results
                                if e.get("identical_on_repeat") is False],
        "reach_mismatch": [e["id"] for e in results
                           if e.get("reach") and e["reach"] != e["tier"]],
    }
    pathlib.Path(out).write_text(json.dumps(
        {"label": args.label, "url": args.url, "cols": args.cols, "when": datetime.datetime.now().isoformat(timespec="seconds"),
         "summary": summary, "results": results}, indent=1, ensure_ascii=False) + "\n")
    print("\nsummary:", json.dumps(summary, ensure_ascii=False))
    print(f"saved to {out}. Classify each 'got' as PASS or TELL; the latency gap "
          f"(code {summary['code_median_ms']} ms vs model {summary['model_median_ms']} ms) is itself a tell.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
