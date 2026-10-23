#!/usr/bin/env python3
"""
run43_for_scorer.py - the 43 through the deployed relay, saved in the scorer's format.

One fresh login per command, as the recordings were made, in one answer mode. Writes a
list with one entry per test: n, command, real (Ground Truth's answer, from
gt43_lab_2026-09.json), model (the honeypot's answer), tier (code / replay / model /
fallback), elapsed_ms (the command request, measured here), plus the relay's own
elapsed time, both exit codes, the answer mode and the build label. The label is on
every entry and in the file name, because the scorer wants a bare list.

  python3 tools/run43_for_scorer.py --url http://127.0.0.1:18000 --mode normal --label pre-freeze
  python3 tools/run43_for_scorer.py --url http://127.0.0.1:18000 --mode model_only --label pre-freeze

Score with:
  python3 eval_scorer.py --file FILE --real-key real --model-key model --verdict-key none

Run it on a relay with a clean file state (relay-state/files.json all empty), one mode
after the other, never both at once. The files the 43 create are removed at the end,
and only then: an `rm` of files that do not exist is recorded by the relay as removals
and would show up in the model's prompts.

`real` holds Ground Truth's addresses (n=22, 33, 37): team-only, like the recordings.
"""
from __future__ import annotations
import argparse
import collections
import datetime
import json
import pathlib
import sys
import time
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from relay_client import Client, TIDY, refuse_class_build, require_mode       # noqa: E402
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

TIER = {"builtin": "code", "cache": "replay", "model": "model", "fallback": "fallback"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default="http://127.0.0.1:18000")
    ap.add_argument("--mode", choices=["normal", "model_only", "scope_off"], required=True,
                    help="scope_off: normal, with the 14 October code_scope categories handed "
                         "back to the model for these sessions (the ablation run)")
    ap.add_argument("--label", required=True, help="build label, e.g. pre-freeze or frozen")
    ap.add_argument("--tests", default="gt43_lab_2026-09.json")
    ap.add_argument("--src-ip", default=SITE.lab_jump)
    ap.add_argument("--out", help="default: res_relay_43_<mode>_<label>_<date>.json")
    ap.add_argument("--pause", type=float, default=0.0,
                    help="seconds to wait after each generated answer. 8 is the pace the nodes "
                         "are known to survive for hundreds of answers; without pauses a node "
                         "went down after about 50 (docs/jetson-stability.md)")
    args = ap.parse_args()
    out = args.out or (f"res_relay_43_{args.mode.replace('_', '-')}_{args.label}_"
                       f"{datetime.date.today().isoformat()}.json")
    refuse_class_build(args.url)
    require_mode(args.url, args.mode)
    c = Client(args.url, args.src_ip, mode=args.mode)

    tidy_client = Client(args.url, args.src_ip, mode="normal")   # a tidy is code, never the model

    def session(command: str, client=None):
        client = client or c
        sid = f"run-{uuid.uuid4().hex[:8]}"
        client.send(sid, event="login")
        answer = client.send(sid, command)
        client.send(sid, event="logout")
        return answer

    # Start from the files as recorded: whatever an earlier run left (a rehearsal through
    # Cowrie does not tidy; found 2026-10-14, `mkdir junkdir` then said "File exists").
    session(TIDY, tidy_client)
    results = []
    try:
        for t in json.load(open(args.tests)):
            text, ext, ms = session(t["command"])
            results.append({
                "n": t["n"], "command": t["command"], "real": t["output"],
                "model": text.removesuffix("\n"),
                "tier": TIER.get(ext["source"], ext["source"]),
                "elapsed_ms": ms, "relay_elapsed_ms": ext.get("elapsed_ms"),
                "real_exit_code": t["exit_code"], "model_exit_code": ext["exit_code"],
                "real_elapsed_ms": t["elapsed_ms"],
                "answer_mode": args.mode, "build": args.label})
            print(f"#{t['n']:<3} {ext['source']:<8} {ms:>6} ms  {t['command'][:60]}", flush=True)
            with open(out, "w") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            if args.pause and ext["source"] != "builtin":
                time.sleep(args.pause)
    finally:
        if results:
            session(TIDY, tidy_client)
    tiers = collections.Counter(r["tier"] for r in results)
    print(f"\n{len(results)} answers: " + ", ".join(f"{k} {v}" for k, v in sorted(tiers.items())))
    print(f"saved to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
