#!/usr/bin/env python3
"""
run_leave_one_out.py - the larger test: every corpus command the model answers, asked
with its own recording hidden from the model's examples.

The 43 test commands are few, and only 13 of them are answered by the model. The corpus
has 284 more commands with the real machine's answers, about 200 of which the relay
hands to the model; but the model is normally SHOWN those recordings as examples, so
asking them as they are would measure copying. Here each one is asked in a session
where its own recording is hidden (`honeypot.hide_examples`, docs/relay-protocol.md),
so the model has to answer from the other recordings and the facts in its prompt.

Three variants (--variant). The first is the comparison the other two are read against:

  none     hides nothing: the same commands, asked the same way, with their recordings
           among the examples as in normal operation.

  own      hides the command's own recording, nothing else (the test as approved).
  strict   also hides every other recording with the same answer, or whose answer
           shares three or more lines in a row with this one's (the rule that keeps
           overlapping recordings away from the 43, build_training_data.windows):
           `cat /proc/sys/kernel/hostname` cannot be copied from `cat /etc/hostname`.
           A lower bound on the same question.

Which commands: the corpus entries the relay answers with the model in normal mode,
found by asking a local copy of the relay with a stand-in model (as tools/tier_tally.py
does). Entries the relay never loads as examples (skip-listed, the five hidden ones,
capture errors) are asked too and marked `was_example: false`: for them every run is
already "left out". One fresh login per command, as the recordings were made.

  .venv/bin/python tools/run_leave_one_out.py --variant own    --label build-1013
  .venv/bin/python tools/run_leave_one_out.py --variant strict --label build-1013

Needs the tunnel to the relay (18000). Writes res_loo_<variant>_<label>_<date>.json
(git-ignored, team-only like the recordings): n, command, real, model, tier, the
timings, both exit codes, what was hidden and which examples the relay says it showed.
Graded by tools/eval_harness.py. It can be stopped and started again: entries already
in the output file are kept (--fresh starts over).

Nothing here creates files on the honeypot: commands that would (touch, mkdir, >, tee,
rm, …) are left out, and listed at the end.
"""
from __future__ import annotations
import argparse
import collections
import datetime
import json
import pathlib
import re
import sys
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from relay_client import Client, refuse_class_build          # noqa: E402
from build_training_data import windows                      # noqa: E402
from honeypot.relay import Relay                             # noqa: E402
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

TIER = {"builtin": "code", "cache": "replay", "model": "model", "fallback": "fallback"}
# A command that changes the machine's file state is not asked: the state is shared with
# every later session.
WRITES = re.compile(r"(^|[;&|]\s*)(touch|mkdir|rm|rmdir|mv|cp|tee|ln|chmod|chown|dd|truncate)\b|>")


class StandIn:
    backends = []

    def complete(self, sid, messages, role="state"):
        return "x", {"backend": "stand-in"}


def targets() -> tuple[list[dict], set[int]]:
    """(the corpus entries the relay gives to the model, the numbers in its example pool)."""
    cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
    tmp = tempfile.TemporaryDirectory()
    cfg["state_dir"], cfg["log"] = tmp.name + "/s", tmp.name + "/l/r.jsonl"
    relay = Relay(cfg, str(ROOT / "honeypot"), pool=StandIn())
    pool = {e["n"] for e in relay.knowledge.examples}
    out = []
    for e in json.load(open(ROOT / "corpus284_lab_2026-09.json")):
        sid = f"loo-plan-{e['n']}"
        relay.handle({"user": sid, "messages": [{"role": "user", "content": ""}],
                      "honeypot": {"event": "login", "src_ip": SITE.lab_jump, "src_port": 1}})
        _, resp = relay.handle({"user": sid, "messages": [{"role": "user", "content": e["command"]}],
                                "honeypot": {"event": "command"}})
        relay.handle({"user": sid, "messages": [{"role": "user", "content": ""}],
                      "honeypot": {"event": "logout"}})
        if resp["honeypot"]["source"] in ("model", "fallback"):
            out.append(e)
    relay._log.close()
    return out, pool


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default="http://127.0.0.1:18000")
    ap.add_argument("--variant", choices=["own", "strict", "none"], required=True)
    ap.add_argument("--label", required=True, help="build label, e.g. build-1013 or frozen")
    ap.add_argument("--src-ip", default=SITE.lab_jump)
    ap.add_argument("--out", help="default: res_loo_<variant>_<label>_<date>.json")
    ap.add_argument("--limit", type=int, help="ask only the first N (a trial run)")
    ap.add_argument("--fresh", action="store_true", help="ignore an existing output file")
    ap.add_argument("--dry-run", action="store_true", help="show the plan, send nothing")
    ap.add_argument("--pause", type=float, default=8.0,
                    help="seconds to wait after each generated answer (default 8, the pace of "
                         "the load test that the nodes are known to survive; see "
                         "docs/jetson-stability.md before lowering it)")
    args = ap.parse_args()
    out_path = pathlib.Path(args.out or f"res_loo_{args.variant}_{args.label}_"
                            f"{datetime.date.today().isoformat()}.json")

    asked, pool = targets()
    corpus = {e["n"]: e for e in json.load(open(ROOT / "corpus284_lab_2026-09.json"))}
    skipped = [e for e in asked if WRITES.search(e["command"])]
    asked = [e for e in asked if not WRITES.search(e["command"])]
    win = {n: windows(e["output"]) for n, e in corpus.items()}

    def hidden(e) -> list[int]:
        if args.variant == "none":
            return []
        hide = {e["n"]}
        if args.variant == "strict":
            mine = e["output"].strip()
            hide |= {n for n in pool if n != e["n"] and (
                win[n] & win[e["n"]] or (mine and corpus[n]["output"].strip() == mine))}
        return sorted(hide)

    plan = [(e, hidden(e)) for e in asked][:args.limit]
    extra = sum(max(len(h) - 1, 0) for _, h in plan)
    print(f"{len(plan)} commands the model answers ({sum(e['n'] in pool for e, _ in plan)} of them "
          f"are normally examples); variant {args.variant}: {extra} other recordings hidden in "
          f"all; {len(skipped)} left out because they write files")
    if args.dry_run:
        for e, h in plan:
            print(f"  {e['n']:4} hide {h}  {e['command'][:70]}")
        return 0

    results = []
    if out_path.exists() and not args.fresh:
        results = json.load(open(out_path))
        print(f"{len(results)} answers already in {out_path}, kept")
    done = {r["n"] for r in results}
    refuse_class_build(args.url)
    c = Client(args.url, args.src_ip, mode="normal")
    for e, hide in plan:
        if e["n"] in done:
            continue
        sid = f"loo-{uuid.uuid4().hex[:8]}"
        c.send(sid, event="login", hide_examples=hide)
        text, ext, ms = c.send(sid, e["command"])
        c.send(sid, event="logout")
        results.append({
            "n": e["n"], "command": e["command"], "real": e["output"],
            "model": text.removesuffix("\n"), "tier": TIER.get(ext["source"], ext["source"]),
            "elapsed_ms": ms, "relay_elapsed_ms": ext.get("elapsed_ms"),
            "real_exit_code": e["exit_code"], "model_exit_code": ext["exit_code"],
            "real_elapsed_ms": e.get("elapsed_ms"), "variant": args.variant,
            "hidden": hide, "was_example": e["n"] in pool, "build": args.label})
        print(f"#{e['n']:<4} {ext['source']:<8} {ms:>6} ms  hid {len(hide)}  {e['command'][:56]}",
              flush=True)
        out_path.write_text(json.dumps(results, indent=1, ensure_ascii=False))
        if ext["source"] != "builtin":
            time.sleep(args.pause)
    tiers = collections.Counter(r["tier"] for r in results)
    print(f"\n{len(results)} answers: " + ", ".join(f"{k} {v}" for k, v in sorted(tiers.items())))
    if skipped:
        print("not asked (they write files): " + "; ".join(e["command"][:40] for e in skipped))
    print(f"saved to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
