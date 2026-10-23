#!/usr/bin/env python3
"""How many answers come from code and from the model (and from recorded replay, which
is off by default since 2026-10-08 and stays at 0 unless --replay is given).

Runs every command of the 43 and of the corpus through the relay, one fresh login per
command, with a stand-in model, and counts the tier that answered. The scope rule
(2026-10-02): code only where needed for speed or for consistency with shared state;
everything else stays with the model. This tally goes in every report.

Run: .venv/bin/python tools/tier_tally.py [--list] [--model-only] [--scope-off] [--replay]
(--scope-off: the sessions of the ablation run, the categories of 14 October handed
back to the model.)
(--model-only: the paper's switch; every line should then be the model's.
 --replay: turn config `replay_tier` on for this tally only, to see what the removed
 tier would have answered. Not the evaluated system.)
"""
import collections
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from honeypot.relay import Relay        # noqa: E402
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

MODE = "model_only" if "--model-only" in sys.argv else "scope_off" if "--scope-off" in sys.argv \
    else "normal"
TIER = {"builtin": "code", "cache": "replay", "model": "model", "fallback": "model"}


class StandIn:
    backends = []

    def complete(self, sid, messages, role="state"):
        return "x", {"backend": "stand-in"}


def tally(path: str, relay: Relay) -> tuple[collections.Counter, dict]:
    counts, by = collections.Counter(), {}
    for i, e in enumerate(json.load(open(ROOT / path))):
        sid = f"tally-{path}-{i}"
        relay.handle({"user": sid, "messages": [{"role": "user", "content": ""}],
                      "honeypot": {"event": "login", "src_ip": SITE.lab_jump, "src_port": 1,
                                   "mode": MODE}})
        _, resp = relay.handle({"user": sid, "messages": [{"role": "user", "content": e["command"]}],
                                "honeypot": {"event": "command"}})
        tier = TIER[resp["honeypot"]["source"]]
        counts[tier] += 1
        by[e["n"]] = (tier, e["command"])
        relay.handle({"user": sid, "messages": [{"role": "user", "content": ""}],
                      "honeypot": {"event": "logout"}})
    return counts, by


def main() -> int:
    cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
    tmp = tempfile.TemporaryDirectory()
    cfg["state_dir"], cfg["log"] = tmp.name + "/s", tmp.name + "/l/r.jsonl"
    if "--replay" in sys.argv:
        cfg["replay_tier"] = True
        print("replay tier ON for this tally (off in config and in the evaluated system)")
    relay = Relay(cfg, str(ROOT / "honeypot"), pool=StandIn())
    for label, path in (("the 43", "gt43_lab_2026-09.json"), ("corpus", "corpus284_lab_2026-09.json")):
        c, by = tally(path, relay)
        total = sum(c.values())
        print(f"{label:7} ({total}): code {c['code']}, replay {c['replay']}, model {c['model']}")
        if c["code"] > c["model"]:
            print(f"  FLAG: code answers more of {label} than the model does")
        if "--list" in sys.argv:
            for n, (tier, cmd) in sorted(by.items()):
                print(f"    {n:4} {tier:6} {cmd}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
