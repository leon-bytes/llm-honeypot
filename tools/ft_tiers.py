#!/usr/bin/env python3
"""Who answers each held-back fine-tuning record on a given build: code or the model.

The fine-tuning scores (offline/finetune-results/evals/*.json) are over 169 held-back
records of three kinds. In model-only mode every one of them reaches the model; in
normal operation the relay answers some in code, and which ones depends on the build.
This runs the build's OWN relay code (a temporary git worktree at that commit, its own
tools/tier_tally.py and config, a stand-in model, nothing sent anywhere) over the
records' commands, one fresh login per command as tier_tally does, and prints JSON:
{"commit": ..., "tiers": {"<source>:<meta n>": "code" | "model", ...}}.

A fresh login is what the corpus and debian records are (a command typed after login,
with the session's earlier lines only as prompt context); the code records come from
generated sessions and are code-made by construction, so they are listed but only the
corpus and debian ones are what the harness reports.

Run: .venv/bin/python tools/ft_tiers.py --commit ebf5224 [--report offline/finetune-results/evals/base.json]
eval_harness.py calls it once per label and keeps the answer (res_ft_tiers_<label>.json).
"""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

INNER = r"""
import json, sys, tempfile, pathlib
sys.path.insert(0, "."); sys.path.insert(0, "tools")
import tier_tally as T
from honeypot.relay import Relay
cmds = json.load(open(sys.argv[1]))
try:                    # a build with the site file (2026-10-16 on): values filled in
    from honeypot.site import SITE
    cfg = SITE.load_json("honeypot/config.json")
except ImportError:     # an older build: the values are in its config
    cfg = json.load(open("honeypot/config.json"))
tmp = tempfile.TemporaryDirectory()
cfg["state_dir"], cfg["log"] = tmp.name + "/s", tmp.name + "/l/r.jsonl"
relay = Relay(cfg, "honeypot", pool=T.StandIn())
T.ROOT = pathlib.Path("/")
_, by = T.tally(sys.argv[1], relay)
print(json.dumps({str(n): tier for n, (tier, _) in by.items()}))
"""


def key(meta: dict) -> str:
    return f"{meta.get('source', 'corpus')}:{meta.get('n')}"


def tiers(commit: str, report: pathlib.Path) -> dict:
    answers = json.load(open(report, encoding="utf-8"))["answers"]
    full = subprocess.run(["git", "rev-parse", "--short", commit], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()
    with tempfile.TemporaryDirectory() as tmp:
        wt = pathlib.Path(tmp) / "wt"
        subprocess.run(["git", "worktree", "add", "--detach", "--quiet", str(wt), full], cwd=ROOT,
                       check=True, capture_output=True)
        try:
            cmds = pathlib.Path(tmp) / "cmds.json"
            cmds.write_text(json.dumps([{"n": i, "command": a["command"]} for i, a in enumerate(answers)]))
            # The worktree has no site.local.json (git ignores it): point it at this one.
            env = dict(os.environ, HONEYPOT_SITE=str(ROOT / "site.local.json"))
            p = subprocess.run([sys.executable, "-c", INNER, str(cmds)], cwd=wt, capture_output=True,
                               text=True, env=env)
            if p.returncode:
                raise RuntimeError(f"the relay of {full} could not be run:\n{p.stderr[-2000:]}")
            by = json.loads(p.stdout.strip().splitlines()[-1])
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(wt)], cwd=ROOT,
                           capture_output=True)
    return {"commit": full, "report": str(report.relative_to(ROOT)) if report.is_relative_to(ROOT)
            else str(report), "tiers": {key(a["meta"]): by[str(i)] for i, a in enumerate(answers)}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--commit", required=True, help="the build's commit")
    ap.add_argument("--report", default=str(ROOT / "offline" / "finetune-results" / "evals" / "base.json"),
                    help="any eval_heldback.py report (only its commands are read)")
    a = ap.parse_args()
    print(json.dumps(tiers(a.commit, pathlib.Path(a.report).resolve()), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
