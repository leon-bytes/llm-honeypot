"""Audit added training records against the held-back val set (169) and gt43.

Checks, per added file: exact command match, exact (command, reply) match, and any reply
sharing 3+ consecutive non-blank lines with a held-back answer (the dataset's own rule).
Also reports the original train.jsonl's overlap with val, for comparison.
"""

import json
import sys
from pathlib import Path

val_path, gt43_path = sys.argv[1:3]
added = sys.argv[3:]


def load(p):
    return [json.loads(line) for line in Path(p).read_text().splitlines()]


def windows(text):
    lines = text.split("\n")
    return {
        tuple(lines[i : i + 3])
        for i in range(len(lines) - 2)
        if sum(bool(x.strip()) for x in lines[i : i + 3]) == 3
    }


held = {"val": load(val_path), "gt43": load(gt43_path)}
for name, recs in held.items():
    cmds = {r["messages"][1]["content"] for r in recs}
    pairs = {(r["messages"][1]["content"], r["messages"][2]["content"]) for r in recs}
    wins = set().union(*(windows(r["messages"][2]["content"]) for r in recs))
    for path in added:
        rows = load(path)
        c = sum(r["messages"][1]["content"] in cmds for r in rows)
        p = sum(
            (r["messages"][1]["content"], r["messages"][2]["content"]) in pairs
            for r in rows
        )
        w = sum(bool(windows(r["messages"][2]["content"]) & wins) for r in rows)
        print(
            f"{path.rsplit('/', 1)[-1]:28s} vs {name:5s}: records {len(rows):6d}  same command {c:4d}  same command+reply {p:4d}  3+ shared lines {w:4d}"
        )
