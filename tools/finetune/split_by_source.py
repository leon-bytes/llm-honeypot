#!/usr/bin/env python3
"""One kind of record out of a training set: the data for one specialist.

The specialist experiment (the user, 2026-10-15): instead of one fine-tune trained on
all three kinds of record, one per kind, each trained only on its own kind, so that each
model node could be a specialist. A record's kind is its `meta.source`:

  corpus   the reference machine's own command answers (files, program output)
  debian   exact program texts (error, usage and version messages) from the Debian userland
  code     answers the honeypot computes in code in normal operation

Writes <out>/train.jsonl (the training records of that kind, in their order) and
<out>/val.jsonl (the held-back records of that kind, which choose the specialist's best
checkpoint, as all held-back records choose the generalist's). The full set's records
are copied byte for byte: nothing is rebuilt or changed. Standard library only.

Run (on the PC, in the fine-tuning folder):
  python scripts/split_by_source.py --data data/20261014 --source corpus --out data/20261014-corpus
"""
import argparse
import json
import pathlib
import sys

SOURCES = ("corpus", "debian", "code")


def split(data: pathlib.Path, source: str, out: pathlib.Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    counts = {}
    for name in ("train.jsonl", "val.jsonl"):
        kept = 0
        with open(data / name, encoding="utf-8") as src, open(out / name, "w", encoding="utf-8") as dst:
            for line in src:
                if json.loads(line).get("meta", {}).get("source", "corpus") == source:
                    dst.write(line)
                    kept += 1
        counts[name] = kept
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", required=True, help="the full set's folder (train.jsonl, val.jsonl)")
    ap.add_argument("--source", required=True, choices=SOURCES)
    ap.add_argument("--out", required=True, help="folder for the subset")
    a = ap.parse_args()
    data, out = pathlib.Path(a.data), pathlib.Path(a.out)
    if (out / "train.jsonl").exists():
        print(f"{out} exists already; kept as it is")
        return 0
    counts = split(data, a.source, out)
    if not counts["train.jsonl"] or not counts["val.jsonl"]:
        sys.exit(f"no {a.source} records in {data}")
    print(f"{a.source}: {counts['train.jsonl']} training records, {counts['val.jsonl']} held back -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
