#!/usr/bin/env python3
"""Score a model's answers to the held-back records with OUR metric, WITHOUT loading the
model. For a teammate whose architecture we cannot run through eval_heldback.py (which
loads a Hugging Face base model and a LoRA adapter): they generate the answers in their
own stack and we score them here, on the same 169 held-back records, the same way.

The teammate:
  1. gets `val.jsonl` from us (the 169 held-back records; team-only data). Each line has
     `messages` ([system, user, assistant]) and `meta` (with `source`). The prompt is the
     first two messages; the recorded answer is the third.
  2. for each record, gives their model the SAME prompt and writes ONE answer. Thinking
     off; greedy decoding (do_sample off), no repetition penalty, to match our runs. The
     output file `generations.jsonl` has one object per line:
         {"prompt_sha256": "<sha256 of the rendered prompt>", "output": "<raw answer>"}
     `prompt_sha256` is the sha256 of the exact prompt string they fed the model; it is
     also printed by eval_heldback.py for each record, so the two line up without sharing
     any order. If they cannot produce the hash, `{"n": <meta.n>, "source": <meta.source>,
     "output": ...}` works too.
  3. runs this:
       python score_generations.py --data <dir with val.jsonl> \\
           --generations generations.jsonl --out evals/<their-model>.json
     and sends us `evals/<their-model>.json`. It is read by compare_evals.py exactly like
     an eval_heldback.py report, so it sits beside our own in the same table.

The answer gets the same clean-up the relay gives every model answer before scoring (a
reasoning block dropped, a code fence or an echoed command line stripped), so the score is
about what an attacker would see. Self-contained: standard library only, nothing from the
repository or from any ML stack. Keep `relay_clean` the same as eval_heldback.py's.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import pathlib
import re
import sys


def rstrip_lines(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.strip("\n").split("\n"))


def relay_clean(text: str, line: str) -> str:
    """What honeypot/shell.py's clean() does to a model answer. A copy, kept identical to
    eval_heldback.py's, so this script needs nothing from the repository."""
    t = re.sub(r"^\s*(?:<think>)?.*?</think>\n*|^\s*<think>.*", "", text, count=1,
               flags=re.S) if "think>" in text else text
    t = t.strip("\n")
    if t.lstrip().startswith("```"):
        t = re.sub(r"^\s*```[\w-]*\n?", "", t)
        t = re.sub(r"\n?```\s*$", "", t)
    lines = t.split("\n")
    if lines and lines[0].strip() in (f"$ {line.strip()}", f"# {line.strip()}"):
        lines = lines[1:]
    return "\n".join(lines).strip("\n")


def render_sha(messages: list) -> str:
    """A fallback key when the teammate cannot give prompt_sha256: a stable hash of the
    system+user messages. Only used to match; the teammate is asked for prompt_sha256
    first, since that is what eval_heldback.py prints."""
    return hashlib.sha256(json.dumps(messages[:-1], ensure_ascii=False).encode()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", required=True, help="folder with val.jsonl (the 169 held-back records)")
    ap.add_argument("--generations", required=True, help="the teammate's generations.jsonl")
    ap.add_argument("--out", required=True, help="JSON report, read by compare_evals.py")
    ap.add_argument("--name", default="", help="a label for the report (default: the --out name)")
    a = ap.parse_args()

    with open(pathlib.Path(a.data).expanduser() / "val.jsonl", encoding="utf-8") as f:
        records = [json.loads(l) for l in f if l.strip()]

    gens_by_sha, gens_by_ns = {}, {}
    with open(pathlib.Path(a.generations).expanduser(), encoding="utf-8") as f:
        for l in f:
            if not l.strip():
                continue
            g = json.loads(l)
            if "output" not in g:
                sys.exit("each generation needs an 'output' field")
            if g.get("prompt_sha256"):
                gens_by_sha[g["prompt_sha256"]] = g["output"]
            if g.get("n") is not None:
                gens_by_ns[(str(g["n"]), g.get("source", "corpus"))] = g["output"]

    stats = collections.defaultdict(lambda: collections.Counter())
    answers, missing = [], []
    for r in records:
        msgs, meta = r["messages"], r["meta"]
        source = meta.get("source", "corpus")
        want = msgs[-1]["content"].strip("\n")
        line = msgs[1]["content"]
        key_sha = meta.get("prompt_sha256") or render_sha(msgs)
        raw = gens_by_sha.get(key_sha)
        if raw is None:
            raw = gens_by_ns.get((str(meta.get("n")), source))
        if raw is None:
            missing.append(meta.get("n"))
            continue
        got = relay_clean(raw, line)
        want_lines = [x for x in want.split("\n") if x.strip()]
        got_lines = set(got.split("\n"))
        for key in (source, "all"):
            s = stats[key]
            s["n"] += 1
            s["exact"] += got == want
            s["exact_rs"] += rstrip_lines(got) == rstrip_lines(want)
            s["lines_want"] += len(want_lines)
            s["lines_found"] += sum(1 for x in want_lines if x in got_lines)
        answers.append({"meta": meta, "command": line, "want": want, "got": got,
                        "raw": raw, "exact": got == want})

    if missing:
        sys.exit(f"{len(missing)} held-back records had no matching generation "
                 f"(first few n: {missing[:10]}). Match by prompt_sha256 or by n+source.")

    report = {}
    for key, s in stats.items():
        report[key] = {"records": s["n"], "exact": s["exact"], "exact_rs": s["exact_rs"],
                       "exact_pct": round(100 * s["exact"] / s["n"], 1),
                       "exact_rs_pct": round(100 * s["exact_rs"] / s["n"], 1),
                       "lines_pct": round(100 * s["lines_found"] / max(s["lines_want"], 1), 1)}
    out = pathlib.Path(a.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"model": a.name or out.stem, "adapter": None,
                               "scored_from_generations": a.generations,
                               "report": report, "answers": answers},
                              indent=1, ensure_ascii=False) + "\n")
    print(f"{'source':8} {'records':>7} {'exact':>12} {'lines':>7}")
    for key in sorted(report, key=lambda k: (k == "all", k)):
        v = report[key]
        print(f"{key:8} {v['records']:7} {v['exact']:6} {v['exact_pct']:5.1f}% {v['lines_pct']:6.1f}%")
    print(f"\nwrote {out}. Send it to us; compare_evals.py reads it beside our own reports.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
