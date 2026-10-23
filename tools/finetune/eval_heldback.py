#!/usr/bin/env python3
"""How well does a model answer the held-back records? For the go/no-go.

Gives every held-back prompt (val.jsonl) to the model, lets it answer the way the
Jetsons do (greedy: the most likely token each time, i.e. temperature 0), and compares
the answer with the recorded one. Run it once for the base model and once with
--adapter for a fine-tuned checkpoint; the two reports are compared by compare_evals.py.

The model's raw answer first gets the clean-up the relay gives every model answer
(code fences, an echoed command and a trailing prompt removed), so the numbers are
about what an attacker would see.

Decoding is the Jetsons' too: greedy, and no repetition penalty. Qwen2.5-3B's own
settings file asks for 1.05, which transformers applies even when greedy (checked
2026-10-14); ollama's default is 1.0 and the relay cannot change it, so it is switched
off here, and step 13 of the guide removes it from the Jetson's file.

Thinking is off, as on the Jetsons: the prompt is rendered with enable_thinking=False
(Qwen3's template then ends it with an empty <think></think> block; Qwen2.5's has no
such switch and ignores it). The report counts the answers that began a reasoning block
anyway ("thought"; it should be 0) and keeps each prompt's length in tokens and the
fingerprint (SHA-256) of its text, which the Jetson measurement
(tools/measure_node_model.py) compares with the node's own to show that the node is
given the same prompt, byte for byte.

Reported per source (corpus, debian, code) and in total:
  exact        the cleaned answer is the recorded text, character for character
  exact_rs     the same, not counting spaces at the ends of lines (some real commands
               end lines with one; this column shows how much hangs on them)
  lines        share of the recorded lines that appear in the answer

This does NOT touch the 43 test commands. They are scored once, at the very end, by the
scorer, on the Jetson.

Run:
  python eval_heldback.py --model ~/ai/finetuning/honeypot/models/qwen2.5-3b-instruct \
      --data ~/ai/finetuning/honeypot/data/20261008 --out ~/ai/finetuning/honeypot/evals/base.json
  python eval_heldback.py --model ... --adapter ~/ai/finetuning/honeypot/runs/run1/best \
      --data ... --out ~/ai/finetuning/honeypot/evals/run1-best.json
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import sys
import time

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import torch                                                    # noqa: E402
from transformers import AutoModelForCausalLM, AutoTokenizer    # noqa: E402


def rstrip_lines(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.strip("\n").split("\n"))


def relay_clean(text: str, line: str) -> str:
    """What honeypot/shell.py's clean() does to a model answer. A copy, so that this
    script needs nothing from the repository; keep the two the same. A reasoning block
    (<think>...</think>) is dropped, finished or not: it never reaches an attacker."""
    t = re.sub(r"^\s*(?:<think>)?.*?</think>\n*|^\s*<think>.*", "", text, count=1,
               flags=re.S) if "think>" in text else text
    t = t.strip("\n")
    if t.lstrip().startswith("```"):
        t = re.sub(r"^\s*```[\w-]*\n?", "", t)
        t = re.sub(r"\n?```\s*$", "", t)
    lines = t.split("\n")
    if lines and lines[0].strip() in (f"$ {line.strip()}", f"# {line.strip()}"):
        lines = lines[1:]
    while lines and re.fullmatch(r"\S+@raspberrypi:\S*[#$]\s*", lines[-1]):
        lines.pop()
    return "\n".join(lines).strip("\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", required=True, help="folder of the base model")
    ap.add_argument("--adapter", help="folder of a LoRA checkpoint (leave out for the base model)")
    ap.add_argument("--data", required=True, help="folder with val.jsonl")
    ap.add_argument("--out", required=True, help="JSON file for the report and every answer")
    ap.add_argument("--limit", type=int, help="only the first N records (dry run)")
    ap.add_argument("--max-new-tokens", type=int, default=1024,
                    help="longest answer; about what the relay's 25 s deadline allows")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()

    model_path = os.path.expanduser(args.model)
    tok = AutoTokenizer.from_pretrained(model_path)
    dtype = torch.bfloat16 if args.device.startswith("cuda") else torch.float32
    model = AutoModelForCausalLM.from_pretrained(model_path, dtype=dtype)
    if args.adapter:
        from peft import PeftModel
        # Folded in before answering (2026-10-14), as on the Jetsons: unmerged, DoRA answers
        # about 2.4 times slower (peft's own measurement) and LoRA a little slower too.
        model = PeftModel.from_pretrained(model, os.path.expanduser(args.adapter)).merge_and_unload()
    model.to(args.device).eval()

    with open(pathlib.Path(args.data).expanduser() / "val.jsonl", encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()][:args.limit]
    stats = collections.defaultdict(lambda: collections.Counter())
    answers, started = [], time.time()
    for k, r in enumerate(records, 1):
        msgs, source = r["messages"], r["meta"].get("source", "corpus")
        prompt = tok.apply_chat_template(
            msgs[:-1], tokenize=False, add_generation_prompt=True, enable_thinking=False)
        x = tok(prompt, add_special_tokens=False, return_tensors="pt").to(args.device)
        with torch.no_grad():
            y = model.generate(**x, do_sample=False, max_new_tokens=args.max_new_tokens,
                               repetition_penalty=1.0, pad_token_id=tok.eos_token_id)
        raw = tok.decode(y[0][x["input_ids"].shape[1]:], skip_special_tokens=True)
        got = relay_clean(raw, msgs[1]["content"])
        want = msgs[-1]["content"].strip("\n")
        want_lines = [l for l in want.split("\n") if l.strip()]
        got_lines = set(got.split("\n"))
        for key in (source, "all"):
            s = stats[key]
            s["n"] += 1
            s["exact"] += got == want
            s["exact_rs"] += rstrip_lines(got) == rstrip_lines(want)
            s["lines_want"] += len(want_lines)
            s["lines_found"] += sum(1 for l in want_lines if l in got_lines)
        answers.append({"meta": r["meta"], "command": msgs[1]["content"], "want": want,
                        "got": got, "raw": raw, "exact": got == want,
                        "prompt_tokens": x["input_ids"].shape[1],
                        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                        "thought": bool(re.match(r"\s*<think>", raw)) or "</think>" in raw})
        if k % 20 == 0:
            print(f"  {k}/{len(records)}  {(time.time() - started) / k:.1f} s per answer", flush=True)

    report = {}
    for key, s in stats.items():
        report[key] = {"records": s["n"], "exact": s["exact"], "exact_rs": s["exact_rs"],
                       "exact_pct": round(100 * s["exact"] / s["n"], 1),
                       "exact_rs_pct": round(100 * s["exact_rs"] / s["n"], 1),
                       "lines_pct": round(100 * s["lines_found"] / max(s["lines_want"], 1), 1)}
    out = pathlib.Path(args.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    thought = sum(a["thought"] for a in answers)
    out.write_text(json.dumps({"model": args.model, "adapter": args.adapter,
                               "thought": thought, "report": report, "answers": answers},
                              indent=1, ensure_ascii=False) + "\n")
    print(f"\n{'source':8} {'records':>7} {'exact':>12} {'exact_rs':>12} {'lines':>7}")
    for key in sorted(report, key=lambda k: (k == "all", k)):
        v = report[key]
        print(f"{key:8} {v['records']:7} {v['exact']:5} ({v['exact_pct']:4.1f}%) "
              f"{v['exact_rs']:5} ({v['exact_rs_pct']:4.1f}%) {v['lines_pct']:6.1f}%")
    if thought:
        print(f"WARNING: {thought} answers began a reasoning block (<think>): thinking was "
              f"not off. The cleaned answers drop it, but check the model file.")
    print(f"saved to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
