#!/usr/bin/env python3
"""heldback_gguf.py - a 4-bit GGUF model's answers to the 169 held-back records, generated
with llama.cpp's llama-server on this machine's CPU, for tools/finetune/score_generations.py.

Written 2026-10-18 to compare a teammate's fine-tuned Llama 3.2 1B ("combo") with our fine-tuned
Qwen3 1.7B on the same records, the same runtime and the same scorer, without touching the
lab (docs/bob-llama1b-combo.md). The CPU gives each model's answers (greedy, so the same
tokens as a board up to rounding), not the board's speed.

Two prompt formats:
  ours  the record's own messages in Qwen3's chat template with thinking off, exactly as
        the PC rendered them (each prompt's sha256 is checked against the PC's report)
  bob   the teammate's "reordered" layout without the Rules section (his prompt_builder.py): the
        same sections of the record's system text in his order, in the Llama 3.2 template

  python3 tools/heldback_gguf.py --server offline/llama.cpp-b11617-x64/bin/llama-b11617/llama-server \
      --model MODEL.gguf --format ours|bob --data offline/training/20261013 \
      --out offline/finetune-results/gguf-cpu/NAME [--pc-report evals/merged-1p7b.json]

Writes NAME/generations.jsonl ({n, source, variant, output, prompt_tokens, ...} per record)
and NAME/run.json. Resumes: records already in generations.jsonl are not asked again.
Standard library only.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

HEADERS = ["Rules:", "Facts about this machine (always true):",
           "Live values right now (use these, do not guess):",
           "Changed on this machine by its users (they exist now, or no longer exist):",
           "This session so far, oldest first:", "Real examples from this exact machine:"]
BOB_ORDER = [HEADERS[1], HEADERS[4], HEADERS[5], HEADERS[3], HEADERS[2]]


def sections(system: str) -> tuple[str, dict]:
    """The record's system text cut at its section headers: the preamble, and each
    section's text with its header."""
    cuts = sorted((system.index("\n\n" + h + "\n"), h) for h in HEADERS if "\n\n" + h + "\n" in system)
    pre = system[:cuts[0][0]]
    out = {}
    for i, (at, h) in enumerate(cuts):
        end = cuts[i + 1][0] if i + 1 < len(cuts) else len(system)
        out[h] = system[at + 2:end]
    assert "\n\n".join([pre] + [out[h] for _, h in cuts]) == system
    return pre, out


def bob_prompt(system: str, command: str, today: datetime.date) -> str:
    pre, sec = sections(system)
    body = "\n\n".join([pre] + [sec[h] for h in BOB_ORDER if h in sec])
    return ("<|start_header_id|>system<|end_header_id|>\n\n"
            f"Cutting Knowledge Date: December 2023\nToday Date: {today.day:02d} {today:%b %Y}\n\n"
            f"{body}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n"
            f"{command}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n")


def our_prompt(system: str, command: str) -> str:
    # Qwen3's template, add_generation_prompt=True, enable_thinking=False
    return (f"<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{command}<|im_end|>\n"
            "<|im_start|>assistant\n<think>\n\n</think>\n\n")


def post(url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--server", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--format", choices=("ours", "bob"), required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pc-report", help="the PC's eval report: its prompt hashes are checked")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--port", type=int, default=18611)
    ap.add_argument("--max-tokens", type=int, default=1024)
    ap.add_argument("--today", default="2026-10-18", help="the teammate's template stamps a date")
    ap.add_argument("--flash-attn", default="off", choices=("on", "off", "auto"),
                    help="off by default: llama.cpp's CPU flash attention changed close calls "
                         "that the boards decide the other way (2026-10-18, lsb_release -c)")
    a = ap.parse_args()
    recs = [json.loads(l) for l in open(pathlib.Path(a.data) / "val.jsonl")]
    today = datetime.date.fromisoformat(a.today)
    prompts = []
    for r in recs:
        system, user = r["messages"][0]["content"], r["messages"][1]["content"]
        prompts.append(our_prompt(system, user) if a.format == "ours" else bob_prompt(system, user, today))
    if a.pc_report:
        pc = {(x["meta"]["n"], x["meta"]["source"], x["meta"].get("variant")): x["prompt_sha256"]
              for x in json.load(open(a.pc_report))["answers"]}
        bad = [r["meta"] for r, p in zip(recs, prompts)
               if pc.get((r["meta"]["n"], r["meta"]["source"], r["meta"].get("variant")))
               != hashlib.sha256(p.encode()).hexdigest()]
        if bad:
            sys.exit(f"{len(bad)} prompts differ from the PC's, e.g. {bad[:3]}")
        print(f"all {len(recs)} prompts identical to the PC's")
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    gen = out / "generations.jsonl"
    done = {json.loads(l)["i"] for l in open(gen)} if gen.exists() else set()
    srv = subprocess.Popen(["nice", "-n", "19", a.server, "-m", a.model, "-c", "8192", "-np", "1",
                            "-t", str(a.threads), "--port", str(a.port), "--host", "127.0.0.1",
                            "--cache-ram", "0", "-fa", a.flash_attn],
                           stdout=subprocess.DEVNULL, stderr=open(out / "server.log", "w"))
    url = f"http://127.0.0.1:{a.port}"
    try:
        for _ in range(120):
            try:
                if post(url + "/tokenize", {"content": "x"}, 5):
                    break
            except Exception:
                time.sleep(1)
        t0 = time.time()
        with open(gen, "a") as f:
            for i, (r, p) in enumerate(zip(recs, prompts)):
                if i in done:
                    continue
                # cache_prompt false: every record read whole, as on a board after a ping
                resp = post(url + "/completion", {"prompt": p, "temperature": 0, "top_k": 1,
                                                  "n_predict": a.max_tokens, "cache_prompt": False,
                                                  "repeat_penalty": 1.0}, 3600)
                t = resp.get("timings", {})
                f.write(json.dumps({"i": i, "n": r["meta"]["n"], "source": r["meta"]["source"],
                                    "variant": r["meta"].get("variant"),
                                    "prompt_sha256": hashlib.sha256(p.encode()).hexdigest(),
                                    "output": resp.get("content", ""),
                                    "prompt_tokens": t.get("prompt_n"), "completion_tokens": t.get("predicted_n"),
                                    "prompt_ms": t.get("prompt_ms"), "predicted_ms": t.get("predicted_ms"),
                                    "stop": resp.get("stop_type") or resp.get("stopped_eos")}) + "\n")
                f.flush()
                print(f"{i + 1}/{len(recs)} {r['meta']['source']:6s} {t.get('prompt_n')} tok "
                      f"{(t.get('prompt_ms', 0) + t.get('predicted_ms', 0)) / 1000:.1f} s", flush=True)
        json.dump({"model": a.model, "format": a.format, "server": a.server, "threads": a.threads,
                   "flash_attn": a.flash_attn,
                   "records": len(recs), "seconds": round(time.time() - t0)},
                  open(out / "run.json", "w"), indent=1)
    finally:
        srv.terminate()
        srv.wait(30)
    return 0


if __name__ == "__main__":
    sys.exit(main())
