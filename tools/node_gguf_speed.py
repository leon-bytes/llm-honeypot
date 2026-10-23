#!/usr/bin/env python3
"""node_gguf_speed.py - a registered model's speed on one Jetson, on held-back records,
the same way for any prompt format: the prompt rendered here (tools/heldback_gguf.py's
renderers), sent raw to ollama's /api/generate, greedy, paced.

Written 2026-10-18 to compare a teammate's fine-tuned Llama 3.2 1B with our fine-tuned Qwen3
1.7B on the same board (docs/bob-llama1b-combo.md). Run it on a FREED board only (the
served model unloaded, the relay stopped or not using this board): it refuses if another
model is loaded, because two models in a board's memory is the freeze risk
(docs/jetson-stability.md). It unloads the model at the end.

  python3 tools/node_gguf_speed.py --node lab-j4 --model honeypot-combo --format bob \
      --records 40 --out res_nodespeed_bob-combo_lab-j4_<date>.json

Per answer: ollama's own counts and durations, the wall time, and the answer (so it can
be compared with the CPU run of the same records). Afterwards the board's server log is
read for its "prompt eval time" lines, which count only the tokens actually read (the
rest came from the cache). Standard library only.
"""
from __future__ import annotations
import argparse
import datetime
import json
import pathlib
import socket
import statistics
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from heldback_gguf import bob_prompt, our_prompt          # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def call(url: str, path: str, body: dict | None = None, timeout: float = 600):
    req = urllib.request.Request(url + path, json.dumps(body).encode() if body is not None else None,
                                 {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def sample(recs: list, n: int) -> list[int]:
    """n records spread over the three sources in their proportions, fixed order."""
    by = {}
    for i, r in enumerate(recs):
        by.setdefault(r["meta"]["source"], []).append(i)
    out = []
    for src, idx in sorted(by.items()):
        k = max(1, round(n * len(idx) / len(recs)))
        step = len(idx) / k
        out += [idx[int(j * step)] for j in range(k)]
    return sorted(out)[:n]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--node", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--format", choices=("ours", "bob"), required=True)
    ap.add_argument("--data", default="offline/training/20261013")
    ap.add_argument("--records", type=int, default=40)
    ap.add_argument("--pause", type=float, default=15.0)
    ap.add_argument("--max-tokens", type=int, default=1024)
    ap.add_argument("--today", default="2026-10-18")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.pause < 8:
        sys.exit("--pause below 8: the nodes freeze under answers without pauses")
    recs = [json.loads(l) for l in open(ROOT / a.data / "val.jsonl")]
    pick = sample(recs, a.records)
    today = datetime.date.fromisoformat(a.today)
    port = free_port()
    tun = subprocess.Popen(["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-L",
                            f"{port}:127.0.0.1:11434", a.node])
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(30):
            try:
                call(url, "/api/version", timeout=3)
                break
            except Exception:
                time.sleep(1)
        loaded = [m["name"] for m in call(url, "/api/ps").get("models", [])]
        if any(not m.startswith(a.model) for m in loaded):
            sys.exit(f"{a.node} has other models loaded: {loaded}; free it first")
        rows = []
        for k, i in enumerate(pick):
            r = recs[i]
            s, u = r["messages"][0]["content"], r["messages"][1]["content"]
            prompt = our_prompt(s, u) if a.format == "ours" else bob_prompt(s, u, today)
            t0 = time.monotonic()
            resp = call(url, "/api/generate", {"model": a.model, "prompt": prompt, "raw": True,
                                                "stream": False, "keep_alive": "10m",
                                                "options": {"temperature": 0, "top_k": 1,
                                                            "num_predict": a.max_tokens,
                                                            "repeat_penalty": 1.0, "num_ctx": 8192}})
            wall = time.monotonic() - t0
            rows.append({"i": i, "n": r["meta"]["n"], "source": r["meta"]["source"],
                         "output": resp.get("response", ""), "wall_ms": round(wall * 1000),
                         **{key: resp.get(key) for key in ("prompt_eval_count", "prompt_eval_duration",
                                                         "eval_count", "eval_duration", "load_duration")}})
            print(f"{k + 1}/{len(pick)} {r['meta']['source']:6s} {wall:.1f} s "
                  f"prompt {resp.get('prompt_eval_count')} out {resp.get('eval_count')}", flush=True)
            time.sleep(a.pause)
        call(url, "/api/generate", {"model": a.model, "keep_alive": 0})
    finally:
        tun.terminate()
    # the board's server log: one "prompt eval time" line per answer, the last ones are ours
    log = subprocess.run(["ssh", a.node, f"grep -a 'prompt eval time' /var/log/syslog | tail -{len(pick)}"],
                         capture_output=True, text=True).stdout
    read = [float(x.split("/")[1].split("tokens")[0]) / (float(x.split("=")[1].split("ms")[0]) / 1000)
            for x in log.splitlines() if "prompt eval time" in x and "/" in x
            and float(x.split("/")[1].split("tokens")[0]) > 50]
    ev = [r for r in rows if (r["eval_count"] or 0) > 1 and r["eval_duration"]]
    summary = {"node": a.node, "model": a.model, "format": a.format, "records": len(rows),
               "wall_ms_median": statistics.median(r["wall_ms"] for r in rows),
               "writing_tokens_per_s": round(statistics.median(r["eval_count"] / (r["eval_duration"] / 1e9) for r in ev), 1),
               "reading_tokens_per_s_ollama": round(statistics.median(
                   r["prompt_eval_count"] / (r["prompt_eval_duration"] / 1e9) for r in rows
                   if r["prompt_eval_count"] and r["prompt_eval_duration"]), 1),
               "reading_tokens_per_s_uncached": round(statistics.median(read), 1) if read else None,
               "prompt_tokens_median": statistics.median(r["prompt_eval_count"] or 0 for r in rows),
               "output_tokens_median": statistics.median(r["eval_count"] or 0 for r in rows)}
    json.dump({"summary": summary, "rows": rows}, open(a.out, "w"), indent=1)
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
