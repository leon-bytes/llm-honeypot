#!/usr/bin/env python3
"""A model as one model node serves it: speed, and the held-back records answered there.

For the fine-tuning go/no-go (docs/finetuning-on-the-5090.md, steps 14 and 15): the PC
scores a fine-tuned model at full precision; what the class meets is the 4-bit file on
a Jetson. This sends every held-back prompt (val.jsonl: the relay's own prompts) to one
Jetson's ollama, exactly as the relay does (honeypot/backend.py's own request:
temperature 0, the same answer limit, the same deadline and first-token wait), cleans
the answer as the relay does, and scores it as eval_heldback.py does. The report has
eval_heldback.py's shape, so compare_evals.py reads it beside the PC's.

Speed per answer: the prompt's tokens over the time to the first token (reading), and
the answer's tokens over the rest (writing); medians in the report.

Thinking off (Qwen3, 2026-10-14): before a model is measured, ollama's own description
of it (/api/show) is checked: a model ollama counts as able to think, or a Qwen3 whose
template does not end the prompt with the empty <think></think> block training saw, is
refused with the reason (docs/finetuning-on-the-5090.md, step 14). An answer that starts
to think anyway stops the run for that model. Then every held-back prompt is rendered on
the node with the relay's own request and ollama's render-only switch
(`_debug_render_only`: the prompt text the model would get, nothing generated), and its
fingerprint compared with the PC's for the same record (its eval report: base.json for a
Qwen2.5, base-q3.json for a Qwen3, in --expect-dir): the same on all 169 means the node
gives the model, byte for byte, the prompt it was trained and scored on. The prompt's
length in tokens as the node counted it is compared too, answer by answer. --check-only
does the template and prompt checks alone (nothing is generated).

Paced (every run that uses a model node waits between answers): --pause 15
by default, never less than 8. It looks at the node's memory and temperature every few
answers (read-only, over SSH) and stops if it is low or hot. It opens its own tunnel to
the node (ssh -L through the alias) and closes it at the end. It changes nothing on the
node except which models ollama holds in memory: a model it loaded is unloaded at the
end (keep_alive 0; the file stays registered), unless --keep-loaded.

Do not run it while another model run uses the same node, and not during a measurement.

  .venv/bin/python tools/measure_node_model.py --node lab-j1 \
      --model qwen2.5:3b-instruct-q4_K_M --model honeypot-ft-1021 --limit 5     # a try
  .venv/bin/python tools/measure_node_model.py --node lab-j1 \
      --model qwen2.5:3b-instruct-q4_K_M --model honeypot-ft-1021
  .venv/bin/python tools/measure_node_model.py --node lab-j2 --model honeypot-ft-1021 --check-only

Writes res_nodemodel_<model>_<node>_<date>.json per model (git-ignored, team-only: the
held-back answers are part of the training data's rules). About 20 s per record at the
default pause: an hour per model for the 169.
"""
from __future__ import annotations
import argparse
import collections
import datetime
import hashlib
import json
import pathlib
import re
import socket
import statistics
import subprocess
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from honeypot.backend import Backend, Thinking    # noqa: E402
from honeypot.shell import clean              # noqa: E402
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

CFG = SITE.load_json(ROOT / "honeypot" / "config.json")
HOSTS = {"lab-j1": SITE.node1_ipv4, "lab-j2": SITE.node2_ipv4, "lab-j3": SITE.node3_ipv4,
         "lab-j4": SITE.node4_ipv4}


def rstrip_lines(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.strip("\n").split("\n"))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def open_tunnel(node: str, port: int) -> subprocess.Popen:
    """ssh -N -L <port>:127.0.0.1:11434 <node>: the node's ollama on this machine's
    <port>. Ours to stop: the handle is kept and terminated, never pkill."""
    p = subprocess.Popen(["ssh", "-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
                          "-o", "ConnectTimeout=8", "-L", f"{port}:127.0.0.1:11434", node])
    for _ in range(60):
        if p.poll() is not None:
            sys.exit(f"the tunnel to {node} did not open (ssh ended with {p.returncode})")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return p
        except OSError:
            time.sleep(0.25)
    p.terminate()
    sys.exit(f"the tunnel to {node} did not open within 15 s")


def ollama(port: int, path: str, body: dict | None = None, timeout: float = 15):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


# How Qwen3's template ends a prompt with thinking off (enable_thinking=False), and so
# what training saw: the model's turn opens with an empty reasoning block.
THINK_OFF_END = "<|im_start|>assistant\n<think>\n\n</think>\n\n"


def template_problem(info: dict) -> str | None:
    """Why the model would think on the node, from ollama's /api/show answer; or None."""
    arch = (info.get("model_info") or {}).get("general.architecture", "")
    if "thinking" in (info.get("capabilities") or []):
        return ("ollama counts it as a model that can think, so it thinks by default: the "
                "file still carries its own chat template, which ollama prefers to the "
                "Modelfile's (docs/finetuning-on-the-5090.md: the third line of step 13, then "
                "ollama create again as in step 14)")
    info_kv = info.get("model_info") or {}
    changed = {k: v for k, v in info_kv.items() if k.startswith("general.sampling.") and (
        (k == "general.sampling.penalty_repeat" and v != 1)
        or (k.split(".")[-1] in ("mirostat", "xtc_probability") and v))}
    if changed:
        return (f"its file asks for {changed}, which ollama applies and the PC's scoring does "
                f"not (decoding must be greedy without a penalty): remove it as in "
                f"docs/finetuning-on-the-5090.md, step 13, then ollama create again")
    if arch.startswith("qwen3") and not info.get("template", "").endswith(THINK_OFF_END):
        return ("a Qwen3 whose template does not end the prompt with the empty "
                "<think></think> block training saw (docs/finetuning-on-the-5090.md, step 14)")
    return None


def key(meta: dict) -> str:
    return json.dumps(meta, sort_keys=True)


def pc_prompts(folder: pathlib.Path, arch: str, data: pathlib.Path | None = None
               ) -> tuple[dict, str | None]:
    """The training prompt per record (meta as the key): its length in tokens and the
    fingerprint of its text. From the PC's eval report of this architecture's base model;
    if that has none (scored with a script older than 14 October, evening), from
    <data>/prompt_fingerprints.json, rendered on the dev machine with the same tokenizers."""
    path = folder / ("base-q3.json" if arch.startswith("qwen3") else "base.json")
    try:
        rep = json.loads(path.read_text())
        got = {key(a["meta"]): {"tokens": a["prompt_tokens"], "sha": a["prompt_sha256"]}
               for a in rep.get("answers", []) if "prompt_sha256" in a}
        if got:
            return got, str(path)
    except (OSError, ValueError):
        pass
    fp = (data or pathlib.Path("/nonexistent")) / "prompt_fingerprints.json"
    try:
        rows = json.loads(fp.read_text())["qwen3" if arch.startswith("qwen3") else "qwen2"]
    except (OSError, ValueError, KeyError):
        return {}, None
    return ({key(a["meta"]): {"tokens": a["prompt_tokens"], "sha": a["prompt_sha256"]}
             for a in rows}, str(fp))


def render_check(port: int, b: Backend, records: list[dict], pc: dict) -> dict:
    """Each held-back prompt as the node renders it from the relay's own request, against
    the PC's. Nothing is generated (ollama's `_debug_render_only`)."""
    same, differ, first = 0, 0, None
    for r in records:
        want = (pc.get(key(r["meta"])) or {}).get("sha")
        if not want:
            continue
        body = {**b.body(r["messages"][:-1], False), "_debug_render_only": True}
        got = ollama(port, "/v1/chat/completions", body, timeout=180)
        text = (got.get("_debug_info") or {}).get("rendered_template")
        if text is not None and hashlib.sha256(text.encode()).hexdigest() == want:
            same += 1
        else:
            differ += 1
            first = first or {"meta": r["meta"], "node_prompt_end": (text or "")[-200:]}
    return {"same": same, "differ": differ, "first_difference": first}


def score(records: list[dict], answers: list[dict]) -> dict:
    """eval_heldback.py's report: per source and in total."""
    stats = collections.defaultdict(collections.Counter)
    for r, a in zip(records, answers):
        want, got = a["want"], a["got"]
        want_lines = [l for l in want.split("\n") if l.strip()]
        got_lines = set(got.split("\n"))
        for key in (r["meta"].get("source", "corpus"), "all"):
            s = stats[key]
            s["n"] += 1
            s["exact"] += got == want
            s["exact_rs"] += rstrip_lines(got) == rstrip_lines(want)
            s["lines_want"] += len(want_lines)
            s["lines_found"] += sum(1 for l in want_lines if l in got_lines)
    return {k: {"records": s["n"], "exact": s["exact"], "exact_rs": s["exact_rs"],
                "exact_pct": round(100 * s["exact"] / s["n"], 1),
                "exact_rs_pct": round(100 * s["exact_rs"] / s["n"], 1),
                "lines_pct": round(100 * s["lines_found"] / max(s["lines_want"], 1), 1)}
            for k, s in stats.items()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--node", required=True, choices=sorted(HOSTS), help="the Jetson's alias")
    ap.add_argument("--model", action="append", required=True,
                    help="an ollama model name on that node; give it once per model")
    ap.add_argument("--data", default="offline/training/20261014", help="folder with val.jsonl")
    ap.add_argument("--limit", type=int, help="only the first N records (a try)")
    ap.add_argument("--pause", type=float, default=15.0, help="seconds between answers (8 at least)")
    ap.add_argument("--check-every", type=int, default=5, help="look at the node every N answers")
    ap.add_argument("--stop-below-mb", type=int, default=1500)
    ap.add_argument("--stop-above-c", type=int, default=85)
    ap.add_argument("--keep-loaded", action="store_true",
                    help="leave the measured models in the node's memory afterwards")
    ap.add_argument("--expect-dir", default="offline/finetune-results/evals",
                    help="the PC's eval reports, for the prompt lengths (skipped if absent)")
    ap.add_argument("--out-dir", default=str(ROOT), help="where the reports go (default: the project)")
    ap.add_argument("--check-only", action="store_true",
                    help="only check that each model is registered and will not think")
    ap.add_argument("--port", type=int, help="local port for the tunnel (default: a free one)")
    ap.add_argument("--no-tunnel", action="store_true",
                    help="--port is already the node's ollama (a test, or a tunnel of your own)")
    args = ap.parse_args()
    if args.pause < 8:
        sys.exit("--pause below 8 s is not allowed on a model node")
    with open(ROOT / args.data / "val.jsonl", encoding="utf-8") as f:
        records = [json.loads(l) for l in f if l.strip()][:args.limit]

    from jetson_load_test import look
    port = args.port or free_port()
    tunnel = None if args.no_tunnel else open_tunnel(args.node, port)
    stamp = datetime.date.today().isoformat()
    written = []
    try:
        def full(m: str) -> str:                    # ollama's own spelling: a tag always
            return m if ":" in m else f"{m}:latest"
        names = {m["name"] for m in ollama(port, "/api/tags").get("models", [])}
        missing = [m for m in args.model if full(m) not in names]
        if missing:
            sys.exit(f"not registered on {args.node}: {', '.join(missing)} (ollama list there)")
        # What the relay keeps loaded (the serving model) must stay loaded: never unloaded.
        loaded_before = {m["name"] for m in ollama(port, "/api/ps").get("models", [])}
        shown = {m: ollama(port, "/api/show", {"model": m}) for m in args.model}
        bad = {m: why for m in args.model if (why := template_problem(shown[m]))}
        for m in args.model:
            print(f"{m}: {'WILL THINK: ' + bad[m] if m in bad else 'thinking off, template fine'}",
                  flush=True)
        if bad:
            sys.exit(f"not measured: {len(bad)} model(s) would think on {args.node}")
        rendered = {}

        def prompts_on_node(m: str) -> None:
            """Render check for one model (it is loaded for it, one model at a time)."""
            arch = (shown[m].get("model_info") or {}).get("general.architecture", "")
            pc, pc_from = pc_prompts(ROOT / args.expect_dir, arch, ROOT / args.data)
            if not pc:
                print(f"{m}: prompts not compared (no fingerprints in {args.expect_dir} or "
                      f"{args.data})", flush=True)
                return
            b = Backend(args.node, f"http://127.0.0.1:{port}/v1", m)
            rendered[m] = v = dict(render_check(port, b, records, pc), compared_with=pc_from)
            print(f"{m}: {v['same']} of {v['same'] + v['differ']} prompts byte for byte as in training"
                  + (f" (DIFFERENT, first: {v['first_difference']['meta']}; do not use this model)"
                     if v["differ"] else ""), flush=True)

        def unload(m: str) -> None:
            if not args.keep_loaded and full(m) not in loaded_before:
                try:
                    ollama(port, "/api/generate", {"model": m, "keep_alive": 0}, timeout=60)
                    print(f"   unloaded {m} (it stays registered)", flush=True)
                except Exception as e:
                    print(f"   could not unload {m}: {e!r}", flush=True)

        if args.check_only:
            for m in args.model:
                prompts_on_node(m)
                unload(m)
            return 1 if any(v["differ"] for v in rendered.values()) else 0
        health = [] if args.no_tunnel else [dict(look(args.node), t=time.time(), at=0)]
        for model in args.model:
            b = Backend(args.node, f"http://127.0.0.1:{port}/v1", model,
                        timeout=CFG["answer_deadline_s"])
            arch = (shown[model].get("model_info") or {}).get("general.architecture", "")
            pc, expect_from = pc_prompts(ROOT / args.expect_dir, arch, ROOT / args.data)
            # Loading a model takes about 30 s: not part of any answer's time.
            print(f"== {model}: loading", flush=True)
            b.chat([{"role": "user", "content": "ok"}], max_tokens=1, timeout=180)
            prompts_on_node(model)
            answers = []
            for k, r in enumerate(records, 1):
                msgs = r["messages"]
                try:
                    text, meta = b.stream(msgs[:-1], time.monotonic() + CFG["answer_deadline_s"],
                                          CFG["first_token_s"], CFG["connect_s"], CFG["stall_s"])
                except Thinking as e:
                    print(f"STOP: record {k}: the model thinks ({e}); fix its template", flush=True)
                    break
                except Exception as e:                  # the node failed: keep what we have
                    print(f"STOP: record {k} failed on the node: {e!r}", flush=True)
                    break
                got, want = clean(text, msgs[1]["content"]), msgs[-1]["content"].strip("\n")
                answers.append({"meta": r["meta"], "command": msgs[1]["content"], "want": want,
                                "got": got, "raw": text, "exact": got == want, **meta,
                                "pc_prompt_tokens": (pc.get(key(r["meta"])) or {}).get("tokens")})
                if k % 10 == 0 or k == len(records):
                    ok = sum(a["exact"] for a in answers)
                    print(f"  {k}/{len(records)}  exact so far {ok}", flush=True)
                if not args.no_tunnel and k % args.check_every == 0:
                    h = look(args.node)
                    health.append(dict(h, t=time.time(), at=k))
                    if not h or h.get("avail", 1e9) < args.stop_below_mb or \
                            h.get("hot", 0) > args.stop_above_c:
                        print(f"STOP: the node {'does not answer' if not h else h}", flush=True)
                        break
                if k < len(records):
                    time.sleep(args.pause)
            if not answers:                     # stopped at the first record
                unload(model)
                break
            done = records[:len(answers)]
            read = [a["prompt_tokens"] / (a["first_token_ms"] / 1000) for a in answers
                    if a.get("prompt_tokens") and a.get("first_token_ms")]
            write = [(a["completion_tokens"] - 1) / ((a["total_ms"] - a["first_token_ms"]) / 1000)
                     for a in answers if (a.get("completion_tokens") or 0) > 1 and a.get("first_token_ms")
                     and a["total_ms"] > a["first_token_ms"]]
            timing = {"answers": len(answers),
                      "reading_tokens_per_s": round(statistics.median(read), 1) if read else None,
                      "writing_tokens_per_s": round(statistics.median(write), 1) if write else None,
                      "first_token_ms_median": statistics.median(a["first_token_ms"] for a in answers
                                                                 if a.get("first_token_ms")) if read else None,
                      "total_ms_median": statistics.median(a["total_ms"] for a in answers),
                      "cut_at_deadline": sum(a["finish_reason"] == "deadline" for a in answers)}
            both = [a for a in answers if a["pc_prompt_tokens"] and a.get("prompt_tokens")]
            prompts = {"compared_with": expect_from, "compared": len(both),
                       "differ": sum(a["prompt_tokens"] != a["pc_prompt_tokens"] for a in both),
                       "rendered": rendered.get(model)}
            report = score(done, answers)
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", model)
            out = pathlib.Path(args.out_dir) / f"res_nodemodel_{safe}_{args.node}_{stamp}.json"
            out.write_text(json.dumps({"model": model, "adapter": None, "node": args.node,
                                       "data": args.data, "pause_s": args.pause, "timing": timing,
                                       "prompts": prompts, "template": shown[model].get("template"),
                                       "report": report, "health": health, "answers": answers},
                                      indent=1, ensure_ascii=False) + "\n")
            written.append(out)
            print(f"== {model}: {report['all']['exact']}/{report['all']['records']} exact; reading "
                  f"{timing['reading_tokens_per_s']} tokens/s, writing {timing['writing_tokens_per_s']} "
                  f"tokens/s (medians); {out.name}", flush=True)
            if prompts["compared"]:
                print(f"   prompt lengths in tokens: {prompts['compared'] - prompts['differ']} of "
                      f"{prompts['compared']} the same as on the PC"
                      + (" (DIFFERENT: the node is not given the training prompt; do not use this model)"
                         if prompts["differ"] else ""), flush=True)
            else:
                print("   prompt lengths: not compared (no PC report with them)", flush=True)
            unload(model)
            if len(answers) < len(records):
                break
            if model != args.model[-1]:
                time.sleep(args.pause)
    finally:
        if tunnel is not None:
            tunnel.terminate()
            tunnel.wait(timeout=10)
    if len(written) > 1:
        print("\nside by side:", flush=True)
        subprocess.run([sys.executable, str(ROOT / "tools" / "finetune" / "compare_evals.py"),
                        *map(str, written)])
    return 0


if __name__ == "__main__":
    sys.exit(main())
