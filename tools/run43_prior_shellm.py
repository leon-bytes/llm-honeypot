#!/usr/bin/env python3
"""run43_prior_shellm.py - the 43 test commands through a prior system's method: shelLM
(stratosphereips/shelLM, `shelLMv2/`, the code behind arXiv 2608.18686), on our model node.

Asked for on 20 Oct 2026: a comparison with a recent system run on our own setup.
This reproduces shelLM v2's request exactly as its `LinuxSSHbot.py` + `OllamaClient` send
it, without running their code (their repository is untrusted; only its personality file
is read, with yaml.safe_load):

- fresh session per command (their Table 5 mode): messages = [system: the personality's
  `prompt`], the model's opening message (generated once per personality, as the start of
  every session), then [user: the command];
- POST {node}/api/chat with model, messages and stream=false, as their client; ollama's
  defaults otherwise. One addition: num_predict 1024, our relay's own cap, so that no
  answer can run for minutes on a board (their client has a 300 s timeout instead);
- the answer as their terminal shows it: cut at `<|end|>`, stripped; then, for grading,
  the trailing prompt line their prompt asks for ("user@host:~$") is removed.

The output has the run-file shape eval_scorer.py reads (`real`, `model`, `elapsed_ms`).
Paced (`--pause`, 15 s default; never less than 8: docs/jetson-stability.md).

  python3 tools/run43_prior_shellm.py --repo offline/prior/shelLM-src \\
      --personality Muris_v3 --node lab-j4 --model qwen2.5:3b-instruct-q4_K_M \\
      --label shellm-muris_v3 --out res_prior_shellm-muris_v3_2026-10-21.json

--examples (a fairness check): the prior system also gets the information about the machine
our model gets, and nothing more. For each command, the corpus examples our relay shows its
model for that command in model_only mode are appended to shelLM's own system prompt (the
personality text, unchanged) under "Real output of this machine for similar commands:", in
the relay's order. They come from the relay itself, built in this process from
honeypot/config.json (hidden_examples withheld, class_show_withheld off, its address
substitutions applied) and read off the prompt it would send; not our SYSTEM prompt, not the
session's history. Needs the project's site.local.json and nothing from the lab. The relay
sets no num_ctx either (the nodes run OLLAMA_CONTEXT_LENGTH=8192), so none is sent here
unless --num-ctx is given. --dry-run builds the 43 prompts, saves them (--prompts-out) and
touches no network. tests/test_prior_shellm.py checks that no test answer is in them.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import re
import socket
import subprocess
import sys
import time
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROMPT_LINE = re.compile(r"^\S*@\S*:[^\n]*[$#]\s*$|^[$#]\s*$")


def personality(repo: pathlib.Path, name: str) -> str:
    data = yaml.safe_load((repo / "shelLMv2/LLM_Plugins/personalities" / f"{name}.yml")
                          .read_text(encoding="utf-8"))
    return str(data["personality"]["prompt"]).strip()           # as load_personality_text


def as_shown(text: str) -> str:
    """Their terminal text (strip_after_end_marker, strip), without the trailing prompt."""
    text = (text or "").split("<|end|>", 1)[0].strip()
    lines = text.split("\n")
    while lines and PROMPT_LINE.match(lines[-1].strip()):
        lines.pop()
    # a prompt glued to the end of the last output line ("... user@host:~$")
    if lines:
        lines[-1] = re.sub(r"\s*\S+@\S+:[^\s]*[$#]\s*$", "", lines[-1])
    return "\n".join(lines).rstrip("\n")


EXAMPLES_HEAD = "Real examples from this exact machine:\n\n"      # shell.Shell._messages
EXAMPLES_TITLE = "Real output of this machine for similar commands:"


def relay_examples(commands: list[str]) -> list[dict]:
    """For each command: the example block our relay shows its model in model_only mode,
    taken from the prompt the relay itself builds (Shell._messages), with the model pool
    replaced by one that records the prompt and answers nothing real."""
    import tempfile
    sys.path.insert(0, str(ROOT))
    from honeypot.relay import Relay
    from honeypot.site import SITE

    class Capture:
        backends = []

        def __init__(self):
            self.messages = None

        def complete(self, sid, messages, role="state"):
            self.messages = messages
            return "", {"backend": "capture"}

    out = []
    with tempfile.TemporaryDirectory() as tmp:
        cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
        cfg.update(state_dir=tmp + "/state", log=tmp + "/relay.jsonl")
        pool = Capture()
        relay = Relay(cfg, str(ROOT / "honeypot"), pool=pool)
        if relay.withheld_shown:
            sys.exit("config class_show_withheld is on: refusing to build prompts")
        try:
            for i, cmd in enumerate(commands):
                sid = f"ex-{i}"
                hp = {"event": "login", "mode": "model_only", "username": "root",
                      "src_ip": SITE.lab_jump, "src_port": 37144}
                relay.handle({"user": sid, "messages": [], "honeypot": hp})
                pool.messages = None
                relay.handle({"user": sid, "messages": [{"role": "user", "content": cmd}],
                              "honeypot": {"event": "command"}})
                relay.handle({"user": sid, "messages": [], "honeypot": {"event": "logout"}})
                block = ""
                if pool.messages and EXAMPLES_HEAD in pool.messages[0]["content"]:
                    block = pool.messages[0]["content"].split(EXAMPLES_HEAD, 1)[1]
                out.append({"block": block,
                            "n": [e["n"] for e in relay.knowledge.retrieve(cmd, relay.shell.k_examples)]
                            if block else []})
        finally:
            relay._log.close()
    return out


def with_examples(system: str, block: str) -> str:
    return f"{system}\n\n{EXAMPLES_TITLE}\n\n{block}" if block else system


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def chat(url: str, model: str, messages: list[dict], num_predict: int,
         num_ctx: int | None = None) -> tuple[str, dict]:
    options = {"num_predict": num_predict, **({"num_ctx": num_ctx} if num_ctx else {})}
    body = json.dumps({"model": model, "messages": messages, "stream": False,
                       "options": options}).encode()
    req = urllib.request.Request(url + "/api/chat", body, {"Content-Type": "application/json"})
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=300) as r:
        d = json.load(r)
    ms = (time.monotonic() - t0) * 1000
    return d["message"]["content"], {"elapsed_ms": round(ms), "done_reason": d.get("done_reason"),
                                     "prompt_tokens": d.get("prompt_eval_count"),
                                     "completion_tokens": d.get("eval_count")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True, type=pathlib.Path)
    ap.add_argument("--personality", required=True)
    ap.add_argument("--node", required=True, help="ssh alias of the model node")
    ap.add_argument("--model", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--pause", type=float, default=15.0)
    ap.add_argument("--num-predict", type=int, default=1024)
    ap.add_argument("--gt", type=pathlib.Path, default=ROOT / "gt43_lab_2026-09.json")
    ap.add_argument("--examples", action="store_true",
                    help="append our relay's model_only examples to the personality text")
    ap.add_argument("--num-ctx", type=int, default=None,
                    help="send options.num_ctx (the relay sends none; default: the node's)")
    ap.add_argument("--dry-run", action="store_true",
                    help="build the 43 prompts, save them to --prompts-out, no network")
    ap.add_argument("--prompts-out", type=pathlib.Path)
    a = ap.parse_args()
    if a.pause < 8:
        sys.exit("--pause below 8 s: the model nodes freeze without pauses")
    system = personality(a.repo, a.personality)
    gt = json.loads(a.gt.read_text())
    ex = (relay_examples([g["command"] for g in gt]) if a.examples
          else [{"block": "", "n": []} for _ in gt])
    systems = [with_examples(system, e["block"]) for e in ex]
    ex_meta = [{"n": g["n"], "examples": len(e["n"]), "corpus": e["n"], "chars": len(e["block"])}
               for g, e in zip(gt, ex)]
    if a.dry_run:
        prompts = [{"n": g["n"], "command": g["command"], "system": sy} for g, sy in zip(gt, systems)]
        if a.prompts_out:
            a.prompts_out.write_text(json.dumps(prompts, indent=1, ensure_ascii=False))
        big = max(len(sy) for sy in systems)
        print(f"{len(prompts)} prompts, largest {big} chars (~{round(big / 3.5)} tokens)")
        return 0
    port = free_port()
    tunnel = subprocess.Popen(["ssh", "-N", "-o", "ExitOnForwardFailure=yes",
                               "-L", f"127.0.0.1:{port}:127.0.0.1:11434", a.node])
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(url + "/api/tags", timeout=2).read()
                break
            except OSError:
                time.sleep(0.2)
        commit = subprocess.run(["git", "-C", str(a.repo), "rev-parse", "HEAD"],
                                capture_output=True, text=True).stdout.strip()
        opening, meta0 = chat(url, a.model, [{"role": "system", "content": system}], a.num_predict,
                            a.num_ctx)
        opening = opening.split("<|end|>", 1)[0].strip()
        print(f"opening ({meta0['elapsed_ms']} ms): {opening[-120:]!r}", flush=True)
        rows = []
        for g, sy in zip(gt, systems):
            time.sleep(a.pause)
            msgs = [{"role": "system", "content": sy},
                    {"role": "assistant", "content": opening},
                    {"role": "user", "content": g["command"]}]
            try:
                raw, meta = chat(url, a.model, msgs, a.num_predict, a.num_ctx)
            except Exception as e:                       # recorded, not hidden
                raw, meta = "", {"elapsed_ms": None, "error": str(e)}
            rows.append({"n": g["n"], "command": g["command"], "real": g["output"],
                         "model": as_shown(raw), "raw": raw, "tier": "model",
                         "elapsed_ms": meta["elapsed_ms"], "real_exit_code": g.get("exit_code"),
                         "real_elapsed_ms": g.get("elapsed_ms"), "answer_mode": "prior-shellm",
                         "build": a.label, **{k: v for k, v in meta.items() if k != "elapsed_ms"}})
            print(f"{g['n']:>2} {meta['elapsed_ms']} ms {meta.get('done_reason')} "
                  f"{g['command'][:40]}", flush=True)
            a.out.write_text(json.dumps(rows, indent=1, ensure_ascii=False))
        a.out.write_text(json.dumps(rows, indent=1, ensure_ascii=False))
        (a.out.with_suffix(".meta.json")).write_text(json.dumps({
            "system": "shelLM v2", "repo_commit": commit, "personality": a.personality,
            "model": a.model, "node": a.node, "opening": opening, "opening_meta": meta0,
            "num_predict": a.num_predict, "num_ctx": a.num_ctx, "pause_s": a.pause,
            "examples_used": a.examples, "examples_per_command": ex_meta,
            "mode": "fresh session per command (their Table 5 mode)"}, indent=1))
    finally:
        tunnel.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
