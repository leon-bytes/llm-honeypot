#!/usr/bin/env python3
"""
relay_client.py - talk to the relay the way Cowrie will, for testing without Cowrie.

Interactive: a pretend SSH session. Prints the login banner and the prompt, sends
each line you type, prints the answer. Ctrl-D or `exit` ends it.

  python3 tools/relay_client.py --url http://127.0.0.1:18000

Batch: runs the 43 test commands the way they were captured on Ground Truth - one
fresh login per command - and writes the answers in the same shape as
gt43_lab_2026-09.json (n, command, output, exit_code, elapsed_ms) plus the relay's
`source`. Then removes the files the 43 create, as the capture did.

  python3 tools/relay_client.py --url http://127.0.0.1:18000 \
      --run gt43_lab_2026-09.json --out res_relay_43.json

--mode model_only asks the relay to let the model answer every line (the paper's
code-vs-model comparison); --mode normal forces the usual tiers. Without --mode the
relay's own config decides. tools/run43_for_scorer.py writes the scorer's format.

The exact-match count it prints is a sanity check, not a score: it ignores
eval_not_gradable.json. Scoring is the scorer's job.
"""
from __future__ import annotations
import argparse
import json
import statistics
import sys
import time
import pathlib
import urllib.request
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

TIDY = "rm -rf /root/junk.txt /root/junk /root/junkdir"


class Client:
    def __init__(self, url: str, src_ip: str, username: str = "root",
                 mode: str | None = None):
        self.url = url.rstrip("/") + "/v1/chat/completions"
        self.src_ip, self.username = src_ip, username
        self.mode = mode            # honeypot.mode; None leaves it to the relay's config
        self.cols = self.rows = None  # the terminal's size at login; None sends none

    def send(self, sid: str, content: str = "", event: str = "command",
             hide_examples=None) -> tuple[str, dict, int]:
        body = {"model": "raspberrypi-shell", "user": sid,
                "messages": [{"role": "user", "content": content}],
                "honeypot": {"event": event, "username": self.username,
                             "src_ip": self.src_ip, "src_port": 40000 + hash(sid) % 20000,
                             "dst_ip": SITE.hp_ipv4, "dst_port": 22}}
        if self.mode:
            body["honeypot"]["mode"] = self.mode
        if event == "login" and self.cols:
            body["honeypot"].update(cols=self.cols, rows=self.rows or 24)
        if hide_examples is not None:
            body["honeypot"]["hide_examples"] = sorted(hide_examples)
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        t0 = time.monotonic()
        with urllib.request.urlopen(req, timeout=90) as r:
            resp = json.load(r)
        ms = round((time.monotonic() - t0) * 1000)
        return resp["choices"][0]["message"]["content"], resp["honeypot"], ms


def require_mode(url: str, mode: str) -> None:
    """Stop unless the relay at `url` knows the answer mode `mode` (its /health lists
    them since 2026-10-15). An older relay would take an unknown mode as normal, and the
    run would be labelled as what it is not."""
    if mode == "normal":
        return
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/health", timeout=15) as r:
            modes = json.load(r).get("modes")
    except Exception as e:                      # noqa: BLE001 - say what failed, then stop
        raise SystemExit(f"cannot read {url.rstrip('/')}/health ({e}); not measured")
    if modes is None and mode == "model_only":
        return                                  # every relay before the list knew this one
    if mode not in (modes or []):
        raise SystemExit(f"the relay at {url} does not know answer mode {mode!r} (it knows "
                         f"{modes or 'normal and model_only'}); deploy the build first; not measured")


def refuse_class_build(url: str) -> None:
    """Stop unless the relay at `url` withholds the corpus entries that overlap test answers.
    Every measurement for the paper is taken with them withheld; the class build shows them
    (config `class_show_withheld`, 2026-10-15) and must never be measured as if it were the
    paper's build. A relay older than that switch has no such field and always withholds."""
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/health", timeout=15) as r:
            health = json.load(r)
    except Exception as e:                      # noqa: BLE001 - say what failed, then stop
        raise SystemExit(f"cannot read {url.rstrip('/')}/health ({e}); not measured")
    if health.get("withheld_shown"):
        raise SystemExit("this relay is the class build (class_show_withheld: the withheld corpus "
                         "examples are shown to the model); it is not measured for the paper")


def interactive(c: Client) -> None:
    sid = f"cli-{uuid.uuid4().hex[:8]}"
    text, ext, _ = c.send(sid, event="login")
    sys.stdout.write(text + ext["prompt"])
    sys.stdout.flush()
    while True:
        try:
            line = input()
        except EOFError:
            c.send(sid, event="logout")
            print()
            return
        text, ext, ms = c.send(sid, line)
        sys.stdout.write(text)
        if ext["close_session"]:
            return
        sys.stdout.write(f"\x1b[2m[{ext['source']} {ms} ms, exit {ext['exit_code']}]\x1b[0m\n"
                         + ext["prompt"])
        sys.stdout.flush()


def run_batch(c: Client, path: str, out: str) -> None:
    tests = json.load(open(path))
    results, exact = [], 0
    for t in tests:
        sid = f"run-{uuid.uuid4().hex[:8]}"
        c.send(sid, event="login")
        text, ext, ms = c.send(sid, t["command"])
        c.send(sid, event="logout")
        output = text.removesuffix("\n")
        same = output == t["output"] and ext["exit_code"] == t["exit_code"]
        exact += same
        results.append({"n": t["n"], "command": t["command"], "output": output,
                        "exit_code": ext["exit_code"], "elapsed_ms": ms,
                        "source": ext["source"], "exact": same})
        print(f"#{t['n']:<3} {ext['source']:<8} {ms:>6} ms  {'SAME' if same else '    '}  "
              f"{t['command'][:60]}")
    sid = f"run-{uuid.uuid4().hex[:8]}"
    c.send(sid, event="login")
    c.send(sid, TIDY)
    c.send(sid, event="logout")
    with open(out, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    by_src: dict[str, list[int]] = {}
    for r in results:
        by_src.setdefault(r["source"], []).append(r["elapsed_ms"])
    print(f"\n{exact}/{len(results)} byte-identical to Ground Truth (not a score; see --help)")
    for src, ms in sorted(by_src.items()):
        ms.sort()
        print(f"  {src:<8} {len(ms):>2} answers  median {statistics.median(ms):>6.0f} ms  "
              f"max {ms[-1]:>6} ms")
    print(f"saved to {out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--src-ip", default=SITE.lab_jump,
                    help="the attacker address the relay is told about")
    ap.add_argument("--run", metavar="FILE", help="batch-run the commands in FILE")
    ap.add_argument("--out", default="res_relay_43.json")
    ap.add_argument("--mode", choices=["normal", "model_only"],
                    help="answer mode for these sessions (default: the relay's config)")
    args = ap.parse_args()
    c = Client(args.url, args.src_ip, mode=args.mode)
    if args.run:
        run_batch(c, args.run, args.out)
    else:
        interactive(c)


if __name__ == "__main__":
    main()
