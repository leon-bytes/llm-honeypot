#!/usr/bin/env python3
"""Does a change of the relay's code change any answer? Every answer two versions of the
relay give, compared byte for byte.

  python3 tools/answers_identical.py COMMIT            # COMMIT's relay against this checkout's
  python3 tools/answers_identical.py COMMIT --tree DIR # ... against another checkout's

Written for the publication refactor of 2026-10-16 (decision log P6), which had to change
no answer; useful for any refactor. Each version runs in its own process, in process (no
network), with the clock frozen, the randomness seeded and a stand-in model that records
the exact messages it is sent. Compared:
- the 43, the 284 corpus commands and the 15 docker shell commands, one fresh login
  each, in each answer mode (normal, model_only, scope_off): output, exit code, cwd,
  prompt, source, and the model's messages when it was asked;
- the bash oracle's lines and the docker client fixture's base-scenario lines (normal);
- the 43 in one session; the login text;
- every recorded Docker API request (phase 1, phase 2 in order, phase 3): status,
  headers, body, and the model's messages for the ones that reach it;
- the model's standing instructions and the relay's config as parsed (comment fields
  aside).
Needs the team-only recordings and site.local.json (both versions are run on its values).
Exit 0: identical; 1: something differs (the first few are named); 2: cannot run.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def compare(a_path, b_path) -> int:
    a = [json.loads(l) for l in open(a_path)]
    b = [json.loads(l) for l in open(b_path)]
    if len(a) != len(b):
        print(f"different number of records: {len(a)} against {len(b)}")
        return 1
    diffs, kinds = [], {}
    for x, y in zip(a, b):
        k = x["kind"] + ("/" + x.get("mode", "") if x["kind"] == "session" else "")
        if x["kind"] == "config":
            x = {kk: v for kk, v in x["cfg"].items() if not kk.startswith("_")}
            y = {kk: v for kk, v in y["cfg"].items() if not kk.startswith("_")}
        same = x == y
        kinds.setdefault(k, [0, 0])[0 if same else 1] += 1
        if not same:
            diffs.append(x.get("tag", k) if isinstance(x, dict) else k)
    steps = sum(len(r["steps"]) - 1 for r in a if r["kind"] == "session")
    prompts = sum(len(s["model"]) for r in a if r["kind"] == "session" for s in r["steps"][1:]) \
        + sum(len(r["model"]) for r in a if r["kind"] == "api")
    print(f"records: {len(a)}, identical {len(a) - len(diffs)}, different {len(diffs)}")
    for k, (s, d) in sorted(kinds.items()):
        print(f"  {k:22s} same {s:5d}  different {d}")
    print(f"command answers: {steps}; model prompts: {prompts}")
    for t in diffs[:10]:
        print("  DIFFERENT:", t)
    return 1 if diffs else 0


def main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "--dump":
        return 0                                     # handled at import below
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    commit = sys.argv[1]
    tree = pathlib.Path(sys.argv[sys.argv.index("--tree") + 1]) if "--tree" in sys.argv else ROOT
    if not (ROOT / "site.local.json").exists() or not (ROOT / "gt43_lab_2026-09.json").exists():
        print("needs site.local.json and the recordings at the project root")
        return 2
    env = dict(os.environ, HONEYPOT_SITE=str(ROOT / "site.local.json"), DATA=str(ROOT))
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp) / "base"
        base.mkdir()
        arch = subprocess.run(["git", "archive", commit, "honeypot"], cwd=ROOT, check=True,
                              capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(base)], input=arch, check=True)
        outs = []
        for name, t in (("base", base), ("tree", tree)):
            out = pathlib.Path(tmp) / f"{name}.jsonl"
            p = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve()), "--dump", str(t), str(out)], env=env,
                               capture_output=True, text=True)
            if p.returncode:
                print(f"the relay of {name} could not be run:\n{p.stderr[-2000:]}")
                return 2
            outs.append(out)
        print(f"{commit} against {tree}:")
        return compare(*outs)


if len(sys.argv) < 4 or sys.argv[1] != "--dump":
    sys.exit(main())

# ---------------------------------------------------------------- --dump TREE OUT
TREE = pathlib.Path(sys.argv[2]).resolve()
OUT = sys.argv[3]
DATA = pathlib.Path(os.environ.get("DATA", str(ROOT)))
T0 = 1792130400.0            # 2026-10-16 01:00 EDT
# the client's address, the same for both versions (the jump host's, as the measurements use)
SRC = json.load(open(os.environ["HONEYPOT_SITE"]))["lab_jump"]
BOOT = 1792100000.0

import datetime as _dt
import hashlib
import http.client
import random
import shlex
import time

# ---- frozen clock and seeded randomness, before anything of the tree is imported
_real_time = time.time
time.time = lambda: T0
time.time_ns = lambda: int(T0 * 1e9)
_lt, _gm, _sf = time.localtime, time.gmtime, time.strftime
time.localtime = lambda s=None: _lt(T0 if s is None else s)
time.gmtime = lambda s=None: _gm(T0 if s is None else s)
time.strftime = lambda f, t=None: _sf(f, _lt(T0) if t is None else t)


class FrozenDT(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return _dt.datetime.fromtimestamp(T0, tz) if tz else _dt.datetime.fromtimestamp(T0)

    @classmethod
    def utcnow(cls):
        return _dt.datetime.utcfromtimestamp(T0)

    @classmethod
    def today(cls):
        return _dt.datetime.fromtimestamp(T0)


_dt.datetime = FrozenDT
_rng = random.Random(7)
os.urandom = lambda n: bytes(_rng.getrandbits(8) for _ in range(n))
random.seed(1234)

os.chdir(TREE)
sys.path.insert(0, str(TREE))
from honeypot import machine                       # noqa: E402
machine.boot_time = lambda: BOOT
from honeypot.relay import Relay                   # noqa: E402
from honeypot import shell as shell_mod           # noqa: E402
from honeypot.dockerapi import serve               # noqa: E402

try:
    from honeypot.site import SITE                 # noqa: E402  (the new tree only)
    load_cfg = SITE.load_json
except ImportError:
    def load_cfg(p):
        return json.load(open(p))


class StandIn:
    backends = []

    def __init__(self):
        self.calls = []

    def complete(self, sid, messages, role="state"):
        self.calls.append({"role": role, "messages": messages})
        h = hashlib.sha256(json.dumps(messages, sort_keys=True).encode()).hexdigest()[:12]
        return f"model answer {h}", {"backend": "stand-in"}


out = open(OUT, "w")


def emit(**kw):
    out.write(json.dumps(kw, ensure_ascii=False, sort_keys=True) + "\n")


cfg = load_cfg(TREE / "honeypot" / "config.json")
emit(kind="config", cfg=cfg)
emit(kind="system", text=shell_mod.SYSTEM if hasattr(shell_mod, "SYSTEM") else None)
tmp = tempfile.TemporaryDirectory()
cfg["state_dir"], cfg["log"] = tmp.name + "/s", tmp.name + "/l/r.jsonl"
cfg["corpus"] = str(DATA / "corpus284_lab_2026-09.json")
cfg["not_gradable"] = str(DATA / "eval_not_gradable.json")
pool = StandIn()
relay = Relay(cfg, str(TREE / "honeypot"), pool=pool)
VOLATILE = ("elapsed_ms",)


def run(sid, mode, lines, tag):
    pool.calls.clear()
    st, r = relay.handle({"user": sid, "messages": [{"role": "user", "content": ""}],
                          "honeypot": {"event": "login", "username": "root",
                                       "src_ip": SRC, "src_port": 40000,
                                       "mode": mode}})
    res = [{"login": r["choices"][0]["message"]["content"],
            "hp": {k: v for k, v in r["honeypot"].items() if k not in VOLATILE}}]
    for line in lines:
        pool.calls.clear()
        st, r = relay.handle({"user": sid, "messages": [{"role": "user", "content": line}],
                              "honeypot": {"event": "command"}})
        res.append({"line": line, "status": st,
                    "out": r["choices"][0]["message"]["content"] if st == 200 else r,
                    "hp": {k: v for k, v in r.get("honeypot", {}).items() if k not in VOLATILE},
                    "model": list(pool.calls)})
    relay.handle({"user": sid, "messages": [{"role": "user", "content": ""}],
                  "honeypot": {"event": "logout"}})
    emit(kind="session", tag=tag, mode=mode, steps=res)


rec = {name: json.load(open(DATA / name)) for name in
       ("gt43_lab_2026-09.json", "corpus284_lab_2026-09.json", "gt_docker_shell_2026-09.json")}
for mode in ("normal", "model_only", "scope_off"):
    for name, entries in rec.items():
        for i, e in enumerate(entries):
            run(f"{mode}-{name}-{i}", mode, [e["command"]], f"{name}#{e.get('n', i)}")
oracle = json.load(open(DATA / "tests/fixtures/bash_oracle.json"))["cases"]
for i, c in enumerate(oracle):
    run(f"oracle-{i}", "normal", [c["line"]], f"bash_oracle#{i}")
cli = json.load(open(DATA / "tests/fixtures/docker_cli.json"))["cases"]
for i, c in enumerate(x for x in cli if x["scenario"] == "base"):
    run(f"cli-{i}", "normal", ["docker " + " ".join(shlex.quote(a) for a in c["argv"])],
        f"docker_cli#{i}")
# one longer session: what the recorded attacker did, in order
run("attack", "normal", [e["command"] for e in rec["gt43_lab_2026-09.json"]], "the43-one-session")

# ---- the fake API over HTTP
log = []
srv = serve(relay.docker_api, "127.0.0.1", 0, log.append)
import threading                                   # noqa: E402
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]


def req(method, path, body):
    pool.calls.clear()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    data = body.encode() if isinstance(body, str) else (json.dumps(body).encode() if body is not None else None)
    conn.request(method, path, body=data, headers=headers)
    r = conn.getresponse()
    b = r.read()
    conn.close()
    return {"status": r.status, "headers": [(k, v) for k, v in r.getheaders()],
            "body_sha": hashlib.sha256(b).hexdigest(), "body": b.decode("latin-1"),
            "model": list(pool.calls)}


for name in ("gt_api_phase1_2026-09.json", "gt_api_phase2_2026-09.json", "gt_api_phase3_2026-10.json"):
    for e in json.load(open(DATA / name)):
        emit(kind="api", tag=f"{name}#{e['n']}", method=e["method"], path=e["path"],
             **req(e["method"], e["path"], e.get("request_body")))
srv.shutdown()
out.close()
