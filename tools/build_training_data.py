#!/usr/bin/env python3
"""Build the fine-tuning data for Jetson 1 (role `state`), from three sources.

  corpus   Ground Truth's recorded answers (corpus284_lab_2026-09.json), each in several
           contexts.
  debian   Exact error, usage, version and short help texts of Debian 13 arm64, recorded
           in a container whose package versions equal Ground Truth's
           (tools/capture_debian_texts.py, offline/debian13-arm64/texts.json). Nothing
           here comes from Ground Truth.
  code     Answers the relay's own code computes (cd, echo, date, uptime, free, df, ps,
           ss, ip, docker ps, ...), in generated sessions with their own state, clock and
           boot. Recorded the way the model-only switch works: the code runs, the prompt
           the model would get is kept, and the code's answer is the target.

Rules (decided 2026-10-02, TASKS.md), the same for every source:
  - Nothing from the 43: no example whose command is one of the 43 test commands
    (normalised), and none whose output shares 3 or more consecutive lines with any of the
    43's answers (this also removes the corpus pieces of /etc/passwd and /etc/os-release,
    n=262-264). In a generated session such a command is never run, and an answer that
    shares lines with a test answer is also taken out of what later prompts show.
  - Patterns, not answers: every example stands in its own context (time, boot, session,
    recent commands), built by a real relay with the relay's own prompt code, so training
    and inference see the same prompt. An example's own recording is never among its
    retrieved examples; each record gets its own per-boot values and install date (R3).
  - No stale values: recordings whose answer depends on the time, the boot or the
    session (knowledge.py's dynamic rules, eval_not_gradable.json) are left out; those
    come from the `code` source instead, with live values.
  - Addresses are the Orchestrator's (R1), as in every relay answer. Zone labels follow
    the zone rules: contexts fall on both sides of 2026-11-01.
  - Retrieved examples come from the corpus only, for every source, as at inference
    (the relay holds only the corpus). Three kinds of recording are never shown: the
    held-back ones, those that fall under the first rule, and any recording of the very
    command being answered. The last keeps the model from learning "copy the example of
    the same command", which no test command ever has.
  - A held-back 10% of each source (val.jsonl) chooses checkpoints and decides the
    go/no-go; the 43 are scored once, at the end.
  - A generated session never runs a held-back corpus or Debian command (2026-10-14):
    the code would answer it exactly as the held-back record does.
  - `--frozen-val DIR` (2026-10-14) keeps an earlier set's held-back records byte for
    byte, so the go/no-go stays comparable across data sets: its val.jsonl is copied, and
    no training record has a corpus example or a Debian command among them. (Generated
    code sessions are new sessions; their commands recur, as within one set.)

Docker commands in the corpus are left for Jetson 3's data (after the class).

Output (git-ignored, team-only data): offline/training/<date>/{train,val}.jsonl and
manifest.json with the counts per source and every exclusion with its reason.

Run: .venv/bin/python tools/build_training_data.py [--variants 6] [--debian-variants 1]
         [--code-sessions 90] [--frozen-val offline/training/20261013] [--out DIR]
"""
from __future__ import annotations
import argparse
import collections
import datetime as dt
import hashlib
import json
import pathlib
import random
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from honeypot import machine                                         # noqa: E402
from honeypot.knowledge import _DYNAMIC, _DYNAMIC_OUTPUT, _grams     # noqa: E402
from honeypot.relay import Relay                                     # noqa: E402
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

WINDOW = 3          # consecutive lines shared with a test answer that disqualify
DEBIAN_TEXTS = ROOT / "offline" / "debian13-arm64" / "texts.json"
MAX_TARGET_LINES = 120      # a longer answer is cut by the relay's deadline anyway


def norm_cmd(c: str) -> str:
    return re.sub(r"\s+", " ", c.replace("'", '"')).strip()


def windows(text: str) -> set:
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return {tuple(lines[i:i + WINDOW]) for i in range(len(lines) - WINDOW + 1)}


# ------------------------------------------------------------------ what may be used

def select(corpus, gt43, not_gradable) -> tuple[list, dict]:
    test_cmds = {norm_cmd(e["command"]) for e in gt43}
    test_windows = set().union(*(windows(e["output"]) for e in gt43))
    volatile = {int(n) for n in not_gradable.get("corpus_284", {})}
    keep, why = [], {}
    for e in corpus:
        n, cmd, out = e["n"], e["command"], e["output"]
        if norm_cmd(cmd) in test_cmds:
            why[n] = "command is one of the 43"
        elif windows(out) & test_windows:
            why[n] = f"shares {WINDOW}+ consecutive lines with a test answer"
        elif "[capture error]" in out:
            why[n] = "capture error"
        elif cmd.strip().split()[0] in ("docker", "docker-compose"):
            why[n] = "docker: Jetson 3's data"
        elif n in volatile or _DYNAMIC.search(cmd) or _DYNAMIC_OUTPUT.search(out):
            why[n] = "answer depends on time, boot or session"
        else:
            keep.append(e)
    return keep, why


def select_debian(texts, gt43, corpus) -> tuple[list, dict]:
    """The container's texts under the same rules, and none the corpus already has."""
    test_cmds = {norm_cmd(e["command"]) for e in gt43}
    test_windows = set().union(*(windows(e["output"]) for e in gt43))
    corpus_cmds = {norm_cmd(e["command"]) for e in corpus}
    keep, why = [], {}
    for e in texts:
        n, cmd, out = e["n"], e["command"], e["output"]
        if norm_cmd(cmd) in test_cmds:
            why[n] = "command is one of the 43"
        elif windows(out) & test_windows:
            why[n] = f"shares {WINDOW}+ consecutive lines with a test answer"
        elif norm_cmd(cmd) in corpus_cmds:
            why[n] = "the corpus has Ground Truth's own answer to this command"
        elif len(out.splitlines()) > MAX_TARGET_LINES:
            why[n] = f"more than {MAX_TARGET_LINES} lines"
        else:
            keep.append(e)
    return keep, why


def split(examples: list, frac: float = 0.10) -> tuple[list, list]:
    """Held back: chosen by a hash of the example's number (corpus) or of its command
    text (debian), so adding examples later does not reshuffle the rest."""
    def key(e):
        tag = e["n"] if isinstance(e["n"], int) else e["command"]
        return hashlib.sha256(f"val-{tag}".encode()).hexdigest()
    ranked = sorted(examples, key=key)
    k = max(1, round(len(ranked) * frac))
    val_ns = {e["n"] for e in ranked[:k]}
    return [e for e in examples if e["n"] not in val_ns], [e for e in examples if e["n"] in val_ns]


# ------------------------------------------------------------------ a relay in a context

class Recorder:
    """Stands in for the Jetsons: keeps the prompt the model would have been sent."""
    backends = []

    def __init__(self):
        self.messages = None

    def complete(self, sid, messages, role="state"):
        self.messages = messages
        return "", {"backend": "recorder"}


class Context:
    """A relay with its own state directory, boot time and clock: one install on one
    boot at one moment, as the deployed relay is. `shown` holds the numbers of the corpus
    recordings it may retrieve examples from."""

    def __init__(self, cfg: dict, rng: random.Random, tmp: str, tag: str, shown: set):
        # Between 1 October and 20 November 2026, so that the clocks change in between.
        day0 = dt.datetime(2026, 10, 1, tzinfo=machine.TZ).timestamp()
        self.boot = day0 + rng.uniform(0, 42 * 86400)
        self.t = self.boot + rng.uniform(300, 9 * 86400)
        machine.boot_time = lambda: self.boot
        machine.now = lambda: dt.datetime.fromtimestamp(self.t, machine.TZ)
        c = dict(cfg, state_dir=f"{tmp}/{tag}/state", log=f"{tmp}/{tag}/relay.jsonl")
        # This install's secret, from the seed: every ID it generates follows from it,
        # so the same seed builds the same data.
        state = pathlib.Path(c["state_dir"])
        state.mkdir(parents=True)
        (state / "install.json").write_text(
            json.dumps({"secret": f"train-{rng.getrandbits(128):032x}"}) + "\n")
        self.recorder = Recorder()
        self.relay = Relay(c, str(ROOT / "honeypot"), pool=self.recorder)
        self.entries = []
        self.relay.record = self.entries.append           # nothing is written to a log
        k = self.relay.knowledge
        self._examples = [x for x in k.examples if x["n"] in shown]
        self.subs = k.subs
        self.hide("")
        self.sid = f"train-{tag}"
        self.send("", "login", src_ip=f"10.77.10.{rng.choice([10, 57, 101, 133])}",
                  src_port=rng.randint(32768, 60999), mode="model_only")
        self.sess = self.relay.store.get(self.sid)

    def send(self, content: str, event: str = "command", **hp):
        status, resp = self.relay.handle({"user": self.sid,
                                          "messages": [{"role": "user", "content": content}],
                                          "honeypot": {"event": event, **hp}})
        assert status == 200, resp
        return resp

    def hide(self, command: str) -> None:
        """Leave out every recording of this very command (see the rules above)."""
        k = self.relay.knowledge
        k.examples = [x for x in self._examples if norm_cmd(x["command"]) != norm_cmd(command)]
        k._grams = [_grams(x["command"]) for x in k.examples]

    def close(self):
        self.relay._log.close()


def one(e: dict, v: int, pool: list, shown: set, cfg: dict, rng: random.Random, tmp: str,
        source: str = "corpus") -> dict:
    """One record for a recorded answer (corpus or debian): the relay's own prompt for
    this command in a fresh context, and the recording as the target. `pool` is the
    corpus's training part, which the session's recent commands are drawn from."""
    ctx = Context(cfg, rng, tmp, f"{source}-{e['n']}-{v}", shown)
    try:
        ctx.hide(e["command"])
        for p in rng.sample(pool, rng.randint(0, 6)):    # recent commands, as the relay keeps
            if p["n"] != e["n"]:
                ctx.sess.transcript.append((p["command"], ctx.subs(p["output"])))
        msgs = ctx.relay.shell._messages(ctx.sess, e["command"])
        target = ctx.subs(e["output"])
    finally:
        ctx.close()
    return {"messages": msgs + [{"role": "assistant", "content": target}],
            "meta": {"source": source, "n": e["n"], "variant": v, "exit_code": e["exit_code"]}}


# ------------------------------------------------------------------ the `code` source

_DIRS = ["/tmp", "/etc", "/var/log", "/root/iot-stack", "/home", "/usr/local/bin", "/opt",
         "/var/tmp", "/srv", "/etc/ssh", "/var", "/usr", "/boot", "/mnt"]
_NEW_DIRS = ["notes", "backup", "data", "work", "scripts", "logs", "old", "project", "dl"]
_FILES = ["notes.txt", "todo.txt", "a.log", "config.bak", "run.sh", "data.csv", "readme",
          "x.tmp", "list.txt", "out.txt"]
_VARS = [("EDITOR", "nano"), ("FOO", "bar"), ("APP_ENV", "prod"), ("N", "42"),
         ("GREETING", "hello"), ("TARGET", SITE.lab_gateway), ("WORKDIR", "/tmp/work")]
_WORDS = ["hello", "test", "ok", "done", "first line", "x", "backup started", "42"]


def _session_script(rng: random.Random) -> list[str]:
    """A plausible session of commands the relay answers in code. What a line needs
    (a file to read, a variable to print) is created earlier in the same session."""
    made_files, made_dirs, made_vars = [], [], []

    def nav():
        return rng.choice([f"cd {rng.choice(_DIRS)}", "cd ..", "cd", "cd ~", "pwd", "pwd",
                           f"cd {rng.choice(_DIRS)}"])

    def env():
        if made_vars and rng.random() < 0.5:
            k = rng.choice(made_vars)
            return rng.choice([f"echo ${k}", f"printenv {k}", f"unset {k}", f'echo "{k} is ${k}"'])
        if rng.random() < 0.4:
            k, val = rng.choice(_VARS)
            made_vars.append(k)
            return f"export {k}={val}"
        return rng.choice(["echo $USER", "echo $PWD", "echo $?", "echo $LANG", "echo $TERM",
                           "echo $LOGNAME", "echo $SSH_CLIENT", "echo $SSH_TTY",
                           "echo $SSH_CONNECTION", "echo $XDG_SESSION_ID", "echo $SHLVL",
                           f"echo {rng.choice(_WORDS)}", 'echo "$USER in $PWD"',
                           "env | grep SSH", "printenv | wc -l", "printenv LANG",
                           "printenv USER", "env | grep XDG", "env | wc -l", "echo $OLDPWD"])

    def clock():
        return rng.choice(["date", "date", "date -u", "date +%s", "date +%F", "date +%T",
                           'date "+%Y-%m-%d %H:%M:%S"', "date +%Z", "date +%z", "date -R",
                           "date +%A", "uptime", "uptime", "uptime -s", "uptime -p"])

    def who():
        return rng.choice(["who", "w", "users", "tty", "who am i", "history", "history | tail -3",
                           "history 5", "who -b", "w -h"])

    def files():
        r = rng.random()
        if made_files and r < 0.45:
            f = rng.choice(made_files)
            return rng.choice([f"cat {f}", f"more {f}", f"ls -l {f}", f"chmod 600 {f}",
                               f"rm {f}", f"cat {f} | wc -l"])
        if r < 0.65:
            f = rng.choice(_FILES)
            made_files.append(f)
            return rng.choice([f"touch {f}", f"echo {rng.choice(_WORDS)} > {f}"])
        if r < 0.8:
            d = rng.choice(_NEW_DIRS)
            made_dirs.append(d)
            return f"mkdir {d}"
        return rng.choice(["ls", "ls", f"ls {rng.choice(made_dirs)}" if made_dirs else "ls",
                           "ls -1", "ls | wc -l"])

    def system():
        return rng.choice(["free", "free -h", "free -m", "free -k", "df", "df /", "df -h /",
                           "df -T", "df -h /boot/firmware", "ps", "ps -ef | grep sshd",
                           "ps -ef | wc -l", "ps -e | tail -5", "ps -u root | head -5",
                           "pgrep sshd", "pgrep -l docker", "pidof dockerd", "pidof sshd",
                           "ps -p 1", "ps -ef | head -5", "ps -ef | grep docker",
                           "pgrep -c sshd", "ps -eo pid,comm | head -8", "free | grep Mem"])

    def network():
        return rng.choice(["ss -tln", "ss -tlnp", "ss -uln", "ss -tan", "ss -tl", "netstat -tln",
                           "netstat -rn", "netstat -i", "netstat -an | head -8", "ip a",
                           "ip -br a", "ip -br link", "ip addr show eth0", "ip -4 a",
                           "ip link show eth0", "hostname -I", "ip a | grep inet",
                           "ip -br a | grep UP", f"ping -c 1 {SITE.lab_gateway}", "ping -c 2 127.0.0.1",
                           "ip -6 a", "ip link", "ifconfig lo", "ifconfig docker0"])

    def docker():
        # The second line: the read-only commands answered in code since 2026-10-13.
        # (`docker stats` is left out: it waits two seconds, as the real one does.)
        return rng.choice(["docker ps", "docker ps -a", "docker images", "docker ps -q",
                           "docker logs --tail 5 iot-stack-mosquitto-1",
                           "docker logs --tail 3 iot-stack-nodered-1", "docker ps --no-trunc",
                           "docker images -q",
                           "docker network ls", "docker volume ls", "docker version",
                           "docker system df", "docker top iot-stack-nodered-1",
                           "docker compose ls", "docker info"])

    # What moved to code on 2026-10-14 (shell.SCOPE_DEFAULTS): with a category handed
    # back to the model, these are the model's to answer, consistent with the rest.
    def lookup():
        n = rng.choice(["ls", "cat", "grep", "docker", "python3", "curl", "nmap", "gcc", "cd",
                        "echo", "vim", "nano", "wget", "ssh", "systemctl", "ip", "if", "for"])
        return rng.choice([f"which {n}", f"type {n}", f"command -v {n}", f"command -V {n}",
                           f"type -t {n}", f"time {rng.choice(['true', 'ls', 'pwd', 'sleep 0'])}"])

    def compute():
        a, b = rng.randint(1, 999), rng.randint(1, 99)
        w = rng.choice(_WORDS)
        return rng.choice([f"echo $(({a}+{b}))", f"echo $(({a}*{b}))", f"echo $(({a}/{b}))",
                           f"echo $(({a}%{b}))", f"echo $((2**{b % 20}))", f"expr {a} + {b}",
                           f"expr {a} \\* {b}", f"seq {b % 7 + 1}", f"seq {a % 5} {a % 5 + 4}",
                           f"echo {w} | md5sum", f"echo {w} | sha256sum", f"echo -n {w} | base64",
                           f"echo {w} | wc -c", f"echo {w} | tr a-z A-Z", "yes | head -3",
                           f'printf "%s\\n" {w} | sha1sum', f"echo {w} | cat -n"])

    def kernel():
        return rng.choice(["cat /etc/hostname", "cat /proc/loadavg", "cat /proc/sys/kernel/osrelease",
                           "cat /proc/sys/kernel/hostname", "cat /proc/swaps", "cat /proc/meminfo",
                           "cat /sys/class/net/eth0/address", "cat /sys/class/net/eth0/mtu",
                           "cat /sys/class/net/eth0/operstate", "cat /sys/devices/system/cpu/online",
                           "getconf _NPROCESSORS_ONLN", "dpkg --print-architecture",
                           "head -3 /proc/meminfo", "grep MemTotal /proc/meminfo", "cat /proc/1/comm"])

    def bashstate():
        return rng.choice(["umask", "alias", "stty size", "locale", "declare -p HOME",
                           "test -d /tmp && echo yes", "[ -f /etc/hostname ] && echo found",
                           "[ -e /nonexistent ] || echo missing", "/tmp", "/usr/bin/nosuch",
                           f"echo $(whoami)", "echo $(hostname)", "sudo whoami", "sudo id -u"])

    def owned():
        if made_files and rng.random() < 0.6:
            f = rng.choice(made_files)
            return rng.choice([f"ls -l {f}", f"cp {f} {f}.bak", f"mv {f} {f}.old", f"chmod 755 {f}",
                               f"head -1 {f}", f"grep {rng.choice(_WORDS).split()[0]} {f}",
                               f"tail -2 {f}", f"wc -l {f}"])
        d = rng.choice(_NEW_DIRS)
        return rng.choice([f"mkdir -p {d}/sub", f"rmdir {d}", f"ls -ld {d}" if made_dirs else "ls -ld /tmp"])

    kinds = [nav, env, clock, who, files, system, network, docker,
             lookup, compute, kernel, bashstate, owned]
    weights = [16, 20, 10, 8, 18, 12, 11, 5, 6, 8, 6, 6, 8]
    return [rng.choices(kinds, weights)[0]() for _ in range(rng.randint(8, 14))]


def code_sessions(count: int, shown: set, cfg: dict, rng: random.Random, tmp: str,
                  gt43: list, held: set = frozenset()) -> tuple[list, dict]:
    """Records from generated sessions, each a list in session order, and a tally of
    what happened to every line."""
    test_cmds = {norm_cmd(e["command"]) for e in gt43}
    test_windows = set().union(*(windows(e["output"]) for e in gt43))
    sessions, tally = [], collections.Counter()
    for s in range(count):
        ctx = Context(cfg, rng, tmp, f"code-{s}", shown)
        records = []
        try:
            for i, line in enumerate(_session_script(rng)):
                if norm_cmd(line) in test_cmds:
                    tally["never run: one of the 43"] += 1
                    continue
                if norm_cmd(line) in held:
                    # its answer would be the held-back record's answer to learn
                    tally["never run: a held-back corpus or Debian command"] += 1
                    continue
                ctx.t += rng.uniform(2, 45)                  # the attacker types and reads
                ctx.recorder.messages, ctx.entries[:] = None, []
                ctx.hide(line)
                ctx.send(line)
                meta = (ctx.entries[-1].get("meta") or {}) if ctx.entries else {}
                code = meta.get("code_answer")
                if not code or code["source"] != "builtin" or ctx.recorder.messages is None:
                    ctx.sess.transcript.pop()                # the model's turn, not code's
                    tally["not answered in code"] += 1
                    continue
                out = code["output"]
                if windows(out) & test_windows:
                    ctx.sess.transcript.pop()                # nor in any later prompt
                    tally[f"shares {WINDOW}+ consecutive lines with a test answer"] += 1
                    continue
                # What later prompts of this session show for this line: the code's
                # answer, as in normal mode (the stand-in model said nothing).
                ctx.sess.transcript[-1] = (line, out)
                if len(out.splitlines()) > MAX_TARGET_LINES:
                    tally[f"more than {MAX_TARGET_LINES} lines"] += 1
                    continue
                tally["kept"] += 1
                records.append({
                    "messages": ctx.recorder.messages + [{"role": "assistant", "content": out}],
                    "meta": {"source": "code", "n": f"c{s}.{i}", "session": s,
                             "exit_code": code["exit_code"]}})
        finally:
            ctx.close()
        sessions.append(records)
    return sessions, dict(tally)


# ------------------------------------------------------------------ build

def frozen(val_dir: pathlib.Path) -> tuple[list, set, set]:
    """An earlier set's held-back records as they are, the corpus numbers and the Debian
    commands in them."""
    lines = (val_dir / "val.jsonl").read_text(encoding="utf-8").splitlines()
    recs = [json.loads(l) for l in lines if l.strip()]
    corpus_ns = {r["meta"]["n"] for r in recs if r["meta"]["source"] == "corpus"}
    debian_cmds = {norm_cmd(r["messages"][-2]["content"]) for r in recs
                   if r["meta"]["source"] == "debian"}
    return recs, corpus_ns, debian_cmds


def build(variants: int, out_dir: pathlib.Path, seed: int = 20261008,
          debian_variants: int = 1, code_session_count: int = 90,
          frozen_val: pathlib.Path | None = None) -> dict:
    corpus = json.load(open(ROOT / "corpus284_lab_2026-09.json"))
    gt43 = json.load(open(ROOT / "gt43_lab_2026-09.json"))
    ng = json.load(open(ROOT / "eval_not_gradable.json"))
    cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
    keep, why = select(corpus, gt43, ng)
    train, val = split(keep)
    fixed = None
    if frozen_val is not None:
        fixed, f_corpus, f_debian = frozen(frozen_val)
        val = [e for e in corpus if e["n"] in f_corpus]
        train = [e for e in keep if e["n"] not in f_corpus]
    # Recordings a prompt may show as examples: all the relay holds, without the
    # held-back ones and without those the first rule removes. Time-dependent recordings
    # stay, as at inference: they are examples of a format, never targets.
    leak = ("command is one of the 43", f"shares {WINDOW}+ consecutive lines with a test answer")
    shown = {e["n"] for e in corpus} - {e["n"] for e in val} - \
        {n for n, r in why.items() if r in leak}
    texts = json.load(open(DEBIAN_TEXTS)) if DEBIAN_TEXTS.exists() else []
    d_keep, d_why = select_debian(texts, gt43, corpus)
    d_train, d_val = split(d_keep) if d_keep else ([], [])
    if fixed is not None:
        d_val = [e for e in d_keep if norm_cmd(e["command"]) in f_debian]
        d_train = [e for e in d_keep if norm_cmd(e["command"]) not in f_debian]

    # With a frozen held-back set, another stream of contexts, so that no generated
    # session repeats one of the held-back sessions.
    rng = random.Random(seed + (1 if fixed is not None else 0))
    tmp = tempfile.TemporaryDirectory()
    out_dir.mkdir(parents=True, exist_ok=True)
    real = (machine.now, machine.boot_time)
    counts = {name: collections.Counter() for name in ("train", "val")}
    try:
        held_cmds = {norm_cmd(e["command"]) for e in val + d_val}
        sessions, c_tally = code_sessions(code_session_count, shown, cfg, rng, tmp.name, gt43,
                                          held_cmds)
        held = max(1, round(len(sessions) * 0.10)) if sessions and fixed is None else 0
        c_split = {"train": sessions[held:], "val": sessions[:held]}
        plan = {"train": [("corpus", train, variants), ("debian", d_train, debian_variants)],
                "val": [("corpus", val, 1), ("debian", d_val, 1)]}
        for name in ("train", "val"):
            if name == "val" and fixed is not None:
                with open(out_dir / "val.jsonl", "w", encoding="utf-8") as f:
                    for rec in fixed:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        counts[name][rec["meta"]["source"]] += 1
                continue
            records = []
            for source, items, nvar in plan[name]:
                for e in items:
                    for v in range(nvar):
                        records.append(one(e, v, train, shown, cfg, rng, tmp.name, source))
            records += [r for s in c_split[name] for r in s]
            if fixed is not None:
                # and no training record is a held-back record word for word
                seen = {json.dumps(r["messages"], ensure_ascii=False) for r in fixed}
                before = len(records)
                records = [r for r in records
                           if json.dumps(r["messages"], ensure_ascii=False) not in seen]
                counts["dropped_as_held_back"] = before - len(records)
            if name == "train":
                random.Random(seed).shuffle(records)        # sources mixed, reproducibly
            with open(out_dir / f"{name}.jsonl", "w", encoding="utf-8") as f:
                for rec in records:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    counts[name][rec["meta"]["source"]] += 1
    finally:
        machine.now, machine.boot_time = real
        tmp.cleanup()
    manifest = {
        "built": dt.datetime.now(machine.TZ).isoformat(timespec="seconds"),
        "rules": "tools/build_training_data.py docstring",
        "seed": seed,
        "variants_per_train_example": variants,
        "frozen_val": str(frozen_val) if frozen_val is not None else None,
        "examples": {"train": [e["n"] for e in train], "val": [e["n"] for e in val]},
        "records": {name: sum(counts[name].values()) for name in ("train", "val")},
        "records_by_source": {name: dict(counts[name]) for name in ("train", "val")},
        "train_records_identical_to_held_back_dropped": counts.get("dropped_as_held_back", 0),
        "excluded": {str(n): r for n, r in sorted(why.items())},
        "sources": {
            "corpus": {"examples": {"train": len(train), "val": len(val)},
                       "recordings_a_prompt_may_show": len(shown),
                       "variants_per_train_example": variants, "excluded": len(why)},
            "debian": {"file": str(DEBIAN_TEXTS.relative_to(ROOT)), "recorded": len(texts),
                       "examples": {"train": [e["n"] for e in d_train],
                                    "val": [e["n"] for e in d_val]},
                       "variants_per_train_example": debian_variants,
                       "excluded": {str(n): r for n, r in d_why.items()}},
            "code": {"sessions": {"train": len(c_split["train"]), "val": len(c_split["val"])},
                     "lines": c_tally},
        },
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--variants", type=int, default=6,
                    help="contexts per corpus example in the training part")
    ap.add_argument("--debian-variants", type=int, default=1,
                    help="contexts per Debian text in the training part")
    ap.add_argument("--code-sessions", type=int, default=90,
                    help="generated sessions answered by the relay's code")
    ap.add_argument("--frozen-val", type=pathlib.Path,
                    help="keep this earlier set's val.jsonl unchanged (the go/no-go set)")
    ap.add_argument("--out", default=str(ROOT / "offline" / "training" /
                                         dt.date.today().strftime("%Y%m%d")))
    args = ap.parse_args()
    m = build(args.variants, pathlib.Path(args.out), debian_variants=args.debian_variants,
              code_session_count=args.code_sessions, frozen_val=args.frozen_val)
    print(f"records: {m['records']['train']} train, {m['records']['val']} held back -> {args.out}")
    for name in ("train", "val"):
        print(f"  {name:5} by source: {m['records_by_source'][name]}")
    print(f"  corpus excluded: {len(m['excluded'])}; debian excluded: "
          f"{len(m['sources']['debian']['excluded'])}; code lines: {m['sources']['code']['lines']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
