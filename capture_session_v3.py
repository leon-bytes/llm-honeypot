#!/usr/bin/env python3
"""
capture_session.py (v3) - record what the reference Pi returns for a list of
commands, matching how the April ground truth was collected.

HOW APRIL DID IT (worked out from evidence in the ground truth):
  * Errors read "-bash: junkcommand: command not found". The leading dash means
    a LOGIN shell, not `bash -c "..."` (which says "bash: line 1:").
  * `env` includes NO_AT_BRIDGE=1, which only appears when the startup files in
    /etc/profile are read - login shells do that, command-string shells don't.
  * `echo $$` returned 4123, then the next command showed bash as 4133, then
    4145. The shell's process ID changed every time.
  * No variables or directory changes carried between commands.

  Conclusion: a NEW login shell per command. Files written to disk persist
  (that's the filesystem), everything about the shell resets.

v1 reused one login shell (right shell, wrong persistence).
v2 used exec_command (right persistence, wrong shell).
v3 opens a fresh shell channel per command, which is both.

SENTINEL HANDLING (fixed Sept 2026 - three defects, all visible in the April
data that this script produced):
  1. The end-of-output marker was the string SENT+"0", which only matches exit
     code 0. Every failing command waited out the whole --timeout instead; all
     16 nonzero-exit entries in ground_truth_43.json and corpus_284.json are
     recorded at ~20,600 ms rather than their real ~640 ms. The marker is now
     the regex SENT(\\d+), so any exit code ends the read immediately.
  2. The instrumented command line was appended to the reference machine's
     HISTFILE on every command - a write to Ground Truth, and it contaminated
     later reads (corpus_284.json has `cat /root/.bash_history` returning this
     script's own "uname -a; echo " line). A prologue now unsets HISTFILE in
     the fresh shell. Bash reads HISTFILE at startup and only writes it back at
     exit, so unsetting it afterwards keeps reads truthful while writing
     nothing to disk. HISTFILE=/dev/null or `history -c` would instead blank
     out the real history that students would see.
  3. The output was cut at the FIRST sentinel occurrence, so any output that
     itself contained the sentinel was truncated (`history | head -5` recorded
     one line instead of five). The LAST SENT(\\d+) match is now the marker.
     The echoed command line holds SENT followed by "$?", not a digit, so the
     (\\d+) requirement already makes the regex skip the echo.

Usage:
  python3 capture_session_v3.py --host REF_IP --jump lab-dev2 \
      --user root --commands ground_truth_43.json --out gt_session.json
(REF_IP: the reference machine's address, ref_ipv4 in site.local.json)
"""
from __future__ import annotations
import argparse, getpass, json, os, pathlib, re, sys, time, uuid

SENT = f"__X{uuid.uuid4().hex[:10]}__"
SENT_RE = re.compile(re.escape(SENT) + r'(\d+)')
ANSI = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]|\x1B\][^\x07]*\x07')

# Unsetting HISTFILE stops the shell writing this script's instrumented command
# lines into the reference machine's history file. See defect 2 above.
DEFAULT_PROLOGUE = "unset HISTFILE"


def load_commands(path: str):
    p = pathlib.Path(path)
    raw = p.read_text(encoding="utf-8")
    if p.suffix == ".json":
        data = json.loads(raw)
        return [(d["n"], d["command"]) if isinstance(d, dict) else (i, d)
                for i, d in enumerate(data, 1)]
    return [(i, l) for i, l in enumerate(
        (x.strip() for x in raw.splitlines()), 1) if l and not l.startswith("#")]


def read_until(chan, pattern, timeout):
    """Read from the channel until `pattern` (a compiled regex) matches."""
    buf, deadline = "", time.monotonic() + timeout
    while time.monotonic() < deadline:
        if chan.recv_ready():
            buf += chan.recv(65536).decode("utf-8", errors="replace")
            if pattern.search(buf):
                return buf, True
        elif chan.exit_status_ready() and not chan.recv_ready():
            break
        else:
            time.sleep(0.02)
    return buf, bool(pattern.search(buf))


def parse_capture(raw, sent=SENT):
    """Pull (output, exit_code) out of one command's raw terminal stream.

    Pure function - no channel, no network - so it can be tested directly.
    """
    sent_re = SENT_RE if sent == SENT else re.compile(re.escape(sent) + r'(\d+)')

    matches = list(sent_re.finditer(raw))
    if matches:
        m = matches[-1]          # LAST match: the output may contain the sentinel
        code, head = int(m.group(1)), raw[:m.start()]
    else:
        code, head = -1, raw

    # Drop the echoed command line. The echo holds the sentinel followed by
    # "$?", so it is the first bare sentinel in `head`; cut to that line's end.
    e = head.find(sent)
    nl = head.find("\n", e) if e != -1 else -1
    body = head[nl + 1:] if nl != -1 else head

    text = ANSI.sub("", body).replace("\r\n", "\n")
    if text.startswith("\r"):
        text = text[1:]
    return text.rstrip("\n"), code


def run_one(cli, cmd, timeout, prologue=DEFAULT_PROLOGUE):
    """Open a fresh login shell, run one command, close it."""
    chan = cli.invoke_shell(term="xterm", width=200, height=24)
    try:
        if prologue:
            # Sent inside the existing banner window, so it costs no measurable
            # time and the ~640 ms baseline stays comparable with April's.
            chan.sendall(prologue + "\n")
        time.sleep(0.6)                     # let the login banner arrive
        while chan.recv_ready():
            chan.recv(65536)                # and discard it (plus the prologue echo)

        chan.sendall(f"{cmd}; echo {SENT}$?\n")
        raw, ok = read_until(chan, SENT_RE, timeout)
        if not ok:
            print(f"  [warn] no marker within {timeout}s: {cmd!r}", file=sys.stderr)
        return parse_capture(raw)
    finally:
        chan.close()


# --end prompt (added 2026-10-13, for recording the HONEYPOT): the end of an answer is
# the next shell prompt, and the exit status is asked for with a second line, `echo $?`.
# The marker method above sends `<command>; echo <marker>$?`, which is fine for a real
# bash but hands the honeypot a different line than the one under test: its answer
# engine would be asked for `<command>; echo <marker>$?` instead of `<command>`, and a
# line no student types. With --end prompt the target gets exactly the test command.
# Never needed for, and never used on, the reference machine: its recordings stay as made.
PROMPT_RE = re.compile(r'(?:^|[\r\n])[^\s@]+@[^\s:]+:[^\r\n]*[#$] $')


def read_until_prompt(chan, timeout):
    """Read until the stream (escape sequences aside) ends in a shell prompt and
    nothing more arrives for a moment."""
    buf, deadline = "", time.monotonic() + timeout
    while time.monotonic() < deadline:
        if chan.recv_ready():
            buf += chan.recv(65536).decode("utf-8", errors="replace")
        elif PROMPT_RE.search(ANSI.sub("", buf)):
            time.sleep(0.15)
            if not chan.recv_ready():
                return buf, True
        elif chan.exit_status_ready():
            break
        else:
            time.sleep(0.02)
    return buf, False


def parse_prompt_capture(raw):
    """The answer in one command's raw terminal stream that ends in a prompt: what lies
    between the echoed command line and that prompt. Pure, so it can be tested."""
    text = ANSI.sub("", raw).replace("\r\n", "\n").replace("\r", "")
    nl = text.find("\n")                       # the end of the echoed command line
    body = text[nl + 1:] if nl != -1 else ""
    m = re.search(r'(?:^|\n)[^\s@]+@[^\s:]+:[^\n]*[#$] $', body)
    if m:
        body = body[:m.start()]
    return body.rstrip("\n")


def run_one_prompt(cli, cmd, timeout):
    """A fresh login shell, the command exactly as given, then `echo $?`.
    Returns (output, exit code, milliseconds from Enter to the next prompt)."""
    chan = cli.invoke_shell(term="xterm", width=200, height=24)
    try:
        _, ok = read_until_prompt(chan, 15)     # the login text and the first prompt
        if not ok:
            print("  [warn] no prompt after login", file=sys.stderr)
        t0 = time.monotonic()
        chan.sendall(cmd + "\n")
        raw, ok = read_until_prompt(chan, timeout)
        ms = (time.monotonic() - t0) * 1000
        if not ok:
            print(f"  [warn] no prompt within {timeout}s: {cmd!r}", file=sys.stderr)
            return parse_prompt_capture(raw), -1, ms
        chan.sendall("echo $?\n")
        raw2, _ = read_until_prompt(chan, 10)
        code = parse_prompt_capture(raw2).strip()
        return parse_prompt_capture(raw), int(code) if code.isdigit() else -1, ms
    finally:
        chan.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True,
                    help="IP or hostname (paramiko does NOT read ~/.ssh/config, "
                         "so an alias like lab-gt will not resolve here)")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", help="omit to be prompted (keeps it out of shell history)")
    ap.add_argument("--password-env", metavar="VAR",
                    help="read the password from environment variable VAR instead of "
                         "prompting. Unlike --password it never reaches a command line, "
                         "so `ps` cannot show it. Used by scripts/gt_capture_taskA.sh, "
                         "which asks once and runs several captures.")
    ap.add_argument("--key")
    ap.add_argument("--jump", help="SSH alias/host to tunnel through, e.g. lab-dev2")
    ap.add_argument("--commands", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--settle", type=float, default=0.2)
    ap.add_argument("--prologue", default=DEFAULT_PROLOGUE,
                    help=f"run in each fresh shell before the command (default: {DEFAULT_PROLOGUE!r})")
    ap.add_argument("--no-prologue", action="store_const", const="", dest="prologue",
                    help="send no prologue - the shell WILL write to the target's HISTFILE")
    ap.add_argument("--end", choices=["marker", "prompt"], default="marker",
                    help="how the end of an answer is found. marker (default): the method "
                         "the reference machine was recorded with. prompt: for the honeypot; "
                         "sends the command exactly as given and waits for the next prompt")
    ap.add_argument("--pause", type=float, default=0.0,
                    help="seconds to wait after each command. For the honeypot: 8 at least, "
                         "its model nodes must not be sent answers back to back")
    args = ap.parse_args()

    try:
        import paramiko
    except ImportError:
        sys.exit("paramiko missing: python3 -m venv .venv && .venv/bin/pip install paramiko")

    cmds = load_commands(args.commands)
    print(f"[capture] {len(cmds)} commands -> {args.host} as {args.user}"
          + (f" via {args.jump}" if args.jump else ""))
    if not args.prologue:
        print("[capture] WARNING: no prologue; the target's ~/.bash_history will be written to",
              file=sys.stderr)

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = {"hostname": args.host, "port": args.port, "username": args.user,
          "timeout": 15, "look_for_keys": False, "allow_agent": False}
    if args.key:
        kw["pkey"] = paramiko.Ed25519Key.from_private_key_file(
            str(pathlib.Path(args.key).expanduser()))
    else:
        pw = args.password
        if not pw and args.password_env:
            pw = os.environ.get(args.password_env)
            if not pw:
                sys.exit(f"--password-env {args.password_env}: "
                         "that environment variable is unset or empty")
        kw["password"] = pw or getpass.getpass(
            f"password for {args.user}@{args.host}: ")
    if args.jump:
        # Reuse the system ssh binary so ~/.ssh/config (ProxyJump, IdentityFile)
        # and the existing lab key do the work; no dev2 credentials in Python.
        # -W forwards raw TCP to the target's port and needs no shell on the jump host.
        kw["sock"] = paramiko.ProxyCommand(
            f"ssh -W {args.host}:{args.port} {args.jump}")
    cli.connect(**kw)

    results = []
    for i, (n, cmd) in enumerate(cmds, 1):
        t0 = time.monotonic()
        try:
            if args.end == "prompt":
                text, code, elapsed = run_one_prompt(cli, cmd, args.timeout)
            else:
                text, code = run_one(cli, cmd, args.timeout, args.prologue)
                elapsed = (time.monotonic() - t0) * 1000
        except Exception as e:
            text, code, elapsed = f"[capture error] {e}", -1, (time.monotonic() - t0) * 1000
        results.append({"n": n, "command": cmd, "output": text,
                        "exit_code": code, "elapsed_ms": round(elapsed, 1)})
        print(f"  [{i:3d}/{len(cmds)}] {cmd[:56]:<56} {len(text):6d}B  exit={code}")
        time.sleep(args.settle + args.pause)

    cli.close()
    pathlib.Path(args.out).write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[capture] wrote {args.out} ({len(results)} entries)")


if __name__ == "__main__":
    main()
