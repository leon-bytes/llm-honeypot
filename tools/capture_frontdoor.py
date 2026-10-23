#!/usr/bin/env python3
"""
capture_frontdoor.py - record what an SSH client sees before and at login.

The shell captures (capture_session_v3.py) deliberately throw away everything
printed before the first command, so the login banner, the MOTD and the prompt
were never recorded. Neither were the SSH identification string as bytes, the
key-exchange lists, or the auth methods the server offers. The class is told to
check these before logging in, so Cowrie has to match them. This records them.

Two parts, run separately or together (--part):

  preauth  No login. Reads the server's identification line as raw bytes, then
           runs the system `ssh -vv` with PreferredAuthentications=none, which
           makes the server list its algorithms and auth methods and then
           refuses. Leaves an entry in the target's journal and nothing else.
  login    One real login (password or key). Records every byte up to the first
           prompt, then, in that same shell, `unset HISTFILE` and a few read-only
           commands (PS1, motd, sshd -T, the PAM lines that print login
           messages), then `exit`. Like every capture login, it adds a session
           to the target's journal and login records.

Run the same thing against Cowrie later and diff the two JSON files.

Usage (inside the venv, from the project root):
  .venv/bin/python tools/capture_frontdoor.py --host REF_IP --jump lab-dev2 \
      --user root --out gt_frontdoor_2026-09.json
  .venv/bin/python tools/capture_frontdoor.py --host HONEYPOT_IP --jump lab-dev2 \
      --part preauth --out orch_frontdoor_preauth.json
(REF_IP, HONEYPOT_IP: the reference machine's and the honeypot's addresses, ref_ipv4 and
hp_ipv4 in site.local.json)
"""
from __future__ import annotations
import argparse, base64, datetime as dt, getpass, json, os, pathlib, re
import socket, subprocess, sys, tempfile, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from capture_session_v3 import SENT, SENT_RE, ANSI, read_until, parse_capture  # noqa: E402

from honeypot.site import SITE           # noqa: E402
GROUND_TRUTH_IP = SITE.ref_ipv4

# Read-only. Run in the login shell after `unset HISTFILE`.
LOGIN_COMMANDS = [
    "printf '%s\\n' \"$PS1\"",
    "cat /etc/motd",
    "ls -la /etc/update-motd.d",
    "grep -Ev '^[[:space:]]*(#|$)' /etc/ssh/sshd_config",
    "cat /etc/ssh/sshd_config.d/*.conf",
    # since 2026-10-13: the drop-in with the algorithm lists is something a participant
    # with root can list, so its name and dates are recorded too
    "ls -la /etc/ssh/sshd_config.d",
    "ls -la /etc/ssh",
    "sshd -T",
    "grep -HEn 'motd|lastlog|chksshpwd|pam_mail|pam_env' /etc/pam.d/sshd /etc/pam.d/common-session",
]

# Which KEXINIT fields to keep, as `ssh -vv` names them.
KEX_FIELDS = ["KEX algorithms", "host key algorithms", "ciphers ctos", "ciphers stoc",
              "MACs ctos", "MACs stoc", "compression ctos", "compression stoc"]
PROMPT_RE = re.compile(r"[#$] $")


def ms(t0: float) -> int:
    return round((time.monotonic() - t0) * 1000)


def read_ident(host: str, port: int, jump: str | None, timeout: float = 10.0) -> dict:
    """Connect, read the server's identification line as bytes, hang up."""
    t0 = time.monotonic()
    buf = b""
    if jump:
        p = subprocess.Popen(["ssh", "-W", f"{host}:{port}", jump],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL)
        try:
            os.set_blocking(p.stdout.fileno(), False)
            deadline = time.monotonic() + timeout
            while b"\n" not in buf and time.monotonic() < deadline:
                chunk = p.stdout.read(256)
                if chunk:
                    buf += chunk
                else:
                    time.sleep(0.01)
        finally:
            p.kill()
            p.wait()
    else:
        with socket.create_connection((host, port), timeout=timeout) as s:
            while b"\n" not in buf:
                chunk = s.recv(256)
                if not chunk:
                    break
                buf += chunk
    line = buf.split(b"\n", 1)[0] + (b"\n" if b"\n" in buf else b"")
    return {"ident": line.decode("ascii", errors="replace").rstrip("\r\n"),
            "ident_raw_b64": base64.b64encode(line).decode(),
            "ends_with_crlf": line.endswith(b"\r\n"),
            "ms_to_ident": ms(t0)}


def parse_ssh_vv(text: str) -> dict:
    """Pull the server's side of the handshake out of `ssh -vv` stderr."""
    out: dict = {"server_kexinit": {}, "negotiated": {}}
    lines = text.splitlines()
    in_peer = False
    for ln in lines:
        body = re.sub(r"^debug\d: ", "", ln)
        if "peer server KEXINIT proposal" in ln:
            in_peer = True
            continue
        if in_peer:
            k, _, v = body.partition(": ")
            if k in KEX_FIELDS:
                out["server_kexinit"][k] = v.split(",") if v else []
            elif k.startswith("reserved") or "KEXINIT proposal" in body:
                in_peer = False
        if m := re.match(r"Remote protocol version (\S+), remote software version (.+)", body):
            out["remote_protocol"], out["remote_software"] = m.group(1).rstrip(","), m.group(2)
        elif m := re.match(r"kex: (algorithm|host key algorithm): (.+)", body):
            out["negotiated"][m.group(1)] = m.group(2)
        elif m := re.match(r"kex: server->client cipher: (\S+) MAC: (\S+) compression: (\S+)", body):
            out["negotiated"]["server->client"] = {"cipher": m.group(1), "mac": m.group(2),
                                                   "compression": m.group(3)}
        elif m := re.match(r"Server host key: (\S+) (\S+)", body):
            out["server_host_key"] = {"type": m.group(1), "fingerprint": m.group(2)}
        elif m := re.match(r"Authentications that can continue: (\S+)", body):
            out["auth_methods"] = m.group(1).split(",")
        elif m := re.match(r"Remote: (.+)", body):
            out.setdefault("server_messages", []).append(m.group(1))
    # Anything not from the debug machinery: a pre-auth Banner, if the server has one.
    out["other_stderr_lines"] = [ln for ln in lines if not ln.startswith("debug")
                                 and not ln.startswith("OpenSSH_")
                                 and not ln.startswith("Warning: Permanently added")]
    return out


def preauth(host: str, port: int, user: str, jump: str | None) -> dict:
    rec = read_ident(host, port, jump)
    with tempfile.NamedTemporaryFile(prefix="kh-") as kh:
        cmd = ["ssh", "-vv", "-p", str(port),
               "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none",
               "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={kh.name}",
               "-o", "ConnectTimeout=10", "-F", "/dev/null"]
        if jump:
            # ProxyCommand, not -J: -J would pass -vv to the jump connection too
            # and interleave dev2's handshake with the one we are recording.
            cmd += ["-o", f"ProxyCommand=ssh -W %h:%p {jump}"]
        cmd += [f"{user}@{host}", "true"]
        t0 = time.monotonic()
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        rec["ms_ssh_vv"] = ms(t0)
    rec["client"] = subprocess.run(["ssh", "-V"], capture_output=True, text=True).stderr.strip()
    rec.update(parse_ssh_vv(p.stderr))
    rec["ssh_vv_stderr"] = p.stderr
    return rec


def login(args, password: str | None) -> dict:
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = {"hostname": args.host, "port": args.port, "username": args.user,
          "timeout": 15, "look_for_keys": False, "allow_agent": False}
    if args.key:
        kw["pkey"] = paramiko.Ed25519Key.from_private_key_file(
            str(pathlib.Path(args.key).expanduser()))
    else:
        kw["password"] = password
    if args.jump:
        kw["sock"] = paramiko.ProxyCommand(f"ssh -W {args.host}:{args.port} {args.jump}")

    rec: dict = {"auth": "key" if args.key else "password", "terminal": "xterm 80x24"}
    t0 = time.monotonic()
    cli.connect(**kw)
    rec["ms_connect_and_auth"] = ms(t0)
    try:
        chan = cli.invoke_shell(term="xterm", width=80, height=24)
        t1 = time.monotonic()
        raw, deadline = b"", time.monotonic() + 15
        while time.monotonic() < deadline:
            if chan.recv_ready():
                raw += chan.recv(65536)
                if PROMPT_RE.search(ANSI.sub("", raw.decode("utf-8", errors="replace"))):
                    break
            else:
                time.sleep(0.02)
        rec["ms_shell_to_prompt"] = ms(t1)
        rec["prompt_seen"] = bool(PROMPT_RE.search(ANSI.sub("", raw.decode("utf-8", errors="replace"))))
        # Everything before the first command, exactly as sent. The prompt is
        # the last line; the rest is the MOTD and any login messages.
        rec["banner_raw_b64"] = base64.b64encode(raw).decode()
        text = raw.decode("utf-8", errors="replace")
        rec["banner_text"] = text
        last = text.replace("\r\n", "\n").rsplit("\n", 1)
        rec["prompt_raw"] = last[-1]
        rec["prompt_plain"] = ANSI.sub("", last[-1])
        rec["login_messages"] = ANSI.sub("", last[0]).rstrip("\r") if len(last) == 2 else ""

        # Keep the history file untouched before typing anything else.
        chan.sendall("unset HISTFILE\n")
        time.sleep(0.4)
        while chan.recv_ready():
            chan.recv(65536)

        rec["commands"] = []
        for c in ([] if args.banner_only else LOGIN_COMMANDS):
            chan.sendall(f"{c}; echo {SENT}$?\n")
            got, ok = read_until(chan, SENT_RE, 20)
            out, code = parse_capture(got)
            rec["commands"].append({"command": c, "output": out, "exit_code": code,
                                    "complete": ok})
        chan.sendall("exit\n")
        time.sleep(0.3)
    finally:
        cli.close()
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", required=True, help="IP (paramiko does not read ~/.ssh/config)")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--user", default="root")
    ap.add_argument("--jump", help="SSH alias to tunnel through, e.g. lab-dev2")
    ap.add_argument("--key", help="log in with this ed25519 key instead of a password")
    ap.add_argument("--password-env", metavar="VAR",
                    help="read the password from this environment variable instead of prompting")
    ap.add_argument("--part", choices=["preauth", "login", "both"], default="both")
    ap.add_argument("--out", required=True)
    ap.add_argument("--banner-only", action="store_true",
                    help="at login, record the login text and the first prompt and stop: do not run "
                         "the read-only commands after it (for the honeypot, where they add nothing "
                         "to the comparison and would each be sent to the model)")
    ap.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    ap.add_argument("--yes", action="store_true",
                    help="skip the confirmation asked before touching Ground Truth")
    args = ap.parse_args()

    if pathlib.Path(args.out).exists() and not args.force:
        sys.exit(f"{args.out} exists; pass --force to overwrite")
    if args.host == GROUND_TRUTH_IP and not args.yes:
        print(f"This connects to Ground Truth ({args.host}): part '{args.part}'.\n"
              "It needs the user's explicit OK and an entry in docs/gt-changes.md.")
        if input("Type yes to go on: ").strip() != "yes":
            sys.exit("stopped, nothing sent")

    password = None
    if args.part in ("login", "both") and not args.key:
        password = (os.environ.get(args.password_env) if args.password_env else None) \
            or getpass.getpass(f"password for {args.user}@{args.host}: ")

    rec = {"host": args.host, "port": args.port, "user": args.user,
           "recorded_at": dt.datetime.now().astimezone().isoformat(timespec="seconds")}
    if args.part in ("preauth", "both"):
        print("[frontdoor] preauth ...", file=sys.stderr)
        rec["preauth"] = preauth(args.host, args.port, args.user, args.jump)
    if args.part in ("login", "both"):
        print("[frontdoor] login ...", file=sys.stderr)
        rec["login"] = login(args, password)

    pathlib.Path(args.out).write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n")
    print(f"[frontdoor] wrote {args.out}", file=sys.stderr)

    pa, lg = rec.get("preauth", {}), rec.get("login", {})
    if pa:
        print(f"ident          {pa['ident']!r}  (CRLF: {pa['ends_with_crlf']})")
        print(f"auth methods   {','.join(pa.get('auth_methods', [])) or '?'}")
        print(f"negotiated     {pa.get('negotiated')}")
        for k, v in pa.get("server_kexinit", {}).items():
            print(f"{k:<14} {','.join(v)}")
        if pa.get("other_stderr_lines"):
            print("other output   " + " | ".join(pa["other_stderr_lines"]))
    if lg:
        print(f"prompt         {lg.get('prompt_plain')!r}  (seen: {lg.get('prompt_seen')})")
        print("login messages:\n" + (lg.get("login_messages") or "(none)"))


if __name__ == "__main__":
    main()
