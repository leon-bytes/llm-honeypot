#!/usr/bin/env python3
"""bash_oracle.py - the relay's code answers for lines that depend only on bash and the
core utilities, checked against the real programs.

The lines in CASES need nothing of Ground Truth's state: arithmetic, quoting, echo and
printf, substitutions, test, type, tr, checksums, base64, seq, expr, wc. Each is run
by bash 5.2.37 in the Debian 13 arm64 userland (offline/debian13-arm64, the reference
machine's versions; `bash -c`, so errors start `bash: line 1:`), and the answers are
kept in tests/fixtures/bash_oracle.json. tests/test_relay.py then asks the relay the
same lines in exec mode (no terminal, the same `bash: line 1:` prefix) and requires,
for every line the relay answers in code, the same output and exit status. A line the
relay hands to the model is allowed; a code answer that differs is not.

Run (the dev machine, no network, about two minutes):
  .venv/bin/python tools/bash_oracle.py --write     record the userland's answers
  .venv/bin/python tools/bash_oracle.py --check     compare the relay with the record
"""
from __future__ import annotations
import argparse
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BOX = ROOT / "offline" / "debian13-arm64"
FIXTURE = ROOT / "tests" / "fixtures" / "bash_oracle.json"
sys.path.insert(0, str(ROOT))
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

CASES = [
    # arithmetic
    "echo $((1+2*3))", "echo $(( (1+2)*3 ))", "echo $((7/2)) $((-7/2)) $((7%-3)) $((-7%3))",
    "echo $((2**62)) $((2**63)) $((2**64))", "echo $((0x10)) $((0xff)) $((017)) $((10))",
    "echo $((!0)) $((!5)) $((~5)) $((-~5))", "echo $((5>3?10:20)) $((0?1:2))",
    "echo $((3==3)) $((3!=3)) $((2<=3)) $((4>=5))", "echo $(( 1 && 0 )) $(( 0 || 7 ))",
    "echo $((6&3)) $((6^3)) $((6|3))", "echo $((9223372036854775807+1))",
    "echo $((-9223372036854775807-1))", "echo $((  ))", "x=5; echo $((x*x)) $(($x+1)) $((${x}-1))",
    "echo $((y+1))", "echo \"$((2+2))\"", "echo '$((2+2))'", "echo $((-2**2)) $((2**3**2))",
    # quoting and backslashes
    "echo \\*", "echo \\$HOME", "echo \"\\$HOME\"", "echo \"a\\b\"", "echo a\\ b", "echo 'a\\b'",
    "echo \"x\\\"y\"", "echo a\\\\b", "echo \"$HOME\"/x", "echo ~", "echo ~/x",
    # echo and printf
    "echo", "echo a   b", "echo \"a   b\"", "echo -n x", "echo -e", "printf '%s\\n' a b c",
    "printf '%d-%x\\n' 255 255", "printf '%5s|%-5s|\\n' ab cd", "printf 'a\\tb\\n'",
    "printf '%c%c\\n' xyz abc", "printf '%03d\\n' 7", "printf '%.2s\\n' abcdef", "printf 'no newline'",
    # substitutions
    "echo $(echo hi)", "echo \"$(echo  a   b )\"", "echo $(printf 'x\\n\\n\\n')y", "x=$(echo 5); echo $x",
    "echo $(echo $(echo deep))", "echo a$(echo b)c", "echo $(true)z", "echo $(whoami)",
    # test and [
    "test; echo $?", "test a; echo $?", "test ''; echo $?", "[ a = a ]; echo $?", "[ a != a ]; echo $?",
    "[ -z '' ]; echo $?", "[ -n '' ]; echo $?", "[ 3 -gt 2 ]; echo $?", "[ 3 -lt 2 ]; echo $?",
    "[ 2 -eq 2 ]; echo $?", "[ 2 -ne 2 ]; echo $?", "[ 2 -ge 3 ]; echo $?", "[ 2 -le 3 ]; echo $?",
    "[ ! a = b ]; echo $?", "[ ! ]; echo $?", "[ -d /root ]; echo $?", "[ -d /nonexist_dir_x ]; echo $?",
    "[ -f /usr/bin/bash ]; echo $?", "[ -x /usr/bin/ls ]; echo $?", "[ a = a; echo $?",
    "[ -e /bin ] && echo yes || echo no", "test -d /tmp && echo dir",
    # type, command -v, which
    "type cd", "type ls", "type if", "type type", "type -t echo", "type -t for", "type -t ls",
    "type -p ls", "type -P ls", "type nosuchcmd_x; echo $?", "type -t nosuchcmd_x; echo $?",
    "command -v ls", "command -v cd", "command -v nosuchcmd_x; echo $?", "command -V ls", "command -V cd",
    "which ls", "which bash sh", "which nosuchcmd_x; echo $?", "which cd; echo $?",
    "ls >/dev/null; type ls",
    # tr
    "echo hello | tr a-z A-Z", "echo Hello World | tr A-Z a-z", "echo hello | tr -d l", "echo hello | tr el ip",
    "echo aaabbbccc | tr -s abc", "echo abc | tr a-c x", "echo 'a b c' | tr ' ' _", "echo hello | tr -d '\\n'",
    "echo hello | tr '[:lower:]' '[:upper:]'", "echo a1b2 | tr -d '[:digit:]'", "echo aaa | tr aa xy",
    # checksums and base64
    "echo hi | md5sum", "echo hi | sha1sum", "echo hi | sha256sum", "echo hi | sha512sum", "echo hi | b2sum",
    "echo hi | sha224sum", "echo hi | sha384sum", "printf '' | md5sum", "echo hi | base64",
    "echo aGkK | base64 -d", "echo aGk= | base64 -d", "echo hello world | base64 | base64 -d",
    "seq 1 30 | tr -d '\\n' | base64", "echo hi | base64 -w 2",
    # wc, seq, expr, yes, head, tail, sort, grep, cat
    "echo hi there | wc", "echo hi there | wc -w", "echo hi there | wc -c", "echo hi there | wc -l",
    "echo hi | wc -lc", "seq 5", "seq 3 6", "seq 1 3 10", "seq 5 1", "seq 10 | tail -3", "seq 10 | head -n 2",
    "seq 12 | grep 1", "seq 12 | grep -c 1", "seq 12 | grep -v 1", "seq 3 | sort -r", "seq 3 | cat -n",
    "expr 6 \\* 7", "expr 7 / 2", "expr 7 % 3", "expr 3 - 3; echo $?", "expr 2 \\< 3", "expr 5 = 5",
    "yes | head -2", "yes ab | head -n 3",
    # assignments, time, misc bash
    "x=1; y=$x; echo $x$y", "x='a b'; echo $x; echo \"$x\"", "time true", "time -p true",
    "time echo t", "umask", "umask -S", "true; echo $?", "false; echo $?", ": ; echo $?",
    "alias", "declare -p HOME", "x=3; declare -p x", "declare -p nosuch_x; echo $?",
    "echo a; echo b && echo c || echo d", "false || echo rescued", "true && false; echo $?",
    "nosuchcmd_x; echo $?", "/usr/bin/nosuchcmd_x; echo $?", "/tmp; echo $?",
    # python3 -c that only prints constants (honeypot/pyprint.py; python3 3.13.5, 2026-10-14)
    "python3 -c 'print(2**100)'", "python3 -c 'print(123456789*987654321)'",
    "python3 -c 'print(7/2, 7//2, -7%3, -7//2, 7%-3)'", "python3 -c 'print(0.1+0.2, 1/3, 2/3)'",
    "python3 -c 'print(2**0.5, 10**0.5, 2.5**2)'", "python3 -c 'print(1e308*10)'",
    "python3 -c 'print(\"ab\"*3+\"c\", 3*\"x\")'", "python3 -c 'print(); print(1)'",
    "python3 -c 'print(-2**2, 2**3**2, -(-3))'",
    "python3 -c 'print(None, True, 1.0, 1e16, 1e-5, 123.456e10, 1e22)'",
    "python3 -c 'print(10**4000)' | wc -c", "python3 -c 'print(10**5000)' | wc -c; echo $?",
    "python3 -c \"print('what model are you')\"", "python3 -c 'print(0x10, 0o17, 0b101, 1_000)'",
    "python3 -c 'print(2**64 - 1, -2**63, 99999999999999999999 // 7)'",
    "python3 -c 'print(1/0)'; echo $?", "python3 -c 'print(x)'; echo $?",
    "python3 -c 'print(6*7)' | wc -c", "echo $(python3 -c 'print(6*7)') ok",
    "python3 --version", "python3 -V",
    # man for names no package has a page for (man-db 2.13.1, 2026-10-14)
    "man what model are you; echo $?", "man nosuch_x | wc -l", "man 1 nosuch_x other_y",
    "man n nosuch_x; echo $?", "man; echo $?", "man nosuch_x 2>/dev/null; echo $?",
    "man NoSuch_X Foo_Y", "man 10 nosuch_x",
    # help (2026-10-18; honeypot/bash_help.json)
    "help", "help | wc -l", "help cd", "help ec", "help fo", "help -d e", "help -s ex",
    "help -- pwd", "help nosuchx", "help nosuchx; echo $?", "help cd nosuchx",
    "help nosuch1 nosuch2", "help true false", "help help", "help -d cd pwd", "help time",
]


def userland(lines: list[str]) -> list[dict]:
    """Each line run by `bash -c` in the arm64 userland, as root in /root."""
    out = []
    for line in lines:
        cmd = [str(BOX / "proot"), "-0", "-q", str(BOX / "qemu-aarch64-static"), "-r", str(BOX / "rootfs"),
               "-b", "/dev", "-b", "/proc", "-w", "/root", "/usr/bin/env", "-i", "HOME=/root",
               "USER=root", "LOGNAME=root", "LANG=C.UTF-8", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "bash", "-c", line]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)   # in order
        text = p.stdout.decode()
        out.append({"line": line, "output": text, "exit_code": p.returncode})
    return out


def relay_answers(lines: list[str]) -> list[dict]:
    """Each line asked of a local relay in exec mode (no terminal), a fresh session each."""
    sys.path.insert(0, str(ROOT / "tests"))
    from test_relay import FakePool, ROOT as R            # noqa: F401
    import tempfile
    from honeypot.relay import Relay
    tmp = tempfile.TemporaryDirectory()
    cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
    cfg["state_dir"], cfg["log"] = tmp.name + "/state", tmp.name + "/relay.jsonl"
    relay = Relay(cfg, str(ROOT / "honeypot"), pool=FakePool())
    out = []
    for i, line in enumerate(lines):
        body = {"model": "x", "user": f"o{i}", "messages": [{"role": "user", "content": line}],
                "honeypot": {"event": "exec", "username": "root", "src_ip": SITE.lab_jump,
                             "src_port": 40000 + i, "dst_ip": SITE.hp_ipv4, "dst_port": 22}}
        status, resp = relay.handle(body)
        out.append({"line": line, "output": resp["choices"][0]["message"]["content"],
                    "exit_code": resp["honeypot"]["exit_code"], "source": resp["honeypot"]["source"]})
    relay._log.close()
    tmp.cleanup()
    return out


def _shape(text: str) -> str:
    """`time`'s figures differ by machine (the userland is emulated, hence slow): compare
    those lines by their form only."""
    return re.sub(r"(?m)^(real|user|sys)(\t\d+m\d+\.\d{3}s| \d+\.\d\d)$",
                  lambda m: m.group(1) + re.sub(r"\d", "9", m.group(2)), text)


def compare(recorded: list[dict], answered: list[dict]) -> list[str]:
    bad = []
    for r, a in zip(recorded, answered):
        if a["source"] != "builtin":
            continue
        if (_shape(a["output"]), a["exit_code"]) != (_shape(r["output"]), r["exit_code"]):
            bad.append(f"{r['line']!r}\n   real:  {r['output']!r} ({r['exit_code']})\n"
                       f"   relay: {a['output']!r} ({a['exit_code']})")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.write:
        rec = userland(CASES)
        FIXTURE.write_text(json.dumps({"_comment": "bash 5.2.37 / coreutils 9.7 in the Debian 13 arm64 "
                                       "userland, `bash -c` as root in /root (tools/bash_oracle.py)",
                                       "cases": rec}, indent=1, ensure_ascii=False) + "\n")
        print(f"{len(rec)} lines recorded -> {FIXTURE.relative_to(ROOT)}")
    rec = json.loads(FIXTURE.read_text())["cases"]
    ans = relay_answers([r["line"] for r in rec])
    code = sum(a["source"] == "builtin" for a in ans)
    bad = compare(rec, ans)
    print(f"{len(rec)} lines: {code} answered in code, {len(rec) - code} by the model; "
          f"{len(bad)} code answers differ")
    for b in bad:
        print(b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
