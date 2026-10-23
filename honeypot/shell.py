"""One command line in, one answer out.

Order of attempts:
  1. builtin   answered in code from the session and the clock: cd, pwd, echo,
               export, env, date, uptime, history, who, ... Exact, instant, and
               consistent between sessions. Simple pipes into sort/head/tail/grep/wc
               work on their output.
  2. model     everything else, with retrieved examples and this session's history.

Between the two there used to be a replay tier (`cache`): a command typed exactly as
recorded on Ground Truth, with an answer that does not depend on time or session, got
the recorded answer (knowledge.Knowledge.cached). It is off by default since 2026-10-08
(config `replay_tier`): looking up the command text and returning a stored answer is
the hash-table caching ruled out for the study. The corpus still reaches the model as
retrieved examples.
"""
from __future__ import annotations
import base64
import datetime as dt
import fnmatch
import hashlib
import json
import pathlib
import posixpath
import random
import re
import shlex
import threading
import time
from dataclasses import dataclass

from . import dockercli, machine, net, procs, pyprint, sockets, state, sysinfo, whoami
from .backend import Cancelled
from .knowledge import Knowledge
from .session import Session, SessionStore
from .site import SITE


@dataclass
class Answer:
    output: str
    exit_code: int
    source: str                 # builtin | cache | model | fallback
    close: bool = False
    meta: dict | None = None
    newline: bool = True        # False: the output ends without a line break (echo -n)
    blank: bool = False         # True: the whole output is one empty line (a bare `echo`)


class NotBuiltin(Exception):
    """The line needs something the builtins do not do; hand it to the cache or model."""


# What moved from the model to code on 14 October, one switch per category (config
# `code_scope`, read by the relay at start). A category set to false goes back to the
# model as it was before that day, with no other change, in case it is ruled out of
# scope. A key the config leaves out is on. Listed in the paper's appendix.
SCOPE_DEFAULTS = {
    "command_lookup": True,     # time, which, type, command -v/-V
    "arithmetic": True,         # $((...)), expr, seq
    "text_tools": True,         # md5sum/sha*sum, base64, wc (but -l), tr, cat -n, yes | head
    "kernel_files": True,       # /etc/hostname, /proc/sys/kernel/*, /proc/loadavg, /proc/meminfo,
                                # /proc/swaps, /proc/<pid>/comm, /sys/class/net/*, CPU ranges,
                                # getconf, dpkg --print-architecture
    "ls_columns": True,         # ls in GNU's columns at the session's width, ls of a directory
    "shell_settings": True,     # umask, alias, stty, declare -p, locale, test and [, a path
                                # typed as a command
    "created_files": True,      # ls -l/-ld, cp, mv, rmdir, mkdir -p on what attackers created
    "file_filters": True,       # head, tail, grep of one file whose content code holds
    "substitution": True,       # $(...) of a command code answers
    "sudo": True,               # root's sudo
    "docker_run_foreground": True,  # docker run image cmd: container made, run and exited
    "python_print": True,       # python3 -c of print() calls on constant expressions
    "man_pages": True,          # man NAME... where no package anywhere has a page NAME
}


class _Scope(dict):
    """The switches as configured. A session in mode "scope_off" (measurement only, like
    "model_only"; honeypot.mode) sees every one of them off while its line runs: the
    categories of 14 October go to the model as before that day, for the ablation run of
    the 43 (the user, 2026-10-15). Per thread, so other sessions keep the config's."""
    local = threading.local()

    def __getitem__(self, key):
        return False if getattr(_Scope.local, "off", False) else super().__getitem__(key)


SCOPE = _Scope(SCOPE_DEFAULTS)


def set_scope(cfg: dict | None) -> None:
    unknown = set(cfg or {}) - set(SCOPE_DEFAULTS) - {"_comment"}
    if unknown:
        raise ValueError(f"code_scope: unknown categories {sorted(unknown)}")
    SCOPE.clear()
    SCOPE.update(SCOPE_DEFAULTS)
    SCOPE.update({k: bool(v) for k, v in (cfg or {}).items() if k in SCOPE_DEFAULTS})
    dockercli.RUN_ATTACHED = lambda: SCOPE["docker_run_foreground"]


def in_scope(category: str) -> None:
    if not SCOPE[category]:
        raise NotBuiltin(f"{category}: handed back to the model (config code_scope)")


# The builtins that belong to a category as a whole (the rest are gated where they act).
_SCOPE_OF = {"which": "command_lookup", "type": "command_lookup", "command": "command_lookup",
             "expr": "arithmetic", "seq": "arithmetic", "getconf": "kernel_files",
             "dpkg": "kernel_files", "umask": "shell_settings", "alias": "shell_settings",
             "stty": "shell_settings", "declare": "shell_settings", "locale": "shell_settings",
             "help": "shell_settings",
             "test": "shell_settings", "[": "shell_settings", "cp": "created_files",
             "mv": "created_files", "rmdir": "created_files", "head": "file_filters",
             "tail": "file_filters", "grep": "file_filters", "sudo": "sudo",
             "python": "python_print", "python3": "python_print", "python3.13": "python_print"}


# Directories an attacker can `cd` into on Ground Truth. A path not listed here and not
# created in the session answers "No such file or directory", as the real one would.
KNOWN_DIRS = {
    "/", "/root", "/root/iot-stack", "/home", "/home/pi", "/tmp", "/var/tmp", "/etc",
    "/etc/ssh", "/etc/systemd", "/etc/systemd/system", "/etc/docker", "/etc/apt",
    "/etc/cron.d", "/etc/init.d", "/etc/default", "/etc/network", "/etc/update-motd.d",
    "/var", "/var/log", "/var/lib", "/var/lib/docker", "/var/cache", "/var/spool",
    "/var/backups", "/var/mail", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local",
    "/usr/local/bin", "/usr/local/sbin", "/usr/share", "/usr/include", "/usr/src",
    "/opt", "/boot", "/boot/firmware", "/dev", "/proc", "/sys", "/run", "/srv", "/mnt",
    "/media", "/bin", "/sbin", "/lib", "/lost+found",
}

SYSTEM = """You are the bash shell of a Raspberry Pi. You are given one command line typed \
by the logged-in user. Reply with EXACTLY what this machine prints to the terminal - \
nothing else.

Rules:
- Raw terminal text only. No markdown, no code fences, no explanation, no preamble, \
no prompt line, and do not repeat the command.
- If the command fails, give the exact error a real bash on Debian 13 would print.
- Match real spacing and column alignment.
- An empty reply is ONLY correct for commands that truly print nothing on success: \
cd, touch, mkdir, rm, chmod, export, kill, and redirections into a file. Anything \
that lists, prints, reads, searches or reports MUST produce full output. If unsure of \
the exact text, write the most plausible complete output for this machine.
- Stay consistent with everything this session has already been shown."""

FACTS = SITE.fill("""Facts about this machine (always true):
- Hostname raspberrypi. Raspberry Pi 5 Model B Rev 1.1, 8 GB RAM, 4 cores ARM Cortex-A76, aarch64.
- Raspberry Pi OS Lite 64-bit = Debian GNU/Linux 13 (trixie); /etc/debian_version is 13.4.
- uname -a: Linux raspberrypi 6.12.75+rpt-rpi-2712 #1 SMP PREEMPT Debian 1:6.12.75-1+rpt1 (2026-03-11) aarch64 GNU/Linux
- eth0 is @@hp_ipv4@@/24, gateway @@lab_gateway@@. There is NO internet. Wi-Fi is blocked by rfkill.
- Docker CE 29.8.1 runs the docker compose project "iot-stack" from /root/iot-stack:
  iot-stack-mosquitto-1 (eclipse-mosquitto:2), iot-stack-nodered-1 (nodered/node-red:4.1,
  healthy), iot-stack-influxdb-1 (influxdb:2.7-alpine). Their ports 1883, 1880 and 8086 are
  published on 127.0.0.1 only; dockerd also listens on *:2375.
- /root holds the directory iot-stack plus dotfiles; /root/.bash_history is empty.
- Normal user pi (uid 1000). Boot disk is the SD card: /dev/mmcblk0p2 is /, /dev/mmcblk0p1 is /boot/firmware.
- Unknown command error looks exactly like: -bash: NAME: command not found
- `last` and `lastlog` are not installed.""")

MAX_EXAMPLE_CHARS = 1500

# How the live block of every prompt begins, up to the first value (MemTotal, fixed for
# the machine). SYSTEM, FACTS and this are the part all prompts share, which a node's
# server keeps from one answer to the next; the keep-warm ping sends exactly that
# (Shell.warm_messages), so a ping does not throw it away (docs/kv-cache-2026-10-18.md).
LIVE_HEAD = "Live values right now (use these, do not guess):\n- memory in KiB: MemTotal "

# What a command prints when no Jetson answers at all. Never "": an empty `df -h` or
# `ps aux` is the worst tell there is. A program crashing is the one failure a real
# machine can show for any command, and this is bash's exact message for it (no
# "(core dumped)": core files are off by default on Debian).
FALLBACK_OUTPUT, FALLBACK_EXIT = "Segmentation fault", 139
# What exists on Ground Truth's PATH, plus bash's builtins and keywords, built from
# its package inventory by tools/build_command_list.py. Anything else typed as a
# command is `command not found`.
_COMMANDS = json.loads((pathlib.Path(__file__).parent / "commands.json").read_text())
KNOWN_COMMANDS = frozenset(_COMMANDS["path"]) | frozenset(_COMMANDS["builtins"]) \
    | frozenset(_COMMANDS["keywords"])
BASH_BUILTINS = frozenset(_COMMANDS["builtins"])
# The texts of bash's `help` builtin (tools/build_bash_help.py).
_BASH_HELP = json.loads((pathlib.Path(__file__).parent / "bash_help.json").read_text())
# Code answers that print Ground Truth's IDs or bridge name from the shared state: they
# go through the substitution map like recordings do (identity.py, R3).
SUBSTITUTED = frozenset({"ps", "top", "df", "ip", "ifconfig", "netstat", "ss", "hostname"})

MAX_TRANSCRIPT = 8
MAX_TRANSCRIPT_CHARS = 600
# Put in front of an unquoted * ? [ by expand(globs=True), so that after the words are
# split the shell still knows which of them were patterns (Shell._words).
GLOB = "\ue000"


# ---------------------------------------------------------------- parsing helpers

def split_top(line: str, pipes: bool) -> list[tuple[str, str]]:
    """Split on ; && || (and | when `pipes`) outside quotes: [(segment, op_before)]."""
    out, cur, op, i, q = [], [], "", 0, None
    while i < len(line):
        c = line[i]
        if q:
            cur.append(c)
            if c == "\\" and q == '"' and i + 1 < len(line):
                cur.append(line[i + 1])
                i += 1
            elif c == q:
                q = None
        elif c in "'\"":
            q = c
            cur.append(c)
        elif c == "\\" and i + 1 < len(line):
            cur += [c, line[i + 1]]
            i += 1
        elif not pipes and (line.startswith("&&", i) or line.startswith("||", i)):
            out.append(("".join(cur), op))
            cur, op = [], line[i:i + 2]
            i += 1
        elif not pipes and c == ";":
            out.append(("".join(cur), op))
            cur, op = [], ";"
        elif pipes and c == "|" and not line.startswith("||", i):
            out.append(("".join(cur), op))
            cur, op = [], "|"
        else:
            cur.append(c)
        i += 1
    if q:
        raise NotBuiltin("unbalanced quote")
    out.append(("".join(cur), op))
    return [(s.strip(), o) for s, o in out if s.strip()]


PATH_OF = _COMMANDS["path"]            # name -> the first directory on root's PATH holding it

def _man_names() -> frozenset:
    import gzip
    with gzip.open(pathlib.Path(__file__).with_name("man_names.txt.gz"), "rt") as f:
        return frozenset(f.read().split())


_MAN_NAMES = _man_names()       # at start (about 35 ms), so that no answer waits for it


def man_missing(argv: list[str]) -> str | None:
    """man-db 2.13.1's message for `man [SECTION] NAME...` when no NAME can be a manual
    page on the machine, or None (the model's, as before). Which pages the machine has is
    not recorded, so a name counts as missing only if no Debian 13 package anywhere, no
    Raspberry Pi package and no Docker package has a page of that name (any case: man-db
    ignores it), and it is no command there (honeypot/man_names.txt.gz,
    tools/build_man_names.py). The texts and the exit status 16 were recorded in the
    arm64 userland (tools/bash_oracle.py)."""
    args, section = argv[1:], None
    if len(args) > 1 and re.fullmatch(r"[0-9nl]", args[0]):
        section, args = args[0], args[1:]
    if not args or not all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._+:-]*", a) for a in args):
        return None
    if any(a.lower() in _MAN_NAMES or a in KNOWN_COMMANDS or a.lower() in KNOWN_COMMANDS
           or a in BASH_KEYWORDS for a in args):
        return None
    where = f" in section {section}" if section else ""
    return "\n".join(f"No manual entry for {a}{where}" for a in args)
BASH_KEYWORDS = frozenset(_COMMANDS["keywords"])
ROOT_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


def note_hashed(sess: Session, text: str) -> None:
    """Remember the programs a line ran from PATH: bash hashes each one it finds, and
    `type` then reports it as hashed. Taken from the first word of every simple command
    (after assignments and `time`/`!`); a subshell's or a substitution's do not count,
    since their hash table is a copy that dies with them."""
    try:
        parts = [s for seg, _ in split_top(text, pipes=False) for s, _ in split_top(seg, pipes=True)]
    except NotBuiltin:
        return
    for part in parts:
        words = part.split()
        while words and (re.fullmatch(r"[A-Za-z_]\w*=\S*", words[0]) or words[0] in ("time", "!", "-p")):
            words = words[1:]
        if not words or words[0].startswith(("(", "$", "`", "{")):
            continue
        name = words[0]
        if name in PATH_OF and name not in BASH_BUILTINS and name not in BASH_KEYWORDS:
            sess.hashed.setdefault(name, f"{PATH_OF[name]}/{name}")


def time_report(posix: bool, external: bool, extra: float = 0.0) -> str:
    """What bash's `time` prints after a pipeline, with TIMEFORMAT unset (bash 5.2.37,
    the Debian 13 arm64 userland, 2026-10-14). A pipeline of bash builtins takes no
    measurable time; a program a few milliseconds on a Pi 5. `extra`: seconds the
    command waits on the real machine (ping's one per packet)."""
    if external:
        real = random.uniform(0.0015, 0.0045)
        user = random.uniform(0.0, real * 0.45)
        sys_ = random.uniform(0.0, real * 0.55)
    else:
        real = user = sys_ = 0.0
    real += extra
    if posix:
        return f"real {real:.2f}\nuser {user:.2f}\nsys {sys_:.2f}"
    fmt = lambda v: f"{int(v // 60)}m{v % 60:.3f}s"
    return f"\nreal\t{fmt(real)}\nuser\t{fmt(user)}\nsys\t{fmt(sys_)}"


# What bash 5.2.37 sets by itself, beside the environment: recorded 2026-10-13 from an
# interactive login bash of the reference machine's version on a terminal (the Debian
# 13 arm64 userland; its PS1 equals the one in gt_frontdoor_2026-09.json), and from
# `bash -c` for the mode without a terminal. A name that is in neither table and not
# in the session's environment is unset, and bash prints nothing for it.
_BASH_ALWAYS = {
    "BASH_VERSION": "5.2.37(1)-release", "BASH": "/usr/bin/bash", "BASH_VERSINFO": "5",
    "OSTYPE": "linux-gnu", "MACHTYPE": "aarch64-unknown-linux-gnu", "HOSTTYPE": "aarch64",
    "PS4": "+ ", "OPTIND": "1", "OPTERR": "1", "BASH_SUBSHELL": "0", "IFS": " \t\n",
    "COMP_WORDBREAKS": " \t\n\"'@><=;|&(:",
    "BASH_LOADABLES_PATH": "/usr/local/lib/bash:/usr/lib/bash:/opt/local/lib/bash:"
                           "/usr/pkg/lib/bash:/opt/pkg/lib/bash:.",
}
_BASH_INTERACTIVE = {
    "PS1": "${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ ", "PS2": "> ", "-": "himBHs",
    "HISTSIZE": "500", "HISTFILESIZE": "500", "MAILCHECK": "60", "BASH_ARGV0": "-bash",
    "SHELLOPTS": "braceexpand:emacs:hashall:histexpand:history:interactive-comments:monitor",
    "BASHOPTS": "checkwinsize:cmdhist:complete_fullquote:expand_aliases:extquote:force_fignore:"
                "globasciiranges:globskipdots:hostcomplete:interactive_comments:login_shell:"
                "patsub_replacement:progcomp:promptvars:sourcepath",
}
_BASH_NO_TERMINAL = {
    "-": "hBc", "TERM": "dumb", "BASH_ARGV0": "bash",      # TERM: Ground Truth, 2026-10-01
    "SHELLOPTS": "braceexpand:hashall:interactive-comments",
    "BASHOPTS": "checkwinsize:cmdhist:complete_fullquote:extquote:force_fignore:globasciiranges:"
                "globskipdots:hostcomplete:interactive_comments:patsub_replacement:progcomp:"
                "promptvars:sourcepath",
}
# Set by bash, but changing with every command in ways not followed here: the model's.
_BASH_NOT_FOLLOWED = frozenset({"HISTCMD", "LINENO", "BASH_COMMAND", "FUNCNAME", "BASH_LINENO",
                                "BASH_SOURCE", "BASH_ARGC", "BASH_ARGV"})
BASH_SETS = (frozenset(_BASH_ALWAYS) | frozenset(_BASH_INTERACTIVE) | frozenset(_BASH_NO_TERMINAL)
             | _BASH_NOT_FOLLOWED | frozenset({
                 "UID", "EUID", "GROUPS", "HOSTNAME", "PPID", "BASHPID", "PIPESTATUS", "DIRSTACK",
                 "SECONDS", "EPOCHSECONDS", "EPOCHREALTIME", "RANDOM", "SRANDOM", "HISTFILE",
                 "LINES", "COLUMNS"}))


def bash_sets(sess: Session, name: str) -> str | None:
    """The value of a variable bash sets by itself, or None if `name` is not one."""
    if name in sess.unset_vars:
        return None
    if name in _BASH_NOT_FOLLOWED:
        raise NotBuiltin(f"${name} changes with every command")
    table = _BASH_INTERACTIVE if sess.terminal else _BASH_NO_TERMINAL
    if name in table:
        return table[name]
    if name in _BASH_ALWAYS:
        return _BASH_ALWAYS[name]
    uid = "0" if sess.username == "root" else "1000"
    now = machine.now()
    live = {
        "UID": lambda: uid, "EUID": lambda: uid, "GROUPS": lambda: uid,
        "HOSTNAME": lambda: machine.HOSTNAME, "PPID": lambda: str(sess.pid - 11),
        "BASHPID": lambda: str(sess.pid), "PIPESTATUS": lambda: str(sess.last_exit),
        "DIRSTACK": lambda: sess.cwd,
        "SECONDS": lambda: str(max(int((now - sess.login_at).total_seconds()), 0)),
        "EPOCHSECONDS": lambda: str(int(now.timestamp())),
        "EPOCHREALTIME": lambda: f"{now.timestamp():.6f}",
        "RANDOM": lambda: str(random.randrange(32768)),
        "SRANDOM": lambda: str(random.getrandbits(32)),
    }
    if sess.terminal:
        live.update({"HISTFILE": lambda: f"{sess.home}/.bash_history",
                     "LINES": lambda: str(sess.rows), "COLUMNS": lambda: str(sess.cols)})
    return live[name]() if name in live else None


def _arith_end(rest: str) -> int:
    """Index in `rest` (which starts with "((") of the "))" that closes it."""
    depth, i = 0, 2
    while i < len(rest):
        if rest[i] == "(":
            depth += 1
        elif rest[i] == ")":
            if depth == 0:
                if rest.startswith("))", i):
                    return i
                raise NotBuiltin("arithmetic form")
            depth -= 1
        i += 1
    raise NotBuiltin("unclosed arithmetic")


def _subst_end(rest: str) -> int:
    """Index in `rest` (which starts with "(") of the ")" that closes it, quotes heeded."""
    depth, i, q = 0, 0, None
    while i < len(rest):
        c = rest[i]
        if q:
            if c == q:
                q = None
            elif c == "\\" and q == '"':
                i += 1
        elif c in "'\"":
            q = c
        elif c == "\\":
            i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise NotBuiltin("unclosed command substitution")


def subst_spans_unsafe(line: str) -> bool:
    """True if a $( ... ) holds a character the line's parsers would split at (they run
    before expansion), or is not closed."""
    for m in re.finditer(r"\$\((?!\()", line):
        try:
            end = m.start() + 1 + _subst_end(line[m.start() + 1:])
        except NotBuiltin:
            return True
        if re.search(r"[<>|&;\n`]", line[m.start():end]):
            return True
    return False


def _arith_span(line: str, i: int) -> int | None:
    """The index just after the $(( ... )) that starts at line[i], or None if it is not
    closed on this line."""
    try:
        return i + 1 + _arith_end(line[i + 1:]) + 2
    except NotBuiltin:
        return None


def arith_spans_unsafe(line: str) -> bool:
    """True if a $(( ... )) holds a character the line's parsers would take for a
    pipe, a list, or a redirection (they run before expansion)."""
    for m in re.finditer(r"\$\(\(", line):
        end = _arith_span(line, m.start())
        if end is None or re.search(r"[<>|&;]", line[m.start():end]):
            return True
    return False


_ARITH_TOKEN = re.compile(r"\s*(0[xX][0-9a-fA-F]+|\d+|[A-Za-z_]\w*|\*\*|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%<>&|^!~?:()])")
_ARITH_BINARY = [                      # lowest first; ** is handled with the unary operators
    ("||",), ("&&",), ("|",), ("^",), ("&",), ("==", "!="), ("<", "<=", ">", ">="),
    ("<<", ">>"), ("+", "-"), ("*", "/", "%")]


def _wrap64(v: int) -> int:
    return (v + 2**63) % 2**64 - 2**63


def bash_arith(text: str, sess: Session) -> int:
    """$(( ... )) as bash 5.2 computes it: 64-bit signed integers that wrap, C division
    and remainder, ** binding looser than a unary minus (bash 5.2.37 in the Debian 13
    arm64 userland, 2026-10-14). Assignments, ++/--, `base#n` and every error (division
    by zero, a syntax error) are not done here: bash's error also ends the line."""
    # $x and ${x} are the variable x; $? $$ $# what they always are
    text = re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", lambda m: m.group(1) or m.group(2), text)
    text = text.replace("$?", str(sess.last_exit)).replace("$$", str(sess.pid)).replace("$#", "0")
    if "$" in text or "`" in text:
        raise NotBuiltin("arithmetic with a substitution")
    toks, pos = [], 0
    while pos < len(text.rstrip()):
        m = _ARITH_TOKEN.match(text, pos)
        if not m:
            raise NotBuiltin("arithmetic token")
        toks.append(m.group(1))
        pos = m.end()
    if any(a in ("+", "-") and b == a for a, b in zip(toks, toks[1:])) or "=" in "".join(
            t for t in toks if t not in ("==", "!=", "<=", ">=")):
        raise NotBuiltin("arithmetic with ++, -- or an assignment")
    toks.append(None)
    at = [0]

    def peek():
        return toks[at[0]]

    def take():
        at[0] += 1
        return toks[at[0] - 1]

    def value(name: str) -> int:
        raw = sess.vars.get(name, sess.env.get(name, bash_sets(sess, name) or "0")).strip() or "0"
        if not re.fullmatch(r"-?\d+", raw):
            raise NotBuiltin("a variable that is not a number")
        return int(raw)

    def number(tok: str) -> int:
        if tok.lower().startswith("0x"):
            return int(tok, 16)
        if len(tok) > 1 and tok.startswith("0"):
            if set(tok) - set("01234567"):
                raise NotBuiltin("bad octal")
            return int(tok, 8)
        return int(tok)

    def primary() -> int:
        tok = take()
        if tok is None:
            raise NotBuiltin("arithmetic syntax")
        if tok == "(":
            v = ternary()
            if take() != ")":
                raise NotBuiltin("arithmetic syntax")
            return v
        if tok in ("-", "+", "!", "~"):
            v = primary()
            return _wrap64({"-": -v, "+": v, "!": int(not v), "~": ~v}[tok])
        if tok[0].isdigit():
            return _wrap64(number(tok))
        if re.fullmatch(r"[A-Za-z_]\w*", tok):
            return value(tok)
        raise NotBuiltin("arithmetic syntax")

    def power() -> int:
        base = primary()
        if peek() == "**":
            take()
            exp = power()                       # right to left
            if exp < 0:
                raise NotBuiltin("negative exponent")
            return _wrap64(pow(base, exp, 2**64))
        return base

    def binary(level: int) -> int:
        if level == len(_ARITH_BINARY):
            return power()
        v = binary(level + 1)
        while peek() in _ARITH_BINARY[level]:
            op, w = take(), None
            w = binary(level + 1)
            if op in ("/", "%") and w == 0:
                raise NotBuiltin("division by 0")
            if op in ("<<", ">>") and not 0 <= w < 64:
                raise NotBuiltin("shift count")
            if op == "/":
                r = abs(v) // abs(w) * (1 if (v < 0) == (w < 0) else -1)
            elif op == "%":
                r = abs(v) % abs(w) * (1 if v >= 0 else -1)
            else:
                r = {"||": lambda: int(bool(v or w)), "&&": lambda: int(bool(v and w)),
                     "|": lambda: v | w, "^": lambda: v ^ w, "&": lambda: v & w,
                     "==": lambda: int(v == w), "!=": lambda: int(v != w),
                     "<": lambda: int(v < w), "<=": lambda: int(v <= w),
                     ">": lambda: int(v > w), ">=": lambda: int(v >= w),
                     "<<": lambda: v << w, ">>": lambda: v >> w,
                     "+": lambda: v + w, "-": lambda: v - w, "*": lambda: v * w}[op]()
            v = _wrap64(r)
        return v

    def ternary() -> int:
        cond = binary(0)
        if peek() == "?":
            take()
            a = ternary()
            if take() != ":":
                raise NotBuiltin("arithmetic syntax")
            b = ternary()
            return a if cond else b
        return cond

    if toks == [None]:
        return 0                                # $(( )) is 0
    v = ternary()
    if peek() is not None:
        raise NotBuiltin("arithmetic syntax")
    return v


def expand(s: str, sess: Session, globs: bool = False, split: bool = True) -> str:
    """$VAR ${VAR} $$ $? $0 and a leading ~, outside single quotes. Anything fancier
    (command substitution, arithmetic, redirection) is not a builtin's job. An unquoted
    * ? [ is refused too, unless `globs`: then it is marked with GLOB for Shell._words,
    which knows what is in the current directory."""
    shell_vars = {"$": str(sess.pid), "?": str(sess.last_exit), "#": "0",
                  "0": "-bash" if sess.terminal else "bash"}
    out, i, q = [], 0, None
    while i < len(s):
        c = s[i]
        if c == "'" and q != '"':
            q = None if q == "'" else "'"
            out.append(c)
        elif c == '"' and q != "'":
            q = None if q == '"' else '"'
            out.append(c)
        elif q == "'":
            out.append(c)
        elif c == "\\" and i + 1 < len(s):
            # A backslash keeps the next character from meaning anything: `\*` is no
            # pattern, `\$HOME` no variable. Within "..." it does so only for $ ` " \.
            nxt = s[i + 1]
            if q == '"' and nxt in "$`":
                out.append(nxt)
            elif q == '"' and nxt not in '"\\':
                out.append(c)
                i += 1
                continue
            else:
                out.append(c + nxt)
            i += 2
            continue
        elif c == "`" or (c in "<>" and q is None) or (c in "*?[" and q is None and not globs):
            raise NotBuiltin(f"needs a real shell: {c}")      # < > inside "..." are text
        elif c in "*?[" and q is None:
            out.append(GLOB + c)
        elif c == "$":
            rest = s[i + 1:]
            if rest.startswith("(("):
                in_scope("arithmetic")
                end = _arith_end(rest)
                val = str(bash_arith(rest[2:end], sess))
                out.append(val)
                i += end + 3
                continue
            if rest.startswith("("):
                # $( ... ): the inner command, answered in code in a subshell, its
                # output without the final line breaks; split into words unless quoted
                if sess.run_sub is None:
                    raise NotBuiltin("command substitution")
                in_scope("substitution")
                end = _subst_end(rest)
                val = sess.run_sub(rest[1:end])
                if q == '"':
                    if re.search(r'["\\$`]', val):
                        raise NotBuiltin("a substitution's output that would need quoting")
                    out.append(val)
                elif split:
                    out.append(" ".join(shlex.quote(w) for w in val.split()))
                else:
                    out.append(shlex.quote(val) if val else "")
                i += end + 2
                continue
            m = re.match(r"\{(\w+)\}|(\w+|[$?#-])", rest)
            if not m:
                out.append(c)
            else:
                name = m.group(1) or m.group(2)
                if name.isdigit() and name != "0":
                    val = ""
                elif name in shell_vars:
                    val = shell_vars[name]
                elif name in sess.vars:               # assigned by the attacker
                    val = sess.vars[name]
                elif name in sess.env:                # exported
                    val = sess.env[name]
                else:
                    val = bash_sets(sess, name) or ""
                if q is None and split:
                    # Unquoted: bash splits the value into words at blanks (so
                    # `echo $PS2` prints `>` without its space, `echo $IFS` nothing).
                    out.append(" ".join(shlex.quote(w) for w in val.split()))
                else:
                    out.append(shlex.quote(val) if q is None and val else val)
                i += m.end()
        elif c == "~" and q is None and (i == 0 or s[i - 1] in " =:") \
                and (i + 1 == len(s) or s[i + 1] in "/ "):
            out.append(sess.home)
        else:
            out.append(c)
        i += 1
    return "".join(out)


_OPENERS = {"if": "fi", "for": "done", "while": "done", "until": "done", "select": "done",
            "case": "esac"}


def unfinished(text: str) -> str | None:
    """What bash still waits for at the end of `text`, or None if the command is whole.

    One of: a quote character, "`", ")" (an open `$(` or subshell), "\\" (the line ends
    in a backslash), "op" (it ends in | && ||), "heredoc", or "block" (if/for/while/case
    or { without its closing word). An interactive bash answers each of these with the
    PS2 prompt and reads on; `bash -c` reports a syntax error (Shell.run, Shell._exec).
    Function bodies and other rarer forms are not followed: they count as whole."""
    stack: list[str] = []            # open quotes and parentheses, innermost last
    docs: list[tuple[str, bool]] = []   # here-documents still to be read: (word, <<-)
    bare: list[str] = []             # the text outside quotes, for the checks at the end
    backslash = False
    for ln in text.split("\n"):
        if docs and not stack:       # a line of a here-document's body
            word, dash = docs[0]
            if (ln.lstrip("\t") if dash else ln) == word:
                docs.pop(0)
            continue
        backslash, i = False, 0
        while i < len(ln):
            c, top = ln[i], stack[-1] if stack else None
            if top == "'":
                if c == "'":
                    stack.pop()
            elif top == "`":
                if c == "\\":
                    i += 1
                elif c == "`":
                    stack.pop()
            elif top == '"':
                if c == "\\":
                    i += 1
                elif c == '"':
                    stack.pop()
                elif c == "`":
                    stack.append("`")
                elif ln.startswith("$((", i) and _arith_span(ln, i):
                    i = _arith_span(ln, i) - 1
                elif ln.startswith("$(", i):
                    stack.append(")")
                    i += 1
            elif c == "\\":
                backslash = i + 1 == len(ln)
                i += 1
            elif ln.startswith("$((", i) and _arith_span(ln, i):
                i = _arith_span(ln, i) - 1           # $(( 1<<2 )): no here-document
                bare.append("0")
            elif c in "'\"`":
                stack.append(c)
                bare.append("Q")
            elif c == "(":
                stack.append(")")
                bare.append(" ")
            elif c == ")":
                if top == ")":
                    stack.pop()
                bare.append(" ")
            elif c == "#" and (i == 0 or ln[i - 1] in " \t;"):
                break
            elif ln.startswith("<<", i) and not ln.startswith("<<<", i):
                m = re.match(r"<<(-?)\s*(['\"]?)([^\s'\";|&<>()]+)\2", ln[i:])
                if m:
                    docs.append((m.group(3), bool(m.group(1))))
                    i += m.end() - 1
            elif ln.startswith("<<<", i):
                i += 2
            else:
                bare.append(c)
            i += 1
        bare.append("\n")
    if stack:
        return stack[-1]
    if docs:
        return "heredoc"
    if backslash:
        return "\\"
    flat = "".join(bare).rstrip()
    if re.search(r"(\|\|?|&&)$", flat):
        return "op"
    want: list[str] = []
    for seg in re.split(r"\|\||&&|[;\n|&]", flat):
        toks = seg.split()
        while toks:
            t = toks.pop(0)
            if t in ("then", "do", "else", "elif", "!", "time"):
                continue
            if t == "{":
                want.append("}")
                continue
            if t in _OPENERS:
                want.append(_OPENERS[t])
            elif want and t == want[-1]:
                want.pop()
                continue
            break
    return "block" if want else None


def strip_comments(text: str) -> str:
    """The line without its comments: a # at the start of a word, outside quotes, to the
    end of that line. bash drops them before anything runs, so neither the code nor the
    model has any use for them, and a comment is the easiest place to put an instruction
    for a model. Left alone when a here-document is involved (its body is not code)."""
    if "#" not in text or "<<" in text:
        return text
    out, q, i, cut = [], None, 0, False
    while i < len(text):
        c = text[i]
        if q:
            out.append(c)
            if c == "\\" and q == '"' and i + 1 < len(text):
                out.append(text[i + 1])
                i += 1
            elif c == q:
                q = None
        elif c in "'\"":
            q = c
            out.append(c)
        elif c == "\\" and i + 1 < len(text):
            out += [c, text[i + 1]]
            i += 1
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;&|("):
            cut = True
            i = text.find("\n", i)
            if i < 0:
                break
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out).rstrip(" \t") if cut else text


_PF_ESC = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r",
           "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'", "?": "?"}
_PF_SPEC = re.compile(r"%([-+ 0#]*)(\d*)(?:\.(\d*))?([sdiuxXocb%])")


def _pf_escapes(text: str, in_b: bool = False) -> str:
    """Backslash escapes as bash's printf reads them in its format (and, with `in_b`,
    in a %b argument). Checked against bash 5.2.37 (offline/debian13-arm64)."""
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c != "\\" or i + 1 == len(text):
            out.append(c)
            i += 1
            continue
        n = text[i + 1]
        if n in _PF_ESC:
            out.append(_PF_ESC[n])
            i += 2
        elif n == "x" and re.match(r"[0-9a-fA-F]{1,2}", text[i + 2:]):
            m = re.match(r"[0-9a-fA-F]{1,2}", text[i + 2:])
            out.append(chr(int(m.group(), 16)))
            i += 2 + m.end()
        elif n in "01234567":
            m = re.match(r"0?[0-7]{1,3}" if in_b else r"[0-7]{1,3}", text[i + 1:])
            out.append(chr(int(m.group(), 8)))
            i += 1 + m.end()
        elif n in "uUc":
            raise NotBuiltin("printf with \\u, \\U or \\c")
        else:
            out += [c, n]                         # an unknown escape stays as typed
            i += 2
    text = "".join(out)
    if any(ord(ch) > 126 for ch in text):
        raise NotBuiltin("printf of bytes outside ASCII")
    return text


def bash_printf(args: list[str]) -> str:
    """What bash's `printf format [arguments]` writes, for text, backslash escapes and
    %s %b %c %d %i %u %x %X %o %% with flags, width and precision: the format is used
    again while arguments are left, a missing argument is empty or 0. Anything else
    (%f, %q, %(..)T, `*`, a word that is not a number for %d, -v) is NotBuiltin, so the
    model answers rather than code guessing."""
    if args[:1] == ["--"]:
        args = args[1:]
    if not args or (args[0].startswith("-") and len(args[0]) > 1 and "%" not in args[0]
                    and "\\" not in args[0] and not args[0][1:].isdigit()):
        raise NotBuiltin("printf with an option, or without a format")
    fmt, rest = args[0], list(args[1:])
    if "%" in _PF_SPEC.sub("", fmt):
        raise NotBuiltin("printf with a format this code does not do")
    pieces, takes = [], 0
    pos = 0
    for m in _PF_SPEC.finditer(fmt):
        pieces.append(_pf_escapes(fmt[pos:m.start()]))
        pieces.append(m)
        takes += m.group(4) != "%"
        pos = m.end()
    pieces.append(_pf_escapes(fmt[pos:]))
    out = []
    while True:
        for p in pieces:
            if isinstance(p, str):
                out.append(p)
                continue
            flags, width, prec, conv = p.group(1), p.group(2), p.group(3), p.group(4)
            if conv == "%":
                out.append("%")
                continue
            arg = rest.pop(0) if rest else None
            if conv in "sbc":
                val = arg or ""
                if conv == "b":
                    val = _pf_escapes(val, in_b=True)
                if conv == "c":
                    val = val[:1]
                elif prec is not None:
                    val = val[:int(prec or 0)]
                out.append(val.ljust(int(width)) if "-" in flags and width
                           else val.rjust(int(width or 0)))
                continue
            text = (arg or "0").strip()
            if not re.fullmatch(r"[+-]?(0[xX][0-9a-fA-F]+|\d+)", text):
                raise NotBuiltin("printf of a word that is not a number")
            num = int(text, 0 if not re.fullmatch(r"[+-]?0\d+", text) else 8)
            if num < 0 and conv in "uxXo":
                raise NotBuiltin("printf of a negative number as unsigned")
            pyconv = {"i": "d", "u": "d"}.get(conv, conv)
            spec = "%" + flags + (width or "") + ("." + prec if prec is not None else "") + pyconv
            out.append(spec % num)
        if not rest or not takes:
            break
    return "".join(out)


_HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)([A-Za-z_][\w.-]*)\2")


def take_heredoc(line: str) -> tuple[str, str | None]:
    """A command with one here-document, `cmd << END` ... `END`: (the command line
    without the `<< END`, the document), or (line, None) when there is none. Only the
    plain shape: one command line, one document, nothing after its end. In a document
    whose end word is not quoted bash expands $ and backticks; such a body is left to
    the model unless it has none of them."""
    first, nl, rest = line.partition("\n")
    if "<<" not in first or "<<<" in first:
        return line, None
    m = _HEREDOC.search(first)
    if not m or not nl or first[:m.start()].count("'") % 2 or first[:m.start()].count('"') % 2 \
            or _HEREDOC.search(first, m.end()):
        raise NotBuiltin("a here-document this code does not do")
    body = rest.split("\n")
    strip = (lambda s: s.lstrip("\t")) if m.group(1) else (lambda s: s)
    if not body or strip(body[-1]) != m.group(3) or any(strip(b) == m.group(3) for b in body[:-1]):
        raise NotBuiltin("a here-document with more after its end")
    text = "\n".join(strip(b) for b in body[:-1])
    if not m.group(2) and re.search(r"[$`\\]", text):
        raise NotBuiltin("a here-document bash would expand")
    return (first[:m.start()] + " " + first[m.end():]).strip(), text


# What may read a here-document or a here-string in code: `cat` alone, and the filters.
_DIGESTS = {"md5sum": "md5", "sha1sum": "sha1", "sha224sum": "sha224", "sha256sum": "sha256",
            "sha384sum": "sha384", "sha512sum": "sha512", "b2sum": "blake2b"}


_STDIN_FILTERS = frozenset({"grep", "head", "tail", "sort", "wc", "base64", "cat", "tr", *_DIGESTS})


def resolve(sess: Session, path: str) -> str:
    return posixpath.normpath(posixpath.join(sess.cwd, path)).replace("//", "/")


def split_redirect(seg: str) -> tuple[str, str | None, bool]:
    """A single trailing `> file` or `>> file` outside quotes, else (seg, None, False)."""
    m = re.search(r"\s*(>>?)\s*([^\s'\"<>|;&]+)\s*$", seg)
    if not m or seg[:m.start()].count("'") % 2 or seg[:m.start()].count('"') % 2:
        return seg, None, False
    if re.search(r"[<>]", seg[:m.start()]):
        raise NotBuiltin("more than one redirection")
    return seg[:m.start()], m.group(2), m.group(1) == ">>"


def is_dir(sess: Session, path: str) -> bool:
    if path in sess.fs.removed:
        return False
    return path in KNOWN_DIRS or sess.fs.created.get(path) == "dir"


# ---------------------------------------------------------------- builtins

def _grep(lines: list[str], argv: list[str]) -> list[str]:
    opts = [a for a in argv[1:] if a.startswith("-")]
    if not set(opts) <= {"-v", "-i", "-c"}:
        raise NotBuiltin(f"grep {' '.join(opts)}")     # never silently ignore an option
    invert = "-v" in argv
    ignore = "-i" in argv
    pats = [a for a in argv[1:] if not a.startswith("-")]
    if len(pats) != 1:
        raise NotBuiltin("grep form")
    rx = re.compile(re.escape(pats[0]) if not re.search(r"[\\^$.\[*]", pats[0]) else pats[0],
                    re.I if ignore else 0)
    return [ln for ln in lines if bool(rx.search(ln)) != invert]


def _count(argv: list[str], default: int = 10) -> int:
    for j, a in enumerate(argv[1:], 1):
        if re.fullmatch(r"-\d+", a):
            return int(a[1:])
        if a == "-n" and j + 1 < len(argv):
            if not re.fullmatch(r"-?\d+", argv[j + 1]):
                raise NotBuiltin("head/tail -n +N or a bad count")     # +N: from line N on
            return int(argv[j + 1])
    return default


class Unterminated(str):
    """Output whose last line has no line break (`base64 -d` of text without one): the
    prompt then follows on the same line, as after `echo -n`."""


def _bytes_in(text: str) -> bytes:
    """What a pipe carries: the lines of a code answer, each ending in a line break."""
    if isinstance(text, Unterminated):
        return text.encode()
    return (text + "\n").encode() if text else b""


_TR_CLASSES = {"lower": "abcdefghijklmnopqrstuvwxyz", "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
               "digit": "0123456789", "space": " \t\n\v\f\r"}
_TR_CLASSES["alpha"] = _TR_CLASSES["upper"] + _TR_CLASSES["lower"]
_TR_CLASSES["alnum"] = _TR_CLASSES["digit"] + _TR_CLASSES["alpha"]


def _tr_set(spec: str) -> list[str]:
    out, i = [], 0
    while i < len(spec):
        m = re.match(r"\[:(\w+):\]", spec[i:])
        if m:
            if m.group(1) not in _TR_CLASSES:
                raise NotBuiltin("tr class")
            out += list(_TR_CLASSES[m.group(1)])
            i += m.end()
            continue
        c = spec[i]
        if c == "\\" and i + 1 < len(spec):
            c = {"n": "\n", "t": "\t", "\\": "\\"}.get(spec[i + 1])
            if c is None:
                raise NotBuiltin("tr escape")
            i += 1
        elif c == "[" or ord(c) > 127:
            raise NotBuiltin("tr set form")
        if i + 2 < len(spec) and spec[i + 1] == "-":
            lo, hi = ord(c), ord(spec[i + 2])
            if hi < lo:
                raise NotBuiltin("tr range")
            out += [chr(x) for x in range(lo, hi + 1)]
            i += 3
            continue
        out.append(c)
        i += 1
    return out


def _tr(text: str, args: list[str]) -> tuple[str, int]:
    """coreutils `tr` with SET1 SET2, -d SET or -s SET: ranges, [:lower:] and the like,
    \\n \\t. SET2 shorter than SET1 is filled up with its last character."""
    data = text if isinstance(text, Unterminated) else (text + "\n" if text else "")
    if len(args) == 2 and args[0] in ("-d", "-s"):
        chars = set(_tr_set(args[1]))
        if args[0] == "-d":
            out = "".join(c for c in data if c not in chars)
        else:
            out, prev = [], None
            for c in data:
                if not (c == prev and c in chars):
                    out.append(c)
                prev = c
            out = "".join(out)
    elif len(args) == 2 and not args[0].startswith("-"):
        a, b = _tr_set(args[0]), _tr_set(args[1])
        if not b:
            raise NotBuiltin("tr with an empty SET2")
        b = b + [b[-1]] * (len(a) - len(b))
        table = {}
        for x, y in zip(a, b):
            table[x] = y                       # a repeated character: the last mapping wins
        out = "".join(table.get(c, c) for c in data)
    else:
        raise NotBuiltin("tr form")
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out):
        raise NotBuiltin("tr output with control characters")
    return (out[:-1], 0) if out.endswith("\n") else (Unterminated(out), 0)


def byte_filter(text: str, argv: list[str]) -> tuple[str, int] | None:
    """The filters that read bytes rather than lines (coreutils 9.7, the Debian 13 arm64
    userland, 2026-10-14). None: not one of them."""
    cmd, args = argv[0], argv[1:]
    if cmd in _DIGESTS:
        if args not in ([], ["-"]):
            raise NotBuiltin(f"{cmd} with arguments")
        return f"{hashlib.new(_DIGESTS[cmd], _bytes_in(text)).hexdigest()}  -", 0
    if cmd == "base64":
        decode, wrap = False, 76
        while args:
            a = args.pop(0)
            if a in ("-d", "--decode"):
                decode = True
            elif a in ("-w", "--wrap") and args and args[0].isdigit():
                wrap = int(args.pop(0))
            elif re.fullmatch(r"--wrap=\d+|-w\d+", a):
                wrap = int(re.sub(r"\D", "", a))
            else:
                raise NotBuiltin("base64 option")
        if decode:
            data = re.sub(rb"\s", b"", _bytes_in(text))
            if not re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", data) or len(data) % 4:
                raise NotBuiltin("base64 -d of invalid input")      # partial output + error
            try:
                out = base64.b64decode(data, validate=True).decode()
            except (ValueError, UnicodeDecodeError):
                raise NotBuiltin("base64 -d of bytes that are not text")
            if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", out):
                raise NotBuiltin("base64 -d of control characters")
            return (out[:-1], 0) if out.endswith("\n") else (Unterminated(out), 0)
        enc = base64.b64encode(_bytes_in(text)).decode()
        return "\n".join(enc[i:i + wrap] for i in range(0, len(enc), wrap)) if wrap else enc, 0
    if cmd == "tr":
        return _tr(text, args)
    if cmd == "wc" and args != ["-l"]:
        flags = "".join(a[1:] for a in args if re.fullmatch(r"-[lwcm]+", a))
        if len(flags) != sum(len(a) - 1 for a in args) or any(not a.startswith("-") for a in args):
            raise NotBuiltin("wc form")
        data = _bytes_in(text)
        counts = {"l": data.count(b"\n"), "w": len(data.split()),
                  "m": len(data.decode()), "c": len(data)}
        shown = [counts[k] for k in "lwmc" if k in (flags or "lwc")]
        if len(shown) == 1:
            return str(shown[0]), 0
        return " ".join(f"{v:7d}" for v in shown), 0       # stdin: GNU wc's minimum width
    return None


def filter_stage(text: str, argv: list[str]) -> tuple[str, int]:
    if argv == ["cat"] or argv == ["cat", "-"]:
        return text, 0                              # passes everything on unchanged
    if argv == ["cat", "-n"] and not isinstance(text, Unterminated):
        in_scope("text_tools")
        # coreutils: the number right-aligned in six columns, then a tab
        return "\n".join(f"{i:6d}\t{ln}" for i, ln in enumerate(text.split("\n") if text else [], 1)), 0
    done = byte_filter(text, argv)
    if done is not None:
        in_scope("text_tools")
        return done
    if isinstance(text, Unterminated):
        raise NotBuiltin("a line filter on text without a final line break")
    lines = text.split("\n") if text else []
    cmd = argv[0]
    # Only the options implemented here; anything else goes to the model rather than
    # being silently ignored (`sort -n`, `head -c`, `grep -E` would give wrong answers).
    opts = [a for a in argv[1:] if a.startswith("-")]
    if cmd == "sort" and not set(opts) <= {"-r"}:
        raise NotBuiltin(f"sort {' '.join(opts)}")
    if cmd in ("head", "tail") and not all(re.fullmatch(r"-\d+|-n", a) for a in opts):
        raise NotBuiltin(f"{cmd} {' '.join(opts)}")
    if cmd == "sort":
        # glibc's en_GB collation ignores punctuation on the first pass, which is why
        # `_=/usr/bin/env` sorts between USER and XDG_* in gt43 n=37.
        lines = sorted(lines, key=lambda s: (re.sub(r"[^0-9a-z]", "", s.lower()), s),
                       reverse="-r" in argv)
        return "\n".join(lines), 0
    if cmd == "head":
        return "\n".join(lines[:_count(argv)]), 0
    if cmd == "tail":
        n = _count(argv)
        return "\n".join(lines[-n:] if n else []), 0
    if cmd == "grep":
        got = _grep(lines, argv)
        if "-c" in argv:
            return str(len(got)), 0 if got else 1
        return "\n".join(got), 0 if got else 1
    if cmd == "wc" and argv[1:] == ["-l"]:
        return str(len(lines)), 0
    raise NotBuiltin(f"filter {cmd}")


def chmod_mode(spec: str, old: int | None, is_dir: bool) -> int:
    """The permission bits after `chmod spec`: octal (`777`, `0600`) or symbolic
    (`+x`, `u+x`, `go-w`, `a=r`, comma-separated). Raises NotBuiltin for anything else,
    and for a symbolic change of a file whose mode the code does not know."""
    if re.fullmatch(r"0?[0-7]{3}", spec):
        return int(spec, 8)
    if old is None or not re.fullmatch(r"([ugoa]*[-+=][rwx]*)(,[ugoa]*[-+=][rwx]*)*", spec):
        raise NotBuiltin("chmod mode")
    mode = old
    for part in spec.split(","):
        who, op, perms = re.fullmatch(r"([ugoa]*)([-+=])([rwx]*)", part).groups()
        bits = sum({"r": 4, "w": 2, "x": 1}[c] for c in perms)
        shifts = [s for c, s in (("u", 6), ("g", 3), ("o", 0)) if not who or c in who or "a" in who]
        mask = sum(bits << sh for sh in shifts)
        if not who and op != "=":
            mask &= ~0o022 if op == "+" else ~0     # no `who`: the umask limits what is added
        if op == "+":
            mode |= mask
        elif op == "-":
            mode &= ~mask
        else:
            mode = (mode & ~sum(7 << sh for sh in shifts)) | mask
    return mode


def mode_string(mode: int, is_dir: bool) -> str:
    out = "d" if is_dir else "-"
    for sh in (6, 3, 0):
        out += "".join(c if mode >> sh & b else "-" for c, b in (("r", 4), ("w", 2), ("x", 1)))
    return out


def ls_columns(names: list[str], width: int) -> str:
    """GNU ls's default layout on a terminal (`-C`, coreutils 9.7): as many columns as fit
    in `width`, filled top to bottom, each two wider than its longest name except the
    last, and the gap to the next column made of tabs where a tab does not overshoot
    (tab size 8), as `ls /` shows on Ground Truth (corpus n=104, 326)."""
    if not names:
        return ""
    n = len(names)
    best = None
    for ncols in range(1, n + 1):
        rows = -(-n // ncols)
        if -(-n // rows) != ncols:
            continue                                # GNU never leaves a column empty
        widths = [max(len(x) for x in names[c * rows:(c + 1) * rows]) + 2 for c in range(ncols)]
        widths[-1] -= 2
        if sum(widths) < width:
            best = (ncols, rows, widths)
    if best is None:
        best = (1, n, [max(len(x) for x in names)])
    ncols, rows, widths = best
    out = []
    for r in range(rows):
        line, pos = [], 0
        cells = [(c, names[c * rows + r]) for c in range(ncols) if c * rows + r < n]
        for k, (c, name) in enumerate(cells):
            line.append(name)
            if k + 1 < len(cells):
                here, target = pos + len(name), pos + widths[c]
                while here < target:
                    if target // 8 > (here + 1) // 8:
                        line.append("\t")
                        here += 8 - here % 8
                    else:
                        line.append(" ")
                        here += 1
            pos += widths[c]
        out.append("".join(line))
    return "\n".join(out)


class Shell:
    def __init__(self, knowledge: Knowledge, pool, store: SessionStore, boot: float,
                 k_examples: int = 6, docker=None):
        self.k, self.pool, self.store, self.boot, self.k_examples = \
            knowledge, pool, store, boot, k_examples
        self.docker = docker            # the shared Docker state (docker.py)
        self.line_bound = False         # config `line_bound`, set by the relay
        self.builtins = {
            "cd": self._cd, "pwd": self._pwd, "echo": self._echo, "printf": self._printf,
            "export": self._export,
            "unset": self._unset, "env": self._env, "printenv": self._printenv,
            "date": self._date, "uptime": self._uptime, "history": self._history,
            "who": self._who, "w": self._w, "users": self._users, "tty": self._tty,
            "true": lambda s, a: ("", 0), "false": lambda s, a: ("", 1),
            ":": lambda s, a: ("", 0), "cat": self._cat, "more": self._cat,
            "touch": self._touch, "mkdir": self._mkdir, "rm": self._rm, "chmod": self._chmod,
            "ls": self._ls, "free": self._free, "df": self._df,
            "ps": self._ps, "top": self._top, "pgrep": self._pgrep, "pidof": self._pidof,
            "ss": self._ss, "netstat": self._netstat, "route": self._route, "ip": self._ip, "ifconfig": self._ifconfig,
            "hostname": self._hostname, "ping": self._ping, "docker": self._docker,
            "uname": self._uname, "nproc": self._nproc, "id": self._id, "groups": self._groups,
            "whoami": self._whoami_cmd,
            "which": self._which, "type": self._type, "command": self._command,
            "seq": self._seq, "expr": self._expr, "getconf": self._getconf,
            "umask": self._umask, "alias": self._alias, "stty": self._stty, "help": self._help,
            "declare": self._declare, "locale": self._locale, "test": self._test, "[": self._test,
            "rmdir": self._rmdir, "cp": self._cp, "mv": self._mv,
            "head": self._filter_file, "tail": self._filter_file, "grep": self._filter_file,
            "sudo": self._sudo, "dpkg": self._dpkg,
            "python": self._python, "python3": self._python, "python3.13": self._python,
        }

    # --- the entry point

    def run(self, sess: Session, line: str) -> Answer:
        prev = getattr(_Scope.local, "off", False)
        _Scope.local.off = prev or sess.mode == "scope_off"
        try:
            return self._run(sess, line)
        finally:
            _Scope.local.off = prev

    def _run(self, sess: Session, line: str) -> Answer:
        line = line.rstrip("\n")
        if not sess.terminal:
            if not line.strip():
                return Answer("", sess.last_exit, "builtin")
            return self._exec(sess, line)
        if sess.pending is not None:
            # The rest of a command bash is still reading. A backslash at the end of a
            # line joins it to the next; otherwise the line break is part of the text.
            line = (sess.pending[:-1] + line if unfinished(sess.pending) == "\\"
                    else sess.pending + "\n" + line)
            sess.pending = None
        elif not line.strip():
            return Answer("", sess.last_exit, "builtin")
        if unfinished(line):
            # An open quote, a line ending in \ | && ||, an unclosed $( or if/for/while:
            # bash prints nothing, shows PS2 and waits (Session.prompt). No model can
            # answer this, since the answer is to print nothing and keep reading.
            sess.pending = line
            return Answer("", sess.last_exit, "builtin")
        sess.history.append(line)
        if line.strip() in ("exit", "logout"):
            return Answer("logout", 0, "builtin", close=True)
        return self.run_line(sess, line)

    def interrupt(self, sess: Session) -> Answer:
        """Ctrl-C: bash drops what was typed so far, a command it was still reading
        included, and `$?` becomes 130. (A command whose answer was still being
        generated has been stopped by the relay before this is called.)"""
        sess.pending = None
        sess.last_exit = 130
        return Answer("", 130, "builtin")

    def run_line(self, sess: Session, line: str) -> Answer:
        """Builtin or model (or, only with config `replay_tier` on, the cache between
        them), for a line already in the history.

        In model-only mode (config `answer_mode`, or per request `honeypot.mode`) the code
        still runs, so the session and machine state stay right (cd, export, files), but
        the model answers; what code (or replay, if on) would have said is kept in the answer's
        meta for the paper's code-vs-model comparison."""
        line = strip_comments(line)
        sess.after_model = None
        sess.run_sub = lambda text: self._subshell(sess, text)
        if not line.strip():
            return Answer("", sess.last_exit, "builtin")      # only a comment: nothing runs
        # The file state is shared by every session, so hold its lock while this line
        # reads or changes it, but not across the slow model call.
        with sess.fs.lock:
            try:
                ans = self._builtin_line(sess, line)
            except NotBuiltin:
                ans = None
            if ans is None:
                self._track_side_effects(sess, line)
                # The recordings were made on a terminal; without one, ls prints one
                # name per line and ps does not cut lines to the screen width.
                hit = (self.k.cached(line, sess.fs, self._paths_read(sess, line))
                       if sess.terminal else None)
                if hit and sess.mode == "model_only":
                    ans = Answer(hit["output"], hit["exit_code"], "cache", meta={"n": hit["n"]})
                    hit = None
                if hit:
                    ans = Answer(hit["output"], hit["exit_code"], "cache",
                                 meta={"n": hit["n"]})
            sess.fs.save()
        would = None
        if sess.mode == "model_only" and ans is not None:
            would = {"source": ans.source, "output": ans.output, "exit_code": ans.exit_code}
            ans, sess.delay = None, 0.0
        if sess.delay:
            time.sleep(sess.delay)          # e.g. ping: as long as on the real machine
            sess.delay = 0.0
        if ans is None:
            self.store.alloc_pids(line.count("|") + 1)     # the processes it would start
            try:
                ans = self._model(sess, line)
            except Cancelled:
                # Ctrl-C: the client passes SIGINT on to a container in the foreground
                if sess.after_model is not None:
                    with sess.fs.lock:
                        sess.after_model(130, machine.now().timestamp(), "")
                    sess.after_model = None
                raise
            if sess.mode == "model_only":
                ans.meta = {**(ans.meta or {}), "mode": "model_only", "code_answer": would}
        if sess.after_model is not None:
            with sess.fs.lock:
                sess.after_model(ans.exit_code, machine.now().timestamp(), ans.output)
            sess.after_model = None
        sess.last_exit = ans.exit_code
        note_hashed(sess, line)
        sess.transcript.append((line, ans.output))
        del sess.transcript[:-MAX_TRANSCRIPT]
        return ans

    def _exec(self, sess: Session, line: str) -> Answer:
        """Exec mode, `ssh host 'cmd'`: bash -c, no terminal, no history. Errors are
        prefixed `bash: line 1:` instead of `-bash:` (Ground Truth, 2026-10-01)."""
        m = re.fullmatch(r"\s*exit(?:\s+(\d+))?\s*", line)
        if m:
            return Answer("", int(m.group(1)) % 256 if m.group(1) else sess.last_exit,
                          "builtin", close=True)
        if line.strip() == "logout":
            return Answer("bash: line 1: logout: not login shell: use `exit'", 1, "builtin")
        open_ = unfinished(line)
        if open_ and open_ not in ("\\", "heredoc"):
            # bash -c has nothing more to read. Its texts, from bash 5.2.37 on Debian
            # 13 arm64 (offline/debian13-arm64): an open quote is reported on the line
            # it is found missing, everything else at the end of the input.
            lines = line.count("\n") + 1
            if open_ in ("'", '"', "`"):
                msg = f"bash: -c: line {lines}: unexpected EOF while looking for matching `{open_}'"
            elif open_ == ")":
                msg = f"bash: -c: line {lines + 1}: unexpected EOF while looking for matching `)'"
            else:
                msg = f"bash: -c: line {lines + 1}: syntax error: unexpected end of file"
            sess.last_exit = 2
            return Answer(msg, 2, "builtin")
        ans = self.run_line(sess, line)        # bash -c keeps no history
        ans.output = re.sub(r"(?m)^-bash: ", "bash: line 1: ", ans.output)
        return ans

    def _subshell(self, sess: Session, text: str) -> str:
        """`$( text )`: run in code in a copy of the shell (a cd or a variable set in it
        is gone afterwards; files it writes stay), and return what it printed without
        the final line breaks. Anything that fails or prints an error goes to the model,
        since the error would go to the terminal, not into the substitution."""
        kept = (sess.cwd, sess.oldpwd, dict(sess.env), dict(sess.vars), set(sess.unset_vars),
                dict(sess.hashed), sess.last_exit, sess.running, sess.piped, sess.no_newline,
                sess.blank, sess.stdin)
        try:
            ans = self._builtin_line(sess, text)
        finally:
            (sess.cwd, sess.oldpwd, sess.env, sess.vars, sess.unset_vars, sess.hashed,
             sess.last_exit, sess.running, sess.piped, sess.no_newline, sess.blank,
             sess.stdin) = kept
        if ans.exit_code != 0:
            raise NotBuiltin("a command substitution that failed")
        return ans.output.rstrip("\n")

    def _dpkg(self, s, a):
        if a[1:] == ["--print-architecture"]:
            # Debian's name for the kernel's machine type (`uname -m`)
            return {"aarch64": "arm64"}[whoami._kernel()["m"]], 0
        raise NotBuiltin("dpkg form")

    def _sudo(self, s, a):
        """root's sudo (1.9.16p2) runs the program as root, i.e. as it is; a word that is
        no program on its secure path is its own error, a shell builtin included."""
        if len(a) < 2 or a[1].startswith("-") or "/" in a[1]:
            raise NotBuiltin("sudo form")
        if a[1] not in PATH_OF:
            if s.piped:
                raise NotBuiltin("sudo's error into a pipe")
            return f"sudo: {a[1]}: command not found", 1
        if a[1] in ("env", "printenv", "sudo", "su", "bash", "sh", "id") or a[1] not in self.builtins:
            raise NotBuiltin("sudo of a program whose output sudo changes, or not in code")
        return self.builtins[a[1]](s, a[1:])

    def _builtin_line(self, sess: Session, line: str) -> Answer | None:
        """Run the whole line in code if every part of it is a builtin, else None.

        Runs against a copy of the state it can change, so a line that turns out to
        need the model half-way leaves no half-applied cd or export behind."""
        if "$((" in line and arith_spans_unsafe(line):
            raise NotBuiltin("arithmetic with < > | & or ;")
        if "$(" in line and subst_spans_unsafe(line):
            raise NotBuiltin("a command substitution with a pipe, list or redirection")
        saved = (sess.cwd, sess.oldpwd, dict(sess.env), sess.fs.snapshot())
        kept = (dict(sess.vars), set(sess.unset_vars), dict(sess.hashed))
        outs, code = [], sess.last_exit
        sess.no_newline = False
        sess.stdin = None
        line, document = take_heredoc(line)
        try:
            if document is not None and len(split_top(line, pipes=False)) != 1:
                raise NotBuiltin("a here-document on a line with more than one command")
            for seg, op in split_top(line, pipes=False):
                if (op == "&&" and code != 0) or (op == "||" and code == 0):
                    continue
                if sess.no_newline:
                    # `echo -n a; echo b` prints "ab": only a last command may end
                    # without a line break here, since the parts are joined by one.
                    raise NotBuiltin("output without a line break in the middle of a line")
                sess.stdin, sess.blank = document, False
                timed = re.match(r"time(?:\s+(-p))?(?:\s+|$)", seg)
                if timed:
                    in_scope("command_lookup")
                    # bash's `time` keyword: the pipeline runs as usual, then the shell
                    # reports how long it took, on the terminal whatever the pipeline's
                    # redirections. Alone it times nothing (gt43 n=15).
                    if "TIMEFORMAT" in sess.vars or "TIMEFORMAT" in sess.env:
                        raise NotBuiltin("time with TIMEFORMAT set")
                    seg = seg[timed.end():]
                if timed and not seg:
                    text, code, err = "", 0, ""
                else:
                    text, code, err = self._pipeline(sess, seg)
                if err:
                    outs.append(err)
                if text or sess.blank:
                    outs.append(text)         # a bare `echo` prints one empty line
                if timed:
                    if sess.no_newline:
                        raise NotBuiltin("time after output without a line break")
                    external = bool(seg) and any(
                        w and w[0] not in BASH_BUILTINS
                        for w in (st.split()[:1] for st, _ in split_top(seg, pipes=True)))
                    outs.append(time_report(timed.group(1) == "-p", external, sess.delay))
                note_hashed(sess, seg)
                sess.last_exit = code
        except NotBuiltin:
            sess.cwd, sess.oldpwd, sess.env, snap = saved
            sess.vars, sess.unset_vars, sess.hashed = kept
            sess.fs.restore(snap)
            raise
        finally:
            sess.stdin = None
        out = "\n".join(outs)
        return Answer(out, code, "builtin", newline=not sess.no_newline,
                      blank=bool(outs) and not out)

    def _pipeline(self, sess: Session, seg: str) -> tuple[str, int, str]:
        """(stdout, exit code, stderr) of one pipeline, all in code or NotBuiltin."""
        quiet = False
        m = re.search(r"\s2>\s*/dev/null(?=\s|$)", seg)
        if m:
            seg, quiet = seg[:m.start()] + seg[m.end():], True
        if re.search(r"\d>|>&", seg):
            raise NotBuiltin("file-descriptor redirection")
        text, code, err = self._pipeline_out(sess, seg)
        return text, code, "" if quiet else err

    def _pipeline_out(self, sess: Session, seg: str) -> tuple[str, int, str]:
        seg, target, append = split_redirect(seg)
        if target is not None:
            path = resolve(sess, expand(target, sess))
            if sess.fs.created.get(path) == "dir" or path in KNOWN_DIRS:
                return "", 1, f"-bash: {target}: Is a directory"
            if not is_dir(sess, posixpath.dirname(path)):
                raise NotBuiltin("redirect outside a known directory")
            text, code, err = self._pipeline_out(sess, seg)
            if sess.no_newline:
                raise NotBuiltin("echo -n into a file")
            blank, sess.blank = sess.blank, False     # the empty line went into the file
            if path != "/dev/null":
                old = sess.fs.contents.get(path, "") if append else ""
                sess.fs.created[path] = "file"
                sess.fs.contents[path] = old + (text + "\n" if text or blank or not append else "")
                sess.fs.removed.discard(path)
                sess.fs.stamp(path)
            return "", code, err
        stages = split_top(seg, pipes=True)
        # A first word that is no command is `command not found` whatever follows it,
        # so the rest is not expanded first: a sentence typed at the prompt ("what model
        # are you?") must never reach the model because it ends in a question mark.
        # Left alone: a command substitution or redirection, which act before the error.
        first = stages[0][0].split(None, 1)[0] if stages[0][0].split() else ""
        # Input from a here-document (`cat << END`) or a here-string (`cat <<< "text"`):
        # only `cat` alone and the filters read it here. Text typed this way must not
        # reach the model as if it were a command (docs/manual-session-2026-10-13.md).
        stdin, sess.stdin = sess.stdin, None
        m = re.search(r"\s*<<<\s*", stages[0][0])
        if m and not (stages[0][0][:m.start()].count("'") % 2
                      or stages[0][0][:m.start()].count('"') % 2):
            if stdin is not None:
                raise NotBuiltin("a here-document and a here-string")
            word = shlex.split(expand(stages[0][0][m.end():], sess, globs=True).replace(GLOB, ""))
            if len(word) != 1:
                raise NotBuiltin("a here-string followed by more words")
            stdin, stages[0] = word[0], (stages[0][0][:m.start()], stages[0][1])
            first = stages[0][0].split(None, 1)[0] if stages[0][0].split() else ""
        if stdin is not None and first in KNOWN_COMMANDS:
            argv = self._words(sess, stages[0][0])
            if argv != ["cat"] and argv[0] not in _STDIN_FILTERS:
                raise NotBuiltin(f"{argv[0]} reading a here-document")
            sess.piped = len(stages) > 1
            sess.running = [(pid, expand(st, sess, globs=True).replace(GLOB, ""))
                            for pid, (st, _) in zip(self.store.alloc_pids(len(stages)), stages)]
            text, code = (stdin, 0) if argv == ["cat"] else filter_stage(stdin, argv)
            for st, _ in stages[1:]:
                fargv = self._words(sess, st)
                if not fargv:
                    raise NotBuiltin("empty stage")
                text, code = filter_stage(text, fargv)
            sess.blank = text == "" and (argv == ["cat"] and len(stages) == 1) and stdin == ""
            return self._ended(sess, text), code, ""
        if len(stages) == 1 and stdin is None and re.match(r"[A-Za-z_]\w*=", first):
            done = self._assign(sess, stages[0][0])
            if done is not None:
                return done
        if (re.fullmatch(r"[\w.+-]+", first) and first not in KNOWN_COMMANDS
                and not re.search(r"[`<>]|\$\(", stages[0][0])):
            argv = [first]
        else:
            argv = self._words(sess, stages[0][0])
        if not argv:
            raise NotBuiltin("")
        err = ""
        if argv[0] == "yes" and len(stages) > 1:
            in_scope("text_tools")
            # `yes` never stops by itself; only a `head` right after it ends it.
            nxt = self._words(sess, stages[1][0])
            if nxt[0] != "head" or not (nxt[1:] == [] or re.fullmatch(r"-\d+", " ".join(nxt[1:]))
                                        or re.fullmatch(r"-n \d+", " ".join(nxt[1:]))):
                raise NotBuiltin("yes into something other than head")
            word = " ".join(argv[1:]) or "y"
            sess.piped, sess.running = True, []
            text, code = "\n".join([word] * _count(nxt)), 0
            stages = stages[1:]
        elif argv[0] == "man" and SCOPE["man_pages"] and (
                len(argv) == 1 or (msg := man_missing(argv)) is not None):
            # man's messages go to stderr, past any pipe, as bash's do.
            text, code, err = ("", 1, "What manual page do you want?\nFor example, try 'man man'."
                               ) if len(argv) == 1 else ("", 16, msg)
        elif argv[0] in self.builtins:
            if argv[0] in _SCOPE_OF:
                in_scope(_SCOPE_OF[argv[0]])
            # A real command (or any pipeline) starts processes: new PIDs, which `ps`
            # shows as this session's children. bash's own builtins start none.
            sess.piped = len(stages) > 1
            sess.running = []
            if sess.piped or argv[0] not in BASH_BUILTINS:
                pids = self.store.alloc_pids(len(stages))
                sess.running = [(pid, expand(st, sess, globs=True).replace(GLOB, ""))
                                for pid, (st, _) in zip(pids, stages)]
            text, code = self.builtins[argv[0]](sess, argv)
            if argv[0] in SUBSTITUTED:
                text = self.k.subs(text)
        elif argv[0] not in KNOWN_COMMANDS and "/" not in argv[0] and "=" not in argv[0]:
            # bash's message goes to stderr, past any pipe; the pipe reads nothing.
            text, code, err = "", 127, f"-bash: {argv[0]}: command not found"
        elif "/" in argv[0] and self._exists(sess, resolve(sess, argv[0])) in (None, "dir"):
            in_scope("shell_settings")
            # A path typed as a command: a directory, or no such program where every
            # program is known (the system's bin directories). bash 5.2.37's texts.
            if self._exists(sess, resolve(sess, argv[0])) == "dir":
                text, code, err = "", 126, f"-bash: {argv[0]}: Is a directory"
            else:
                text, code, err = "", 127, f"-bash: {argv[0]}: No such file or directory"
        else:
            raise NotBuiltin(argv[0])
        for st, _ in stages[1:]:
            fargv = self._words(sess, st)
            if not fargv:
                raise NotBuiltin("empty stage")
            text, code = filter_stage(text, fargv)
        return self._ended(sess, text), code, err

    @staticmethod
    def _ended(sess: Session, text: str) -> str:
        """Output whose last line has no line break leaves the prompt on that line."""
        if isinstance(text, Unterminated):
            if text:
                sess.no_newline = True
            return str(text)
        return text

    _READONLY = frozenset({"UID", "EUID", "PPID", "BASHOPTS", "SHELLOPTS", "BASH_VERSINFO"})

    def _assign(self, sess: Session, text: str) -> tuple[str, int, str] | None:
        """`x=5`, `a=1 b="two words"`: a line of nothing but assignments sets shell
        variables and prints nothing (bash does this itself; no program runs). None if
        the line is something else, e.g. `VAR=value command`, which is left as it was."""
        # split=False: the value of an assignment is not split into words (x=$y)
        words = shlex.split(expand(text, sess, globs=True, split=False).replace(GLOB, ""))
        if not words or not all(re.match(r"[A-Za-z_]\w*=", w) for w in words):
            return None
        for w in words:
            name, _, value = w.partition("=")
            if value.startswith("("):
                raise NotBuiltin("an array")
            if name in self._READONLY:
                return "", 1, f"-bash: {name}: readonly variable"
            if name in sess.env:
                sess.env[name] = value               # an exported name stays exported
            else:
                sess.vars[name] = value
            sess.unset_vars.discard(name)
        return "", 0, ""

    def _words(self, sess: Session, text: str) -> list[str]:
        """The words of one command as bash hands them over: variables expanded, quotes
        removed, and each unquoted pattern (* ? [) replaced by the names it matches in
        the current directory, or left as typed when it matches none. Without this any
        `echo is this real?` went to the model, which is slow and reads it as a question."""
        out = []
        for w in shlex.split(expand(text, sess, globs=True)):
            if GLOB not in w:
                out.append(w)
                continue
            typed = w.replace(GLOB, "")
            if "/" in typed or typed.startswith("."):
                raise NotBuiltin("a pattern outside the current directory, or for dotfiles")
            names = self._names(sess)
            if names is None:
                raise NotBuiltin("a pattern in a directory whose content is not recorded")
            pat, i = [], 0
            while i < len(w):
                if w[i] == GLOB:
                    i += 1
                    pat.append(w[i])
                else:
                    pat.append(f"[{w[i]}]" if w[i] in "*?[" else w[i])
                i += 1
            hits = [n for n in names if fnmatch.fnmatchcase(n, "".join(pat))]
            out += hits or [typed]
        return out

    def _names(self, s: Session, where: str | None = None) -> list[str] | None:
        """The visible names in a directory (the current one by default) in `ls` order,
        or None where the directory's content is not known to the code."""
        where = where or s.cwd
        if where == "/sys/class/net":
            # one entry per network interface, as `ip link` lists them (consistent with it)
            return sorted(self.k.subs("\n".join(i.name for i in self._ifaces())).split("\n"),
                          key=lambda n: (re.sub(r"[^0-9a-z]", "", n.lower()), n))
        if where in self.BASE_LISTING:
            names = [n for n in self.BASE_LISTING[where]
                     if posixpath.join(where, n) not in s.fs.removed]
        elif s.fs.created.get(where) == "dir" and where not in s.fs.removed:
            names = []
        else:
            return None
        names += [posixpath.basename(p) for p in s.fs.created
                  if posixpath.dirname(p) == where and not posixpath.basename(p).startswith(".")]
        return sorted(names, key=lambda n: (re.sub(r"[^0-9a-z]", "", n.lower()), n))

    # --- builtins: each returns (output without trailing newline, exit code)

    def _cd(self, s: Session, a: list[str]) -> tuple[str, int]:
        if len(a) > 2:
            return "-bash: cd: too many arguments", 1
        target = a[1] if len(a) > 1 else s.home
        printed = ""
        if target == "-":
            if not s.oldpwd:
                return "-bash: cd: OLDPWD not set", 1
            target = printed = s.oldpwd
        path = resolve(s, target)
        if s.fs.created.get(path) == "file":
            return f"-bash: cd: {a[1]}: Not a directory", 1
        if not is_dir(s, path):
            return f"-bash: cd: {a[1]}: No such file or directory", 1
        s.oldpwd, s.cwd = s.cwd, path
        s.env["OLDPWD"], s.env["PWD"] = s.oldpwd, path
        return printed, 0

    def _pwd(self, s, a):
        return s.cwd, 0

    def _echo(self, s, a):
        args, newline = a[1:], True
        while args and args[0] in ("-n", "-e", "-E"):
            if args[0] == "-e" and any("\\" in x for x in args[1:]):
                raise NotBuiltin("echo -e escapes")
            newline &= args[0] != "-n"
            args = args[1:]
        if not newline:
            # The prompt then follows on the same line (relay.handle adds no line
            # break). Into a pipe or a file the missing break matters to what reads
            # it, which this code does not model.
            if s.piped or not args or not "".join(args):
                raise NotBuiltin("echo -n into a pipe, or of nothing")
            s.no_newline = True
        elif not "".join(args):
            if s.piped:
                raise NotBuiltin("an empty line into a pipe")
            s.blank = True                # `echo` alone prints one empty line
        return " ".join(args), 0

    def _printf(self, s, a):
        if a[1:] in ([], ["--"]):
            return "-bash: printf: usage: printf [-v var] format [arguments]", 2
        out = bash_printf(a[1:])
        if out.endswith("\n"):
            out = out[:-1]
            if not out:
                if s.piped:
                    raise NotBuiltin("an empty line into a pipe")
                s.blank = True
            return out, 0
        if out:
            # no line break at the end: the prompt follows on the same line, as echo -n
            if s.piped:
                raise NotBuiltin("printf without a final line break into a pipe")
            s.no_newline = True
        return out, 0

    def _python(self, s, a):
        """`python3 -c CODE [args]` when CODE only prints constant expressions
        (honeypot/pyprint.py), and `--version`; anything else is the model's, as before."""
        if a[1:] in (["--version"], ["-V"]):
            return f"Python {pyprint.VERSION}", 0
        if len(a) < 3 or a[1] != "-c":
            raise NotBuiltin("python3 other than -c")
        out = pyprint.output(a[2])
        if out is None:
            raise NotBuiltin("python3 -c with more than prints of constants")
        out = out[:-1]                       # print's last line break; the relay adds one
        if not out:
            if s.piped:
                raise NotBuiltin("an empty line into a pipe")
            s.blank = True
        return out, 0

    def _export(self, s, a):
        for kv in a[1:]:
            if kv.startswith("-"):
                raise NotBuiltin("export option")
            k, eq, v = kv.partition("=")
            if not re.fullmatch(r"[A-Za-z_]\w*", k):
                return f"-bash: export: `{kv}': not a valid identifier", 1
            if eq:
                s.env[k] = v
                s.vars.pop(k, None)
                s.unset_vars.discard(k)
            elif k in s.vars:                        # `x=5`, then `export x`
                s.env[k] = s.vars.pop(k)
        if len(a) == 1:
            raise NotBuiltin("export listing")
        return "", 0

    def _unset(self, s, a):
        for k in a[1:]:
            s.env.pop(k, None)
            s.vars.pop(k, None)
            if k in BASH_SETS:
                s.unset_vars.add(k)
        return "", 0

    def _env(self, s, a):
        if len(a) > 1:
            raise NotBuiltin("env with arguments")
        return "\n".join(s.env_lines("/usr/bin/env")), 0

    def _printenv(self, s, a):
        if len(a) == 1:
            return "\n".join(s.env_lines("/usr/bin/printenv")), 0
        vals = [s.env[k] for k in a[1:] if k in s.env]
        return "\n".join(vals), 0 if len(vals) == len(a) - 1 else 1

    def _date(self, s, a):
        t = machine.now()
        if len(a) == 1:
            return machine.date_local(t), 0
        if a[1:] == ["-u"] or a[1:] == ["--utc"]:
            return machine.date_utc(t), 0
        if len(a) == 2 and a[1].startswith("+"):
            return t.strftime(a[1][1:]), 0
        if len(a) == 3 and a[1] == "-u" and a[2].startswith("+"):
            return t.astimezone(dt.timezone.utc).strftime(a[2][1:]), 0
        raise NotBuiltin("date form")

    def _uptime(self, s, a):
        t = machine.now()
        if len(a) == 1:
            return machine.uptime_line(t, self.boot, len(self.store.active())), 0
        if a[1:] in (["-p"], ["--pretty"]):
            return machine.uptime_pretty(t, self.boot), 0
        if a[1:] in (["-s"], ["--since"]):
            return machine.uptime_since(self.boot), 0
        raise NotBuiltin("uptime form")

    def _cat(self, s, a):
        if len(a) != 2 or a[1].startswith("-"):
            raise NotBuiltin("cat form")
        path = resolve(s, a[1])
        if path in s.fs.contents:
            if s.fs.contents[path] == "\n" and not s.piped:
                s.blank = True                # a file holding one empty line
            return s.fs.contents[path].removesuffix("\n"), 0
        if s.fs.created.get(path) == "dir":
            return f"{a[0]}: {a[1]}: Is a directory", 1
        if path in s.fs.removed:
            return f"{a[0]}: {a[1]}: No such file or directory", 1
        if path == "/proc/uptime":
            return machine.proc_uptime(machine.now(), self.boot), 0
        if path == "/proc/net/dev":
            return self.k.subs(net.proc_net_dev(self._ifaces())), 0
        if path == "/proc/net/route":
            # padded to the kernel's record length; the last line's padding is kept
            # off, as every answer's trailing line break is
            return self.k.subs(net.proc_net_route(self._ifaces())), 0
        if path == "/root/.bash_history":
            return "", 0                  # 0 bytes by decision (R16)
        virtual = self._virtual_file(s, path) if SCOPE["kernel_files"] else None
        if virtual is not None:
            return virtual, 0
        m = re.fullmatch(r"/proc/(\d+)(/.*)?", path)
        if m and SCOPE["kernel_files"] and all(pr.pid != int(m.group(1)) for pr in self._procs(s)):
            # every process is in the table `ps` shows; no other has a /proc entry
            return f"{a[0]}: {a[1]}: No such file or directory", 1
        raise NotBuiltin("cat of a recorded file")

    def _virtual_file(self, s, path: str) -> str | None:
        """Files the kernel writes from what other commands report, so they must agree
        with those commands: the host name (`hostname`), the kernel (`uname`), the
        processors (`nproc`), the load (`uptime`), the processes (`ps`), swap (`free`)
        and the network interfaces (`ip link`). None for any other path."""
        k = whoami._kernel()
        fixed = {"/etc/hostname": machine.HOSTNAME, "/proc/sys/kernel/hostname": machine.HOSTNAME,
                 "/proc/sys/kernel/osrelease": k["r"], "/proc/sys/kernel/version": k["v"],
                 "/proc/sys/kernel/ostype": k["s"]}
        if path in fixed:
            return fixed[path]
        if re.fullmatch(r"/sys/devices/system/cpu/(online|possible|present)", path):
            return f"0-{int(whoami.nproc(['nproc'])[0]) - 1}"
        if path == "/proc/loadavg":
            la = machine.load_average(machine.now().timestamp())
            table = self._procs(s)
            running = max(1, sum(1 for p in table if p.stat.startswith("R")))
            last = s.running[-1][0] if s.running else max(p.pid for p in table)
            return (f"{la[0]:.2f} {la[1]:.2f} {la[2]:.2f} "
                    f"{running}/{sum(p.nlwp for p in table)} {last}")
        m = re.fullmatch(r"/proc/(\d+)/comm", path)
        if m:
            # the process's name, from the table `ps` shows (kernel threads too)
            hit = [pr for pr in self._procs(s) if pr.pid == int(m.group(1))]
            return hit[0].comm[:15] if hit else None
        if path == "/proc/meminfo":
            return state.meminfo(state.memory(machine.now().timestamp(), self.boot))
        if path == "/proc/swaps":
            # the kernel's own layout (mm/swapfile.c, swap_show): name padded to 40,
            # an extra tab after a number below 10,000,000
            mem = state.memory(machine.now().timestamp(), self.boot)
            tab = lambda v: "\t" if v < 10000000 else ""
            return ("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
                    f"/dev/zram0{' ' * 30}partition\t{mem.swap_total}\t{tab(mem.swap_total)}"
                    f"{mem.swap_used}\t{tab(mem.swap_used)}100")
        m = re.fullmatch(r"/sys/class/net/([\w.-]+)/(address|operstate|mtu|ifindex|type|tx_queue_len)", path)
        if m:
            for i in self._ifaces():
                if self.k.subs(i.name) == m.group(1) or i.name == m.group(1):
                    return self.k.subs({
                        "address": i.mac, "operstate": i.state.lower(), "mtu": str(i.mtu),
                        "ifindex": str(i.index), "type": "772" if i.link_type == "loopback" else "1",
                        "tx_queue_len": str(i.qlen if i.qlen is not None else 0)}[m.group(2)])
        return None

    def _touch(self, s, a):
        paths = [resolve(s, x) for x in a[1:] if not x.startswith("-")]
        if not paths or len(paths) != len(a) - 1:
            raise NotBuiltin("touch form")
        for p in paths:
            if not is_dir(s, posixpath.dirname(p)):
                raise NotBuiltin("touch outside a known directory")
        for p in paths:
            if p not in KNOWN_DIRS and p not in s.fs.created:
                s.fs.created[p] = "file"
                s.fs.contents[p] = ""
            s.fs.removed.discard(p)
            if p in s.fs.created:
                s.fs.stamp(p)
        return "", 0

    def _mkdir(self, s, a):
        args = [x for x in a[1:] if not x.startswith("-")]
        opts = [x for x in a[1:] if x.startswith("-")]
        if not args or not set(opts) <= {"-p", "--parents"}:
            raise NotBuiltin("mkdir option")
        parents, errs = bool(opts), []
        if parents:
            in_scope("created_files")
        for x in args:
            p = resolve(s, x)
            if (p in KNOWN_DIRS or p in s.fs.created) and p not in s.fs.removed:
                if parents and is_dir(s, p):
                    continue                          # -p: an existing directory is fine
                errs.append(f"mkdir: cannot create directory \u2018{x}\u2019: File exists")
                continue
            chain = [p]
            while parents and not is_dir(s, posixpath.dirname(chain[-1])):
                up = posixpath.dirname(chain[-1])
                if up in s.fs.created or up in KNOWN_DIRS or up == "/":
                    raise NotBuiltin("mkdir -p through a file")
                chain.append(up)
            if not is_dir(s, posixpath.dirname(chain[-1])):
                raise NotBuiltin("mkdir outside a known directory")
            for q in reversed(chain):
                s.fs.created[q] = "dir"
                s.fs.removed.discard(q)
                s.fs.stamp(q, keep_mode=False)
        return "\n".join(errs), 1 if errs else 0

    def _rm(self, s, a):
        args = [x for x in a[1:] if not x.startswith("-")]
        flags = "".join(x[1:] for x in a[1:] if x.startswith("-"))
        if not args or set(flags) - set("rfRv"):
            raise NotBuiltin("rm form")
        paths = [resolve(s, x) for x in args]
        if any(p not in s.fs.created for p in paths):
            raise NotBuiltin("rm of a file the session did not create")
        errs = []
        for x, p in zip(args, paths):
            if s.fs.created[p] == "dir" and not set(flags) & set("rR"):
                errs.append(f"rm: cannot remove '{x}': Is a directory")
                continue
            for q in [q for q in s.fs.created if q == p or q.startswith(p + "/")]:
                del s.fs.created[q]
                s.fs.contents.pop(q, None)
                s.fs.meta.pop(q, None)
        return "\n".join(errs), 1 if errs else 0

    # --- moving what the attackers created (coreutils 9.7's texts)

    def _filter_file(self, s, a):
        """`head -5 FILE`, `tail FILE`, `grep word FILE`: one file whose content the code
        holds (one the attackers wrote, or one the kernel writes), read as `cat` reads it,
        then the same filter as in a pipe."""
        words, i = [], 1
        while i < len(a):                               # the operands, not option values
            if a[0] in ("head", "tail") and a[i] == "-n":
                i += 2
                continue
            if not a[i].startswith("-"):
                words.append(a[i])
            i += 1
        need = 2 if a[0] == "grep" else 1               # grep: the pattern, then the file
        if len(words) != need or words[-1] != a[-1]:
            raise NotBuiltin(f"{a[0]} without exactly one file at the end")
        files = words[-1:]
        text, code = self._cat(s, ["cat", files[0]])
        if code:
            raise NotBuiltin(f"{a[0]} of something cat refuses")
        return filter_stage(text, a[:-1])

    def _rmdir(self, s, a):
        if len(a) < 2 or any(x.startswith("-") for x in a[1:]):
            raise NotBuiltin("rmdir form")
        errs = []
        for x in a[1:]:
            p = resolve(s, x)
            if p in s.fs.removed or (p not in s.fs.created and self._exists(s, p) is None):
                errs.append(f"rmdir: failed to remove '{x}': No such file or directory")
            elif s.fs.created.get(p) == "file":
                errs.append(f"rmdir: failed to remove '{x}': Not a directory")
            elif s.fs.created.get(p) == "dir":
                if any(q.startswith(p + "/") for q in s.fs.created):
                    errs.append(f"rmdir: failed to remove '{x}': Directory not empty")
                else:
                    del s.fs.created[p]
                    s.fs.meta.pop(p, None)
            else:
                raise NotBuiltin("rmdir of a directory the session did not create")
        if errs and s.piped:
            raise NotBuiltin("rmdir's error into a pipe")
        return "\n".join(errs), 1 if errs else 0

    def _target(self, s, src: str, dst: str) -> str:
        """Where cp or mv puts `src`: into `dst` if it is a directory, else at `dst`."""
        d = resolve(s, dst)
        if is_dir(s, d):
            d = posixpath.join(d, posixpath.basename(resolve(s, src)))
        if not is_dir(s, posixpath.dirname(d)) or d in KNOWN_DIRS:
            raise NotBuiltin("cp/mv to a place the code does not know")
        if s.fs.created.get(d) == "dir":
            raise NotBuiltin("cp/mv onto a directory")
        return d

    def _cp(self, s, a):
        if len(a) != 3 or any(x.startswith("-") for x in a[1:]):
            raise NotBuiltin("cp form")
        src, dst = a[1], a[2]
        p = resolve(s, src)
        if p in s.fs.removed or (p not in s.fs.created and self._exists(s, p) is None):
            return f"cp: cannot stat '{src}': No such file or directory", 1
        if is_dir(s, p):
            return f"cp: -r not specified; omitting directory '{src}'", 1
        if p in s.fs.contents:
            text = s.fs.contents[p]
        else:
            virtual = self._virtual_file(s, p)
            if virtual is None:
                raise NotBuiltin("cp of a file whose content the code does not hold")
            text = virtual + "\n"
        d = self._target(s, src, dst)
        new = d not in s.fs.created
        s.fs.created[d] = "file"
        s.fs.contents[d] = text
        s.fs.removed.discard(d)
        s.fs.stamp(d, keep_mode=not new)
        return "", 0

    def _mv(self, s, a):
        if len(a) != 3 or any(x.startswith("-") for x in a[1:]):
            raise NotBuiltin("mv form")
        src, dst = a[1], a[2]
        p = resolve(s, src)
        if p in s.fs.removed or (p not in s.fs.created and self._exists(s, p) is None):
            return f"mv: cannot stat '{src}': No such file or directory", 1
        if p not in s.fs.created:
            raise NotBuiltin("mv of something the session did not create")
        d = self._target(s, src, dst)
        if d == p:
            raise NotBuiltin("mv onto itself")
        for q in sorted([q for q in s.fs.created if q == p or q.startswith(p + "/")]):
            r = d + q[len(p):]
            s.fs.created[r] = s.fs.created.pop(q)
            if q in s.fs.contents:
                s.fs.contents[r] = s.fs.contents.pop(q)
            if q in s.fs.meta:
                s.fs.meta[r] = s.fs.meta.pop(q)        # mv keeps the date
            s.fs.removed.discard(r)
        return "", 0

    def _chmod(self, s, a):
        if len(a) < 3 or any(resolve(s, x) not in s.fs.created for x in a[2:]):
            raise NotBuiltin("chmod of a file the session did not create")
        for x in a[2:]:
            p = resolve(s, x)
            old = s.fs.meta.get(p, [None, None])[1]
            mode = chmod_mode(a[1], old, s.fs.created[p] == "dir")
            if p in s.fs.meta:
                s.fs.meta[p][1] = mode            # chmod changes the inode, not the date
        return "", 0

    # What a plain `ls` shows in directories whose content was recorded.
    BASE_LISTING = {"/root": ["iot-stack"]}

    def _ls(self, s, a):
        opts = "".join(x[1:] for x in a[1:] if x.startswith("-") and len(x) > 1)
        if "l" in opts:
            in_scope("created_files")
            return self._ls_long(s, a)
        if not SCOPE["ls_columns"]:
            # as before 14 October: no operand, two spaces between names, one line
            if len(a) > 1 or s.piped:
                raise NotBuiltin("ls with arguments")
            names = self._names(s)
            if names is None:
                raise NotBuiltin("ls of an unrecorded directory")
            if not s.terminal:
                return "\n".join(names), 0
            if len("  ".join(names)) >= 80:
                raise NotBuiltin("ls needs columns")
            return "  ".join(names), 0
        if len(a) > 2 or (len(a) == 2 and a[1].startswith("-")):
            raise NotBuiltin("ls with options or several operands")
        names = self._names(s, resolve(s, a[1]) if len(a) == 2 else None)
        if names is None:
            raise NotBuiltin("ls of an unrecorded directory")
        if not s.terminal or s.piped:
            return "\n".join(names), 0          # not a tty: one name per line
        if not s.cols_known and len("  ".join(names)) >= 80:
            # The front end has not said how wide the terminal is: a listing that would
            # wrap at 80 columns may be one line on the attacker's screen.
            raise NotBuiltin("ls wider than 80 columns on a terminal of unknown width")
        return ls_columns(names, s.cols), 0

    # --- where a command comes from: `which` (a program), `type` and `command -v`
    # (bash builtins). From the PATH table of commands.json and bash's own lists; the
    # texts and exit codes are bash 5.2.37's and debianutils' (the Debian 13 arm64
    # userland, 2026-10-14). Only while the session has not changed what a name means
    # (an alias, a function, PATH, a program file of its own): then the model answers.

    def _lookup_unchanged(self, s, words: list[str]) -> None:
        if any("/" in w for w in words):
            raise NotBuiltin("a path given to which/type")
        if s.env.get("PATH", ":".join(ROOT_PATH)) != ":".join(ROOT_PATH) or "PATH" in s.vars:
            raise NotBuiltin("PATH changed in the session")
        if any(re.search(r"\balias\b|\bunalias\b|\(\)|\bfunction\b|\bhash\b|\benable\b", h)
               for h in s.history):
            raise NotBuiltin("the session may have changed a name")
        if any(p.startswith(tuple(d + "/" for d in ROOT_PATH)) for p in [*s.fs.created, *s.fs.removed]):
            raise NotBuiltin("a file of the session in a PATH directory")

    def _which(self, s, a):
        names = a[1:]
        if any(n.startswith("-") for n in names):
            raise NotBuiltin("which option")
        self._lookup_unchanged(s, names)
        found = [f"{PATH_OF[n]}/{n}" for n in names if n in PATH_OF]
        return "\n".join(found), 0 if names and len(found) == len(names) else 1

    def _kind(self, s, name: str) -> str | None:
        if name in BASH_KEYWORDS:
            return "keyword"
        if name in BASH_BUILTINS:
            return "builtin"
        return "file" if name in PATH_OF else None

    def _type(self, s, a):
        args = a[1:]
        opt = args[0] if args and args[0] in ("-t", "-p", "-P") else None
        if opt:
            args = args[1:]
        if args and args[0] == "--":
            args = args[1:]
        if any(x.startswith("-") for x in args):
            raise NotBuiltin("type option")
        self._lookup_unchanged(s, args)
        lines, code = [], 0
        for n in args:
            kind = self._kind(s, n)
            if kind is None:
                code = 1
                if opt is None:
                    if s.piped:
                        raise NotBuiltin("type's error into a pipe")
                    lines.append(f"-bash: type: {n}: not found")
            elif opt == "-t":
                lines.append(kind)
            elif opt in ("-p", "-P"):
                if kind == "file":
                    lines.append(s.hashed.get(n) or f"{PATH_OF[n]}/{n}")
                elif opt == "-P":
                    code = 1                      # -P looks on PATH only; builtins have none
            elif kind == "file":
                lines.append(f"{n} is hashed ({s.hashed[n]})" if n in s.hashed
                             else f"{n} is {PATH_OF[n]}/{n}")
            else:
                lines.append(f"{n} is a shell {kind}")
        return "\n".join(lines), code

    def _command(self, s, a):
        if len(a) < 2 or a[1] not in ("-v", "-V"):
            raise NotBuiltin("command running a command")
        verbose, args = a[1] == "-V", a[2:]
        if any(x.startswith("-") for x in args):
            raise NotBuiltin("command option")
        self._lookup_unchanged(s, args)
        lines, any_found = [], False
        for n in args:
            kind = self._kind(s, n)
            if kind is None:
                if verbose:
                    if s.piped:
                        raise NotBuiltin("command's error into a pipe")
                    lines.append(f"-bash: command: {n}: not found")
                continue
            any_found = True
            path = s.hashed.get(n) or f"{PATH_OF[n]}/{n}" if kind == "file" else None
            if not verbose:
                lines.append(path or n)
            elif kind == "file":
                lines.append(f"{n} is hashed ({s.hashed[n]})" if n in s.hashed else f"{n} is {path}")
            else:
                lines.append(f"{n} is a shell {kind}")
        return "\n".join(lines), 0 if any_found or not args else 1

    # --- small programs that compute (coreutils 9.7, the Debian 13 arm64 userland)

    def _seq(self, s, a):
        if not 2 <= len(a) <= 4 or not all(re.fullmatch(r"-?\d+", x) for x in a[1:]):
            raise NotBuiltin("seq form")                   # options, decimals, errors
        nums = [int(x) for x in a[1:]]
        first, step, last = (1, 1, nums[0]) if len(nums) == 1 else \
            (nums[0], 1, nums[1]) if len(nums) == 2 else nums
        if step == 0 or abs((last - first) // step) > 10000:
            raise NotBuiltin("seq: a zero step or a long sequence")
        return "\n".join(str(v) for v in range(first, last + (1 if step > 0 else -1), step)), 0

    _EXPR_OPS = {"+": lambda a, b: a + b, "-": lambda a, b: a - b, "*": lambda a, b: a * b,
                 "/": lambda a, b: abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1),
                 "%": lambda a, b: abs(a) % abs(b) * (1 if a >= 0 else -1),
                 "<": lambda a, b: int(a < b), "<=": lambda a, b: int(a <= b),
                 "=": lambda a, b: int(a == b), "==": lambda a, b: int(a == b),
                 "!=": lambda a, b: int(a != b), ">=": lambda a, b: int(a >= b),
                 ">": lambda a, b: int(a > b)}

    def _expr(self, s, a):
        """`expr A op B` on integers; its exit status is 1 when the result is 0."""
        if len(a) != 4 or a[2] not in self._EXPR_OPS or not all(
                re.fullmatch(r"-?\d+", x) for x in (a[1], a[3])):
            raise NotBuiltin("expr form")
        x, y = int(a[1]), int(a[3])
        if a[2] in "/%" and y == 0:
            raise NotBuiltin("expr: division by zero")
        v = self._EXPR_OPS[a[2]](x, y)
        return str(v), 1 if v == 0 else 0

    def _getconf(self, s, a):
        if a[1:] in (["_NPROCESSORS_ONLN"], ["_NPROCESSORS_CONF"], ["NPROCESSORS_ONLN"]):
            return whoami.nproc(["nproc"])[0], 0
        raise NotBuiltin("getconf name")

    # --- bash builtins that report the session (bash 5.2.37, the arm64 userland)

    def _umask(self, s, a):
        if any(re.match(r"umask\s+[0-7ugoa]", h.strip()) for h in s.history[:-1]):
            raise NotBuiltin("umask changed in the session")
        forms = {(): "0022", ("-S",): "u=rwx,g=rx,o=rx", ("-p",): "umask 0022"}
        if tuple(a[1:]) not in forms:
            raise NotBuiltin("umask setting or option")
        return forms[tuple(a[1:])], 0

    def _help(self, s, a):
        """bash's `help`, from its own texts (honeypot/bash_help.json, recorded from bash
        5.2.37 by tools/build_bash_help.py). A word names the topic it equals, else every
        topic it begins, in bash's order; nothing matched by any word is bash's error.
        A pattern (* ? [), an option other than -d or -s, a width other than 80 for the
        table, or a COLUMNS the session set are the model's."""
        args = a[1:]
        flag = None
        if args and args[0] in ("-d", "-s"):
            flag, args = args[0][1], args[1:]
        if args and args[0] == "--":
            args = args[1:]
        if any(x.startswith("-") or any(c in x for c in "*?[") for x in args) \
                or "COLUMNS" in s.vars or "COLUMNS" in s.env:
            raise NotBuiltin("help with a pattern, an option or a width set")
        if not args:
            if flag or (s.terminal and s.cols != 80):
                raise NotBuiltin("help's table at another width")
            return _BASH_HELP["list80"].removesuffix("\n"), 0
        out = []
        for word in args:
            exact = [t for t in _BASH_HELP["topics"] if t["name"] == word]
            for t in exact or [t for t in _BASH_HELP["topics"] if t["name"].startswith(word)]:
                out.append(t[flag] + "\n" if flag else t["long"])
        if not out:
            if s.piped:
                raise NotBuiltin("help's error into a pipe")    # it goes to stderr
            w = args[-1]
            return (f"-bash: help: no help topics match `{w}'.  Try `help help' "
                    f"or `man -k {w}' or `info {w}'."), 1
        return "".join(out).removesuffix("\n"), 0

    def _alias(self, s, a):
        if any(re.search(r"\balias\s+\S+=", h) for h in s.history[:-1]) or any("=" in x for x in a[1:]) \
                or any(x.startswith("-") for x in a[1:]):
            raise NotBuiltin("aliases defined in the session")
        if s.piped and a[1:]:
            raise NotBuiltin("alias's error into a pipe")
        # root's .bashrc on Ground Truth defines none (corpus n=245)
        return "\n".join(f"-bash: alias: {x}: not found" for x in a[1:]), 1 if a[1:] else 0

    def _stty(self, s, a):
        if a[1:] != ["size"] or not s.terminal:
            raise NotBuiltin("stty form")
        return f"{s.rows} {s.cols}", 0

    @staticmethod
    def _dq(value: str) -> str:
        return '"' + re.sub(r'(["\\$`])', r"\\\1", value) + '"'

    def _declare(self, s, a):
        if len(a) < 3 or a[1] != "-p":
            raise NotBuiltin("declare form")
        lines, code = [], 0
        for name in a[2:]:
            if name in s.env and name not in s.vars:
                lines.append(f"declare -x {name}={self._dq(s.env[name])}")
            elif name in s.vars and name not in s.env:
                lines.append(f"declare -- {name}={self._dq(s.vars[name])}")
            elif name in s.env or bash_sets(s, name) is not None or not re.fullmatch(r"[A-Za-z_]\w*", name) \
                    or name in ("PS1", "PS2", "PS4", "IFS", "OPTIND", "HISTSIZE", "HISTFILESIZE"):
                raise NotBuiltin("a variable with attributes this code does not keep")
            else:
                if s.piped:
                    raise NotBuiltin("declare's error into a pipe")
                lines.append(f"-bash: declare: {name}: not found")
                code = 1
        return "\n".join(lines), code

    _LC = ("CTYPE", "NUMERIC", "TIME", "COLLATE", "MONETARY", "MESSAGES", "PAPER", "NAME",
           "ADDRESS", "TELEPHONE", "MEASUREMENT", "IDENTIFICATION")

    def _locale(self, s, a):
        lang = s.env.get("LANG")
        if a[1:] or lang != "en_GB.UTF-8" or "LANG" in s.vars or any(
                n.startswith("LC_") or n == "LANGUAGE" for n in [*s.env, *s.vars]):
            raise NotBuiltin("locale with options or a changed locale")
        return "\n".join([f"LANG={lang}", "LANGUAGE="] + [f'LC_{c}="{lang}"' for c in self._LC]
                         + ["LC_ALL="]), 0

    _SYSTEM_BIN = {"/usr/bin": "/usr/bin", "/bin": "/usr/bin", "/usr/sbin": "/usr/sbin", "/sbin": "/usr/sbin"}

    def _exists(self, s, path: str) -> str | None:
        """"dir", "file" or "prog" for a path the code knows to exist, None for one it
        knows not to; NotBuiltin when it cannot tell."""
        if path in s.fs.removed:
            return None
        if is_dir(s, path):
            return "dir"
        if path in s.fs.created:
            return "file"
        if path in ("/proc/uptime", "/proc/net/dev", "/proc/net/route", "/root/.bash_history") \
                or self._virtual_file(s, path) is not None:
            return "file"
        d, name = posixpath.split(path)
        if s.fs.created.get(d) == "dir" and d not in s.fs.removed:
            return None                           # a directory of the session's: all known
        if d in self._SYSTEM_BIN:
            if name not in PATH_OF:
                return None                       # every program there is in the PATH table
            if self._SYSTEM_BIN.get(PATH_OF[name]) == self._SYSTEM_BIN[d]:
                return "prog"
        raise NotBuiltin("a path the code does not know")

    _UNARY = {"-e", "-f", "-d", "-s", "-r", "-x", "-z", "-n"}
    _INT_OPS = {"-eq": int.__eq__, "-ne": int.__ne__, "-lt": int.__lt__, "-le": int.__le__,
                "-gt": int.__gt__, "-ge": int.__ge__}

    def _test(self, s, a):
        """`test` and `[` with up to four arguments, by POSIX's rules for the count."""
        args = a[1:]
        if a[0] == "[":
            if not args or args[-1] != "]":
                if s.piped:
                    raise NotBuiltin("['s error into a pipe")
                return "-bash: [: missing `]'", 2
            args = args[:-1]

        def unary(op: str, x: str) -> bool:
            if op == "-z":
                return x == ""
            if op == "-n":
                return x != ""
            kind = self._exists(s, resolve(s, x)) if x else None
            if op in ("-e", "-r"):
                return kind is not None
            if op == "-f":
                return kind in ("file", "prog")
            if op == "-d":
                return kind == "dir"
            if op == "-x":
                if kind == "file":
                    raise NotBuiltin("-x on a file of the session")
                return kind in ("dir", "prog")
            if op == "-s":
                if kind == "file":
                    p = resolve(s, x)
                    return bool(s.fs.contents.get(p)) if p in s.fs.contents else \
                        not p.startswith(("/proc/", "/sys/"))
                return kind is not None
            raise NotBuiltin(op)

        def ev(args: list[str]) -> bool:
            if len(args) == 0:
                return False
            if len(args) == 1:
                return args[0] != ""
            if args[0] == "!":
                return not ev(args[1:])
            if len(args) == 2 and args[0] in self._UNARY:
                return unary(*args)
            if len(args) == 3 and args[1] in ("=", "==", "!="):
                return (args[0] == args[2]) != (args[1] == "!=")
            if len(args) == 3 and args[1] in self._INT_OPS:
                if not all(re.fullmatch(r"\s*-?\d+\s*", x) for x in (args[0], args[2])):
                    raise NotBuiltin("integer expression expected")
                return self._INT_OPS[args[1]](int(args[0]), int(args[2]))
            if len(args) == 3 and args[0] == "(" and args[2] == ")":
                return args[1] != ""
            raise NotBuiltin("test form")

        if len(args) > 4:
            raise NotBuiltin("test with more than four arguments")
        return "", 0 if ev(args) else 1

    def _ls_long(self, s, a):
        """`ls -l` and `ls -ld` of what the attackers created: every one of those has a
        date and a mode in the shared file state. The machine's own files are left to
        the model (their dates and sizes are known only from the test answers)."""
        opts = "".join(x[1:] for x in a[1:] if x.startswith("-"))
        operands = [x for x in a[1:] if not x.startswith("-")]
        if set(opts) - set("ld") or any(x.startswith("--") for x in a[1:]):
            raise NotBuiltin("ls option")
        if any(not re.fullmatch(r"[\w./+-]+", x) for x in operands):
            raise NotBuiltin("a name ls would quote")
        operands = operands or ["."]

        def entry(path: str, shown: str) -> tuple:
            if path not in s.fs.created or path not in s.fs.meta or path in s.fs.removed:
                raise NotBuiltin("ls -l of something the session did not create")
            mtime, mode = s.fs.meta[path]
            is_dir_ = s.fs.created[path] == "dir"
            if is_dir_:
                nlink = 2 + sum(1 for q, k in s.fs.created.items()
                                if k == "dir" and posixpath.dirname(q) == path)
                size = 4096
            else:
                nlink, size = 1, len(s.fs.contents.get(path, "").encode())
            when = dt.datetime.fromtimestamp(mtime, machine.TZ)
            return (mode_string(mode, is_dir_), nlink, size,
                    f"{when:%b} {when.day:>2} {when:%H:%M}", shown, is_dir_)

        def rows(entries: list[tuple]) -> list[str]:
            wl = max(len(str(e[1])) for e in entries)
            ws = max(len(str(e[2])) for e in entries)
            return [f"{m} {n:>{wl}} root root {z:>{ws}} {d} {name}" for m, n, z, d, name, _ in entries]

        key = lambda e: (re.sub(r"[^0-9a-z]", "", e[4].lower()), e[4])
        paths = [(resolve(s, x), x) for x in operands]
        dirs = [(p, x) for p, x in paths if "d" not in opts and is_dir(s, p)]
        if not dirs:
            return "\n".join(rows(sorted((entry(p, x) for p, x in paths), key=key))), 0
        if len(paths) > 1:
            raise NotBuiltin("ls -l of several operands with a directory")
        where = dirs[0][0]
        if s.fs.created.get(where) != "dir":
            raise NotBuiltin("ls -l of a directory the session did not create")
        kids = sorted((entry(q, posixpath.basename(q)) for q in s.fs.created
                       if posixpath.dirname(q) == where and not posixpath.basename(q).startswith(".")),
                      key=key)
        total = sum(4 if e[5] else -(-e[2] // 4096) * 4 for e in kids)
        return "\n".join([f"total {total}"] + (rows(kids) if kids else [])), 0

    def _history(self, s, a):
        lines = [f"{i:5d}  {c}" for i, c in enumerate(s.history, 1)]
        if len(a) == 2 and a[1].isdigit():
            lines = lines[-int(a[1]):]
        elif len(a) > 1:
            raise NotBuiltin("history option")
        return "\n".join(lines), 0

    def _who(self, s, a):
        if len(a) > 1:
            raise NotBuiltin("who option")
        # Debian 13's who names the tty "sshd" (corpus n=129).
        return "\n".join(f"{x.username:<8} {'sshd':<12} {x.login_at:%Y-%m-%d %H:%M} ({x.src_ip})"
                         for x in self.store.active()), 0

    def _w(self, s, a):
        if len(a) > 1:
            raise NotBuiltin("w option")
        t = machine.now()
        rows = [machine.uptime_line(t, self.boot, len(self.store.active())),
                "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU  WHAT"]
        for x in self.store.active():
            if not x.terminal:
                # Measured as pi on Ground Truth (2026-10-01): no TTY, no IDLE, and WHAT
                # is the session's privileged sshd process. Not measured for root.
                rows.append(f"{x.username:<8} {'':<8} {x.src_ip:<16} {x.login_at:%H:%M}"
                            f"{'':11}0.00s  0.01s sshd-session: {x.username} [priv]")
                continue
            what = "w" if x is s else "-bash"
            idle = "1.00s" if x is s else "2:03 "
            rows.append(f"{x.username:<8} pts/{x.tty:<4} {x.src_ip:<16} {x.login_at:%H:%M}    "
                        f"{idle}  0.02s   ?    {what}")
        return "\n".join(rows), 0

    def _users(self, s, a):
        return " ".join(sorted(x.username for x in self.store.active())), 0

    def _free(self, s, a):
        try:
            return sysinfo.free(state.memory(machine.now().timestamp(), self.boot), a)
        except sysinfo.Unsupported as e:
            raise NotBuiltin(str(e))

    def _df(self, s, a):
        def exists(path):
            if path in s.fs.removed:
                return False
            if is_dir(s, path) or s.fs.created.get(path) == "file":
                return True
            if s.fs.created.get(posixpath.dirname(path)) == "dir":
                return False                # an attacker's directory: all of it is known
            return None                     # not known either way: the model decides
        rows = state.mounts(machine.now().timestamp(), self.boot, s.fs)
        try:
            return sysinfo.df(rows, a, lambda p: resolve(s, p), exists)
        except sysinfo.Unsupported as e:
            raise NotBuiltin(str(e))

    def _procs(self, s):
        now = machine.now().timestamp()
        extra = self.docker.container_procs(now) if self.docker else None
        return procs.table(now, self.boot, self.store.active(), s, s.running, extra=extra)

    def _ps(self, s, a):
        # On a terminal ps cuts lines at its width; into a pipe it does not (n=179).
        width = None if (s.piped or not s.terminal) else s.cols
        try:
            return procs.ps(self._procs(s), a, machine.now().timestamp(), s, width)
        except procs.Unsupported as e:
            raise NotBuiltin(str(e))

    _TOP_BATCH_ONCE = {"-bn1", "-bn 1", "-b -n1", "-b -n 1", "-n1 -b", "-n 1 -b", "-n1b"}

    def _top(self, s, a):
        if " ".join(a[1:]) not in self._TOP_BATCH_ONCE:
            raise NotBuiltin("top other than -bn1 (interactive top takes over the terminal)")
        now = machine.now()
        return procs.top(self._procs(s), now, self.boot, len(self.store.active()),
                         state.memory(now.timestamp(), self.boot), s.cols), 0

    def _socks(self):
        return sockets.table(self.store.active(), self.k.subs)

    def _ss(self, s, a):
        # On a terminal ss spreads its columns over the width; into a pipe it does not.
        width = None if (s.piped or not s.terminal) else s.cols
        try:
            return sockets.ss(self._socks(), a, width, len(self.store.active()))
        except sockets.Unsupported as e:
            raise NotBuiltin(str(e))

    def _ifaces(self):
        d = self.docker
        return net.interfaces(machine.now().timestamp(), self.boot, self.k.subs,
                              tuple(self.store.traffic), d.host_links() if d else None,
                              d.docker0_since if d else None)

    def _ip(self, s, a):
        try:
            return net.ip(self._ifaces(), a, machine.now().timestamp() - self.boot)
        except net.Unsupported as e:
            raise NotBuiltin(str(e))

    def _ifconfig(self, s, a):
        try:
            return net.ifconfig(self._ifaces(), a)
        except net.Unsupported as e:
            raise NotBuiltin(str(e))

    def _hostname(self, s, a):
        # Scope rule (2026-10-02): code only for speed or shared state. `hostname -I`
        # lists the live addresses (shared with ip/ifconfig). The name itself, with `id`,
        # `uname`, `nproc` and `groups`, is computed since 2026-10-08 (whoami.py): the
        # first things anybody types, a few ms on the real machine.
        if a[1:] == ["-I"]:
            return net.hostname_i(self._ifaces()), 0
        return self._whoami(whoami.hostname, a)

    @staticmethod
    def _whoami(fn, *args):
        try:
            return fn(*args)
        except sysinfo.Unsupported as e:
            raise NotBuiltin(str(e))

    def _uname(self, s, a):
        return self._whoami(whoami.uname, a)

    def _nproc(self, s, a):
        return self._whoami(whoami.nproc, a)

    def _id(self, s, a):
        return self._whoami(whoami.id_, a, s.username)

    def _groups(self, s, a):
        return self._whoami(whoami.groups, a, s.username)

    def _whoami_cmd(self, s, a):
        return self._whoami(whoami.whoami, a, s.username)

    def _ping(self, s, a):
        try:
            out, code, secs = net.ping(a, f"{s.sid}-{len(s.history)}")
        except net.Unsupported as e:
            raise NotBuiltin(str(e))
        s.delay += secs
        return out, code

    def _docker(self, s, a):
        """The read-only `docker` commands, with every flag, answered from the fake
        API's own answers, so the shell cannot show what the API does not (R10, R11;
        dockercli.py has the list). The ones that change state fall through to the
        model. A command that takes time on the real machine (`docker stats`) adds
        that to `s.delay` there."""
        if self.docker is None:
            raise NotBuiltin("docker: no shared state")
        try:
            return dockercli.render(self.docker, a, s, machine.now().timestamp())
        except dockercli.ModelOutput as e:
            s.after_model = e.after
            raise NotBuiltin(str(e))
        except dockercli.Unsupported as e:
            raise NotBuiltin(str(e))

    def _route(self, s, a):
        if a[1:] != ["-n"]:                 # without -n it looks every address up by name
            raise NotBuiltin("route form")
        return self.k.subs(net.route_n(self._ifaces())), 0

    def _netstat(self, s, a):
        if a[1:] == ["-i"]:                 # live counters, shared with ifconfig
            return net.netstat_i(self._ifaces()), 0
        if a[1:] in (["-rn"], ["-nr"], ["-r", "-n"], ["-n", "-r"]):
            return net.route_n(self._ifaces(), netstat=True), 0
        try:
            return sockets.netstat(self._socks(), a)
        except sockets.Unsupported as e:
            raise NotBuiltin(str(e))

    def _pgrep(self, s, a):
        try:
            return procs.pgrep(self._procs(s), a)
        except procs.Unsupported as e:
            raise NotBuiltin(str(e))

    def _pidof(self, s, a):
        try:
            return procs.pidof(self._procs(s), a)
        except procs.Unsupported as e:
            raise NotBuiltin(str(e))

    def _tty(self, s, a):
        if not s.terminal:
            return "not a tty", 1
        return f"/dev/pts/{s.tty}", 0

    # --- the shared state, approximated from what the attacker typed

    @staticmethod
    def _paths_read(sess: Session, line: str) -> list[str]:
        """The paths a file-reading command looks at; the cwd if it names none."""
        try:
            argv = shlex.split(line)
        except ValueError:
            return [sess.cwd]
        paths = [resolve(sess, a) for a in argv[1:] if not a.startswith("-") and
                 re.match(r"[\w./~-]", a)]
        return paths or [sess.cwd]

    def _track_side_effects(self, sess: Session, line: str) -> None:
        """Note files and directories the line creates or removes, and apply any cd,
        so later commands (and the cache's on/off switch) see them."""
        try:
            segs = split_top(line, pipes=False)
        except NotBuiltin:
            return
        for seg, _ in segs:
            # A > inside quotes or inside $(( )) is no redirection.
            bare = re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", " ", seg)
            bare = re.sub(r"\$\(\([^()]*(?:\([^()]*\)[^()]*)*\)\)", " ", bare)
            for m in re.finditer(r">>?\s*([^\s;&|]+)", bare):
                target = resolve(sess, m.group(1))
                if not target.startswith("/dev/"):      # 2>/dev/null creates nothing
                    sess.fs.created.setdefault(target, "file")
                    sess.fs.stamp(target)
            try:
                argv = shlex.split(seg)
            except ValueError:
                continue
            if not argv:
                continue
            args = [x for x in argv[1:] if not x.startswith("-")]
            if argv[0] == "touch":
                for p in args:
                    if sess.fs.created.setdefault(resolve(sess, p), "file") == "file":
                        sess.fs.contents.setdefault(resolve(sess, p), "")
                        sess.fs.stamp(resolve(sess, p))
            elif argv[0] == "mkdir":
                for p in args:
                    sess.fs.created[resolve(sess, p)] = "dir"
                    sess.fs.stamp(resolve(sess, p), keep_mode=False)
            elif argv[0] == "rm" or argv[0] == "rmdir":
                for p in args:
                    path = resolve(sess, p)
                    sess.fs.meta.pop(path, None)
                    if sess.fs.created.pop(path, None) is None:
                        sess.fs.removed.add(path)
            elif argv[0] in ("cp", "mv") and len(args) >= 2:
                sess.fs.created.setdefault(resolve(sess, args[-1]), "file")
                if argv[0] == "mv":
                    sess.fs.removed.add(resolve(sess, args[0]))
            elif argv[0] == "cd":
                try:
                    self._cd(sess, argv)
                except NotBuiltin:
                    pass

    # --- the model

    def _stack_dates(self) -> str:
        """The compose project's files, owner root, with the dates the Docker state
        gives them, so `ls -l` there agrees with the API's creation times."""
        if self.docker is None:
            return ""
        rows = []
        for path, kind, mtime, size in self.docker.stack_files():
            when = dt.datetime.fromtimestamp(mtime // 10**9, machine.TZ)
            mode = "drwxr-xr-x" if kind == "dir" else "-rw-r--r--"
            rows.append(f"{path}{'/' if kind == 'dir' else ''} {mode} {size} bytes, "
                        f"ls -l date {when:%b %e %H:%M}")
        return "\n- files of the compose project: " + "; ".join(rows)

    def warm_messages(self) -> list[dict]:
        """The keep-warm ping: the shared beginning of every prompt (SYSTEM, FACTS, the
        live block's first words and MemTotal) and a one-word line. Answered with one
        token, it leaves that beginning in the node's cache, where the next real prompt
        finds it; a bare "ok" replaced it and cost the next answer ~0.8 s of reading
        (measured 2026-10-16: a third of all generated answers)."""
        total = state.memory(machine.now().timestamp(), self.boot).total
        return [{"role": "system", "content": f"{SYSTEM}\n\n{FACTS}\n\n{LIVE_HEAD}{total}"},
                {"role": "user", "content": "ok"}]

    def _messages(self, sess: Session, line: str) -> list[dict]:
        t = machine.now()
        mem = state.memory(t.timestamp(), self.boot)
        root = next(m for m in state.mounts(t.timestamp(), self.boot, sess.fs)
                    if m.target == "/")
        live = (f"{LIVE_HEAD}{mem.total}, MemFree {mem.free}, MemAvailable "
                f"{mem.available}, Buffers {mem.buffers}, Cached {mem.cache}, Shmem "
                f"{mem.shared}; swap {mem.swap_total} total, 0 used\n"
                f"- / is /dev/mmcblk0p2 ext4: {root.size} 1K-blocks, {root.used} used, "
                f"{root.avail} available\n"
                f"- date prints: {machine.date_local(t)}\n"
                f"- uptime prints: {machine.uptime_line(t, self.boot, len(self.store.active()))}\n"
                + (f"- the login shell's PID ($$) is {sess.pid}, its tty is /dev/pts/{sess.tty}\n"
                   if sess.terminal else
                   f"- this is `ssh host 'command'`: bash -c with NO terminal, PID {sess.pid}. "
                   f"Output is not a tty: ls prints one name per line, nothing is cut to a "
                   f"screen width, no colours, no pager. Errors start `bash: line 1:` "
                   f"instead of `-bash:`\n")
                + f"- user {sess.username}, current directory {sess.cwd}, "
                f"exit status of the last command ($?) {sess.last_exit}\n"
                + "".join(f"- this session has set {k}={v}\n" for k, v in sess.env.items()
                          if sess.base_env.get(k) != v)
                + "".join(f"- this session has unset {k}\n" for k in sess.base_env
                          if k not in sess.env)
                + (f"- the user connected from {sess.src_ip} port {sess.src_port}"
                   if sess.src_ip else "")
                + self._stack_dates())
        system = f"{SYSTEM}\n\n{FACTS}\n\n{live}"
        if sess.fs.created or sess.fs.removed:
            system += ("\n\nChanged on this machine by its users (they exist now, or no "
                       "longer exist):\n" +
                       "\n".join(f"- created {k}{'/' if v == 'dir' else ''}"
                                 for k, v in sess.fs.created.items()) +
                       "".join(f"\n- removed {p}" for p in sorted(sess.fs.removed)))
        if sess.transcript:
            system += "\n\nThis session so far, oldest first:\n\n" + "\n\n".join(
                f"$ {c}\n{o[:MAX_TRANSCRIPT_CHARS]}" for c, o in sess.transcript)
        ex = self.k.retrieve(line, self.k_examples, sess.hide_examples)
        if ex:
            system += "\n\nReal examples from this exact machine:\n\n" + "\n\n".join(
                f"$ {e['command']}\n{e['output'][:MAX_EXAMPLE_CHARS]}" for e in ex)
        return [{"role": "system", "content": system}, {"role": "user", "content": line}]

    def container_output(self, c: dict, argv: list, tty: bool, kind: str) -> tuple[Answer, str]:
        """What a program prints inside a container, for the fake API (an exec, or a
        container's own command, which becomes its log): the model's answer through the
        same path as the shell's `docker exec` in a running container, which the code
        also leaves to the model (dockercli.exec). The model is asked the docker command
        line that does the same from the host's shell, without a terminal and without
        that shell's history, since an API client has neither (decided 2026-10-15, the
        user: the API stays computed from state, and what no state holds is the model's).
        Returns the answer and the line asked."""
        name = (c.get("Name") or "").lstrip("/") or c["Id"][:12]
        if kind == "exec":
            words = ["docker", "exec", *(["-t"] if tty else []), name, *argv]
        else:
            binds = (c.get("HostConfig") or {}).get("Binds") or []
            words = ["docker", "run", "--name", name,
                     *[w for bnd in binds for w in ("-v", bnd)],
                     (c.get("Config") or {}).get("Image", ""), *argv]
        line = shlex.join(words)
        sess = Session(sid=f"docker-api-{kind}-{c['Id'][:12]}", username="root", src_ip="",
                       src_port=0, dst_ip="", dst_port=0, tty=None,
                       pid=self.store.alloc_pids(1)[0], xdg_session_id=0,
                       login_at=machine.now(), cwd="/root", fs=self.store.fs)
        return self._model(sess, line), line

    def _model(self, sess: Session, line: str) -> Answer:
        t0 = time.monotonic()
        try:
            # Config `line_bound` (off = unchanged): a command that fixes the line count
            # (`head -5`) stops the generation at that many lines.
            bound = line_limit(line) if self.line_bound else None
            kw = {"max_lines": bound} if bound else {}
            text, meta = self.pool.complete(sess.sid, self._messages(sess, line), route(line),
                                            **kw)
        except Cancelled:                    # Ctrl-C: the relay answers for it
            raise
        except Exception as e:
            return Answer(FALLBACK_OUTPUT, FALLBACK_EXIT, "fallback",
                          meta={"error": str(e), "ms": round((time.monotonic() - t0) * 1000)})
        if meta.get("finish_reason") == "deadline":
            text = whole_lines(text)
        # Which recordings the model was shown, by corpus number, for the log.
        meta = {**meta, "examples": [e["n"] for e in self.k.retrieve(
            line, self.k_examples, sess.hide_examples)]}
        out = self.k.subs(clean(text, line, bound))
        # The model sometimes drops bash's prefix: `foo: command not found`.
        out = re.sub(r"(?m)^(?:-?bash: (?:line \d+: )?)?([^\s:]+): command not found$",
                     r"-bash: \1: command not found", out)
        if not out and meta.get("finish_reason") == "deadline":
            return Answer(FALLBACK_OUTPUT, FALLBACK_EXIT, "fallback",
                          meta={**meta, "error": "deadline before a whole line"})
        return Answer(out, guess_exit(line, out), "model", meta=meta)


def route(line: str) -> str:
    """Which Jetson role answers a line (fixed rules, logged with each answer)."""
    first = line.strip().split()[0] if line.strip() else ""
    if first in ("docker", "docker-compose"):
        return "docker"
    return "state"


def whole_lines(text: str) -> str:
    """An answer cut off at the deadline, without its half-written last line."""
    return text[:text.rfind("\n") + 1]


def line_limit(line: str) -> int | None:
    """The most lines a command line can print, when its last command is `head` or `tail`
    of a single pipeline with a count GNU coreutils reads plainly (`-N`, `-n N`, `-nN`,
    `--lines=N`, `--lines N`, or none = 10); else None. Conservative: any `;`, `&`, `||`,
    redirection, substitution, backtick or newline, any other option (`-c`, `-f`, `-v`,
    `-z`, `-q`, `+N`, `-n -N`), several file operands (headers) or anything unparsable
    gives None. Used by config `line_bound`."""
    if re.search(r"[;&<>`\n]|\$\(|\|\|", line):
        return None
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars="|")
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        return None
    seg = toks[len(toks) - toks[::-1].index("|"):] if "|" in toks else toks
    if not seg or "|" in seg or seg[0] not in ("head", "tail"):
        return None
    count, files, i = None, 0, 1
    while i < len(seg):
        a = seg[i]
        m = re.fullmatch(r"-(\d+)|-n(\d+)|--lines=(\d+)", a)
        if m is None and a in ("-n", "--lines") and i + 1 < len(seg) \
                and re.fullmatch(r"\d+", seg[i + 1]):
            m = re.fullmatch(r"(\d+)", seg[i + 1])
            i += 1
        if m is not None:
            if count is not None:
                return None
            count = int(next(g for g in m.groups() if g is not None))
        elif a.startswith("-") and a != "-":
            return None
        else:
            files += 1
        i += 1
    if files > 1:
        return None
    n = 10 if count is None else count
    return n or None


def clean(text: str, line: str, max_lines: int | None = None) -> str:
    """Strip what a chat model wraps around terminal output."""
    # A reasoning block (Qwen3's <think>...</think>) is never terminal output, and no
    # recording contains the tags. The models run with thinking off (the prompt ends in
    # an empty block), so one would mean a wrong template on a node: it is dropped, and
    # so is an unfinished one (cut at the deadline) and the rest of a block that began
    # in the prompt. Nothing of it reaches the attacker. Not \s* after the tag: the
    # answer's own first line may start with spaces.
    t = re.sub(r"^\s*(?:<think>)?.*?</think>\n*|^\s*<think>.*", "", text, count=1,
               flags=re.S) if "think>" in text else text
    t = t.strip("\n")
    if t.lstrip().startswith("```"):
        t = re.sub(r"^\s*```[\w-]*\n?", "", t)
        t = re.sub(r"\n?```\s*$", "", t)
    lines = t.split("\n")
    if lines and lines[0].strip() in (f"$ {line.strip()}", f"# {line.strip()}"):
        lines = lines[1:]
    while lines and re.fullmatch(r"\S+@raspberrypi:\S*[#$]\s*", lines[-1]):
        lines.pop()
    if max_lines:
        lines = lines[:max_lines]
    # Spaces at the ends of lines stay (since 2026-10-08): `ip route`, `lsblk` and others
    # end lines with one on the real machine, and stripping them made a perfect answer
    # wrong (docs/replay-removal-latency.md).
    return "\n".join(lines).strip("\n")


def guess_exit(line: str, out: str) -> int:
    """The model does not report exit codes; infer the usual ones from the text."""
    first = line.strip().split()[0] if line.strip() else ""
    if "command not found" in out:
        return 127
    if re.search(r"No such file or directory|cannot access|Permission denied|Not a directory|"
                 r"invalid option|Is a directory|cannot stat|missing operand|unrecognized option",
                 out):
        return 2 if first in ("ls", "grep") else 1
    if not out and re.search(r"\|\s*grep\b|^\s*grep\b", line):
        return 1
    return 0
