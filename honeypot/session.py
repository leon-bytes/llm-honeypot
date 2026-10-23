"""Per-attacker session state. It lives here, in the relay, not in Cowrie, because the
fake Docker API will have to read and change the same state."""
from __future__ import annotations
import datetime as dt
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field

from . import machine

# The order `env` prints in on Ground Truth (gt43 n=22); new exports go before `_`.
_ENV_ORDER = ["SHELL", "NO_AT_BRIDGE", "PWD", "LOGNAME", "XDG_SESSION_TYPE", "MOTD_SHOWN",
              "HOME", "LANG", "SSH_CONNECTION", "XDG_SESSION_CLASS", "TERM", "USER", "SHLVL",
              "XDG_SESSION_ID", "XDG_RUNTIME_DIR", "SSH_CLIENT", "PATH",
              "DBUS_SESSION_BUS_ADDRESS", "SSH_TTY", "TEXTDOMAIN"]

IDLE_EXPIRY_S = 3600


@dataclass
class Session:
    sid: str
    username: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    tty: int | None             # None: no terminal (exec mode, `ssh host 'cmd'`)
    pid: int
    xdg_session_id: int
    login_at: dt.datetime
    cwd: str = "/root"
    oldpwd: str | None = None
    last_exit: int = 0
    history: list[str] = field(default_factory=list)
    # (command, output) pairs, shown to the model so it remembers what it said.
    transcript: list[tuple[str, str]] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    fs: "FileState | None" = None      # the machine's, shared with every other session
    cols: int = 80                     # the client's terminal width (protocol `cols`)
    cols_known: bool = False           # whether the front end has sent the width at all
    rows: int = 24                     # and its height (protocol `rows`)
    # Names the attacker has `unset`: a variable bash sets by itself (shell.BASH_SETS)
    # is gone after that.
    unset_vars: set = field(default_factory=set)
    # Shell variables the attacker assigned without exporting them (`x=5`): `echo $x`
    # prints them, `env` does not.
    vars: dict = field(default_factory=dict)
    # Programs bash has found on PATH in this session, name -> path: `type ls` says
    # "ls is hashed (/usr/bin/ls)" once `ls` has run (shell.note_hashed).
    hashed: dict = field(default_factory=dict)
    # What code still has to do once the model has answered the current line (a
    # container run in the foreground exits: dockercli.ModelOutput), or None.
    after_model: object = None
    # Runs a command substitution's text in a subshell of this session (set by the
    # shell for the line being run; shell.expand calls it), or None.
    run_sub: object = None
    # The pipeline running right now, as (pid, text): what `ps` shows as this session's
    # children, and whether its output goes to a pipe (then `ps` does not cut lines).
    running: list = field(default_factory=list)
    piped: bool = False
    # Seconds the answer to the current line takes on a real machine (e.g. ping's one
    # per packet); the relay waits that long outside the machine-wide lock.
    delay: float = 0.0
    base_env: dict = field(default_factory=dict)   # the login environment, to show changes
    # The lines of a command bash is still reading (an open quote, a line ending in a
    # backslash or a pipe, ...), or None. While set, the prompt is PS2 (shell.run).
    pending: str | None = None
    no_newline: bool = False           # the line being run ends in `echo -n` (shell.py)
    blank: bool = False                # the command just run printed one empty line
    stdin: str | None = None           # a here-document for the command being run
    mode: str = "normal"               # "model_only": the model answers every line
    # Corpus numbers the model is not shown as examples in this session (measurement
    # only: the leave-one-out test, `honeypot.hide_examples`). Empty for every attacker.
    hide_examples: frozenset = frozenset()
    last_seen: float = field(default_factory=time.monotonic)

    @property
    def terminal(self) -> bool:
        return self.tty is not None

    @property
    def home(self) -> str:
        return "/root" if self.username == "root" else f"/home/{self.username}"

    def prompt(self) -> str:
        """PS1 `${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ ` (gt_frontdoor), or
        PS2 `> ` while bash waits for the rest of a command. readline sends the
        bracketed-paste switch before every prompt it draws, PS2 included."""
        if self.pending is not None:
            ps2 = self.vars.get("PS2", self.env.get("PS2", "" if "PS2" in self.unset_vars else "> "))
            return f"{machine.PROMPT_PREFIX}{ps2}"
        w = self.cwd
        if w == self.home or w.startswith(self.home + "/"):
            w = "~" + w[len(self.home):]
        sign = "#" if self.username == "root" else "$"
        ps1 = self.vars.get("PS1", self.env.get("PS1"))
        if ps1 is not None or "PS1" in self.unset_vars:
            # The attacker changed the prompt (`PS1='$ '`, `export PS1=...`, `unset PS1`).
            return machine.PROMPT_PREFIX + self._render_ps1(ps1 or "", w, sign)
        return f"{machine.PROMPT_PREFIX}{self.username}@{machine.HOSTNAME}:{w}{sign} "

    def _render_ps1(self, ps1: str, w: str, sign: str) -> str:
        """bash's prompt escapes (bash(1), PROMPTING) in a PS1 the attacker set."""
        t = machine.now()
        esc = {
            "u": self.username, "h": machine.HOSTNAME, "H": machine.HOSTNAME, "w": w,
            "W": "~" if w == "~" else (w.rstrip("/").rsplit("/", 1)[-1] or "/"),
            "$": sign, "\\": "\\", "n": "\n", "r": "\r", "s": "-bash", "v": "5.2", "V": "5.2.37",
            "t": t.strftime("%H:%M:%S"), "T": t.strftime("%I:%M:%S"), "@": t.strftime("%I:%M %p"),
            "A": t.strftime("%H:%M"), "d": t.strftime("%a %b %d"), "[": "", "]": "",
            "e": "\x1b", "a": "\x07", "j": "0", "l": str(self.tty if self.tty is not None else 0),
            "!": str(len(self.history) + 1), "#": str(len(self.history) + 1),
        }
        ps1 = ps1.replace("${debian_chroot:+($debian_chroot)}", "").replace("\\033", "\x1b")
        out, i = [], 0
        while i < len(ps1):
            c = ps1[i]
            if c == "\\" and i + 1 < len(ps1) and ps1[i + 1] in esc:
                out.append(esc[ps1[i + 1]])
                i += 2
            else:
                out.append(c)
                i += 1
        text = "".join(out)

        def var(m):
            name = m.group(1) or m.group(2)
            return self.vars.get(name, self.env.get(name, m.group(0) if name not in self.unset_vars else ""))
        return re.sub(r"\$\{(\w+)\}|\$([A-Za-z_]\w*)", var, text)

    def env_lines(self, underscore: str) -> list[str]:
        known = [f"{k}={self.env[k]}" for k in _ENV_ORDER if k in self.env]
        extra = [f"{k}={v}" for k, v in self.env.items() if k not in _ENV_ORDER]
        return known + extra + [f"_={underscore}"]


class FileState:
    """Files and directories attackers created or removed. Machine-wide, like the real
    Pi's disk: a file one login creates is there at the next login and for every other
    user, and it survives a relay restart. The start of the shared state model."""

    def __init__(self, path: str):
        self.lock = threading.RLock()
        self.path = path
        self.created: dict[str, str] = {}     # path -> "file" | "dir"
        self.contents: dict[str, str] = {}    # file path -> its text, when known
        self.removed: set[str] = set()
        # path -> [mtime (epoch seconds), mode (permission bits)], for `ls -l`; a path
        # created before this was kept has none, and `ls -l` of it is the model's.
        self.meta: dict[str, list] = {}
        try:
            with open(path) as f:
                d = json.load(f)
            self.created, self.contents = d["created"], d["contents"]
            self.removed = set(d["removed"])
            self.meta = d.get("meta", {})
        except (OSError, ValueError, KeyError):
            pass

    def snapshot(self):
        return (dict(self.created), dict(self.contents), set(self.removed),
                {k: list(v) for k, v in self.meta.items()})

    def restore(self, snap) -> None:
        self.created, self.contents, self.removed, self.meta = snap

    def stamp(self, path: str, mode: int | None = None, keep_mode: bool = True) -> None:
        """The file was written or created now; a new one gets the default mode (umask
        022: 644 for a file, 755 for a directory)."""
        old = self.meta.get(path)
        if mode is None:
            mode = old[1] if old and keep_mode else (0o755 if self.created.get(path) == "dir" else 0o644)
        self.meta[path] = [time.time(), mode]

    def save(self) -> None:
        try:
            with open(self.path, "w") as f:
                json.dump({"created": self.created, "contents": self.contents,
                           "removed": sorted(self.removed), "meta": self.meta}, f)
        except OSError:
            pass

    def touches(self, paths: list[str]) -> bool:
        """Whether any change lies inside, or contains, one of these paths."""
        changed = list(self.created) + list(self.removed)
        return any(c == p or c.startswith(p.rstrip("/") + "/") or p.startswith(c + "/")
                   for c in changed for p in paths)


class SessionStore:
    """All live sessions, plus the per-user `Last login` record that survives restarts."""

    def __init__(self, state_dir: str, initial_last_login: dict, boot: float | None = None):
        self._lock = threading.Lock()
        self._sessions: dict[str, Session] = {}
        self._next_tty = 0
        self._next_pid = 2439          # Ground Truth's `echo $$` in the 43 (n=23)
        self.boot = boot               # when set, PIDs also grow with uptime (pid_floor)
        self._last_alloc = 0
        # What the sessions sent and received over SSH since the relay started, for
        # eth0's counters: rx bytes, rx packets, tx bytes, tx packets.
        self.traffic = [0, 0, 0, 0]
        self._next_xdg = 7             # gt43 n=22
        self._last_login_path = os.path.join(state_dir, "last_login.json")
        os.makedirs(state_dir, exist_ok=True)
        self.fs = FileState(os.path.join(state_dir, "files.json"))
        try:
            with open(self._last_login_path) as f:
                self._last_login = json.load(f)
        except (OSError, ValueError):
            self._last_login = dict(initial_last_login)

    def get(self, sid: str) -> Session | None:
        with self._lock:
            s = self._sessions.get(sid)
            if s:
                s.last_seen = time.monotonic()
            return s

    def active(self) -> list[Session]:
        with self._lock:
            cutoff = time.monotonic() - IDLE_EXPIRY_S
            for sid in [k for k, s in self._sessions.items() if s.last_seen < cutoff]:
                del self._sessions[sid]
            return sorted(self._sessions.values(), key=lambda s: (s.tty is None, s.tty or 0))

    def open(self, sid: str, username: str, src_ip: str, src_port: int,
             dst_ip: str, dst_port: int, terminal: bool = True) -> tuple[Session, str | None]:
        """Start a session. Returns it and the previous login's `Last login` text.

        terminal=False is exec mode (`ssh host 'cmd'`). Measured on Ground Truth
        2026-10-01: no pts, and /var/log/lastlog and wtmp do not change, so the next
        `Last login:` is not updated; logind still registers the session, so `who`
        and `w` list it while it runs."""
        with self._lock:
            used = {s.tty for s in self._sessions.values()}
            tty = next(i for i in range(64) if i not in used) if terminal else None
            # PIDs only grow on a real machine; each login costs a few.
            # PIDs only grow; a login costs a few. sshd-session [priv] is pid-20 and
            # sshd-session pid-11 (procs.py), so leave room after the last command's PIDs.
            self._next_pid = max(self._next_pid + 14, self._last_alloc + 21, self._floor())
            self._next_xdg += 1
            s = Session(sid=sid, username=username, src_ip=src_ip, src_port=src_port,
                        dst_ip=dst_ip, dst_port=dst_port, tty=tty, pid=self._next_pid,
                        xdg_session_id=self._next_xdg, login_at=machine.now(), fs=self.fs)
            s.cwd = s.home
            uid = 0 if username == "root" else 1000
            s.env = {
                "SHELL": "/bin/bash", "NO_AT_BRIDGE": "1", "PWD": s.home, "LOGNAME": username,
                "XDG_SESSION_TYPE": "tty", "MOTD_SHOWN": "pam", "HOME": s.home,
                "LANG": "en_GB.UTF-8",
                "SSH_CONNECTION": f"{src_ip} {src_port} {dst_ip} {dst_port}",
                "XDG_SESSION_CLASS": "user", "TERM": "xterm", "USER": username, "SHLVL": "1",
                "XDG_SESSION_ID": str(s.xdg_session_id), "XDG_RUNTIME_DIR": f"/run/user/{uid}",
                "SSH_CLIENT": f"{src_ip} {src_port} {dst_port}",
                "PATH": ("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                         if uid == 0 else "/usr/local/bin:/usr/bin:/bin:/usr/games"),
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus",
                "SSH_TTY": f"/dev/pts/{tty}", "TEXTDOMAIN": "pam_chksshpwd",
            }
            s.base_env = dict(s.env)
            if not terminal:
                # Exec mode's env on Ground Truth (2026-10-01): no pty, so no TERM or
                # SSH_TTY; not a login shell, so nothing from /etc/profile.d.
                for k in ("NO_AT_BRIDGE", "TERM", "SSH_TTY", "TEXTDOMAIN"):
                    del s.env[k]
                s.base_env = dict(s.env)
            self._sessions[sid] = s
            prev = self._last_login.get(username)
            if not terminal:
                return s, prev
            self._last_login[username] = f"{machine.ctime(s.login_at)} from {src_ip}"
            try:
                with open(self._last_login_path, "w") as f:
                    json.dump(self._last_login, f)
            except OSError:
                pass
            return s, prev

    def _floor(self) -> int:
        # The machine's clock (machine.now), which a test or the training-data builder
        # may set; in the running relay it is the real time.
        return machine.pid_floor(machine.now().timestamp(), self.boot) if self.boot else 0

    def count_traffic(self, received: str, sent: str) -> None:
        """One command line in, its output out, with SSH's packet overhead."""
        with self._lock:
            self.traffic[0] += len(received.encode()) + 96
            self.traffic[1] += 2
            self.traffic[2] += len(sent.encode()) + 96 + 52 * (len(sent) // 1400)
            self.traffic[3] += 2 + len(sent) // 1400

    def alloc_pids(self, n: int) -> list[int]:
        """PIDs for the processes a command starts, machine-wide and increasing."""
        with self._lock:
            self._next_pid = max(self._next_pid, self._floor())
            start = self._next_pid + 1
            self._next_pid += n
            self._last_alloc = self._next_pid
            return list(range(start, start + n))

    def close(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)
