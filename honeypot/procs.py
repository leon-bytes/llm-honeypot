"""The simulated machine's process table, and `ps`, `top`, `pgrep`, `pidof` over it.

One table, so that `ps`, `top`, `pgrep`, `ss -p` (and later the Docker API's
`/containers/<id>/top`) all show the same processes with the same PIDs (R15).

Where each part comes from:
  - kernel threads: honeypot/kthreads.json, CAPTURED MACHINE STATE from Ground Truth
    (2026-10-02, tools/build_kthreads.py); the paper reports them as captured
  - services: Ground Truth's recordings, never the 43. PIDs, users, sizes and command
    lines of NetworkManager, containerd, sshd, dockerd, one shim, influxd and node-red
    from corpus n=179/182/183/188; the container processes and their parents from the
    API's /containers/<id>/top (phase 1 n=18/22/26); the set of services from n=189 and
    the tree from n=181. Values no recording shows are marked `# est.` below.
  - sessions: the relay's live sessions (sshd-session, bash) and the command running now.
Output formats follow procps-ng 4.0.4 and are checked against corpus n=177-184.
"""
from __future__ import annotations
import datetime as dt
import json
import math
import pathlib
import re
from dataclasses import dataclass, field

from . import machine
from .state import MEM_TOTAL, Memory


class Unsupported(Exception):
    pass


@dataclass
class Proc:
    pid: int
    ppid: int
    user: str
    comm: str
    args: str               # "" for kernel threads: shown as [comm]
    start: float            # epoch seconds
    cpu: float              # seconds of CPU used so far
    vsz: int = 0            # KiB
    rss: int = 0
    shr: int = 0
    stat: str = "S"
    tty: str = "?"
    pr: str = "20"
    ni: int = 0
    nlwp: int = 1
    kernel: bool = False

    @property
    def cmdline(self) -> str:
        return f"[{self.comm}]" if self.kernel else self.args


_KT = json.loads((pathlib.Path(__file__).parent / "kthreads.json").read_text())

# Ground Truth booted 20:34:32 and the containers started 20:35:01 (API phase 1
# StartedAt), so service offsets below are seconds after boot.
_CIDS = {"mosquitto": "d3775f38b3d46fd726f64510ab68d268e93aae6709f80cbc02c5710a256f3b89",
         "nodered": "d139ff53533c7de3002a3a73db79943a968d3ab1da93dd637a4e292bd1ed3334",
         "influxdb": "443074d3a15d7c1ec1140452284abb8d481f98c9ad8c224c39698f50fb7c0594"}
_SHIM = ("/usr/bin/containerd-shim-runc-v2 -namespace moby -id {} "
         "-address /run/containerd/containerd.sock")
_PROXY = ("/usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port {p} "
          "-container-ip {ip} -container-port {p} -use-listen-fd")

# pid, ppid, user, comm, args, start offset s, vsz, rss, shr, stat, cpu at boot,
# cpu per second of uptime, threads, tty
SERVICES = [
    (1, 0, "root", "systemd", "/sbin/init", 0, 25312, 14784, 10128, "Ss", 2.745, 2e-4, 1, "?"),
    (248, 1, "root", "systemd-journal", "/usr/lib/systemd/systemd-journald",   # est.
     2, 49392, 10880, 9856, "Ss", 0.25, 6e-5, 1, "?"),
    (287, 1, "root", "systemd-udevd", "/usr/lib/systemd/systemd-udevd",        # est.
     2, 25812, 7552, 5504, "Ss", 0.55, 1e-6, 1, "?"),
    (597, 1, "systemd-timesync", "systemd-timesyn",                            # est.
     "/usr/lib/systemd/systemd-timesyncd", 4, 91008, 6912, 6016, "Ssl", 0.05, 4e-6, 2, "?"),
    (664, 1, "root", "cron", "/usr/sbin/cron -f", 5, 6640, 2560, 2304, "Ss",   # est.
     0.01, 1e-6, 1, "?"),
    (668, 1, "messagebus", "dbus-daemon", "/usr/bin/dbus-daemon --system "     # est.
     "--address=systemd: --nofork --nopidfile --systemd-activation --syslog-only",
     5, 8580, 4864, 4096, "Ss", 0.12, 4e-6, 1, "?"),
    (673, 1, "root", "bluetoothd", "/usr/libexec/bluetooth/bluetoothd", 5,     # est.
     9132, 5376, 4736, "Ss", 0.03, 1e-7, 1, "?"),
    (679, 1, "root", "systemd-logind", "/usr/lib/systemd/systemd-logind", 5,   # est.
     17508, 7936, 6912, "Ss", 0.08, 5e-6, 1, "?"),
    (687, 1, "root", "NetworkManager", "/usr/sbin/NetworkManager --no-daemon", 5,
     343040, 20832, 17152, "Ssl", 0.20, 2e-5, 4, "?"),
    (710, 1, "root", "wpa_supplicant",                                         # est.
     "/usr/sbin/wpa_supplicant -u -s -O DIR=/run/wpa_supplicant GROUP=netdev", 5,
     16304, 9472, 7552, "Ss", 0.02, 1e-7, 1, "?"),
    (790, 1, "root", "agetty", "/sbin/agetty -o -- \\u --noreset --noclear - linux",  # est.
     6, 6000, 2048, 1920, "Ss+", 0.0, 0.0, 1, "tty1"),
    (792, 1, "root", "agetty", "/sbin/agetty -o -- \\u --noreset --noclear "       # est.
     "--keep-baud 115200,57600,38400,9600 - vt220", 6, 6000, 2048, 1920, "Ss+", 0.0, 0.0,
     1, "ttyAMA10"),
    (823, 1, "root", "containerd", "/usr/bin/containerd", 6, 2042752, 47904, 32768, "Ssl",
     0.30, 2e-4, 11, "?"),
    (826, 1, "root", "sshd", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", 6,
     11760, 7808, 6912, "Ss", 0.05, 1e-6, 1, "?"),
    (840, 1, "root", "dockerd", "/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375 "
     "--containerd=/run/containerd/containerd.sock", 7, 2463312, 91840, 51200, "Ssl", 0.55,
     3e-4, 16, "?"),
    (1092, 840, "root", "docker-proxy", _PROXY.format(p=1880, ip="172.18.0.2"), 28,  # est.
     1745920, 4352, 3840, "Sl", 0.0, 1e-6, 8, "?"),
    (1099, 840, "root", "docker-proxy", _PROXY.format(p=1883, ip="172.18.0.3"), 28,  # est.
     1745920, 4352, 3840, "Sl", 0.0, 1e-6, 8, "?"),
    (1106, 840, "root", "docker-proxy", _PROXY.format(p=8086, ip="172.18.0.4"), 28,  # est.
     1745920, 4480, 3840, "Sl", 0.0, 1e-6, 9, "?"),
    (1125, 1, "root", "containerd-shim", _SHIM.format(_CIDS["mosquitto"]), 28,   # est.
     1268192, 11904, 9216, "Sl", 0.05, 2e-5, 12, "?"),
    (1126, 1, "root", "containerd-shim", _SHIM.format(_CIDS["nodered"]), 28,     # est.
     1268192, 11776, 9216, "Sl", 0.05, 2e-5, 11, "?"),
    (1134, 1, "root", "containerd-shim", _SHIM.format(_CIDS["influxdb"]), 28,
     1268192, 12208, 9216, "Sl", 0.05, 2e-5, 12, "?"),
    (1198, 1126, "pi", "entrypoint.sh", "/bin/bash ./entrypoint.sh", 29,
     4152, 3072, 2816, "Ss", 0.0, 0.0, 1, "?"),
    (1199, 1134, "pi", "influxd", "influxd", 29, 1410656, 104112, 54272, "Ssl", 0.30,
     4e-4, 9, "?"),
    (1200, 1125, "1883", "mosquitto", "/usr/sbin/mosquitto -c /mosquitto/config/mosquitto.conf",
     29, 6352, 3456, 2944, "Ss", 0.02, 2e-5, 1, "?"),
    (1345, 1198, "pi", "node-red", "node-red", 31, 495792, 82288, 39936, "Sl", 1.00, 5e-4,
     11, "?"),
]

# Typical sizes (KiB) of the session's own processes; sshd-session [priv] from n=179.
_SESSION_SIZES = {"priv": (22144, 13040, 11008), "user": (22304, 7124, 5888),
                  "bash": (8424, 5120, 3456), "cmd": (9016, 3712, 3200)}


def table(t: float, boot: float, sessions: list, current=None,
          running: list[tuple[int, str]] | None = None,
          extra: list["Proc"] | None = None) -> list[Proc]:
    """Every process at time t. `sessions` are the relay's live sessions; `running` is
    the current session's pipeline as (pid, text) pairs, shown as its children; `extra`
    are host processes of containers started through the Docker API (docker.py), so they
    appear in `ps` the same as the stack's own (R15)."""
    up = max(t - boot, 0)
    procs = list(extra or [])
    floor = machine.pid_floor(t, boot)
    for k in _KT["threads"]:
        if k["pid"] > floor:
            continue                  # a runtime worker this machine has not started yet
        procs.append(Proc(k["pid"], 0 if k["pid"] == 2 else 2, "root", k["comm"], "",
                          boot, 0.0, stat=k["stat"], pr=k["pr"], ni=k["ni"], kernel=True))
    for (pid, ppid, user, comm, args, off, vsz, rss, shr, stat, c0, rate, nlwp,
         tty) in SERVICES:
        procs.append(Proc(pid, ppid, user, comm, args, boot + off,
                          c0 + rate * max(up - off, 0), vsz, rss, shr, stat, tty, nlwp=nlwp))
    if sessions:
        first = min(sessions, key=lambda s: s.login_at)
        t0 = first.login_at.timestamp()
        procs.append(Proc(first.pid - 33, 1, "root", "systemd", "/usr/lib/systemd/systemd --user",
                          t0, 0.15, 23008, 12656, 10112, "Ss"))
        procs.append(Proc(first.pid - 32, first.pid - 33, "root", "(sd-pam)", "(sd-pam)",
                          t0, 0.0, 24896, 3996, 1536, "S"))
    for s in sessions:
        t0 = s.login_at.timestamp()
        procs.append(Proc(s.pid - 20, 826, s.username, "sshd-session",
                          f"sshd-session: {s.username} [priv]", t0, 0.05,
                          *_SESSION_SIZES["priv"], "Ss"))
        tty = f"pts/{s.tty}" if s.terminal else "?"
        procs.append(Proc(s.pid - 11, s.pid - 20, s.username, "sshd-session",
                          f"sshd-session: {s.username}@{'pts/' + str(s.tty) if s.terminal else 'notty'}",
                          t0, 0.01, *_SESSION_SIZES["user"], "S"))
        if s.terminal:
            busy = s is current and running
            procs.append(Proc(s.pid, s.pid - 11, s.username, "bash", "-bash", t0, 0.02,
                              *_SESSION_SIZES["bash"], "Ss" if busy else "Ss+", tty))
    if current is not None and running:
        parent = current.pid if current.terminal else current.pid - 11
        tty = f"pts/{current.tty}" if current.terminal else "?"
        for i, (pid, text) in enumerate(running):
            argv0 = text.split()[0] if text.split() else "?"
            procs.append(Proc(pid, parent, current.username, argv0.rsplit("/", 1)[-1][:15],
                              text, t, 0.0, *_SESSION_SIZES["cmd"],
                              ("R" if i == 0 else "S") + ("+" if current.terminal else ""),
                              tty))
    procs.sort(key=lambda p: p.pid)
    return procs


# ------------------------------------------------------------------ formatting helpers

def _user(name: str) -> str:
    return name if len(name) <= 8 else name[:7] + "+"


def _stime(start: float, now: float) -> str:
    """ps STIME/START: the time today, else month and day."""
    a = dt.datetime.fromtimestamp(start, machine.TZ)
    b = dt.datetime.fromtimestamp(now, machine.TZ)
    if a.date() == b.date():
        return a.strftime("%H:%M")
    if a.year == b.year:
        return a.strftime("%b%d")
    return a.strftime("%Y")


def _time_hms(cpu: float) -> str:
    s = int(cpu)
    d, s = divmod(s, 86400)
    return (f"{d}-" if d else "") + f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}"


def _time_ms(cpu: float) -> str:
    s = int(cpu)
    return f"{s // 60}:{s % 60:02d}"


def _pcpu(p: Proc, now: float) -> str:
    """procps: CPU time over elapsed time, in tenths of a percent, rounded down."""
    el = max(now - p.start, 1)
    return f"{int(p.cpu * 1000 / el) / 10:.1f}"


def _pmem(p: Proc) -> str:
    return f"{int(p.rss * 1000 / MEM_TOTAL) / 10:.1f}"


def _layout(cols: list[tuple[str, int, bool]], rows: list[list[str]],
            width: int | None) -> str:
    """procps column layout: each column at its fixed place unless the text before it
    pushed it right (corpus n=179: a 7-digit VSZ shifts RSS and TTY; STAT is back in
    place). Right-aligned columns end at their place, left-aligned ones start there.
    The last column is not padded, and a terminal cuts every line at its width."""
    pos, places = 0, []
    for _, w, _ in cols:
        places.append(pos)
        pos += w + 1
    out = []
    for r in [[c[0] for c in cols]] + rows:
        line = ""
        for i, (text, (_, w, right)) in enumerate(zip(r, cols)):
            start = places[i]
            if i:
                line += " "
            if right:
                end = max(start + w, len(line) + len(text))
                line += " " * (end - len(text) - len(line)) + text
            else:
                line += " " * max(start - len(line), 0) + text
                if i < len(cols) - 1:
                    line += " " * max(start + w - len(line), 0)
        out.append(line[:width] if width else line)
    return "\n".join(out)


# ------------------------------------------------------------------ ps

_FIELDS = {   # -o name: (header, width, right-aligned, value)
    "pid": ("PID", 7, True, lambda p, n: str(p.pid)),
    "ppid": ("PPID", 7, True, lambda p, n: str(p.ppid)),
    "user": ("USER", 8, False, lambda p, n: _user(p.user)),
    "uid": ("UID", 5, True, lambda p, n: {"root": "0", "pi": "1000", "messagebus": "990",
                                           "systemd-timesync": "992"}.get(p.user, p.user)),
    "comm": ("COMMAND", 15, False, lambda p, n: p.comm),
    "cmd": ("CMD", 27, False, lambda p, n: p.cmdline),
    "args": ("COMMAND", 27, False, lambda p, n: p.cmdline),
    "command": ("COMMAND", 27, False, lambda p, n: p.cmdline),
    "%cpu": ("%CPU", 4, True, _pcpu),
    "pcpu": ("%CPU", 4, True, _pcpu),
    "%mem": ("%MEM", 4, True, lambda p, n: _pmem(p)),
    "pmem": ("%MEM", 4, True, lambda p, n: _pmem(p)),
    "vsz": ("VSZ", 6, True, lambda p, n: str(p.vsz)),
    "rss": ("RSS", 5, True, lambda p, n: str(p.rss)),
    "stat": ("STAT", 4, False, lambda p, n: p.stat),
    "tty": ("TT", 8, False, lambda p, n: p.tty),
    "time": ("TIME", 8, True, lambda p, n: _time_hms(p.cpu)),
    "start": ("STARTED", 8, True, lambda p, n: dt.datetime.fromtimestamp(
        p.start, machine.TZ).strftime("%H:%M:%S")),
    "nlwp": ("NLWP", 4, True, lambda p, n: str(p.nlwp)),
    "ni": ("NI", 3, True, lambda p, n: "-" if p.pr == "rt" else str(p.ni)),
}
_SORT = {"pid": lambda p: p.pid, "ppid": lambda p: p.ppid, "%mem": lambda p: p.rss,
         "pmem": lambda p: p.rss, "rss": lambda p: p.rss, "vsz": lambda p: p.vsz,
         "%cpu": lambda p: p.cpu, "pcpu": lambda p: p.cpu, "user": lambda p: p.user,
         "comm": lambda p: p.comm, "time": lambda p: p.cpu, "start_time": lambda p: p.start}


def ps(procs: list[Proc], argv: list[str], now: float, me, width: int | None) -> tuple[str, int]:
    """The common forms: ps; ps -e/-A [-f]; ps aux / ps -aux; -o/-eo fields; --sort."""
    args = argv[1:]
    sort = None
    if "--sort" in args:
        i = args.index("--sort")
        sort, args = args[i + 1], args[:i] + args[i + 2:]
    sort_arg = [a for a in args if a.startswith("--sort=")]
    if sort_arg:
        sort = sort_arg[0].split("=", 1)[1]
        args = [a for a in args if not a.startswith("--sort=")]
    fields = None
    flags = ""
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "-eo", "-Ao") and i + 1 < len(args):
            flags += "e" if a != "-o" else ""
            fields = args[i + 1].split(",")
            i += 2
            continue
        rest.append(a)
        i += 1
    for a in rest:
        if re.fullmatch(r"-?(aux|axu|uax|eaux)", a):
            flags += "B"
        elif re.fullmatch(r"-[eAf]+", a):
            flags += a[1:]
        else:
            raise Unsupported(f"ps {a}")
    if fields is not None and "B" in flags:
        raise Unsupported("ps aux with -o")

    if "B" in flags:
        sel = procs
        cols = [("USER", 8, False), ("PID", 7, True), ("%CPU", 4, True), ("%MEM", 4, True),
                ("VSZ", 6, True), ("RSS", 5, True), ("TTY", 8, False), ("STAT", 4, False),
                ("START", 5, False), ("TIME", 6, True), ("COMMAND", 0, False)]
        row = lambda p: [_user(p.user), str(p.pid), _pcpu(p, now), _pmem(p), str(p.vsz),
                         str(p.rss), p.tty, p.stat, _stime(p.start, now), _time_ms(p.cpu),
                         p.cmdline]
    elif fields is not None:
        sel = procs if ("e" in flags or "A" in flags) else _mine(procs, me)
        try:
            spec = [_FIELDS[f.lower().lstrip("%") if f.lower() not in _FIELDS else f.lower()]
                    for f in fields]
        except KeyError as e:
            raise Unsupported(f"ps field {e}")
        cols = [(h, w, r) for h, w, r, _ in spec[:-1]] + [(spec[-1][0], 0, spec[-1][2])]
        row = lambda p: [fn(p, now) for _, _, _, fn in spec]
    elif "e" in flags or "A" in flags:
        sel = procs
        if "f" in flags:
            cols = [("UID", 8, False), ("PID", 7, True), ("PPID", 7, True), ("C", 2, True),
                    ("STIME", 5, False), ("TTY", 8, False), ("TIME", 8, True), ("CMD", 0, False)]
            row = lambda p: [_user(p.user), str(p.pid), str(p.ppid),
                             str(int(float(_pcpu(p, now)))), _stime(p.start, now), p.tty,
                             _time_hms(p.cpu), p.cmdline]
        else:
            cols = [("PID", 7, True), ("TTY", 8, False), ("TIME", 8, True), ("CMD", 0, False)]
            row = lambda p: [str(p.pid), p.tty, _time_hms(p.cpu), p.comm]
    elif not flags:
        sel = _mine(procs, me)
        cols = [("PID", 7, True), ("TTY", 8, False), ("TIME", 8, True), ("CMD", 0, False)]
        row = lambda p: [str(p.pid), p.tty, _time_hms(p.cpu), p.comm]
    else:
        raise Unsupported(f"ps {' '.join(argv[1:])}")

    if sort:
        keys = sort.split(",")
        for k in reversed(keys):
            name = k.lstrip("+-")
            if name not in _SORT:
                raise Unsupported(f"ps --sort {k}")
            sel = sorted(sel, key=_SORT[name], reverse=k.startswith("-"))
    return _layout(cols, [row(p) for p in sel], width), 0


def _mine(procs: list[Proc], me) -> list[Proc]:
    """Plain `ps`: processes on this terminal with this user's id."""
    if me is None or not me.terminal:
        return []
    tty = f"pts/{me.tty}"
    return [p for p in procs if p.tty == tty and p.user == me.username]


# ------------------------------------------------------------------ top -b -n 1

def top(procs: list[Proc], now: dt.datetime, boot: float, users: int, mem: Memory,
        width: int) -> str:
    """procps-ng 4.0.4 `top -bn1` (corpus n=184 for the header and the first rows)."""
    lines = ["top -" + machine.uptime_line(now, boot, users)]
    running = sum(1 for p in procs if p.stat.startswith("R"))
    lines.append(f"Tasks:{len(procs):4d} total,{running:4d} running,"
                 f"{len(procs) - running:4d} sleeping,{0:4d} stopped,{0:4d} zombie")
    lines.append("%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st ")
    mib = lambda k: k / 1024
    lines.append(f"MiB Mem :{mib(mem.total):9.1f} total,{mib(mem.free):9.1f} free,"
                 f"{mib(mem.used):9.1f} used,{mib(mem.buff_cache):9.1f} buff/cache     ")
    lines.append(f"MiB Swap:{mib(mem.swap_total):9.1f} total,"
                 f"{mib(mem.swap_total - mem.swap_used):9.1f} free,{mib(mem.swap_used):9.1f} used."
                 f"{mib(mem.available):9.1f} avail Mem ")
    lines.append("")
    lines.append("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND")
    room = max(width - 1 - 71, 1)
    for p in procs:
        name = p.comm if len(p.comm) <= room else p.comm[:room - 1] + "+"
        cs = int(p.cpu * 100)
        timep = f"{cs // 6000}:{cs % 6000 // 100:02d}.{cs % 100:02d}"
        state = p.stat[0]
        lines.append(f"{p.pid:7d} {_user(p.user):<8} {p.pr:>3} {p.ni:>3} {p.vsz:7d} {p.rss:6d} "
                     f"{p.shr:6d} {state} {0.0:5.1f} {p.rss * 100 / MEM_TOTAL:5.1f} "
                     f"{timep:>9} {name}")
    return "\n".join(lines)


# ------------------------------------------------------------------ pgrep, pidof

def pgrep(procs: list[Proc], argv: list[str]) -> tuple[str, int]:
    full = long_ = listname = False
    pats = []
    for a in argv[1:]:
        if a == "-f":
            full = True
        elif a == "-a":
            long_ = True
        elif a == "-l":
            listname = True
        elif a.startswith("-"):
            raise Unsupported(f"pgrep {a}")
        else:
            pats.append(a)
    if len(pats) != 1:
        raise Unsupported("pgrep pattern count")
    rx = re.compile(pats[0])
    hits = [p for p in procs if rx.search(p.cmdline if full else p.comm[:15])]
    hits = [p for p in hits if p.pid not in _self_pids(procs, argv)]
    if not hits:
        return "", 1
    if long_:
        return "\n".join(f"{p.pid} {p.cmdline if not p.kernel else p.comm}" for p in hits), 0
    if listname:
        return "\n".join(f"{p.pid} {p.comm[:15]}" for p in hits), 0
    return "\n".join(str(p.pid) for p in hits), 0


def _self_pids(procs: list[Proc], argv: list[str]) -> set[int]:
    """pgrep never lists itself."""
    me = " ".join(argv)
    return {p.pid for p in procs if p.args == me and p.stat.startswith("R")}


def pidof(procs: list[Proc], argv: list[str]) -> tuple[str, int]:
    names = [a for a in argv[1:] if not a.startswith("-")]
    if not names or len(names) != len(argv) - 1:
        raise Unsupported("pidof options")
    hits = []
    for p in sorted(procs, key=lambda p: -p.pid):
        if p.kernel:
            continue
        first = p.args.split()[0] if p.args.split() else ""
        base = first.rsplit("/", 1)[-1].rstrip(":")
        if base in names or p.comm in names:
            hits.append(str(p.pid))
    return (" ".join(hits), 0) if hits else ("", 1)
