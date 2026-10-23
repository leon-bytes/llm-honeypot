"""What the simulated machine is: fixed facts, and the answers derived from its clock.

Every value here is taken from the Ground Truth recordings, never from the
machine the relay runs on: the Orchestrator has a newer kernel (6.18.50 vs
6.12.75), a newer OpenSSH (deb13u4 vs deb13u2) and /etc/debian_version 13.7 vs
13.4, so reading anything off it would give the honeypot away.
"""
from __future__ import annotations
import datetime as dt
import json
import math
import os
import pathlib
import re
import time
from zoneinfo import ZoneInfo

TZ = ZoneInfo("America/New_York")
HOSTNAME = "raspberrypi"
CORES = 4

# gt_frontdoor_2026-09.json, login.login_messages. The "Last login" line goes
# between these two parts; sshd ends it with "\r\n", which the terminal's own
# "\n" -> "\r\n" turns into the "\r\r\n" recorded on the wire.
MOTD = (
    "Linux raspberrypi 6.12.75+rpt-rpi-2712 #1 SMP PREEMPT Debian 1:6.12.75-1+rpt1 "
    "(2026-03-11) aarch64\n"
    "\n"
    "The programs included with the Debian GNU/Linux system are free software;\n"
    "the exact distribution terms for each program are described in the\n"
    "individual files in /usr/share/doc/*/copyright.\n"
    "\n"
    "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\n"
    "permitted by applicable law.\n"
)
AFTER_LAST_LOGIN = (
    "\n"
    "Wi-Fi is currently blocked by rfkill.\n"
    "Use raspi-config to set the country before use.\n"
    "\n"
)
# Bash switches bracketed paste on before every prompt (gt_frontdoor login.prompt_raw).
PROMPT_PREFIX = "\x1b[?2004h"


def boot_time() -> float:
    """The Orchestrator's own boot time, so every session derives the same uptime (R5)."""
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except OSError:
        pass
    return time.time() - 3600


BOOT_SLACK_S = 60


def pinned_boot_time(state_dir: str, write: bool = True) -> float:
    """The boot time the honeypot goes by: the kernel's, as first read in this boot and
    kept in the state directory. The kernel derives its value from the wall clock, so
    it moves whenever the clock is corrected (on the Orchestrator by 10 s in one night,
    2026-10-06, with no reboot), and everything generated per boot is seeded with it:
    MACs, veth names, endpoint and sandbox IDs. A restarted relay therefore keeps the
    stored time while the kernel's is within a minute of it; only a reboot, which
    moves it by far more, starts a new one."""
    kernel = boot_time()
    path = pathlib.Path(state_dir) / "boot.json"
    try:
        kept = float(json.loads(path.read_text())["boot"])
        if abs(kept - kernel) <= BOOT_SLACK_S:
            return kept
    except (OSError, ValueError, KeyError, TypeError):
        pass
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"boot": kernel}) + "\n")
        os.replace(tmp, path)
    return kernel


def pid_floor(t: float, boot: float) -> int:
    """The machine's PID counter at time t: 2439 at 11 minutes (gt43 n=23), then about
    0.8 new PIDs a second, mostly the containers' health checks (Ground Truth reached
    278422 after 4 days: offline/gt-kthreads-20261002.txt)."""
    up = max(t - boot, 0)
    return int(2439 + 0.798 * max(up - 660, 0))


def now() -> dt.datetime:
    return dt.datetime.now(TZ)


def date_local(t: dt.datetime) -> str:
    """en_GB `date`: the day is space-padded, `Thu  1 Oct 09:05:03 EDT 2026` (checked on
    the Orchestrator, same OS and locale as Ground Truth)."""
    return t.strftime("%a %e %b %H:%M:%S %Z %Y")


# ------------------------------------------------------------------ time zone
#
# The machine is in America/New_York, and its clocks change: on 2026-11-01 at 02:00
# EDT (-0400) becomes EST (-0500), the day the class setup is frozen. A real machine
# labels every time it prints with the zone in force AT THAT TIME, not at the time of
# asking: in November `stat` still shows a file from September with -0400, and
# `systemctl status` shows a boot of 2 November with EST. Every recording was made in
# September and says EDT / -0400 throughout, so any recorded or generated text whose
# date has moved must have its zone label moved with it.

_ZONE_TOKEN = r"(?P<zone>EDT|EST|-0[45]:?00)"
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MON = "|".join(_MONTHS)
_WD = "Mon|Tue|Wed|Thu|Fri|Sat|Sun"
_CLOCK = r"(?P<h>[01]\d|2[0-3]):(?P<mi>[0-5]\d):(?P<s>[0-5]\d|60)"
# `2026-09-28 20:34:39 EDT` (systemctl), `2026-09-28 20:43:56.703222586 -0400` (stat),
# `2026-09-28T20:35:02.101164686-04:00` (dockerd's log lines, Docker's JSON).
_ZONED_ISO = re.compile(
    rf"\b(?P<y>\d{{4}})-(?P<mo>\d\d)-(?P<d>\d\d)(?P<sep>[ T]){_CLOCK}"
    rf"(?P<frac>[.,]\d+)?(?P<gap> ?){_ZONE_TOKEN}(?![\d:])")
# `Mon 28 Sep 20:47:03 EDT 2026` (en_GB date) and `Mon Sep 28 20:47:03 EDT 2026` (C).
_ZONED_DATE = re.compile(
    rf"\b(?P<wd>{_WD}) (?:(?P<d1>[ \d]\d) (?P<mon1>{_MON})|(?P<mon2>{_MON}) (?P<d2>[ \d]\d)) "
    rf"{_CLOCK} (?P<zone>EDT|EST) (?P<y>\d{{4}})\b")
# timedatectl: `Time zone: America/New_York (EDT, -0400)`. The zone in force now.
_ZONE_NOW = re.compile(r"America/New_York \((?:EDT|EST), -0[45]00\)")


def zone_label(t: dt.datetime, like: str) -> str:
    """The zone of the aware time `t`, written the way `like` is: `EDT`, `-0400` or
    `-04:00`."""
    if like[0] != "-":
        return t.strftime("%Z")
    off = t.strftime("%z")
    return off[:3] + ":" + off[3:] if ":" in like else off


def _zone_for_wall_time(y, mo, d, h, mi, s, like: str) -> str:
    """The zone label a wall-clock time must carry. `like` is kept when it is one the
    rules allow: in the hour that happens twice when the clocks go back (01:00-01:59 on
    2026-11-01) both labels are right, and only the one who wrote the time knows which.
    A time that does not exist (the skipped hour in March) is left alone too."""
    try:
        naive = dt.datetime(y, mo, d, h, mi, min(s, 59))
    except ValueError:
        return like
    allowed = []
    for fold in (0, 1):
        t = naive.replace(tzinfo=TZ, fold=fold)
        back = t.astimezone(dt.timezone.utc).astimezone(TZ).replace(tzinfo=None)
        if back == naive:                       # this wall time exists with this fold
            allowed.append(zone_label(t, like))
    if not allowed or like in allowed:
        return like
    return allowed[0]


def _fix_iso(m: re.Match) -> str:
    g = m.groupdict()
    zone = _zone_for_wall_time(int(g["y"]), int(g["mo"]), int(g["d"]), int(g["h"]),
                               int(g["mi"]), int(g["s"]), g["zone"])
    return m.group(0)[:m.start("zone") - m.start()] + zone


def _fix_date(m: re.Match) -> str:
    g = m.groupdict()
    mon = _MONTHS.index(g["mon1"] or g["mon2"]) + 1
    zone = _zone_for_wall_time(int(g["y"]), mon, int(g["d1"] or g["d2"]), int(g["h"]),
                               int(g["mi"]), int(g["s"]), g["zone"])
    return (m.group(0)[:m.start("zone") - m.start()] + zone
            + m.group(0)[m.end("zone") - m.start():])


def zone_rewriters() -> list:
    """(pattern, replacement) passes that make every zone label in a text the one the
    zone rules give for the time it stands next to. For the relay's substitution pass
    (knowledge.Substitutions), so they reach recorded examples and model answers alike;
    answers made in code already ask the zone database (date_local, docker.go_time).
    Run them after anything that moves a date. A text that is already right is returned
    unchanged: every recording passes through as it is (tests/test_relay.py)."""
    return [(_ZONED_ISO, _fix_iso), (_ZONED_DATE, _fix_date),
            (_ZONE_NOW, lambda m: now().strftime("America/New_York (%Z, %z)"))]


# ------------------------------------------------------------------ ls -l and age
#
# `ls -l` prints the time of day for a file changed in the last six months and the
# year for an older one: `Apr 12 20:07` becomes `Apr 12  2026`. The recordings are from
# late September 2026, when the files of the OS image (12 April) were still "recent";
# from about 12 October the real machine prints the year for them. Like the zone label,
# this depends on when the answer is printed, so it is corrected in the same pass.

SIX_MONTHS_S = 31556952 // 2          # GNU ls: half a mean Gregorian year
# The start of an `ls -l` line up to its date: type and mode, links, owner, group, size
# (or `major, minor` of a device), then `Mon DD HH:MM`.
_LS_LINE = re.compile(
    rf"(?m)^(?P<head>[-dlcbps][-rwxsStT]{{9}}[.+@]? +\d+ +\S+ +\S+ +(?:\d+, +)?\d+ )"
    rf"(?P<mon>{_MON}) (?P<d>[ \d]\d) (?P<h>[01]\d|2[0-3]):(?P<mi>[0-5]\d)(?= )")


def _ls_date(m: re.Match) -> str:
    """The line with the year in place of the time, if the file is older than six
    months now. The line gives no year; it is the latest one that does not put the file
    in the future, which is right for every date in the recordings until six months
    after the oldest of them, 2027-03-29."""
    t = now()
    mon, day = _MONTHS.index(m.group("mon")) + 1, int(m.group("d"))
    for year in (t.year, t.year - 1):
        try:
            when = dt.datetime(year, mon, day, int(m.group("h")), int(m.group("mi")), tzinfo=TZ)
        except ValueError:
            continue
        if when <= t + dt.timedelta(hours=1):          # ls calls a file up to now "recent"
            break
    else:
        return m.group(0)
    if (t - when).total_seconds() <= SIX_MONTHS_S:
        return m.group(0)
    return f"{m.group('head')}{m.group('mon')} {m.group('d')}  {when.year}"


def ls_age_rewriters() -> list:
    """The (pattern, replacement) pass for the six-month rule of `ls -l`, for the relay's
    substitution pass: recorded examples when the relay starts, and every model answer
    when it is given. A listing that is right is returned unchanged."""
    return [(_LS_LINE, _ls_date)]


def date_utc(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%a %e %b %H:%M:%S UTC %Y")


def ctime(t: dt.datetime) -> str:
    """sshd's `Last login:` format: `Mon Sep 28 20:48:22 2026`."""
    return t.strftime("%a %b %e %H:%M:%S %Y")


def load_average(t: float) -> tuple[float, float, float]:
    """A quiet box: small, slowly drifting values that are the same for every session."""
    m = t / 60.0
    one = 0.04 + 0.04 * math.sin(m / 3.0) + 0.02 * math.sin(m * 1.7)
    five = 0.03 + 0.02 * math.sin(m / 9.0)
    fifteen = 0.01 + 0.01 * math.sin(m / 27.0)
    return tuple(round(max(0.0, x), 2) for x in (one, five, fifteen))


def _dhm(secs: float) -> tuple[int, int, int]:
    days, rem = divmod(int(secs), 86400)
    hours, rem = divmod(rem, 3600)
    return days, hours, rem // 60


def uptime_line(t: dt.datetime, boot: float, users: int) -> str:
    """procps `uptime`: ` 20:46:08 up 11 min,  1 user,  load average: 0.00, 0.02, 0.00`."""
    days, hours, mins = _dhm(t.timestamp() - boot)
    s = f" {t:%H:%M:%S} up "
    if days:
        s += f"{days} day{'s' if days != 1 else ''}, "
    s += f"{hours:2d}:{mins:02d}, " if hours else f"{mins} min, "
    la = load_average(t.timestamp())
    return (s + f"{users:2d} user{'s' if users != 1 else ''},  "
            f"load average: {la[0]:.2f}, {la[1]:.2f}, {la[2]:.2f}")


def uptime_pretty(t: dt.datetime, boot: float) -> str:
    """procps `uptime -p`: `up 2 days, 9 hours, 51 minutes`."""
    days, hours, mins = _dhm(t.timestamp() - boot)
    weeks, days = divmod(days, 7)
    parts = [f"{n} {unit}{'s' if n != 1 else ''}"
             for n, unit in ((weeks, "week"), (days, "day"), (hours, "hour"), (mins, "minute"))
             if n]
    return "up " + (", ".join(parts) if parts else "0 minutes")


def uptime_since(boot: float) -> str:
    return dt.datetime.fromtimestamp(boot, TZ).strftime("%Y-%m-%d %H:%M:%S")


def proc_uptime(t: dt.datetime, boot: float) -> str:
    """`/proc/uptime`: seconds up, then idle seconds summed over the 4 cores."""
    up = t.timestamp() - boot
    return f"{up:.2f} {up * CORES * 0.9975:.2f}"
