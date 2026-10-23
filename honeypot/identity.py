"""The honeypot's own install- and boot-specific identifiers (R3, decided 2026-10-02).

Principle: anything a separate install would generate at random differs from Ground
Truth's; configuration and content match. So the honeypot has its own Docker daemon ID,
container IDs, network IDs, endpoint IDs, sandbox IDs, container MACs and anonymous
volume names, while image IDs, layer digests, compose config hashes, names, labels and
settings stay Ground Truth's.

- Once per install (stable across restarts and reboots): generated from a secret made on
  first start and kept in the relay's state directory.
- Once per boot (as Docker regenerates them when the containers start): from the same
  secret and the boot time.

`pairs()` maps every Ground Truth value, full and 12-character short form, to the
honeypot's; the relay adds them to its substitution map, so recordings, model answers
and code answers all show the same IDs. The bridge name `br-<network id>` follows
automatically, since it contains the short network ID.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
import pathlib
import re

from . import machine, net

# Ground Truth's values (gt_api_phase1_2026-09.json, after the 2026-09-28 reboot).
INSTALL = {
    "daemon": "718043f1-59cd-4543-8775-b2ee353985c7",
    "container-nodered": "d139ff53533c7de3002a3a73db79943a968d3ab1da93dd637a4e292bd1ed3334",
    "container-influxdb": "443074d3a15d7c1ec1140452284abb8d481f98c9ad8c224c39698f50fb7c0594",
    "container-mosquitto": "d3775f38b3d46fd726f64510ab68d268e93aae6709f80cbc02c5710a256f3b89",
    "network-iot-stack_default": "f5676ba9b003828d64655fe9859da8587bc3ed69104684860b336f000430c855",
    "network-host": "1bca9fb4face9c109d453852922dd3ac628143208254af5fda04425a5290723e",
    "network-none": "57821afcfdc550dfab3d4cc4c38f786880689b3dcdd0d4c394d5cd5da9396901",
    "volume-anonymous-mosquitto": "ff693fcfe6b68afd5f4868310999134480b3a79e78de11eb79a715fe7c97cb95",
}
BOOT = {
    "network-bridge": "e980f9666992d9dd0234a6875e5a14f3cb4dba30c0e823c639802fd30b599618",
    "endpoint-nodered": "4c041bd786603a343258463284408fe72c71a6b1c8ac1ec5c771aba5506716f6",
    "endpoint-influxdb": "fcd21c095dc66693d39645e9839ff233dfae8af89893d91c057ca76a56dbd896",
    "endpoint-mosquitto": "28ded3c3aad0d1e98c17bc3b46351800750e0a6946f187beea3e617788d9f56a",
    "sandbox-nodered": "3e2c4e7e6d58436ae82619e91033809a9b7314f480dd73f5c2a202f5a215d9a5",
    "sandbox-influxdb": "222f59dd49b03bc2b62de6efd75e273da1465a235daf8ba65db9f85b781d2fbe",
    "sandbox-mosquitto": "3114f5769576a1a73156ab4cfbe6436fa2341ca16188a4df8f6fe19550d7c1c1",
    "mac-nodered": "56:cc:29:53:91:03",
    "mac-influxdb": "82:ef:5e:94:60:08",
    "mac-mosquitto": "da:8f:73:fd:64:ce",
}


def secret(state_dir: str) -> str:
    """This install's secret: made once, then read back, so the IDs never change."""
    path = pathlib.Path(state_dir) / "install.json"
    try:
        return json.loads(path.read_text())["secret"]
    except (OSError, ValueError, KeyError):
        s = os.urandom(32).hex()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"secret": s}) + "\n")
        return s


def _make(kind_value: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    if ":" in kind_value:                              # a MAC
        return net._random_mac(seed)
    if "-" in kind_value:                              # a UUID (the daemon ID)
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{'89ab'[int(h[16], 16) % 4]}{h[17:20]}-{h[20:32]}"
    return h[:len(kind_value)]


def pairs(state_dir: str, boot: float, secret_value: str | None = None) -> dict[str, str]:
    s = secret_value or secret(state_dir)
    out = {}
    for name, gt in INSTALL.items():
        out[gt] = _make(gt, f"{s}-install-{name}")
    for name, gt in BOOT.items():
        out[gt] = _make(gt, f"{s}-boot-{int(boot)}-{name}")
    for gt, own in list(out.items()):                  # short forms, as Docker prints them
        if len(gt) == 64:
            out[gt[:12]] = own[:12]
    return out


def all_pairs(config_subs: dict, state_dir: str, boot: float,
              secret_value: str | None = None) -> dict[str, str]:
    """Every literal Ground Truth value -> this machine's: the addresses (config), the
    per-boot network values (net.py) and the IDs above. The relay answers through this
    map, and tools/build_scorer_identity.py hands the same map to the scorer."""
    return {**config_subs, **net.boot_substitutions(boot),
            **pairs(state_dir, boot, secret_value)}


# ------------------------------------------------------------------ install time

# Ground Truth was set up on 2026-09-27 (local): Docker installed 18:03, the stack
# created 18:04, and the rest of that day's work (/home/pi 22:51, / 22:12, root's
# .bash_history 17:59) in the file dates the corpus shows. A second install would not
# have been done the same day to the nanosecond, so the honeypot moves that whole day,
# as one block, to a day of its own a few days before the class: order and gaps stay.
# Image creation times are build times, not install times, and do not move.
GT_SETUP_DAY = dt.date(2026, 9, 27)
_NS = 10**9
_DAY_NS = 86400 * _NS


def _local_ns(day: dt.date, hour: int = 0, minute: int = 0) -> int:
    t = dt.datetime(day.year, day.month, day.day, hour, minute, tzinfo=machine.TZ)
    return int(t.timestamp()) * _NS


def install_shift_ns(secret_value: str, boot: float, class_start: dt.date) -> int:
    """How far this install's setup day lies after Ground Truth's, in nanoseconds:
    3-5 days before the class, a different time of day (within 2 h), and its own
    nanoseconds. Fixed for the install, except that the setup has to be over an hour
    before this boot (the containers were started by it): while the Orchestrator was
    booted earlier than that, the day moves back to fit, whole days at a time, if need
    be to before Ground Truth's own (a negative shift)."""
    h = hashlib.sha256(f"{secret_value}-install-shift".encode()).digest()
    day = class_start - dt.timedelta(days=3 + h[0] % 3)
    minutes = int.from_bytes(h[1:3], "big") % 241 - 120
    shift = ((day - GT_SETUP_DAY).days * _DAY_NS + minutes * 60 * _NS
             + int.from_bytes(h[3:7], "big") % _NS)
    setup_over = _local_ns(GT_SETUP_DAY + dt.timedelta(days=1))
    while setup_over + shift > int(boot - 3600) * _NS:
        shift -= _DAY_NS
    return shift


def _day_rewriters(moves: dict):
    """(pattern, replacement) passes that rewrite times of day on Ground Truth's days, in
    the three forms answers show them: `Sep 28 20:34` (ls, the journal),
    `Mon 2026-09-28 20:34:42` (systemctl, stat, who) and `Mon 28 Sep 20:47` (en_GB
    date), each with or without seconds and weekday. `moves` maps each day to
    `move(gt_ns, with_seconds)`, giving the new time or None to leave it. All days go
    in one pass, so a rewritten date is never rewritten again."""
    wd = r"(?:(?P<wd>Mon|Tue|Wed|Thu|Fri|Sat|Sun) )?"
    hms = r"(?P<h>[01]\d|2[0-3]):(?P<m>[0-5]\d)(?::(?P<s>[0-5]\d))?\b"
    # What may follow the time and has to move with it: the zone the time was printed
    # in (`20:34:39 EDT`, stat's `20:43:56.703222586 -0400`). The moved time gets the
    # zone in force at ITS moment, which is exact even in the hour that happens twice
    # when the clocks go back.
    tail = r"(?P<frac>\.\d+)?(?: (?P<zone>EDT|EST|-0[45]00)\b)?"
    by_text = {}
    forms = [(lambda d: f"{d:%b} {d.day:2d}", "%b %e %H:%M", "%a %b %e %H:%M"),
             (lambda d: f"{d:%Y-%m-%d}", "%Y-%m-%d %H:%M", "%a %Y-%m-%d %H:%M"),
             (lambda d: f"{d.day} {d:%b}", "%e %b %H:%M", "%a %e %b %H:%M")]
    out = []
    for spell, plain, with_day in forms:
        days = {spell(d): d for d in moves}
        alts = "|".join(re.escape(k) for k in days)

        def repl(m, days=days, plain=plain, with_day=with_day):
            day, sec = days[m.group("day")], m.group("s")
            gt = _local_ns(day, int(m.group("h")), int(m.group("m"))) + int(sec or 0) * _NS
            new = moves[day](gt, sec is not None)
            if new is None:
                return m.group(0)
            t = dt.datetime.fromtimestamp(new // _NS, machine.TZ)
            text = t.strftime(with_day if m.group("wd") else plain)
            if not m.group("wd") and plain.startswith("%e"):
                text = text.lstrip()
            text += (t.strftime(":%S") if sec else "") + (m.group("frac") or "")
            if m.group("zone"):
                text += " " + machine.zone_label(t, m.group("zone"))
            return text
        out.append((re.compile(rf"\b{wd}(?P<day>{alts}) {hms}{tail}"), repl))
    return out


# Ground Truth's boot, which every recording was taken in (2026-09-28 20:34:32). Dates
# from it on (`/dev`, `/proc`, `/sys` at the boot; `/root`, `/run`, `/tmp` and the
# journal from the capture session minutes later) are boot-relative: they become the
# same distance after this machine's boot (R5).
GT_BOOT_DAY = dt.date(2026, 9, 28)
GT_BOOT_NS = _local_ns(GT_BOOT_DAY, 20, 34) + 32 * _NS


def date_rewriters(shift_ns: int, boot: float):
    """For text answers: dates on Ground Truth's setup day move by this install's shift,
    so a replayed listing agrees with the Docker API's creation times; dates from its
    boot on become the same distance after this machine's boot. A minute-only boot date
    maps minute to minute, so `20:34` is the minute this machine booted. A zone label
    behind a moved time (`EDT`, `-0400`) becomes the one in force at the new time, and
    a last pass corrects any zone label that does not fit the time it stands next to."""
    boot_min = int(boot) // 60 * 60 * _NS

    def after_boot(gt, with_seconds):
        if gt < GT_BOOT_NS - (0 if with_seconds else 32 * _NS):
            return None                       # before the boot: not boot-relative
        if with_seconds:
            return int(boot) * _NS + gt - GT_BOOT_NS
        return boot_min + gt - (GT_BOOT_NS - 32 * _NS)
    # Then every zone label is checked against the zone rules (machine.zone_rewriters):
    # the recordings say EDT / -0400 throughout, and the clocks change on 2026-11-01.
    # And `ls -l` dates older than six months get the year instead of the time
    # (machine.ls_age_rewriters): the recordings are from September 2026.
    return (_day_rewriters({GT_SETUP_DAY: lambda gt, sec: gt + shift_ns,
                            GT_BOOT_DAY: after_boot})
            + machine.zone_rewriters() + machine.ls_age_rewriters())
