"""Who and what this machine is: `uname`, `hostname`, `nproc`, `id`, `groups`, `whoami`.

Computed from facts the relay already holds, not looked up: the kernel line of the
login banner (machine.MOTD, recorded in gt_frontdoor_2026-09.json), the hostname, the
number of cores, and the fact that the only account that can log in is root. The option
rules are coreutils 9.7's (`uname`, `nproc`, `id`, `groups`) and hostname 3.25's;
checked against the corpus (n=21-29, 43, 45, 52, 53, 123-127), never against the 43.

Decided 2026-10-08, after the replay tier was removed: these are among the first
things anybody types, and the model answered `id` wrongly in three different ways
(docs/replay-removal-latency.md).

Each function returns (output, exit code) or raises Unsupported for a form it does not
reproduce (an unknown option, another user), so the relay hands that line to the model.
"""
from __future__ import annotations

from . import machine
from .sysinfo import Unsupported, _flags


def _kernel() -> dict[str, str]:
    """uname's fields, read off the banner's first line: `Linux raspberrypi
    6.12.75+rpt-rpi-2712 #1 SMP PREEMPT Debian 1:6.12.75-1+rpt1 (2026-03-11) aarch64`,
    which is `uname -snrvm`."""
    words = machine.MOTD.split("\n")[0].split()
    return {"s": words[0], "n": words[1], "r": words[2], "v": " ".join(words[3:-1]),
            "m": words[-1],
            # Debian does not fill these two in; -a leaves them out when unknown.
            "p": "unknown", "i": "unknown",
            "o": "GNU/Linux"}


def uname(argv: list[str]) -> tuple[str, int]:
    flags, operands = _flags(argv, "asnrvmpio", {
        "--all": "a", "--kernel-name": "s", "--nodename": "n", "--kernel-release": "r",
        "--kernel-version": "v", "--machine": "m", "--processor": "p",
        "--hardware-platform": "i", "--operating-system": "o"})
    if operands:
        raise Unsupported("uname operand")
    k = _kernel()
    if "a" in flags:
        order = [f for f in "snrvmpio" if k[f] != "unknown"]
    else:
        order = [f for f in "snrvmpio" if f in (flags or {"s"})]
    return " ".join(k[f] for f in order), 0


def hostname(argv: list[str]) -> tuple[str, int]:
    """The name, short or fully qualified: the machine has no domain, so all three are
    the same (corpus n=43, 45). `hostname -I` is net.hostname_i; setting a name and the
    other lookups are left to the model."""
    if argv[1:] in ([], ["-s"], ["--short"], ["-f"], ["--fqdn"], ["--long"]):
        return machine.HOSTNAME, 0
    raise Unsupported("hostname option")


def nproc(argv: list[str]) -> tuple[str, int]:
    args, ignore = argv[1:], 0
    if args and args[0] == "--all":
        args = args[1:]
    if args and args[0].startswith("--ignore="):
        value, args = args[0].split("=", 1)[1], args[1:]
        if not value.isdigit():
            raise Unsupported("nproc --ignore value")
        ignore = int(value)
    if args:
        raise Unsupported("nproc option")
    return str(max(machine.CORES - ignore, 1)), 0


def _only_root(username: str, operands: list[str]) -> None:
    """These answers are known for root, the one account that can log in. Another
    user's groups would have to come from a recording of /etc/group."""
    if username != "root" or any(o != "root" for o in operands) or len(operands) > 1:
        raise Unsupported("a user other than root")


def id_(argv: list[str], username: str) -> tuple[str, int]:
    flags, operands = _flags(argv, "ugGnr", {"--user": "u", "--group": "g", "--groups": "G",
                                             "--name": "n", "--real": "r"})
    _only_root(username, operands)
    what = flags & set("ugG")
    if len(what) > 1 or (not what and flags):       # id's own error texts: the model's
        raise Unsupported("id option combination")
    if not what:
        return "uid=0(root) gid=0(root) groups=0(root)", 0
    return ("root" if "n" in flags else "0"), 0


def whoami(argv: list[str], username: str) -> tuple[str, int]:
    """The same fact as `id -un`. Options and operands are the model's (error texts)."""
    if argv[1:]:
        raise Unsupported("whoami with arguments")
    return username, 0


def groups(argv: list[str], username: str) -> tuple[str, int]:
    if any(a.startswith("-") for a in argv[1:]):
        raise Unsupported("groups option")
    _only_root(username, argv[1:])
    return ("root : root" if argv[1:] else "root"), 0
