"""Output formats of system commands, reproduced from the tools' own rules (procps-ng
4.0.4 `free`, coreutils 9.7 `df`) and checked against Ground Truth's recordings
(tests/test_relay.py). The numbers come from state.py.

Each function returns (output, exit code) or raises Unsupported for an option it does
not reproduce, so the relay can hand that line to the model instead.
"""
from __future__ import annotations
import math

from .state import Memory, Mount


class Unsupported(Exception):
    pass


def _flags(argv: list[str], allowed: str, long: dict[str, str]) -> tuple[set[str], list[str]]:
    """Short flags (bundled like -hT) and known long options -> set of letters; plus
    the operands. Anything else is Unsupported."""
    flags, operands = set(), []
    for a in argv[1:]:
        if a in long:
            flags.add(long[a])
        elif a.startswith("-") and len(a) > 1 and not a.startswith("--"):
            for ch in a[1:]:
                if ch not in allowed:
                    raise Unsupported(f"{argv[0]} -{ch}")
                flags.add(ch)
        elif a.startswith("-"):
            raise Unsupported(a)
        else:
            operands.append(a)
    return flags, operands


# ------------------------------------------------------------------ free

def _free_human(kib: int) -> str:
    """procps' scale_size: one decimal while it fits in 3 characters, else whole units."""
    size = kib * 1024
    if size == 0:
        return "0B"
    if size < 1024:
        return f"{size}B"
    for i, unit in enumerate(("Ki", "Mi", "Gi", "Ti", "Pi"), start=1):
        x = size / 1024 ** i
        if x >= 1024 and unit != "Pi":
            continue
        s = f"{x:.1f}"
        return (s if len(s) <= 3 else f"{int(x)}") + unit
    raise AssertionError


def free(mem: Memory, argv: list[str]) -> tuple[str, int]:
    flags, operands = _flags(argv, "bkmghtw", {
        "--bytes": "b", "--kibi": "k", "--mebi": "m", "--gibi": "g", "--human": "h",
        "--total": "t", "--wide": "w"})
    if operands:
        raise Unsupported("free operands")
    units = [f for f in "bkmgh" if f in flags]
    if len(units) > 1:
        raise Unsupported("several units")
    unit = units[0] if units else "k"
    conv = {"b": lambda v: str(v * 1024), "k": str, "m": lambda v: str(v >> 10),
            "g": lambda v: str(v >> 20), "h": _free_human}[unit]
    wide = "w" in flags
    head = ["total", "used", "free", "shared"] + (["buffers", "cache"] if wide
                                                   else ["buff/cache"]) + ["available"]
    lines = [" " * 8 + "".join(f"{h:>12}" for h in head)]
    mem_vals = [mem.total, mem.used, mem.free, mem.shared] + (
        [mem.buffers, mem.cache] if wide else [mem.buff_cache]) + [mem.available]
    lines.append(f"{'Mem:':<8}" + "".join(f"{conv(v):>12}" for v in mem_vals))
    swap_free = mem.swap_total - mem.swap_used
    lines.append(f"{'Swap:':<8}" + "".join(f"{conv(v):>12}" for v in
                                          (mem.swap_total, mem.swap_used, swap_free)))
    if "t" in flags:
        lines.append(f"{'Total:':<8}" + "".join(f"{conv(v):>12}" for v in (
            mem.total + mem.swap_total, mem.used + mem.swap_used, mem.free + swap_free)))
    return "\n".join(lines), 0


# ------------------------------------------------------------------ df

def _df_human(kib: int) -> str:
    """coreutils' human_ceiling in powers of 1024: rounds up, one decimal below 10."""
    if kib == 0:
        return "0"
    x, units = float(kib), "KMGTPE"
    i = 0
    while i < len(units) - 1 and (x >= 1024 or math.ceil(x) >= 1024):
        x /= 1024
        i += 1
    if x < 10:
        d = math.ceil(x * 10) / 10
        if d < 10:
            return f"{d:.1f}{units[i]}"
    return f"{math.ceil(x)}{units[i]}"


def _pct(used: int, avail: int) -> str:
    """coreutils: used / (used + available), rounded up; '-' when there is nothing."""
    if used + avail == 0:
        return "-"
    return f"{math.ceil(used * 100 / (used + avail))}%"


def _mount_of(path: str, rows: list[Mount]) -> Mount:
    best = None
    for m in rows:
        if path == m.target or path.startswith(m.target.rstrip("/") + "/"):
            if best is None or len(m.target) >= len(best.target):
                best = m
    assert best is not None
    return best


def df(rows: list[Mount], argv: list[str], resolve, exists) -> tuple[str, int]:
    """`resolve(path)` makes an operand absolute; `exists(path)` says whether it does."""
    flags, operands = _flags(argv, "hikTP", {
        "--human-readable": "h", "--inodes": "i", "--print-type": "T", "--portability": "P"})
    if "P" in flags:
        raise Unsupported("df -P")
    human, inodes, show_type = "h" in flags, "i" in flags, "T" in flags
    out_rows, errors = rows, []
    if operands:
        out_rows = []
        for op in operands:
            path = resolve(op)
            if exists(path) is False:
                errors.append(f"df: {op}: No such file or directory")
            elif exists(path) is None:
                raise Unsupported(f"df of an unknown path {op}")
            else:
                out_rows.append(_mount_of(path, rows))

    # (header, minimum width, right-aligned) per field, as in coreutils' df.c.
    fields = [("Filesystem", 14, False)]
    if show_type:
        fields.append(("Type", 4, False))
    if inodes:
        fields += [("Inodes", 5, True), ("IUsed", 5, True), ("IFree", 5, True),
                   ("IUse%", 5, True)]
    elif human:
        fields += [("Size", 5, True), ("Used", 5, True), ("Avail", 5, True),
                   ("Use%", 4, True)]
    else:
        fields += [("1K-blocks", 5, True), ("Used", 5, True), ("Available", 5, True),
                   ("Use%", 4, True)]
    fields.append(("Mounted on", 0, False))

    def cells(m: Mount) -> list[str]:
        c = [m.source] + ([m.fstype] if show_type else [])
        if inodes:
            c += [str(m.inodes), str(m.iused), str(m.ifree), _pct(m.iused, m.ifree)]
        else:
            fmt = _df_human if human else str
            c += [fmt(m.size), fmt(m.used), fmt(m.avail), _pct(m.used, m.avail)]
        return c + [m.target]

    table = [[f[0] for f in fields]] + [cells(m) for m in out_rows]
    widths = [max([f[1]] + [len(r[i]) for r in table]) for i, f in enumerate(fields)]
    lines = []
    for r in table:
        parts = [(c.rjust(w) if f[2] else c.ljust(w))
                 for c, w, f in zip(r[:-1], widths, fields)]
        lines.append(" ".join(parts + [r[-1]]))
    out = "\n".join(errors + (lines if out_rows else []))
    return out, 1 if errors else 0
