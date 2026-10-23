"""The simulated machine's sockets, and `ss` / `netstat` over them (R14).

The listening sockets and their order are Ground Truth's (corpus n=165, `ss -tuln`);
their owners are the process table's (procs.py) so `ss -p`, `netstat -p` and `ps`
agree. The file descriptors of sshd, docker-proxy and dockerd are Ground Truth's too
(gt43 n=39, the same in all three recordings); NetworkManager's is not in any
recording. Each live relay session adds its own established SSH connection. Counts for
`ss -s` follow corpus n=166. Addresses are Ground Truth's and are passed through the
relay's substitution map (R1) BEFORE formatting, because netstat truncates long IPv6
addresses and a substitution afterwards would not match.

Formats are reproduced from the tools' sources: iproute2 6.15.0 misc/ss.c
(render_calc_width: columns sized to content, spare screen width shared out evenly,
remainder to the last columns first; no extension into a pipe) and net-tools 2.10
netstat.c (fixed columns, addresses cut at 22 characters, program names at 19).
"""
from __future__ import annotations
from dataclasses import dataclass, field

from .site import SITE


class Unsupported(Exception):
    pass


@dataclass
class Sock:
    proto: str                  # tcp | udp
    v6: bool
    state: str                  # LISTEN | UNCONN | ESTAB
    laddr: str
    lport: str
    raddr: str
    rport: str
    sendq: int = 0
    owners: list = field(default_factory=list)     # [(comm, pid, fd, cmdline)]
    v6only: bool = True


GT = SITE.ref_ipv4


def table(sessions, subs=lambda s: s) -> list[Sock]:
    """Kernel order as on Ground Truth: udp, then tcp listeners, then connections."""
    sshd = ("sshd", 826, None, "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups")
    socks = [
        Sock("udp", True, "UNCONN", subs(SITE.ref_ipv6_link), "546", "*", "*",
             owners=[("NetworkManager", 687, 27, "/usr/sbin/NetworkManager --no-daemon")]),  # fd est.
        Sock("tcp", False, "LISTEN", "0.0.0.0", "22", "0.0.0.0", "*", 128,
             [(sshd[0], 826, 6, sshd[3])]),                                        # fd est.
        Sock("tcp", False, "LISTEN", "127.0.0.1", "8086", "0.0.0.0", "*", 4096,
             [("docker-proxy", 1106, 8, "/usr/bin/docker-proxy")]),
        Sock("tcp", False, "LISTEN", "127.0.0.1", "1883", "0.0.0.0", "*", 4096,
             [("docker-proxy", 1099, 8, "/usr/bin/docker-proxy")]),
        Sock("tcp", False, "LISTEN", "127.0.0.1", "1880", "0.0.0.0", "*", 4096,
             [("docker-proxy", 1092, 8, "/usr/bin/docker-proxy")]),
        Sock("tcp", True, "LISTEN", "::", "22", "::", "*", 128, [(sshd[0], 826, 7, sshd[3])]),
        Sock("tcp", True, "LISTEN", "::", "2375", "::", "*", 4096,
             [("dockerd", 840, 3, "/usr/bin/dockerd")], v6only=False),
    ]
    for s in sorted(sessions, key=lambda s: s.login_at):
        socks.append(Sock("tcp", False, "ESTAB", subs(GT), "22", s.src_ip, str(s.src_port), 0,
                          [("sshd-session", s.pid - 11, 4, f"sshd-session: {s.username}@"
                            f"{'pts/' + str(s.tty) if s.terminal else 'notty'}"),
                           ("sshd-session", s.pid - 20, 4, f"sshd-session: {s.username} [priv]")]))
    return socks


def _flags(argv: list[str], allowed: str) -> set[str]:
    out = set()
    for a in argv[1:]:
        if not a.startswith("-") or a.startswith("--"):
            raise Unsupported(a)
        for ch in a[1:]:
            if ch not in allowed:
                raise Unsupported(f"-{ch}")
            out.add(ch)
    return out


# ------------------------------------------------------------------ ss

def ss(socks: list[Sock], argv: list[str], width: int | None, sessions: int) -> tuple[str, int]:
    f = _flags(argv, "tulnpas")
    if "s" in f:
        if f - {"s"}:
            raise Unsupported("ss -s with others")
        return ss_summary(sessions), 0
    if "n" not in f:
        raise Unsupported("ss without -n resolves service names")
    protos = {p for p, c in (("tcp", "t"), ("udp", "u")) if c in f} or {"tcp", "udp"}
    if not f & {"t", "u"}:
        raise Unsupported("ss without -t/-u also lists unix sockets")
    if "a" in f:
        sel = [s for s in socks if s.proto in protos]
        states = 2
    elif "l" in f:
        sel = [s for s in socks if s.proto in protos and s.state in ("LISTEN", "UNCONN")]
        states = 2                                    # LISTEN and CLOSE: State is shown
    else:
        sel = [s for s in socks if s.proto in protos and s.state == "ESTAB"]
        states = 2                                    # the connected set has many states
    cols = []                                         # (header, align, ldelim, cells)
    rows = [{} for _ in sel]
    show_netid = len(protos) > 1
    if show_netid:
        cols.append(("Netid", "L", "", [s.proto for s in sel]))
    if states > 1:
        cols.append(("State", "L", " ", [s.state for s in sel]))
    cols.append(("Recv-Q", "L", " ", [f"{0:<6d}" for s in sel]))
    cols.append(("Send-Q", "L", " ", [f"{s.sendq:<6d}" for s in sel]))

    def addr(a: str, v6: bool, v6only: bool) -> str:
        if v6 and a == "::" and not v6only:
            return "*"
        return f"[{a}]" if v6 and ":" in a else a
    cols.append(("Local Address:", "R", " ", [addr(s.laddr, s.v6, s.v6only) + ":" for s in sel]))
    cols.append(("Port", "L", "", [s.lport for s in sel]))
    cols.append(("Peer Address:", "R", " ",
                 [("*" if s.raddr == "*" else addr(s.raddr, s.v6, s.v6only)) + ":" for s in sel]))
    cols.append(("Port", "L", "", [s.rport for s in sel]))
    if "p" in f:
        cols.append(("Process", "L", "", [
            " users:(" + ",".join(f'("{c}",pid={p},fd={d})' for c, p, d, _ in s.owners) + ")"
            if s.owners else "" for s in sel]))
    cols.append(("", "L", "", ["" for s in sel]))     # COL_EXT, always last

    # render_calc_width: content width (+ left delimiter after the first column) ...
    widths, first = [], True
    for h, _, delim, cells in cols:
        m = max([len(h)] + [len(c) for c in cells])
        w = m + len(delim) if (not first and m) else m
        if width:
            w = min(w, width)
        widths.append(w)
        if w:
            first = False
    # ... then spare screen width shared out evenly, the remainder to the last first.
    if width:
        used = [i for i, w in enumerate(widths) if w]
        total = sum(widths)
        if total < width:
            pad = width - total
            spacing, rem = divmod(pad, len(used))
            for i in reversed(used):
                widths[i] += spacing
                if rem:
                    widths[i] += 1
                    rem -= 1
    lines = []
    for r in range(-1, len(sel)):
        line, started = "", False
        for (h, align, delim, cells), w in zip(cols, widths):
            if not w:
                continue
            text = h if r < 0 else cells[r]
            printed = 0
            if started:
                line += delim
                printed = len(delim)
            started = True
            if align == "R":
                s = w - len(text) - printed
                line += " " * max(s, 0)
            line += text
            if align == "L":
                s = w - (printed + len(text))
                line += " " * max(s, 0)
        lines.append(line)
    return "\n".join(lines), 0


def ss_summary(sessions: int) -> str:
    """`ss -s` (corpus n=166, one session): each SSH session adds a TCP connection."""
    n = sessions
    rows = [("RAW", 1, 0, 1), ("UDP", 2, 1, 1), ("TCP", 6 + n, 4 + n, 2),
            ("INET", 9 + n, 5 + n, 4), ("FRAG", 0, 0, 0)]
    out = [f"Total: {169 + 4 * n}",
           f"TCP:   {14 + n} (estab {n}, closed 8, orphaned 0, timewait 0)", "",
           "Transport Total     IP        IPv6"]
    out += [f"{name}\t  {a:<9d} {b:<9d} {c:<9d}" for name, a, b, c in rows]
    return "\n".join(out)


# ------------------------------------------------------------------ netstat

def _nt_addr(a: str, port: str, v6: bool) -> str:
    """net-tools addr_do_one: "addr:port", cut to 22 characters keeping the port."""
    if v6 and a == "*":
        a = "::"
    if not v6 and a == "*":
        a = "0.0.0.0"
    if len(a) + len(port) > 22:
        plen = min(len(port), 22 - 4)
        return a[:22 - plen] + ":" + port[:plen]
    return f"{a}:{port}"


def netstat(socks: list[Sock], argv: list[str]) -> tuple[str, int]:
    f = _flags(argv, "tulnpa")
    if "n" not in f:
        raise Unsupported("netstat without -n resolves names")
    if not f & {"t", "u"}:
        raise Unsupported("netstat without -t/-u also lists unix sockets")
    kind = ("(servers and established)" if "a" in f
            else "(only servers)" if "l" in f else "(w/o servers)")
    head = "Proto Recv-Q Send-Q Local Address           Foreign Address         State      "
    if "p" in f:
        head += " " + f"{'PID/Program name':<20}"
    lines = [f"Active Internet connections {kind}", head]
    order = []
    for proto in ("tcp", "udp"):
        if proto[0] not in f:
            continue
        for v6 in (False, True):
            order += [s for s in socks if s.proto == proto and s.v6 == v6]
    for s in order:
        listening = s.state in ("LISTEN", "UNCONN")
        if not ("a" in f or ("l" in f) == listening):
            continue
        local = _nt_addr(s.laddr, s.lport, s.v6)
        remote = _nt_addr(s.raddr, s.rport, s.v6)
        if s.proto == "tcp":
            state = {"LISTEN": "LISTEN", "ESTAB": "ESTABLISHED"}[s.state]
            prot = "tcp6" if s.v6 else "tcp"
            sendq = 0 if s.state == "LISTEN" else s.sendq
            line = (f"{prot:<4s}  {0:6d} {sendq:6d} {local:<{max(23, len(local))}s} "
                    f"{remote:<{max(23, len(remote))}s} {state:<11s}")
        else:
            prot = "udp6" if s.v6 else "udp"
            line = f"{prot:<5s} {0:6d} {0:6d} {local:<23s} {remote:<23s} {'':<11s}"
        if "p" in f:
            c, pid, _, cmdline = s.owners[-1] if s.owners else (None, None, None, "")
            prog = "-"
            if pid:
                name = cmdline.split("\0")[0]
                first = name.split(" ")[0] if name.startswith("/") else name
                if first.startswith("/"):
                    first = first.rsplit("/", 1)[1]
                prog = f"{pid}/{first}"[:19]
            line += " " + f"{prog:<20s}"
        lines.append(line)
    return "\n".join(lines), 0
