"""The simulated machine's network interfaces, and the commands that show them (R1, R3).

Fixed facts are Ground Truth's (corpus n=44, 148-170), with its addresses already
replaced by the Orchestrator's (config `substitutions`, R1). What Ground Truth
regenerates at every boot (R3: docker0's and the bridge's MACs, the veth names and
MACs, the link-local addresses derived from them) is generated here once per boot from
the boot time, so it never equals Ground Truth's and stays the same until the
Orchestrator reboots. `boot_substitutions()` maps Ground Truth's recorded values to
these, so the recorded examples shown to the model say the same as the code.

Formats: iproute2 6.15.0 (`ip`), net-tools 2.10 (`ifconfig`, `netstat -i`, `route`),
the kernel's /proc/net/dev; checked against the corpus.
"""
from __future__ import annotations
import hashlib
import ipaddress
from dataclasses import dataclass, field

from .site import SITE


class Unsupported(Exception):
    pass


# Ground Truth's per-boot values in the corpus (recorded after the 2026-09-28 reboot).
GT_DOCKER0_MAC = "82:a8:0e:64:b2:e0"
GT_BR_MAC = "16:ec:28:5c:a3:f4"
GT_VETHS = [("vethdf4ff70", "da:35:41:1c:2a:1b"), ("vethf6d7760", "e6:e6:c8:3a:da:35"),
            ("veth09cfd98", "22:52:2d:1e:bb:0b")]
BRIDGE = "br-f5676ba9b003"          # stable: named after the compose network id (R3)


def _rand(seed: str, n: int) -> bytes:
    return hashlib.sha256(seed.encode()).digest()[:n]


def _random_mac(seed: str) -> str:
    """What the kernel's eth_hw_addr_random gives: unicast, locally administered."""
    b = bytearray(_rand(seed, 6))
    b[0] = (b[0] & 0xFC) | 0x02
    return ":".join(f"{x:02x}" for x in b)


def link_local(mac: str) -> str:
    """The EUI-64 link-local address the kernel derives from a MAC."""
    b = [int(x, 16) for x in mac.split(":")]
    b[0] ^= 0x02
    eui = b[:3] + [0xFF, 0xFE] + b[3:]
    groups = [f"{eui[i] << 8 | eui[i + 1]:x}" for i in range(0, 8, 2)]
    return str(ipaddress.IPv6Address("fe80::" + ":".join(groups)))


@dataclass
class Boot:
    docker0_mac: str
    br_mac: str
    veths: list                     # [(name, mac)] in index order 6, 7, 8


def boot_values(boot: float) -> Boot:
    """The three veth names are random, but handed out so that they sort the way Ground
    Truth's do: ifconfig, netstat -i and ls list interfaces by name, so a recording with
    the names substituted then still reads as a sorted list, and says the same as the
    code. Which veth gets which name is arbitrary on a real machine too."""
    seed = f"honeypot-boot-{int(boot)}"
    draw = 0
    while True:
        names = sorted("veth" + hashlib.sha256(
            f"{seed}-veth{i}{draw or ''}".encode()).hexdigest()[:7] for i in range(3))
        # ls sorts names as text, net-tools reads runs of digits as numbers ("83" before
        # "5856"). Ground Truth's three sort the same both ways; so must these.
        if len(set(names)) == 3 and names == sorted(names, key=_nstr_key):
            break
        draw += 1
    rank = sorted(range(3), key=lambda i: GT_VETHS[i][0])       # index order -> name order
    veths = [None] * 3
    for name, i in zip(names, rank):
        veths[i] = (name, _random_mac(f"{seed}-vethmac{i}"))
    return Boot(_random_mac(f"{seed}-docker0"), _random_mac(f"{seed}-br"), veths)


def boot_substitutions(boot: float) -> dict[str, str]:
    """Ground Truth's per-boot values -> this boot's, for the relay's substitution map."""
    b = boot_values(boot)
    pairs = {GT_DOCKER0_MAC: b.docker0_mac, GT_BR_MAC: b.br_mac,
             link_local(GT_BR_MAC): link_local(b.br_mac)}
    for (gname, gmac), (name, mac) in zip(GT_VETHS, b.veths):
        pairs[gname] = name
        pairs[gmac] = mac
        pairs[link_local(gmac)] = link_local(mac)
    return pairs


# ------------------------------------------------------------------ container links

@dataclass
class Link:
    """The host side of a running container's veth pair: what `ip a` shows for it.
    The three recorded containers' links are Ground Truth's shape (`recorded` is their
    place, 0 to 2, in index order 6, 7, 8). A link made for a container started later
    is modelled, not recorded (TASKS.md, "host-network view"): the kernel gives it the
    next interface index (never reused soon), the next free netns id (the lowest, as
    the kernel's idr does), a random name and MAC, and its peer is `@if2`, as for every
    recorded veth (the peer is made in the container's namespace, after its lo)."""
    index: int
    name: str
    mac: str
    master: str                     # the bridge it is a port of
    netnsid: int
    since: float                    # when it came up (boot for the recorded three)
    recorded: int | None = None


def seeded_links(boot: float) -> list[Link]:
    """The links of the three recorded containers, up since boot."""
    b = boot_values(boot)
    return [Link(6 + i, name, mac, BRIDGE, i, boot, i) for i, (name, mac) in enumerate(b.veths)]


def new_link(seed: str, index: int, master: str, netnsid: int, since: float) -> Link:
    """A link for a container started on a bridge network. Docker names the host side
    `veth` and seven random hex digits; the MAC is the kernel's random one."""
    name = "veth" + hashlib.sha256(f"{seed}-veth-{index}".encode()).hexdigest()[:7]
    return Link(index, name, _random_mac(f"{seed}-vethmac-{index}"), master, netnsid, since)


def _link_counters(k: Link, t: float, boot: float) -> tuple[tuple, tuple]:
    if k.recorded is not None:
        slow = int(max(t - boot, 0) / 600)
        txs = ((1784, 24), (1742, 23), (1590, 21))[k.recorded]
        return (126 + 28 * slow, 3 + slow // 3, 0, 0), (txs[0] + 90 * slow, txs[1] + slow, 0, 0)
    # Modelled: a recorded veth's first minutes, then the same slow growth. Not recorded.
    up = max(t - k.since, 0)
    slow, f = int(up / 600), min(up / 660, 1.0)
    rx = (126 + 28 * slow, 3 + slow // 3, 0, 0) if up >= 2 else (0, 0, 0, 0)
    return rx, (int(1590 * f) + 90 * slow, int(21 * f) + slow, 0, 0)


def link_iface(k: Link, t: float, boot: float) -> "Iface":
    rx, tx = _link_counters(k, t, boot)
    return Iface(k.index, k.name, "@if2", ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], 1500,
                 "noqueue", "UP", None, k.mac, master=k.master, netnsid=k.netnsid,
                 addrs=[Addr(6, link_local(k.mac), 64, "link", "", "proto kernel_ll")],
                 ifconfig_flags=4163, rx=rx, tx=tx)


# ------------------------------------------------------------------ the interfaces

@dataclass
class Addr:
    family: int                     # 4 or 6
    addr: str
    plen: int
    scope: str                      # global | link | host
    brd: str = ""
    flags: str = ""                 # e.g. "dynamic noprefixroute", "proto kernel_ll"
    lease: tuple | None = None      # (lease seconds, seconds after boot it was obtained)


@dataclass
class Iface:
    index: int
    name: str
    peer: str                       # "@if2" for veths
    flags: list
    mtu: int
    qdisc: str
    state: str
    qlen: int | None
    mac: str
    link_type: str = "ether"
    master: str = ""
    netnsid: int | None = None
    addrs: list = field(default_factory=list)
    ifconfig_flags: int = 0
    txqueuelen: int = 0
    rx: tuple = (0, 0, 0, 0)        # bytes, packets, errs, drop
    tx: tuple = (0, 0, 0, 0)
    irq: int = 0


def interfaces(t: float, boot: float, subs, traffic=(0, 0, 0, 0), links=None,
               docker0_since: float | None = None) -> list[Iface]:
    """`traffic` is what the relay's own sessions sent and received: (rx bytes, rx
    packets, tx bytes, tx packets), added to eth0's counters. `links`: the running
    containers' veths (the shared Docker state's `host_links()`); None means the three
    recorded ones, as at boot. `docker0_since`: when docker0 first had a port, if ever."""
    b = boot_values(boot)
    up = max(t - boot, 0)
    mins = up / 60
    eth_mac = subs(SITE.ref_mac_eth)
    wlan_mac = subs(SITE.ref_mac_wlan)
    rxb, rxp, txb, txp = traffic
    lo = Iface(1, "lo", "", ["LOOPBACK", "UP", "LOWER_UP"], 65536, "noqueue", "UNKNOWN", 1000,
               "00:00:00:00:00:00", link_type="loopback",
               addrs=[Addr(4, "127.0.0.1", 8, "host"),
                      Addr(6, "::1", 128, "host", flags="noprefixroute")],
               ifconfig_flags=73, txqueuelen=1000)
    eth0 = Iface(2, "eth0", "", ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], 1500, "fq_codel",
                 "UP", 1000, eth_mac,
                 addrs=[Addr(4, subs(SITE.ref_ipv4), 24, "global", SITE.lab_broadcast,
                             "dynamic noprefixroute", (43200, 6)),
                        Addr(6, subs(SITE.ref_ipv6), 128, "global", "",
                             "dynamic noprefixroute", (43200, 7)),
                        Addr(6, subs(SITE.ref_ipv6_slaac), 64, "global", "",
                             "noprefixroute"),
                        Addr(6, subs(SITE.ref_ipv6_link), 64, "link", "",
                             "noprefixroute")],
                 ifconfig_flags=4163, txqueuelen=1000, irq=106,   # gt43 n=33, every recording
                 # Ground Truth's counters at 11 minutes (n=159) less the capture's own
                 # traffic; then background traffic (DHCP, NTP, RA) and the sessions'.
                 rx=(61000 + int(38 * up) + rxb, 520 + int(mins * 9) + rxp, 0, 0),
                 tx=(42000 + int(22 * up) + txb, 330 + int(mins * 6) + txp, 0, 0))
    wlan0 = Iface(3, "wlan0", "", ["BROADCAST", "MULTICAST"], 1500, "noop", "DOWN", 1000,
                  wlan_mac, ifconfig_flags=4098, txqueuelen=1000)
    links = seeded_links(boot) if links is None else sorted(links, key=lambda k: k.index)
    docker0 = Iface(4, "docker0", "", ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"], 1500,
                    "noqueue", "DOWN", None, b.docker0_mac,
                    addrs=[Addr(4, "172.17.0.1", 16, "global", "172.17.255.255")],
                    ifconfig_flags=4099, tx=(0, 0, 0, 2))
    if docker0_since is not None:
        # Modelled, not recorded: with its first port the bridge gets carrier, and the
        # kernel then gives it a link-local address, which stays when the port goes. Its
        # counters follow the compose bridge's recorded shape (one container's traffic in,
        # the bridge's own announcements out).
        d = int(max(t - docker0_since, 0) / 600)
        docker0.addrs.append(Addr(6, link_local(b.docker0_mac), 64, "link", "", "proto kernel_ll"))
        docker0.rx, docker0.tx = (126 + 28 * d, 3 + d // 3, 0, 0), (526 + 110 * d, 5 + d, 0, 2)
        if any(k.master == "docker0" for k in links):
            docker0.flags = ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"]
            docker0.state, docker0.ifconfig_flags = "UP", 4163
    slow = int(mins / 10)            # containers' occasional traffic (telemetry lookups)
    br = Iface(5, BRIDGE, "", ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], 1500, "noqueue",
               "UP", None, b.br_mac,
               addrs=[Addr(4, "172.18.0.1", 16, "global", "172.18.255.255"),
                      Addr(6, link_local(b.br_mac), 64, "link", "", "proto kernel_ll")],
               ifconfig_flags=4163, rx=(252 + 84 * slow, 9 + slow, 0, 0),
               tx=(526 + 110 * slow, 5 + slow, 0, 2))
    if not any(k.master == BRIDGE for k in links):
        # Every compose container stopped: the bridge loses carrier (its route then reads
        # `linkdown`), and keeps its address and counters. The same rule as docker0's.
        br.flags = ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"]
        br.state, br.ifconfig_flags = "DOWN", 4099
    return [lo, eth0, wlan0, docker0, br] + [link_iface(k, t, boot) for k in links]


def _lft(a: Addr, up: float) -> str:
    if not a.lease:
        return "valid_lft forever preferred_lft forever"
    lease, obtained = a.lease
    left = lease - int((up - obtained) % (lease / 2))    # renewed at half the lease
    return f"valid_lft {left}sec preferred_lft {left}sec"


# ------------------------------------------------------------------ ip

def _ip_head(i: Iface, mode: bool, family: int | None) -> str:
    name = i.name + (i.peer if family != 6 else ("@eth0" if i.peer else ""))
    s = f"{i.index}: {name}: <{','.join(i.flags)}> mtu {i.mtu} "
    if family == 6:                       # `ip -6` omits qdisc, master and group (n=154)
        return s + f"state {i.state} " + (f"qlen {i.qlen}" if i.qlen else "")
    s += f"qdisc {i.qdisc} " + (f"master {i.master} " if i.master else "")
    s += f"state {i.state} " + ("mode DEFAULT " if mode else "") + "group default "
    if i.qlen:
        s += f"qlen {i.qlen}"
    return s


def _ip_link_line(i: Iface) -> str:
    if i.link_type == "loopback":
        return "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00"
    s = f"    link/ether {i.mac} brd ff:ff:ff:ff:ff:ff"
    if i.netnsid is not None:
        s += f" link-netnsid {i.netnsid}"
    return s


def _ip_addr_lines(i: Iface, family: int | None, up: float) -> list[str]:
    out = []
    for a in i.addrs:
        if family and a.family != family:
            continue
        if a.family == 4:
            s = f"    inet {a.addr}/{a.plen} " + (f"brd {a.brd} " if a.brd else "")
            s += f"scope {a.scope} " + (f"{a.flags} " if a.flags else "") + i.name
        else:
            s = f"    inet6 {a.addr}/{a.plen} scope {a.scope} " + (f"{a.flags} " if a.flags else "")
        out += [s, f"       {_lft(a, up)}"]
    return out


def ip(ifs: list[Iface], argv: list[str], up: float) -> tuple[str, int]:
    args = argv[1:]
    family = None
    brief = False
    while args and args[0].startswith("-"):
        o = args.pop(0)
        if o == "-4":
            family = 4
        elif o == "-6":
            family = 6
        elif o in ("-br", "-brief"):
            brief = True
        else:
            raise Unsupported(f"ip {o}")
    if not args:
        raise Unsupported("ip with no object")
    obj, rest = args[0], args[1:]
    if "route".startswith(obj) and obj[0] == "r":
        # `ip r`, `ip route [show|list]`, also with -4 or -br (which changes nothing
        # here, iproute2 6.15.0). A selector (`get`, `dev`, a prefix) or -6: the model.
        if family == 6 or rest not in ([], ["show"], ["list"], ["ls"], ["s"]):
            raise Unsupported(f"ip {' '.join(args)}")
        return ip_route(ifs), 0
    if rest and rest[0] in ("show", "s", "list", "ls", "lst"):
        rest = rest[1:]
    if rest and rest[0] == "dev":
        rest = rest[1:]
    if len(rest) > 1:
        raise Unsupported(f"ip {' '.join(args)}")
    sel = ifs
    if rest:
        sel = [i for i in ifs if i.name == rest[0]]
        if not sel:
            return f'Device "{rest[0]}" does not exist.', 1
    if "address".startswith(obj) or obj == "a":
        if brief:
            return _ip_brief(sel, family, addrs=True), 0
        lines = []
        for i in sel:
            body = _ip_addr_lines(i, family, up)
            if family and not body:
                continue
            lines.append(_ip_head(i, False, family))
            if not family:
                lines.append(_ip_link_line(i))
            lines += body
        return "\n".join(lines), 0
    if "link".startswith(obj) and len(obj) >= 1 and obj[0] == "l":
        if family:
            raise Unsupported("ip -4/-6 link")
        if brief:
            return _ip_brief(sel, None, addrs=False), 0
        lines = []
        for i in sel:
            lines += [_ip_head(i, True, None), _ip_link_line(i)]
        return "\n".join(lines), 0
    raise Unsupported(f"ip {obj}")


def _ip_brief(ifs: list[Iface], family: int | None, addrs: bool) -> str:
    """iproute2 -brief: name (16), state (14), then addresses or MAC and flags."""
    out = []
    for i in ifs:
        name = i.name + i.peer
        if addrs:
            al = [f"{a.addr}/{a.plen}" for a in i.addrs if not family or a.family == family]
            if family and not al:
                continue
            out.append(f"{name:<16} {i.state:<14} " + "".join(a + " " for a in al))
        else:
            out.append(f"{name:<16} {i.state:<14} {i.mac} <{','.join(i.flags)}> ")
    return "\n".join(out)


# ------------------------------------------------------------------ routes
#
# In code since 2026-10-13 (the user's first manual session: 10 s from the model, and a
# wrong first line). The routing table is not a text of its own: the kernel derives it
# from the interfaces, so it is computed from the same interface list as `ip a`,
# `ifconfig` and /proc/net/dev, and the four ways of printing it cannot disagree with
# them or with each other. Formats: corpus n=152 (`ip route`), n=170 (`route -n`),
# n=168 (`netstat -rn`), n=160 (/proc/net/route).

GATEWAY = SITE.lab_gateway          # the lab router, also the DHCP server (n=152)
DHCP_METRIC = 100                    # NetworkManager's for a wired connection


@dataclass
class Route:
    dst: str                         # network address, "0.0.0.0" for the default route
    plen: int
    gw: str                          # "" for a connected network
    dev: str
    src: str
    metric: int
    proto: str                       # dhcp | kernel
    linkdown: bool = False


def routes(ifs: list[Iface]) -> list[Route]:
    """The IPv4 routes of the main table, in the kernel's order (shortest prefix
    first, then by address): for every interface that is administratively up and has
    an IPv4 address the network it is on, and for the one whose address came from
    DHCP also the default route. An interface without carrier (docker0 with no
    container on it) keeps its route, marked `linkdown`."""
    out = []
    for i in ifs:
        if i.link_type == "loopback" or "UP" not in i.flags:
            continue
        for a in i.addrs:
            if a.family != 4:
                continue
            net = ipaddress.ip_network(f"{a.addr}/{a.plen}", strict=False)
            dhcp = "dynamic" in a.flags
            down = "NO-CARRIER" in i.flags
            if dhcp:
                out.append(Route("0.0.0.0", 0, GATEWAY, i.name, a.addr, DHCP_METRIC, "dhcp"))
            out.append(Route(str(net.network_address), a.plen, "", i.name, a.addr,
                             DHCP_METRIC if dhcp else 0, "kernel", down))
    return sorted(out, key=lambda r: (r.plen != 0, ipaddress.ip_address(r.dst)))


def ip_route(ifs: list[Iface]) -> str:
    lines = []
    for r in routes(ifs):
        s = f"default via {r.gw} dev {r.dev} proto {r.proto} " if not r.plen \
            else f"{r.dst}/{r.plen} dev {r.dev} proto {r.proto} scope link "
        s += f"src {r.src} " + (f"metric {r.metric} " if r.metric else "")
        lines.append(s + ("linkdown " if r.linkdown else ""))
    return "\n".join(lines)


def _mask(plen: int) -> str:
    return str(ipaddress.ip_network(f"0.0.0.0/{plen}").netmask)


def route_n(ifs: list[Iface], netstat: bool = False) -> str:
    """net-tools 2.10: `route -n`, and with `netstat` the columns of `netstat -rn`."""
    head = ("Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface" if netstat
            else "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface")
    lines = ["Kernel IP routing table", head]
    for r in routes(ifs):
        flags = "UG" if r.gw else "U"
        cols = (f"{flags:<5} {0:>5} {0:<5} {0:>6}" if netstat
                else f"{flags:<5} {r.metric:<6} {0:<6} {0:>3}")
        lines.append(f"{r.dst:<15} {r.gw or '0.0.0.0':<15} {_mask(r.plen):<15} {cols} {r.dev}")
    return "\n".join(lines)


def proc_net_route(ifs: list[Iface]) -> str:
    """/proc/net/route: addresses as hexadecimal in the machine's byte order, every
    line filled with spaces to 127 characters (the kernel's fixed record)."""
    def hx(addr: str) -> str:
        return "%08X" % int.from_bytes(ipaddress.ip_address(addr).packed, "little")
    lines = ["Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"]
    for r in routes(ifs):
        lines.append(f"{r.dev}\t{hx(r.dst)}\t{hx(r.gw or '0.0.0.0')}\t{3 if r.gw else 1:04X}\t0\t0\t"
                     f"{r.metric}\t{hx(_mask(r.plen))}\t0\t0\t0")
    return "\n".join(f"{line:<127}" for line in lines)


# ------------------------------------------------------------------ ifconfig

def _nstr_key(name: str):
    """net-tools' nstrcmp: digits compare as numbers."""
    import re
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name)]


def _ifc_scaled(n: int) -> str:
    short, ext = n * 10, "B"
    for limit, unit in ((1 << 60, "EiB"), (1 << 50, "PiB"), (1 << 40, "TiB"), (1 << 30, "GiB"),
                        (1 << 20, "MiB"), (1 << 10, "KiB")):
        if n > limit:
            short, ext = n * 10 // limit, unit
            break
    return f"{short // 10}.{short % 10} {ext}"


# ifconfig lists IPv6 addresses in /proc/net/if_inet6 order, which is the kernel's hash
# order and not `ip a`'s: Ground Truth had the stable address first before its
# 2026-09-28 reboot and has had this order since (gt43 n=33): the link-local, the DHCPv6
# address, then the stable one.
_INET6_ORDER = {"link": 0, "global-128": 1, "global-64": 2}


def _nettools_counters(i: Iface) -> tuple[tuple, tuple]:
    """(rx, tx) as ifconfig and netstat -i show them. For the compose bridge that is all
    zeros, drops included, in every recording (gt43 n=33, corpus n=167), although
    /proc/net/dev recorded between them has its counters (n=159: 9 packets in, 5 out,
    2 dropped). The veths, docker0 and eth0 read the same in all three. The bridge's
    name is the only one that fills all 15 characters, which is taken to be why."""
    if len(i.name) >= 15:
        return (0, 0, 0, 0), (0, 0, 0, 0)
    return i.rx, i.tx


def _ifconfig_one(i: Iface) -> str:
    names = {"UP": 1, "BROADCAST": 2, "LOOPBACK": 8, "RUNNING": 64, "MULTICAST": 4096}
    fl = [n for n, bit in names.items() if i.ifconfig_flags & bit]
    lines = [f"{i.name}: flags={i.ifconfig_flags}<{','.join(fl)}>  mtu {i.mtu}"]
    for a in i.addrs:
        if a.family == 4:
            mask = str(ipaddress.IPv4Network(f"0.0.0.0/{a.plen}").netmask)
            lines.append(f"        inet {a.addr}  netmask {mask}" +
                         (f"  broadcast {a.brd}" if i.ifconfig_flags & 2 else ""))
    v6 = [a for a in i.addrs if a.family == 6]
    v6.sort(key=lambda a: _INET6_ORDER.get(
        "link" if a.scope == "link" else f"global-{a.plen}", 0) if i.name == "eth0" else 0)
    for a in v6:
        scope = {"global": "0x0<global>", "link": "0x20<link>", "host": "0x10<host>"}[a.scope]
        lines.append(f"        inet6 {a.addr}  prefixlen {a.plen}  scopeid {scope}")
    if i.link_type == "loopback":
        lines.append(f"        loop  txqueuelen {i.txqueuelen}  (Local Loopback)")
    else:
        lines.append(f"        ether {i.mac}  txqueuelen {i.txqueuelen}  (Ethernet)")
    rx, tx = _nettools_counters(i)
    lines.append(f"        RX packets {rx[1]}  bytes {rx[0]} ({_ifc_scaled(rx[0])})")
    lines.append(f"        RX errors {rx[2]}  dropped {rx[3]}  overruns 0  frame 0")
    lines.append(f"        TX packets {tx[1]}  bytes {tx[0]} ({_ifc_scaled(tx[0])})")
    lines.append(f"        TX errors {tx[2]}  dropped {tx[3]} overruns 0  carrier 0  collisions 0")
    if i.irq:
        lines.append(f"        device interrupt {i.irq}  ")
    return "\n".join(lines) + "\n"


def ifconfig(ifs: list[Iface], argv: list[str]) -> tuple[str, int]:
    args = argv[1:]
    show_all = "-a" in args
    args = [a for a in args if a != "-a"]
    if any(a.startswith("-") for a in args) or len(args) > 1:
        raise Unsupported("ifconfig options")
    if args:
        sel = [i for i in ifs if i.name == args[0]]
        if not sel:
            return f"{args[0]}: error fetching interface information: Device not found", 1
    else:
        sel = [i for i in ifs if show_all or i.ifconfig_flags & 1]
    sel = sorted(sel, key=lambda i: _nstr_key(i.name))
    return "\n".join(_ifconfig_one(i) for i in sel).rstrip("\n") + "\n", 0


# ------------------------------------------------------------------ the rest

def hostname_i(ifs: list[Iface]) -> str:
    """hostname -I: global addresses, IPv4 first, each followed by a space (n=44)."""
    v4 = [a.addr for i in ifs for a in i.addrs if a.family == 4 and a.scope == "global"]
    v6 = [a.addr for i in ifs for a in i.addrs if a.family == 6 and a.scope == "global"]
    return "".join(a + " " for a in v4 + v6)


def proc_net_dev(ifs: list[Iface]) -> str:
    out = ["Inter-|   Receive                                                |  Transmit",
           " face |bytes    packets errs drop fifo frame compressed multicast|bytes    "
           "packets errs drop fifo colls carrier compressed"]
    mcast = {"eth0": 2}
    for i in ifs:
        out.append(f"{i.name:>6s}:{i.rx[0]:8d} {i.rx[1]:7d} {i.rx[2]:4d} {i.rx[3]:4d} {0:4d} "
                   f"{0:5d} {0:10d} {mcast.get(i.name, 0):9d} {i.tx[0]:8d} {i.tx[1]:7d} "
                   f"{i.tx[2]:4d} {i.tx[3]:4d} {0:4d} {0:5d} {0:7d} {0:10d}")
    return "\n".join(out)


def netstat_i(ifs: list[Iface]) -> str:
    out = ["Kernel Interface table",
           "Iface             MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg"]
    for i in sorted([i for i in ifs if i.ifconfig_flags & 1], key=lambda i: _nstr_key(i.name)):
        flg = ("B" if i.ifconfig_flags & 2 else "") + ("L" if i.ifconfig_flags & 8 else "")
        flg += ("M" if i.ifconfig_flags & 4096 else "") + ("R" if i.ifconfig_flags & 64 else "")
        flg += "U"
        # net-tools ife_print_short: "%-15.15s %5d %8llu %6lu %6lu %-6lu ..."
        rx, tx = _nettools_counters(i)
        out.append(f"{i.name[:15]:<15s} {i.mtu:5d} {rx[1]:8d} {rx[2]:6d} {rx[3]:6d} {0:<6d} "
                   f"{tx[1]:8d} {tx[2]:6d} {tx[3]:6d} {0:6d} {flg}")
    return "\n".join(out)


# ------------------------------------------------------------------ ping (R19)

# Hosts that answer ping, as seen from this machine: itself, its containers, localhost
# and the lab machines that exist (the same answers Ground Truth gets on the same LAN).
_LIVE = {SITE.lab_gateway: 0.42, SITE.lab_jump: 0.38, SITE.ref_ipv4: 0.31, SITE.node1_ipv4: 0.35,
         SITE.node2_ipv4: 0.35, SITE.node3_ipv4: 0.35, SITE.node4_ipv4: 0.35,
         "172.18.0.2": 0.07, "172.18.0.3": 0.07, "172.18.0.4": 0.07}
_SELF = {SITE.hp_ipv4, "172.17.0.1", "172.18.0.1"}


def ping(argv: list[str], seed: str) -> tuple[str, int, float]:
    """(output, exit code, seconds it takes). iputils 20240905 formats; the network
    unreachable case is Ground Truth's own (corpus n=171, R19)."""
    args = argv[1:]
    count = None
    hosts = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-c" and i + 1 < len(args) and args[i + 1].isdigit():
            count = int(args[i + 1])
            i += 2
            continue
        if a.startswith("-c") and a[2:].isdigit():
            count = int(a[2:])
        elif a.startswith("-"):
            raise Unsupported(f"ping {a}")
        else:
            hosts.append(a)
        i += 1
    if count is None or not 1 <= count <= 30 or len(hosts) != 1:
        raise Unsupported("ping without -c runs until Ctrl-C")
    host = hosts[0]
    try:
        addr = ipaddress.IPv4Address(host)
    except ValueError:
        if host in ("localhost", "raspberrypi") or host.startswith("ip6-") or ":" in host:
            raise Unsupported("ping of a local name or IPv6")
        # The lab resolver (the router) has DNS switched off, so every lookup is
        # refused at once. Message: glibc's EAI_AGAIN. Not recorded: est.
        return f"ping: {host}: Temporary failure in name resolution", 2, 0.02
    ip = str(addr)
    elapsed = (count - 1) * 1000 + 3
    head = f"PING {ip} ({ip}) 56(84) bytes of data."
    stats = f"--- {ip} ping statistics ---"
    if addr.is_loopback or ip in _SELF or ip in _LIVE:
        base = 0.045 if (addr.is_loopback or ip in _SELF) else _LIVE[ip]
        times = []
        lines = [head]
        for seq in range(1, count + 1):
            j = int(hashlib.sha256(f"{seed}{ip}{seq}".encode()).hexdigest()[:4], 16) / 65535
            t = round(base * (0.75 + 0.6 * j), 3)
            times.append(t)
            lines.append(f"64 bytes from {ip}: icmp_seq={seq} ttl=64 time={t:.3f} ms"
                         if t < 1 else f"64 bytes from {ip}: icmp_seq={seq} ttl=64 time={t:.2f} ms")
        mean = sum(times) / len(times)
        mdev = (sum(x * x for x in times) / len(times) - mean * mean) ** 0.5
        lines += ["", stats, f"{count} packets transmitted, {count} received, 0% packet loss, "
                  f"time {elapsed if count > 1 else 0}ms",
                  f"rtt min/avg/max/mdev = {min(times):.3f}/{mean:.3f}/{max(times):.3f}/{mdev:.3f} ms"]
        return "\n".join(lines), 0, (count - 1) + max(times) / 1000
    if addr in ipaddress.IPv4Network(SITE.lab_net) or addr in ipaddress.IPv4Network(SITE.student_net) \
            or addr in ipaddress.IPv4Network("172.17.0.0/16") or addr in ipaddress.IPv4Network("172.18.0.0/16"):
        raise Unsupported("ping of an address on a local network that does not answer")
    # Anything else goes to the router, which has no route onwards (R19, n=171).
    lines = [head] + [f"From {GATEWAY} icmp_seq={s} Destination Net Unreachable"
                      for s in range(1, count + 1)]
    lines += ["", stats, f"{count} packets transmitted, 0 received, +{count} errors, "
              f"100% packet loss, time {elapsed if count > 1 else 0}ms"]
    return "\n".join(lines), 1, (count - 1) + 0.004
