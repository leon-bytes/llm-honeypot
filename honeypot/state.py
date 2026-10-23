"""The simulated machine's live numbers: memory and disks, computed fresh from the
clock, the boot time and the shared file state. One place, so that `free`, `df`, the
model's live facts (and later `top`, `/proc/meminfo`, the Docker API) all agree.

Every starting value is Ground Truth's own, recorded 11 minutes after a boot (corpus
n=56-62 for memory, n=94-97 for disks). They then drift with uptime the way a real Pi
running this stack does, and repeat exactly within one minute, so two commands typed
close together agree with each other.
"""
from __future__ import annotations
import hashlib
import math
from dataclasses import dataclass

# ------------------------------------------------------------------ helpers


def _jitter(t: float, salt: str, amp: float) -> float:
    """A value in [-amp, amp], fixed for one minute."""
    h = hashlib.sha256(f"{salt}:{int(t // 60)}".encode()).digest()
    return (int.from_bytes(h[:4], "big") / 0xFFFFFFFF * 2 - 1) * amp


def _ramp(up: float, scale_s: float) -> float:
    """0 at boot, rising towards 1: warm-up of caches and services."""
    return 1 - math.exp(-max(up, 0) / scale_s)


# ------------------------------------------------------------------ memory (KiB)

MEM_TOTAL = 8256464
SWAP_TOTAL = 2097136
# free + used + buff/cache exceeds total by this much on Ground Truth (n=58): procps 4
# computes used as total - available, and available counts reclaimable cache.
_RECLAIM_OVERLAP = 103328


@dataclass
class Memory:
    total: int
    used: int
    free: int
    shared: int
    buffers: int
    cache: int                  # page cache + reclaimable slab; buff/cache = buffers + cache
    available: int
    swap_total: int = SWAP_TOTAL
    swap_used: int = 0

    @property
    def buff_cache(self) -> int:
        return self.buffers + self.cache


def memory(t: float, boot: float) -> Memory:
    up = t - boot
    used = int(460992 + 26000 * _ramp(up, 6 * 3600) + _jitter(t, "used", 2400))
    shared = int(13552 + 900 * _ramp(up, 86400) + _jitter(t, "shared", 60))
    buffers = int(88832 + 60000 * _ramp(up, 2 * 86400) + _jitter(t, "buf", 200))
    cache = int(752432 + 1300000 * _ramp(up, 2 * 86400) + _jitter(t, "cache", 1500))
    available = MEM_TOTAL - used
    free = MEM_TOTAL - used - buffers - cache + _RECLAIM_OVERLAP
    return Memory(MEM_TOTAL, used, free, shared, buffers, cache, available)


# /proc/meminfo's fields that the memory model does not move: Ground Truth's own values
# (corpus n=56), in the kernel's order. None marks a field computed in meminfo().
_MEMINFO = [("MemTotal", None), ("MemFree", None), ("MemAvailable", None), ("Buffers", None),
            ("Cached", None), ("SwapCached", 0), ("Active", None), ("Inactive", None),
            ("Active(anon)", None), ("Inactive(anon)", 0), ("Active(file)", None),
            ("Inactive(file)", None), ("Unevictable", 0), ("Mlocked", 0), ("SwapTotal", None),
            ("SwapFree", None), ("Zswap", 0), ("Zswapped", 0), ("Dirty", 224), ("Writeback", 0),
            ("AnonPages", None), ("Mapped", 246208), ("Shmem", None), ("KReclaimable", None),
            ("Slab", None), ("SReclaimable", None), ("SUnreclaim", 44752), ("KernelStack", 4448),
            ("PageTables", 9136), ("SecPageTables", 112), ("NFS_Unstable", 0), ("Bounce", 0),
            ("WritebackTmp", 0), ("CommitLimit", 6225360), ("Committed_AS", 1349680),
            ("VmallocTotal", 68447887360), ("VmallocUsed", 55232), ("VmallocChunk", 0),
            ("Percpu", 1344), ("CmaTotal", 65536), ("CmaFree", 55296)]
# On Ground Truth reclaimable slab was this share of what `free` counts as cache beyond
# the buffers (251888 of 752320, n=56): procps 4 adds SReclaimable to Cached.
_SRECLAIM_SHARE = 251888 / (500432 + 251888)


def meminfo(mem: Memory) -> str:
    """`/proc/meminfo` from the same numbers `free` prints, so the two agree to the KiB:
    free = MemFree, shared = Shmem, buff/cache = Buffers + Cached + SReclaimable,
    available = MemAvailable. The page-list fields follow from those as they did on
    Ground Truth; the rest are its recorded values. The kernel's layout: the name and
    colon in 16 columns, the number in 8, then ` kB`."""
    sre = round(mem.cache * _SRECLAIM_SHARE)
    cached = mem.cache - sre
    inactive_file = round(169488 * (mem.buffers + cached) / (88832 + 500432))
    active_file = mem.buffers + cached - mem.shared - inactive_file + 240
    anon = 190848 + (mem.used - 460992) // 2
    v = {"MemTotal": mem.total, "MemFree": mem.free, "MemAvailable": mem.available,
         "Buffers": mem.buffers, "Cached": cached, "Active(anon)": anon + mem.shared - 400,
         "Active(file)": active_file, "Inactive(file)": inactive_file,
         "SwapTotal": mem.swap_total, "SwapFree": mem.swap_total - mem.swap_used,
         "AnonPages": anon, "Shmem": mem.shared, "KReclaimable": sre, "SReclaimable": sre,
         "Slab": sre + 44752}
    v["Active"] = v["Active(anon)"] + active_file
    v["Inactive"] = inactive_file
    return "\n".join(f"{name + ':':<16}{v[name] if val is None else val:>8} kB"
                     for name, val in _MEMINFO)


# ------------------------------------------------------------------ disks (KiB)


@dataclass
class Mount:
    source: str
    fstype: str
    target: str
    size: int                   # 1K blocks
    used: int
    avail: int
    inodes: int
    iused: int

    @property
    def ifree(self) -> int:
        return self.inodes - self.iused


ROOT_SIZE = 122614632
ROOT_RESERVED = ROOT_SIZE - 6434220 - 111152696     # ext4's reserved blocks (n=94)
# The three containers' rootfs mounts (n=94). Their ids follow the containers, not the
# boot: they change only if a container is recreated.
CONTAINER_ROOTFS = [
    "d3775f38b3d46fd726f64510ab68d268e93aae6709f80cbc02c5710a256f3b89",
    "443074d3a15d7c1ec1140452284abb8d481f98c9ad8c224c39698f50fb7c0594",
    "d139ff53533c7de3002a3a73db79943a968d3ab1da93dd637a4e292bd1ed3334",
]


def _file_kib(text: str) -> int:
    """Disk use of a file: whole 4 KiB pages, an empty file uses none."""
    return math.ceil(len(text.encode()) / 4096) * 4


def mounts(t: float, boot: float, fs=None) -> list[Mount]:
    """`df`'s rows in Ground Truth's order (n=94). `fs` is the shared FileState."""
    up = t - boot
    days = max(up, 0) / 86400
    tmp_used = tmp_files = root_extra = root_files = 0
    if fs is not None:
        for path, kind in fs.created.items():
            size = _file_kib(fs.contents.get(path, "")) if kind == "file" else 0
            if path == "/tmp" or path.startswith("/tmp/"):
                tmp_used += size
                tmp_files += 1
            elif not path.startswith(("/dev/", "/proc/", "/sys/", "/run/")):
                root_extra += size
                root_files += 1
    # Container logs and the journal grow slowly; the journal lives in /run (volatile).
    root_used = int(6434220 + 1536 * days) + root_extra
    root_iused = int(107045 + 12 * days) + root_files
    run_used = int(min(13456 + 4096 * days, 165000))
    root_avail = ROOT_SIZE - ROOT_RESERVED - root_used
    root = ("/dev/mmcblk0p2", "ext4", "/", ROOT_SIZE, root_used, root_avail,
            7775376, root_iused)
    rows = [
        ("udev", "devtmpfs", "/dev", 4086480, 0, 4086480, 255405, 505),
        ("tmpfs", "tmpfs", "/run", 1651296, run_used, 1651296 - run_used, 258014,
         997 + int(days * 3)),
        root,
        ("tmpfs", "tmpfs", "/dev/shm", 4128224, 0, 4128224, 258014, 1),
        ("tmpfs", "tmpfs", "/run/lock", 5120, 48, 5072, 258014, 5),
        ("tmpfs", "tmpfs", "/run/credentials/systemd-journald.service", 1024, 0, 1024,
         1024, 1),
        ("tmpfs", "tmpfs", "/tmp", 4128240, tmp_used, 4128240 - tmp_used, 1048576,
         9 + tmp_files),
        ("/dev/mmcblk0p1", "vfat", "/boot/firmware", 516204, 74763, 441442, 0, 0),
        ("tmpfs", "tmpfs", "/run/credentials/getty@tty1.service", 1024, 0, 1024, 1024, 1),
        ("tmpfs", "tmpfs", "/run/credentials/serial-getty@ttyAMA10.service", 1024, 0, 1024,
         1024, 1),
    ]
    rows += [("overlay", "overlay", f"/var/lib/docker/rootfs/overlayfs/{cid}",
              *root[3:]) for cid in CONTAINER_ROOTFS]
    # root's runtime dir: there while root is logged in, which an attacker always is.
    rows.append(("tmpfs", "tmpfs", "/run/user/0", 825632, 32, 825600, 206408, 32))
    return [Mount(*r) for r in rows]
