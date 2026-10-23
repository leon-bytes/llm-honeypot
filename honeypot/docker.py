"""The simulated machine's Docker state: containers, images, networks and volumes.

One object, so that the fake Docker API (port 2375, dockerapi.py) and the shell's
`docker` commands show the same machine (R11): the paper's cross-surface consistency
claim rests on both reading from here, never on two separately generated answers.

The objects at rest come from Ground Truth's recorded API answers (docker_seed.json,
built by tools/build_docker_seed.py). On load they pass through the relay's
substitution map, so they carry this install's own IDs and MACs (identity.py, R3), and
their install-time timestamps move by this install's shift (identity.install_shift_ns).
What changes with the clock is filled in at answer time:

- `Created` is when the stack was first brought up and stays put; `State.StartedAt`
  moves to this machine's boot. They are independent (R12): `docker ps` shows
  `CREATED 6 days ago` next to `Up 13 minutes`.
- The start and stop times carry a per-boot jitter, so their nanoseconds are this
  machine's, not copies of Ground Truth's.
- nodered's health check runs every ~30.1 s from its start; `State.Health.Log` is the
  last five probes (R12). The other two have no health check and get none.
- The containers' processes, PIDs and thread counts are the process table's (procs.py),
  and their network counters are their veths' (net.py), so `ps`, `ip -s link` and the
  API agree.
- The logs are rebuilt from the lines recorded, at the times this machine's history
  puts them: the first run from the (shifted) install time to the last shutdown, then
  this boot's.

Every other view (`/containers/json`, `/system/df`, `/info`'s counts) is derived from
these documents, so it cannot drift from them.
"""
from __future__ import annotations
import copy
import datetime as dt
import fnmatch
import hashlib
import json
import pathlib
import random
import re

from . import machine, net, procs
from .site import SITE

SEED = pathlib.Path(__file__).parent / "docker_seed.json"
NS = 10**9

# Ground Truth booted 20:34:32 (whole seconds, as /proc/stat's btime gives it) and
# its containers started 29.7-29.9 s later, in this order (phase 1 n=17/21/25); they
# had stopped 44.7 s before the boot, at shutdown. The default bridge network is
# recreated just before the containers start (n=7).
_START_OFFSET = {"mosquitto": 29.719, "influxdb": 29.759, "nodered": 29.842}
_STOP_OFFSET = {"influxdb": -44.731, "mosquitto": -44.721, "nodered": -44.703}
_BRIDGE_OFFSET = 29.559
_BRIDGE_NAME = "bridge"
# nodered's probes, measured: one every 30.1006 s, each taking 92-102 ms (n=17).
_PROBE_PERIOD_NS = 30_100_600_000
_HEALTH_LOG = 5

# /stats CPU, fitted to n=19/23/27: a burst at start, then nodered pays per health probe
# (a `node` process every 30 s) and the other two tick over slowly. Seconds; the share
# spent in the kernel is the recorded one.
_CPU = {"nodered": (3.0, 0.0, 0.081852, 0.16002),
        "influxdb": (1.204142, 5.6e-5, 0.0, 0.15449),
        "mosquitto": (0.053224, 5.0e-5, 0.0, 0.60317)}
# Which veth (net.py, index order) is whose: netns ids go in start order.
_VETH = {"mosquitto": 0, "influxdb": 1, "nodered": 2}

# A freshly created container's fixed scaffolding, taken from Ground Truth's own
# create (gt_api_phase2 n=9): the daemon's default HostConfig, the still-empty network
# attachment, and the storage block. These carry no per-boot value (a created container
# has no IP, MAC, pid or endpoint yet), so unlike the running state they live here rather
# than in the recorded seed. The attacker's own HostConfig overlays the defaults (R25).
_HOSTCONFIG_DEFAULT = {
    "Binds": None, "ContainerIDFile": "", "LogConfig": {"Type": "json-file", "Config": {}},
    "NetworkMode": "bridge", "PortBindings": {},
    "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}, "AutoRemove": False,
    "VolumeDriver": "", "VolumesFrom": None, "ConsoleSize": [0, 0], "CapAdd": None,
    "CapDrop": None, "CgroupnsMode": "private", "Dns": None, "DnsOptions": None,
    "DnsSearch": None, "ExtraHosts": None, "GroupAdd": None, "IpcMode": "private",
    "Cgroup": "", "Links": None, "OomScoreAdj": 0, "PidMode": "", "Privileged": False,
    "PublishAllPorts": False, "ReadonlyRootfs": False, "SecurityOpt": None, "UTSMode": "",
    "UsernsMode": "", "ShmSize": 67108864, "Runtime": "runc", "Isolation": "",
    "CpuShares": 0, "Memory": 0, "NanoCpus": 0, "CgroupParent": "", "BlkioWeight": 0,
    "BlkioWeightDevice": None, "BlkioDeviceReadBps": None, "BlkioDeviceWriteBps": None,
    "BlkioDeviceReadIOps": None, "BlkioDeviceWriteIOps": None, "CpuPeriod": 0,
    "CpuQuota": 0, "CpuRealtimePeriod": 0, "CpuRealtimeRuntime": 0, "CpusetCpus": "",
    "CpusetMems": "", "Devices": None, "DeviceCgroupRules": None, "DeviceRequests": None,
    "MemoryReservation": 0, "MemorySwap": 0, "MemorySwappiness": None,
    "OomKillDisable": False, "PidsLimit": None, "Ulimits": None, "CpuCount": 0,
    "CpuPercent": 0, "IOMaximumIOps": 0, "IOMaximumBandwidth": 0,
    "MaskedPaths": ["/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore",
                    "/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi",
                    "/proc/timer_list", "/proc/timer_stats",
                    "/sys/devices/virtual/powercap", "/sys/firmware"],
    "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
                      "/proc/sysrq-trigger"],
}
_ENDPOINT_EMPTY = {
    "IPAMConfig": None, "Links": None, "Aliases": None, "DriverOpts": None,
    "GwPriority": 0, "NetworkID": "", "EndpointID": "", "Gateway": "", "IPAddress": "",
    "MacAddress": "", "IPPrefixLen": 0, "IPv6Gateway": "", "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0, "DNSNames": None,
}
_STORAGE_DEFAULT = {"RootFS": {"Snapshot": {"Name": "overlayfs"}}}

# What a program prints inside a container (an exec, or a container's own command, which
# is what its log holds) is in no state the honeypot keeps: it comes from the model,
# through the same path as the shell's `docker exec` (DockerState.program_output, set by
# the relay to Shell.container_output; decided 2026-10-15, the user). Until 15 October
# the recorded attack's two exec commands and its container's command were answered
# here from their recordings, looked up by the exact command: stored answers, the
# lookup the replay tier was removed for on 8 October. Removed.

# /stats for a started container that is not one of the three recorded ones: the host's
# PID limit, and empty cgroup memory/IO blocks (a near-idle container that has done no
# I/O). The CPU and network numbers are computed in stats(); this is the fixed rest.
_MODELED_STATS = {
    "memory_stats": {"stats": {}}, "pids_limit": 9578,
    "blkio_stats": {"io_service_bytes_recursive": [], "io_serviced_recursive": [],
                    "io_queue_recursive": [], "io_service_time_recursive": [],
                    "io_wait_time_recursive": [], "io_merged_recursive": [],
                    "io_time_recursive": [], "sectors_recursive": []},
}

# Docker's namesgenerator, a <adjective>_<surname> when the client sends no name=
# (moby/pkg/namesgenerator). A real subset of its two word lists, so every generated
# name is one the real daemon could also produce (the recording's bold_maxwell and
# dreamy_turing are both here); the attacker cannot predict which name they get.
_NAMES_LEFT = (
    "admiring", "adoring", "affectionate", "agitated", "amazing", "awesome", "blissful",
    "bold", "brave", "busy", "charming", "clever", "compassionate", "competent",
    "confident", "cool", "dazzling", "determined", "dreamy", "eager", "ecstatic",
    "elastic", "elated", "elegant", "eloquent", "epic", "exciting", "fervent", "festive",
    "focused", "friendly", "frosty", "funny", "gallant", "gifted", "goofy", "gracious",
    "happy", "hardcore", "heuristic", "hopeful", "hungry", "inspiring", "intelligent",
    "jolly", "jovial", "keen", "kind", "laughing", "loving", "lucid", "magical", "modest",
    "musing", "mystifying", "nervous", "nice", "nifty", "nostalgic", "objective",
    "optimistic", "peaceful", "pedantic", "pensive", "practical", "priceless", "quirky",
    "quizzical", "relaxed", "reverent", "romantic", "serene", "sharp", "silly", "sleepy",
    "stoic", "strange", "stupefied", "suspicious", "sweet", "tender", "thirsty",
    "trusting", "unruffled", "upbeat", "vibrant", "vigilant", "vigorous", "wizardly",
    "wonderful", "youthful", "zealous", "zen",
)
_NAMES_RIGHT = (
    "albattani", "allen", "almeida", "archimedes", "ardinghelli", "aryabhata", "austin",
    "babbage", "banach", "bardeen", "bartik", "bassi", "bell", "benz", "bhabha",
    "blackwell", "bohr", "booth", "borg", "bose", "boyd", "brahmagupta", "brattain",
    "brown", "carson", "cartwright", "chandrasekhar", "chatelet", "chebyshev", "cohen",
    "colden", "cori", "cray", "curie", "darwin", "davinci", "dijkstra", "dirac",
    "driscoll", "easley", "edison", "einstein", "elion", "engelbart", "euclid", "euler",
    "faraday", "fermat", "fermi", "feynman", "franklin", "gagarin", "galileo", "galois",
    "gates", "gauss", "germain", "goldberg", "goldstine", "goldwasser", "goodall",
    "hamilton", "hawking", "heisenberg", "hermann", "herschel", "hertz", "hodgkin",
    "hofstadter", "hopper", "hugle", "hypatia", "jackson", "jang", "jennings", "jepsen",
    "johnson", "joliot", "jones", "kalam", "kapitsa", "kare", "keller", "kepler",
    "khorana", "kilby", "kirch", "knuth", "kowalevski", "lalande", "lamarr", "lamport",
    "leakey", "leavitt", "lewin", "lichterman", "liskov", "lovelace", "lumiere",
    "mahavira", "margulis", "maxwell", "mayer", "mccarthy", "mcclintock", "mclean",
    "mcnulty", "meitner", "mendel", "mendeleev", "meninsky", "mestorf", "minsky",
    "mirzakhani", "moore", "morse", "murdock", "neumann", "newton", "nightingale",
    "nobel", "noether", "northcutt", "noyce", "panini", "pare", "pascal", "pasteur",
    "payne", "perlman", "pike", "poincare", "poitras", "ptolemy", "raman", "ramanujan",
    "ride", "ritchie", "roentgen", "rosalind", "saha", "sammet", "shannon", "shaw",
    "shockley", "sinoussi", "snyder", "spence", "stallman", "stonebraker", "swanson",
    "swartz", "swirles", "tesla", "thompson", "torvalds", "turing", "varahamihira",
    "visvesvaraya", "volhard", "wescoff", "wiles", "williams", "wilson", "wing",
    "wozniak", "wright", "yalow", "yonath",
)


# ------------------------------------------------------------------ Go's time formats

_RFC3339 = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?"
                      r"(Z|[+-]\d\d:\d\d)$")


def parse_time(s: str) -> int:
    """RFC 3339 with up to nanoseconds, as Docker writes it -> epoch nanoseconds."""
    m = _RFC3339.match(s)
    if not m:
        raise ValueError(f"not an RFC 3339 time: {s!r}")
    y, mo, d, h, mi, sec, frac, zone = m.groups()
    tz = (dt.timezone.utc if zone == "Z" else
          dt.timezone((1 if zone[0] == "+" else -1)
                      * dt.timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))))
    whole = dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), tzinfo=tz)
    return int(whole.timestamp()) * NS + int((frac or "").ljust(9, "0"))


def go_time(ns: int, local: bool = False, fixed: bool = False) -> str:
    """Go's RFC3339Nano: trailing zeros of the fraction dropped, `Z` for UTC, else the
    local offset (`2026-09-28T21:57:48.835828312-04:00`). `fixed`: always nine digits,
    as `docker logs --timestamps` prints them."""
    secs, frac = divmod(ns, NS)
    t = dt.datetime.fromtimestamp(secs, machine.TZ if local else dt.timezone.utc)
    out = t.strftime("%Y-%m-%dT%H:%M:%S")
    if fixed:
        out += f".{frac:09d}"
    elif frac:
        out += "." + f"{frac:09d}".rstrip("0")
    if not local:
        return out + "Z"
    off = t.strftime("%z")
    return out + off[:3] + ":" + off[3:]


def human_duration(seconds: float) -> str:
    """go-units HumanDuration, what `Up …`, `… ago` and the API's Status use."""
    s = int(seconds)
    if s < 1:
        return "Less than a second"
    if s == 1:
        return "1 second"
    if s < 60:
        return f"{s} seconds"
    minutes = int(seconds / 60)
    if minutes == 1:
        return "About a minute"
    if minutes < 60:
        return f"{minutes} minutes"
    hours = int(seconds / 3600 + 0.5)
    if hours == 1:
        return "About an hour"
    if hours < 48:
        return f"{hours} hours"
    if hours < 24 * 7 * 2:
        return f"{hours // 24} days"
    if hours < 24 * 30 * 2:
        return f"{hours // 24 // 7} weeks"
    if hours < 24 * 365 * 2:
        return f"{hours // 24 // 30} months"
    return f"{int(seconds / 3600) // 24 // 365} years"


class BadFilter(ValueError):
    """A `filters` value Docker rejects with 400; the message is Docker's."""


# ------------------------------------------------------------------ the state


def _service(c: dict) -> str:
    return c["Config"]["Labels"].get("com.docker.compose.service", "")


def _main_pids() -> dict[str, int]:
    """Ground Truth container id -> its main process, from the process table: the
    child of the containerd shim that names the container."""
    shims = {row[0]: row[4].split(" -id ")[1].split()[0]
             for row in procs.SERVICES if row[3] == "containerd-shim"}
    return {shims[row[1]]: row[0] for row in procs.SERVICES if row[1] in shims}


class DockerState:
    def __init__(self, boot: float, seed: str, subs=None, shift_ns: int = 0,
                 seed_path: pathlib.Path = SEED):
        """`boot`: this machine's boot time (epoch s). `seed`: this install's secret
        (identity.secret), which makes the per-boot jitter this machine's own. `subs`:
        the relay's substitution map. `shift_ns`: how far this install's setup day lies
        after Ground Truth's (identity.install_shift_ns)."""
        raw = SITE.load_json(seed_path)      # its credentials are site values (site.py)
        gt_pids = _main_pids()
        self._pid = {_service(c): gt_pids[c["Id"]] for c in raw["containers"]}
        data = json.loads(subs(json.dumps(raw, ensure_ascii=False))) if subs else raw
        self.boot = boot
        self.shift_ns = shift_ns
        self._seed = f"{seed}-{int(boot)}"
        self._created = 0                            # how many containers have been created
        self._started: dict[str, dict] = {}          # cid -> host procs of a running one
        self._pid_counter = 1399                     # a band free of kthreads and sessions
        self._execs: dict[str, dict] = {}            # exec id -> its spec and exit code
        self._exec_counter = 0
        # What a program run inside a container prints: a function (container, argv,
        # tty, kind "exec" | "run") -> (text, exit status), the model's answer through
        # the shell's path (relay.py sets it). None (tests, tools): no output.
        self.program_output = None
        # The log of a container created here, once its command's output is known
        # (asked for when the log is first read, or written by a foreground run):
        # container id -> [(Docker's receive time, stream, text)]. Kept like any log.
        self._program_logs: dict[str, list] = {}
        # The host side of each running container's veth (net.py), by container id: the
        # recorded three from boot, one more for every container started on a bridge
        # network, gone when it stops. `ip a`, the routes, /proc/net/dev and `/stats`
        # all read these, so the shell's network view follows the API's state.
        self._links: dict[str, net.Link] = {}
        self._next_ifindex = 9                       # 6, 7, 8 are the recorded three
        self.docker0_since: float | None = None      # when docker0 first had a port
        self.containers: list[dict] = data["containers"]
        self.images: list[dict] = data["images"]
        self._networks: list[dict] = data["networks"]
        self._volumes: list[dict] = data["volumes"]
        self.version: dict = data["version"]
        self._info: dict = data["info"]
        self._df: dict = data["df"]
        self._stats: dict = data["stats"]
        self._logs: dict = data["logs"]
        self._image_manifests: dict = data["image_manifests"]
        self._image_inspect: dict = data["image_inspect"]
        self._image_history: dict = data["image_history"]
        self._subs = subs if subs else (lambda s: s)     # for answers built, not loaded
        boot_ns = int(boot) * NS
        for c in self.containers:
            name = _service(c)
            c["Created"] = go_time(parse_time(c["Created"]) + shift_ns)
            st = c["State"]
            st["StartedAt"] = go_time(boot_ns + self._jitter_ns(
                f"start-{name}", _START_OFFSET[name], 0.12))
            st["FinishedAt"] = go_time(boot_ns + self._jitter_ns(
                f"stop-{name}", _STOP_OFFSET[name], 0.12))
            st["Pid"] = self._pid[name]
        seeded = net.seeded_links(boot)
        for c in self.containers:
            if c["State"]["Status"] == "running" and _service(c) in _VETH:
                self._links[c["Id"]] = seeded[_VETH[_service(c)]]
        for n in self._networks:
            if n["Name"] == _BRIDGE_NAME:
                n["Created"] = go_time(boot_ns + self._jitter_ns(
                    "bridge", _BRIDGE_OFFSET, 0.12), local=True)
            else:
                n["Created"] = go_time(parse_time(n["Created"]) + shift_ns, local=True)
        for v in self._volumes:                     # whole seconds, as Docker shows them
            t = parse_time(v["CreatedAt"]) + shift_ns
            v["CreatedAt"] = go_time(t - t % NS, local=True)

    def _frac(self, salt: str) -> float:
        h = hashlib.sha256(f"{self._seed}-{salt}".encode()).digest()
        return int.from_bytes(h[:8], "big") / 2**64

    def _jitter_ns(self, what: str, base_s: float, amp_s: float) -> int:
        """base_s plus a per-boot shift in [0, amp_s), shared by everything this boot
        so the recorded order holds, plus a few ms of its own."""
        return int((base_s + self._frac("shift") * amp_s + self._frac(what) * 0.004) * NS)

    # -------------------------------------------------------------- lookups

    def find(self, ref: str) -> dict | None:
        """A container by name (with or without the leading `/`), full id or unique id
        prefix, the way Docker resolves the reference in a URL or a command."""
        ref = ref.strip()
        if not ref:
            return None
        for c in self.containers:
            if c["Name"] in (ref, "/" + ref) or c["Id"] == ref:
                return c
        hits = [c for c in self.containers if c["Id"].startswith(ref)]
        return hits[0] if len(hits) == 1 else None

    def find_volume(self, name: str) -> dict | None:
        return next((v for v in self._volumes if v["Name"] == name), None)

    def stack_files(self) -> list[tuple[str, str, int, int]]:
        """/root/iot-stack as (path, kind, mtime ns, size): written by the setup a
        second before `docker compose up` created the project network (gt_setup.sh step
        8), so its dates move with the install shift like the API's. Sizes: the files
        gt_setup.sh wrote (the compose file is gt_docker_shell n=14 plus its newline)."""
        net_ns = parse_time(next(n["Created"] for n in self._networks
                                 if n["Name"] == "iot-stack_default"))
        conf, compose = net_ns - 1_200_000_000, net_ns - 1_000_000_000
        return [("/root/iot-stack", "dir", compose, 4096),
                ("/root/iot-stack/docker-compose.yml", "file", compose, 1551),
                ("/root/iot-stack/mosquitto", "dir", conf, 4096),
                ("/root/iot-stack/mosquitto/config", "dir", conf, 4096),
                ("/root/iot-stack/mosquitto/config/mosquitto.conf", "file", conf, 179)]

    # -------------------------------------------------------------- create (R23-R25)

    def _gen_name(self, k: int) -> str:
        """A Docker-style <adjective>_<surname> for a container created without name=,
        deterministic in this boot's seed so a replay is stable."""
        h = hashlib.sha256(f"{self._seed}-name-{k}".encode()).digest()
        return (_NAMES_LEFT[int.from_bytes(h[:4], "big") % len(_NAMES_LEFT)] + "_"
                + _NAMES_RIGHT[int.from_bytes(h[4:8], "big") % len(_NAMES_RIGHT)])

    def _image_descriptor(self, img: dict) -> dict:
        """The container's ImageManifestDescriptor: the image's own descriptor plus the
        platform from its manifest (the image list carries the descriptor without it)."""
        desc = copy.deepcopy(img.get("Descriptor") or {})
        try:
            first = self._image_manifests[img["Id"]][0]
            # The manifest carries the platform under ImageData (phase 3); the place
            # read here until 2026-10-13 does not exist, so a container created through
            # the API had no platform in its inspect document (phase 2 n=9 has one).
            platform = (first.get("Descriptor") or {}).get("platform") \
                or (first.get("ImageData") or {}).get("Platform")
            if platform:
                desc["platform"] = copy.deepcopy(platform)
        except (KeyError, IndexError, TypeError):
            pass
        return desc

    def create_container(self, config: dict, name: str | None, now: float):
        """`POST /containers/create`: add one container to this in-memory state in the
        `created` state — never started, no process, no network endpoint yet (R23). It
        reflects whatever the request sent (image, command, binds, privileged/pid flags;
        R25) and picks up the image's declared VOLUMEs as anonymous volumes (R24), so the
        shell, the API, `/volumes` and `/system/df` keep agreeing (R11). Mutates only
        this object, the one both surfaces read; nothing is ever run.

        Returns `(doc, None)` on success, or `(None, (kind, detail))` where `kind` is
        `"no_image"` (detail: the image reference, with `:latest` filled in as Docker
        reports it), `"name"` (detail: the clashing name and its holder's id) or
        `"no_command"` (neither the request nor the image names anything to run)."""
        config = config or {}
        image_ref = config.get("Image") or ""
        img = self.find_image(image_ref) if image_ref else None
        if img is None:
            return None, ("no_image", _ref_with_tag(image_ref))

        self._created += 1
        k = self._created
        cname = (name or self._gen_name(k)).lstrip("/")
        holder = next((c for c in self.containers if c["Name"] == "/" + cname), None)
        if holder is not None:
            return None, ("name", (cname, holder["Id"]))
        cid = hashlib.sha256(f"{self._seed}-container-{k}-{cname}".encode()).hexdigest()
        now_ns = int(now * NS)

        img_cfg = copy.deepcopy((self._image_inspect.get(img["Id"]) or {}).get("Config")
                                or {})
        # What the request leaves empty comes from the image, by the daemon's own rules
        # (moby daemon/commit.go merge() and daemon/create.go mergeAndVerifyConfig() at
        # docker-v29.8.1). The docker client sends every field, empty ones as "" or
        # null, so "is the key there" is the wrong question: empty means the image's.
        # The image's command is used only when the request names no entrypoint.
        env = list(config.get("Env") or [])
        named = {e.split("=", 1)[0] for e in env}
        env += [e for e in img_cfg.get("Env") or [] if e.split("=", 1)[0] not in named] \
            if env else list(img_cfg.get("Env") or [])
        entrypoint, cmd = config.get("Entrypoint"), config.get("Cmd")
        if not entrypoint:
            if not cmd:
                cmd = img_cfg.get("Cmd")
            if entrypoint is None:
                entrypoint = img_cfg.get("Entrypoint")
        if entrypoint == [""]:
            entrypoint = None
        if not entrypoint and not cmd:
            self._created -= 1
            return None, ("no_command", None)
        cfg = {"Hostname": config.get("Hostname") or cid[:12],
               "Domainname": config.get("Domainname", ""),
               "User": config.get("User") or img_cfg.get("User") or "",
               "AttachStdin": bool(config.get("AttachStdin", False)),
               "AttachStdout": bool(config.get("AttachStdout", False)),
               "AttachStderr": bool(config.get("AttachStderr", False))}
        exposed = {**(config.get("ExposedPorts") or {}),
                   **{p: v for p, v in (img_cfg.get("ExposedPorts") or {}).items()
                      if p not in (config.get("ExposedPorts") or {})}}
        if exposed:
            cfg["ExposedPorts"] = exposed
        cfg.update({
            "Tty": bool(config.get("Tty", False)),
            "OpenStdin": bool(config.get("OpenStdin", False)),
            "StdinOnce": bool(config.get("StdinOnce", False)),
            "Env": env,
            "Cmd": cmd,
            "Image": image_ref,
            "Volumes": {**config["Volumes"], **(img_cfg.get("Volumes") or {})}
            if config.get("Volumes") else img_cfg.get("Volumes"),
            "WorkingDir": config.get("WorkingDir") or img_cfg.get("WorkingDir") or "",
            "Entrypoint": entrypoint,
            "Labels": {**(img_cfg.get("Labels") or {}), **(config.get("Labels") or {})},
        })

        combined = list(cfg["Entrypoint"] or []) + list(cfg["Cmd"] or [])
        hc = copy.deepcopy(_HOSTCONFIG_DEFAULT)
        hc.update(config.get("HostConfig") or {})     # reflect the attacker's flags (R25)
        # The daemon holds these as Go maps and writes them with their keys in order.
        for holder, key in ((cfg, "ExposedPorts"), (cfg, "Volumes"), (cfg, "Labels"),
                            (hc, "PortBindings")):
            if isinstance(holder.get(key), dict):
                holder[key] = dict(sorted(holder[key].items()))
        mounts = self._new_mounts(hc.get("Binds") or [], cfg.get("Volumes") or {}, cid,
                                  now_ns)

        netmode = hc.get("NetworkMode") or "default"
        netname = "bridge" if netmode in ("default", "bridge") else netmode
        doc = {
            "Id": cid, "Created": go_time(now_ns),
            "Path": combined[0] if combined else "", "Args": combined[1:],
            "State": {"Status": "created", "Running": False, "Paused": False,
                      "Restarting": False, "OOMKilled": False, "Dead": False, "Pid": 0,
                      "ExitCode": 0, "Error": "", "StartedAt": "0001-01-01T00:00:00Z",
                      "FinishedAt": "0001-01-01T00:00:00Z"},
            "Image": img["Id"], "ResolvConfPath": "", "HostnamePath": "", "HostsPath": "",
            "LogPath": "", "Name": "/" + cname, "RestartCount": 0, "Driver": "overlayfs",
            "Platform": "linux", "MountLabel": "", "ProcessLabel": "",
            "AppArmorProfile": "", "ExecIDs": None, "HostConfig": hc,
            "Storage": copy.deepcopy(_STORAGE_DEFAULT), "Mounts": mounts, "Config": cfg,
            "NetworkSettings": {"SandboxID": "", "SandboxKey": "", "Ports": {},
                                "Networks": {netname: copy.deepcopy(_ENDPOINT_EMPTY)}},
            "ImageManifestDescriptor": self._image_descriptor(img),
        }
        self.containers.append(doc)
        # Keep the derived views consistent: /system/df reads a size for every container.
        self._df["container_size"][doc["Name"]] = [0, img.get("Size", 0)]
        return doc, None

    def _new_mounts(self, binds: list, volumes: dict, cid: str, now_ns: int) -> list:
        """The new container's Mounts: the host binds it asked for, then an anonymous
        volume for each VOLUME the image declares that nothing maps (R24). Each anonymous
        volume is also registered in /volumes and /system/df so the surfaces agree."""
        mounts, mapped = [], set()
        for b in binds:
            parts = b.split(":")
            src, dst = parts[0], (parts[1] if len(parts) > 1 else parts[0])
            mode = parts[2] if len(parts) > 2 else ""
            mapped.add(dst)
            mounts.append({"Type": "bind", "Source": src, "Destination": dst,
                           "Mode": mode, "RW": "ro" not in mode.split(","),
                           "Propagation": "rslave"})
        for i, dest in enumerate(d for d in volumes if d not in mapped):
            vid = hashlib.sha256(f"{self._seed}-vol-{cid}-{i}".encode()).hexdigest()
            mount = f"/var/lib/docker/volumes/{vid}/_data"
            mounts.append({"Type": "volume", "Name": vid, "Source": mount,
                           "Destination": dest, "Driver": "local", "Mode": "",
                           "RW": True, "Propagation": ""})
            self._volumes.append({
                "CreatedAt": go_time(now_ns - now_ns % NS, local=True), "Driver": "local",
                "Labels": {"com.docker.volume.anonymous": ""}, "Mountpoint": mount,
                "Name": vid, "Options": None, "Scope": "local"})
            self._df["volume_size"][vid] = 0
        return mounts

    # -------------------------------------------------------------- start (R23)

    def _alloc_pid(self) -> int:
        """A PID for a container's host process. 1400+ is a band with no kernel thread
        (next one after 712 is above 3000) and below the session PIDs (2439+), so a
        handful of started containers never collide with the rest of the table."""
        self._pid_counter += 1
        return self._pid_counter

    def start_container(self, c: dict, now: float) -> str:
        """`POST /containers/<id>/start` (R23): move a `created` container to `running`.
        It fills in StartedAt and a real main Pid, joins the default bridge with an
        endpoint, and gets its host processes (a containerd-shim and the container's main
        process) added to the shared process table, so `docker top`, the API and host
        `ps` all show it (R15). Returns `"running"` if it was started, `"already"` if it
        was already running (the daemon answers that with 304), or the daemon's error
        text if it refuses (a network that does not exist). Only this in-memory state
        changes; no process is ever run.

        On a bridge network it also gets its veth on the host (`_link_up`, net.py), so
        `ip a`, the routes, /proc/net/dev and `/stats` show it; modelled, not recorded
        (TASKS.md, "host-network view")."""
        if c["State"]["Status"] == "running":
            return "already"
        mode = c["HostConfig"].get("NetworkMode") or "default"
        if mode not in ("default", "bridge", "host", "none") and not mode.startswith("container:") \
                and self.find_network(mode) is None:
            # The daemon accepts `create` with any network name and refuses at start.
            # NOT RECORDED on the reference machine; from the daemon's source at
            # docker-v29.8.1: daemon/start_linux.go wraps libnetwork's ErrNoSuchNetwork
            # ("network %s not found", a 404) in "failed to set up container networking",
            # and daemon/start.go then stores the error in the container's state and
            # sets exit code 128 (exitUnknown) on a container that stays `created`.
            error = f"failed to set up container networking: network {mode} not found"
            c["State"].update({"Error": error, "ExitCode": 128})
            return error
        now_ns = int(now * NS)
        shim_pid, main_pid = self._alloc_pid(), self._alloc_pid()
        c["State"].update({"Status": "running", "Running": True, "Pid": main_pid,
                           "StartedAt": go_time(now_ns)})
        self._attach_bridge(c, now_ns)
        self._link_up(c, now)
        c["NetworkSettings"]["Ports"] = self._publish_ports(c)
        self._started[c["Id"]] = {
            "shim": shim_pid, "main": main_pid, "start": now,
            "user": c["Config"].get("User") or "root",
            "comm": ((c["Path"].rsplit("/", 1)[-1] if c["Path"] else "") or "sh")[:15],
            "argv": " ".join([c["Path"], *c["Args"]]) if c["Path"] else ""}
        return "running"

    def _publish_ports(self, c: dict) -> dict:
        """`NetworkSettings.Ports` of a container that has just started: every port it
        exposes, with the host side of those it publishes. A port published without a
        host address is bound for IPv4 and IPv6, as the three recorded containers would
        be without their `127.0.0.1:`; one without a host port gets the next free port
        from the kernel's local range (32768 up). With the host's network or none there
        is nothing to publish. NOT RECORDED on the reference machine (its three
        containers all name address and port): this is the daemon's documented
        behaviour, not a measured answer."""
        mode = c["HostConfig"].get("NetworkMode") or "default"
        if mode in ("host", "none") or mode.startswith("container:"):
            return {}
        taken = {b["HostPort"] for cc in self.containers
                 for binds in (cc["NetworkSettings"].get("Ports") or {}).values()
                 for b in binds or []}
        ports = {p: None for p in c["Config"].get("ExposedPorts") or {}}
        for port, binds in (c["HostConfig"].get("PortBindings") or {}).items():
            out = []
            for b in binds or []:
                host = b.get("HostPort") or next(str(n) for n in range(32768, 61000)
                                                 if str(n) not in taken)
                taken.add(host)
                out += [{"HostIp": ip, "HostPort": host}
                        for ip in ([b["HostIp"]] if b.get("HostIp") else ["0.0.0.0", "::"])]
            ports[port] = out or None
        return dict(sorted(ports.items()))

    def _attach_bridge(self, c: dict, now_ns: int) -> None:
        """Give the started container an endpoint on its network (the default bridge
        unless it asked for another): the first free address in the pool, the gateway,
        and the MAC Docker derives from the address. The API's inspect and `network
        inspect` then show it attached (R11)."""
        mode = c["HostConfig"].get("NetworkMode") or "default"
        name = "bridge" if mode in ("default", "bridge") else mode
        n = self.find_network(name)
        ep = c["NetworkSettings"]["Networks"].get(name) or copy.deepcopy(_ENDPOINT_EMPTY)
        cfg = (n or {}).get("IPAM", {}).get("Config") or []
        if cfg:
            subnet = cfg[0]["Subnet"]
            prefix = subnet.rsplit(".", 1)[0]
            gw = cfg[0].get("Gateway") or f"{prefix}.1"
            used = {e["IPAddress"] for cc in self.containers
                    for e in [cc["NetworkSettings"]["Networks"].get(name)]
                    if e and e.get("IPAddress")}
            ip = next(f"{prefix}.{h}" for h in range(2, 255) if f"{prefix}.{h}" not in used)
            ep.update({"NetworkID": n["Id"], "EndpointID": self._hex(c["Id"], "endpoint"),
                       "Gateway": gw, "IPAddress": ip,
                       "IPPrefixLen": int(subnet.split("/")[1]), "MacAddress": _bridge_mac(ip)})
        c["NetworkSettings"]["Networks"] = {name: ep}
        # The netns path's directory is taken from a recorded container, not hard-coded,
        # so the daemon's runtime dir is never a literal in this module (R26 guard).
        sample = next((cc["NetworkSettings"]["SandboxKey"] for cc in self.containers
                       if cc["NetworkSettings"].get("SandboxKey")), "")
        sandbox = self._hex(c["Id"], "sandbox")
        c["NetworkSettings"]["SandboxID"] = sandbox
        c["NetworkSettings"]["SandboxKey"] = \
            (sample.rsplit("/", 1)[0] + "/" if sample else "") + sandbox[:12]

    def _link_up(self, c: dict, now: float) -> None:
        """A container that got an address on a bridge network gets its veth on the host:
        a port of that network's bridge (`com.docker.network.bridge.name`, else `br-` and
        the network id's first 12 digits, which is the compose bridge's name). The host's
        network view (net.py) is modelled from this, not recorded: TASKS.md,
        "host-network view"."""
        name, ep = next(iter(c["NetworkSettings"]["Networks"].items()), (None, None))
        n = self.find_network(name) if name else None
        if not ep or not ep.get("IPAddress") or not n or n.get("Driver") != "bridge":
            return
        master = (n.get("Options") or {}).get("com.docker.network.bridge.name") \
            or "br-" + n["Id"][:12]
        if master == self._subs(net.BRIDGE):       # net.py names it by Ground Truth's id
            master = net.BRIDGE
        used = {k.netnsid for k in self._links.values()}
        netnsid = next(i for i in range(len(used) + 1) if i not in used)
        self._links[c["Id"]] = net.new_link(self._seed, self._next_ifindex, master, netnsid, now)
        self._next_ifindex += 1
        if master == "docker0" and self.docker0_since is None:
            self.docker0_since = now

    def host_links(self) -> list:
        """The running containers' veths, in interface-index order (net.interfaces)."""
        return sorted(self._links.values(), key=lambda k: k.index)

    def _hex(self, cid: str, salt: str) -> str:
        return hashlib.sha256(f"{self._seed}-{salt}-{cid}".encode()).hexdigest()

    def container_procs(self, now: float) -> list:
        """Host process rows for every API-started container that is running: its
        containerd-shim (child of PID 1) and the container's main process (child of the
        shim). Both `docker top` and the host `ps` read these, so the two agree (R15)."""
        running = {c["Id"] for c in self.containers if c["State"]["Status"] == "running"}
        out = []
        for cid, p in self._started.items():
            if cid not in running:
                continue
            up = max(now - p["start"], 0)
            out.append(procs.Proc(p["shim"], 1, "root", "containerd-shim",
                                  procs._SHIM.format(cid), p["start"], 0.05 + 2e-5 * up,
                                  1268192, 11888, 9216, "Sl", nlwp=12))
            out.append(procs.Proc(p["main"], p["shim"], p["user"], p["comm"], p["argv"],
                                  p["start"], 0.02, 2048, 1280, 1024, "Ss", nlwp=1))
        return out

    # -------------------------------------------------------------- exec (R23)

    def exec_create(self, c: dict, config: dict) -> str:
        """`POST /containers/<id>/exec`: register an exec against a running container and
        return its id. Nothing runs until exec_start."""
        self._exec_counter += 1
        exec_id = hashlib.sha256(
            f"{self._seed}-exec-{self._exec_counter}-{c['Id']}".encode()).hexdigest()
        self._execs[exec_id] = {
            "container": c["Id"], "cmd": list(config.get("Cmd") or []),
            "stdout": bool(config.get("AttachStdout", False)),
            "stderr": bool(config.get("AttachStderr", False)),
            "tty": bool(config.get("Tty", False)), "exit": None}
        return exec_id

    def exec_start(self, exec_id: str):
        """`POST /exec/<id>/start`: run the exec, record its exit code, and return
        `(spec, stdout, stderr)`; `None` if the exec id is unknown."""
        rec = self._execs.get(exec_id)
        if rec is None:
            return None
        c = self.find(rec["container"])
        stdout, stderr, code = self.exec_output(c, rec["cmd"], rec["tty"])
        rec["exit"] = code
        return rec, stdout, stderr

    def exec_output(self, c: dict | None, argv: list, tty: bool = False) -> tuple[bytes, bytes, int]:
        """What a command run inside the container prints: the model's answer
        (program_output). It comes as the terminal would show it, so it all goes on
        stdout. Without a model (program_output None): nothing, status 0."""
        if self.program_output is None or c is None or not argv:
            return b"", b"", 0
        text, code = self.program_output(c, list(argv), tty, "exec")
        return ((text + "\n").encode() if text else b""), b"", code

    def record_program_log(self, c: dict, text: str, now_ns: int) -> None:
        """A container's command printed `text` (the model's answer): that is its log, on
        both surfaces, received 25 ms after its start, or when the answer came if sooner."""
        at = min(parse_time(c["State"]["StartedAt"]) + 25_000_000, now_ns)
        self._program_logs[c["Id"]] = [(at, 1, text + "\n")] if text else []

    # -------------------------------------------------------------- stop (R23)

    def stop_container(self, c: dict, now: float) -> None:
        """Mark a running container exited at `now` with code 137 - a shell as PID 1
        ignores SIGTERM, so the daemon SIGKILLs it after its timeout (the caller does the
        wait; phase 2 n=19). Its host processes go and its endpoint is released, so the
        process table, `network inspect` and `docker ps` all stop showing it (R11)."""
        self.finish_container(c, now, 137)

    def finish_container(self, c: dict, now: float, code: int) -> None:
        """The container's main process ended at `now` with exit status `code`: the state
        a `stop`, or a program run in the foreground coming to its end, leaves behind."""
        c["State"].update({"Status": "exited", "Running": False, "Pid": 0,
                           "ExitCode": code, "Error": "", "FinishedAt": go_time(int(now * NS))})
        self._started.pop(c["Id"], None)
        self._links.pop(c["Id"], None)
        self._release_endpoint(c)

    def _release_endpoint(self, c: dict) -> None:
        """Drop the container's network endpoint and sandbox, freeing its address - what
        a stopped container shows (empty endpoint, no SandboxKey)."""
        ns = c["NetworkSettings"]
        ns["Networks"] = {name: copy.deepcopy(_ENDPOINT_EMPTY) for name in ns["Networks"]}
        ns["SandboxID"] = ns["SandboxKey"] = ""
        ns["Ports"] = {}

    # -------------------------------------------------------------- delete (R23-R24)

    def delete_container(self, c: dict, remove_volumes: bool) -> None:
        """`DELETE /containers/<id>`: drop the container and everything it added to this
        state - its host processes, its size entry and, with `?v=1`, the anonymous volumes
        it created that nothing else uses (R24). A named volume is kept. This is what puts
        the state back to its pre-attack set (R11)."""
        self.containers.remove(c)
        self._started.pop(c["Id"], None)
        self._links.pop(c["Id"], None)
        self._program_logs.pop(c["Id"], None)
        self._df["container_size"].pop(c["Name"], None)
        if not remove_volumes:
            return
        for m in c["Mounts"]:
            if m["Type"] != "volume":
                continue
            vol = self.find_volume(m.get("Name"))
            anon = vol and (vol.get("Labels") or {}).get("com.docker.volume.anonymous") \
                is not None
            used = any(mm.get("Name") == m.get("Name")
                       for cc in self.containers for mm in cc["Mounts"])
            if anon and not used:
                self._volumes.remove(vol)
                self._df["volume_size"].pop(m["Name"], None)

    # -------------------------------------------------------------- live fields

    def _health_log(self, c: dict, now_ns: int) -> list[dict]:
        started = parse_time(c["State"]["StartedAt"])
        k_last = (now_ns - started) // _PROBE_PERIOD_NS
        out = []
        for k in range(max(1, k_last - _HEALTH_LOG), k_last + 1):
            start, end = self._probe_times(c, started, k)
            if end > now_ns:            # still running: not in the log yet
                continue
            out.append({"Start": go_time(start, local=True),
                        "End": go_time(end, local=True), "ExitCode": 0, "Output": ""})
        return out[-_HEALTH_LOG:]

    def _probe_times(self, c: dict, started: int, k: int) -> tuple[int, int]:
        """Start and end of nodered's k-th health probe: every ~30.1 s, ~0.1 s long."""
        h = hashlib.sha256(f"{self._seed}-probe-{c['Id']}-{k}".encode()).digest()
        start = (started + k * _PROBE_PERIOD_NS
                 + int.from_bytes(h[:4], "big") % 2_000_000 - 1_000_000)
        return start, start + 92_000_000 + int.from_bytes(h[4:8], "big") % 10_000_000

    def _probes_done(self, c: dict, now_ns: int) -> int:
        if "Health" not in c["State"]:
            return 0
        return max((now_ns - parse_time(c["State"]["StartedAt"])) // _PROBE_PERIOD_NS, 0)

    def inspect(self, ref: str, now: float, size: bool = False) -> dict | None:
        """`GET /containers/<ref>/json` and `docker inspect <ref>`: one document."""
        c = self.find(ref)
        if c is None:
            return None
        doc = copy.deepcopy(c)
        health = doc["State"].get("Health")
        if health is not None:
            log = self._health_log(c, int(now * NS))
            health["Log"] = log
            health["Status"] = "healthy" if log else "starting"
        if size:                                   # after the fixed fields, as Go orders
            rw, rootfs = self._df["container_size"][doc["Name"]]
            out = {}
            for k, v in doc.items():
                out[k] = v
                if k == "Storage":
                    out["SizeRw"], out["SizeRootFs"] = rw, rootfs
            doc = out
        return doc

    def status_text(self, doc: dict, now: float) -> str:
        """The `STATUS` column of `docker ps` and the API's `Status`."""
        st = doc["State"]
        if st["Status"] == "running":
            up = now - parse_time(st["StartedAt"]) / NS
            out = "Up " + human_duration(up)
            health = st.get("Health")
            if health:
                out += (" (healthy)" if health["Status"] == "healthy" else
                        f" (health: {health['Status']})")
            return out
        if st["Status"] == "created":
            return "Created"
        ago = now - parse_time(st["FinishedAt"]) / NS
        return f"Exited ({st['ExitCode']}) {human_duration(ago)} ago"

    # -------------------------------------------------------------- list views

    def _summary(self, doc: dict, now: float, size: bool, manifest: bool = True) -> dict:
        cfg, hc, ns = doc["Config"], doc["HostConfig"], doc["NetworkSettings"]
        # A port that is exposed and not published lists with its private side only.
        ports = [{"IP": b["HostIp"], "PrivatePort": int(p.split("/")[0]),
                  "PublicPort": int(b["HostPort"]), "Type": p.split("/")[1]}
                 for p, binds in (ns["Ports"] or {}).items() for b in binds or []] \
            + [{"PrivatePort": int(p.split("/")[0]), "Type": p.split("/")[1]}
               for p, binds in (ns["Ports"] or {}).items() if not binds]
        networks = {}
        for name, n in ns["Networks"].items():
            n = dict(n)
            n["Aliases"] = n["DNSNames"] = None
            networks[name] = n
        # A volume the image declares but nothing maps (mosquitto's /mosquitto/log)
        # lists with an empty Source, though inspect shows its path (n=4 vs n=25).
        mapped = {b.split(":")[1] for b in hc["Binds"] or []}
        mounts = [dict(m, Source="") if m["Type"] == "volume"
                  and m["Destination"] not in mapped else m for m in doc["Mounts"]]
        health = doc["State"].get("Health")
        out = {"Id": doc["Id"], "Names": [doc["Name"]], "Image": cfg["Image"],
               "ImageID": doc["Image"]}
        if manifest:
            out["ImageManifestDescriptor"] = doc["ImageManifestDescriptor"]
        out.update({"Command": " ".join([doc["Path"], *doc["Args"]]),
                    "Created": parse_time(doc["Created"]) // NS, "Ports": ports})
        if size:
            out["SizeRw"], out["SizeRootFs"] = self._df["container_size"][doc["Name"]]
        out.update({
            "Labels": cfg["Labels"],
            "State": doc["State"]["Status"],
            "Status": self.status_text(doc, now),
            "HostConfig": {"NetworkMode": hc["NetworkMode"]},
            "Health": {"Status": health["Status"] if health else "none",
                       "FailingStreak": health["FailingStreak"] if health else 0},
            "NetworkSettings": {"Networks": networks},
            "Mounts": mounts,
        })
        return out

    def list_containers(self, now: float, all: bool = False, limit: int = -1,
                        size: bool = False, filters: dict | None = None) -> list[dict]:
        """`GET /containers/json`, newest first, as Docker sorts it."""
        docs = [self.inspect(c["Id"], now) for c in
                sorted(self.containers, key=lambda c: parse_time(c["Created"]),
                       reverse=True)]
        if limit > 0:
            all, docs = True, docs[:limit]
        filters = filters or {}
        all = all or "status" in filters          # a status filter looks at every state
        return [self._summary(d, now, size) for d in docs if self._match(d, filters)
                and (all or d["State"]["Status"] == "running")]

    _CONTAINER_FILTERS = {"id", "name", "label", "status", "health", "ancestor", "network",
                          "volume", "exited", "before", "since", "publish", "expose",
                          "isolation", "is-task"}

    def _match(self, d: dict, filters: dict) -> bool:
        for key, values in filters.items():
            if key not in self._CONTAINER_FILTERS:
                raise BadFilter(f"invalid filter '{key}'")
            health = (d["State"].get("Health") or {}).get("Status", "none")
            tests = {
                "id": lambda v: d["Id"].startswith(v),
                "name": lambda v: re.search(v, d["Name"]) is not None,
                "label": lambda v: _label_match(d["Config"]["Labels"], v),
                "status": lambda v: d["State"]["Status"] == v,
                "health": lambda v: health == v,
                "ancestor": lambda v: v in (d["Config"]["Image"], d["Image"])
                or d["Image"].removeprefix("sha256:").startswith(v),
                "network": lambda v: any(v in (name, n["NetworkID"])
                                         for name, n in d["NetworkSettings"]["Networks"]
                                         .items()),
                "volume": lambda v: any(v in (m.get("Name"), m["Destination"])
                                        for m in d["Mounts"]),
            }
            states = ("created", "restarting", "running", "removing", "paused", "exited",
                      "dead")
            if key == "status":
                bad = [v for v in values if v not in states]
                if bad:
                    raise BadFilter(f"invalid filter 'status={bad[0]}'")
            test = tests.get(key)
            # Several values of one filter are alternatives, except for labels, which
            # must all be there (moby's MatchKVList). compose relies on it: it asks for
            # the project's label and the "not a one-off" label together.
            if test and not (all if key == "label" else any)(test(v) for v in values):
                return False
        return True

    def list_images(self, filters: dict | None = None, shared_size: bool = False,
                    manifests: bool = False) -> list:
        """`GET /images/json`: `Containers` counts the containers using each image.
        `manifests` (what `docker images` asks for): each image's manifest list, after
        `Descriptor` (phase 3 n=3)."""
        out = []
        for img in self.images:
            img = copy.deepcopy(img)
            img["Containers"] = sum(c["Image"] == img["Id"] for c in self.containers)
            if shared_size:
                img["SharedSize"] = self._df["image_shared"][img["Id"]]
            if manifests:
                img = _insert_after(img, "Descriptor", "Manifests",
                                    self.image_manifests(img["Id"]))
            if _image_match(img, filters or {}):
                out.append(img)
        return out

    def image_table(self) -> list[dict]:
        """One row per image for the shell's `docker images`: repo tag, short id, the
        on-disk (Total) and content (compressed) sizes from the manifest, and whether a
        container uses it - all from this shared state, so it agrees with the API."""
        out = []
        for im in self.images:
            size = (self._image_manifests[im["Id"]][0].get("Size") or {}) \
                if self._image_manifests.get(im["Id"]) else {}
            out.append({"repo": im["RepoTags"][0],
                        "id": im["Id"].removeprefix("sha256:")[:12],
                        "total": size.get("Total", im.get("Size", 0)),
                        "content": size.get("Content", 0),
                        "in_use": any(c["Image"] == im["Id"] for c in self.containers)})
        return out

    def pull_error(self, from_image: str, tag: str) -> str:
        """The 500 message of a failed `POST /images/create` (R2, gt_api_phase2 n=6): the
        pull cannot resolve the registry - the lab has no internet and nothing is stored.
        Ground Truth's own IPv6 is substituted to this install's (R3); the lab resolver
        and the refusal read the same on both machines, and the source UDP port is fresh
        each time (both volatile, `docs/not-gradable.md`)."""
        ref = from_image or ""
        tag = tag or "latest"
        # The name as Docker normalises it. A bare request sends `alpine` (the
        # recording); the docker client sends `docker.io/library/alpine`, and until
        # 2026-10-13 that came back as `docker.io/docker.io/library/alpine`.
        domain, _, rest = ref.partition("/")
        if rest and ("." in domain or ":" in domain or domain == "localhost"):
            path = rest                          # a registry is named
        else:
            domain, path = "docker.io", ref
        if domain in ("docker.io", "index.docker.io"):
            domain, host = "docker.io", "registry-1.docker.io"
            path = path if "/" in path else "library/" + path
        else:
            host = domain                        # another registry: by analogy, not recorded
        port = random.randint(32768, 60999)
        msg = (f'failed to resolve reference "{domain}/{path}:{tag}": failed to do '
               f'request: Head "https://{host}/v2/{path}/manifests/{tag}": '
               f'dial tcp: lookup {host.split(":")[0]} on [{SITE.lab_resolver6}]:53: read '
               f'udp [{SITE.ref_ipv6}]:{port}->[{SITE.lab_resolver6}]:53: read: '
               f'connection refused')
        return self._subs(msg)

    def image_manifests(self, image_id: str) -> list[dict]:
        """An image's manifests, with the containers using it taken from the state."""
        out = copy.deepcopy(self._image_manifests[image_id])
        for m in out:
            m["ImageData"]["Containers"] = sorted(
                c["Id"] for c in self.containers if c["Image"] == image_id)
        return out

    def find_image(self, ref: str) -> dict | None:
        """An image by reference, the way Docker resolves one: `name:tag` (`:latest` if
        no tag), with or without `docker.io/` and `library/`, `name@sha256:…`, or an id
        (`sha256:…` or a prefix of its hex)."""
        ref = ref.strip()
        if not ref:
            return None
        hexid = ref.removeprefix("sha256:")
        if re.fullmatch(r"[0-9a-f]{1,64}", hexid):
            hits = [i for i in self.images
                    if i["Id"].removeprefix("sha256:").startswith(hexid)]
            if len(hits) == 1:
                return hits[0]
        name = re.sub(r"^(docker\.io/)?(library/)?", "", ref)
        if "@" not in name and ":" not in name.rsplit("/", 1)[-1]:
            name += ":latest"
        for i in self.images:
            if name in i["RepoTags"] or name in i["RepoDigests"]:
                return i
        return None

    def image_inspect(self, img: dict, manifests: bool = False) -> dict:
        """`GET /images/<ref>/json` (phase 3 n=6, 9, 12). `Metadata.LastTagTime` is when
        the image was loaded on this machine, so it moves with the install; the image's
        own `Created` is its build time and does not."""
        doc = copy.deepcopy(self._image_inspect[img["Id"]])
        tagged = parse_time(doc["Metadata"]["LastTagTime"]) + self.shift_ns
        doc["Metadata"]["LastTagTime"] = go_time(tagged)
        if manifests:
            doc["Manifests"] = self.image_manifests(img["Id"])
        return doc

    def image_history(self, img: dict) -> list[dict]:
        """`GET /images/<ref>/history` (phase 3 n=8, 11, 14): build history, fixed."""
        return copy.deepcopy(self._image_history[img["Id"]])

    def list_networks(self, filters: dict | None = None) -> list[dict]:
        """`GET /networks`."""
        out = []
        for n in self._networks:
            tests = {"name": lambda v: v in n["Name"],
                     "id": lambda v: n["Id"].startswith(v),
                     "driver": lambda v: n["Driver"] == v,
                     "label": lambda v: _label_match(n["Labels"], v),
                     "scope": lambda v: n["Scope"] == v,
                     "type": lambda v: v == ("builtin" if n["Name"] in
                                             ("bridge", "host", "none") else "custom")}
            for key in filters or {}:
                if key not in tests and key != "dangling":
                    raise BadFilter(f"invalid filter '{key}'")
            if all((all if k == "label" else any)(tests[k](v) for v in vs)
                   for k, vs in (filters or {}).items() if k in tests):
                out.append(copy.deepcopy(n))
        return out

    def find_network(self, ref: str) -> dict | None:
        """A network by name, full id or unique id prefix."""
        for n in self._networks:
            if ref in (n["Name"], n["Id"]):
                return n
        hits = [n for n in self._networks if n["Id"].startswith(ref)] if ref else []
        return hits[0] if len(hits) == 1 else None

    def network_inspect(self, n: dict) -> dict:
        """`GET /networks/<id>` (phase 3 n=16-23): the list entry, then the containers
        attached to it and its address use, both from the state. A bridge network keeps
        three addresses for itself (network, gateway, broadcast); host and none have no
        address pool."""
        doc = copy.deepcopy(n)
        attached = {}
        for c in sorted(self.containers, key=lambda c: c["Id"]):
            ep = c["NetworkSettings"]["Networks"].get(n["Name"])
            if ep and c["State"]["Status"] == "running":
                ip = f"{ep['IPAddress']}/{ep['IPPrefixLen']}"
                attached[c["Id"]] = {"Name": c["Name"].lstrip("/"),
                                     "EndpointID": ep["EndpointID"],
                                     "MacAddress": ep["MacAddress"],
                                     "IPv4Address": ip, "IPv6Address": ""}
        doc["Containers"] = attached
        subnets = {}
        for cfg in doc["IPAM"]["Config"] or []:
            plen = int(cfg["Subnet"].split("/")[1])
            used = 3 + len(attached)
            subnets[cfg["Subnet"]] = {"IPsInUse": used,
                                      "DynamicIPsAvailable": 2 ** (32 - plen) - used}
        doc["Status"] = {"IPAM": {"Subnets": subnets} if subnets else {}}
        return doc

    def events(self, since_ns: int, until_ns: int, filters: dict | None = None) -> list:
        """`GET /events` in a window: nodered's health checks, three events per probe
        (exec_create, exec_start, exec_die with its exit code; phase 3 n=40), at the
        times of the probes `State.Health.Log` shows. Nothing else happens on this
        machine. Attributes are the container's labels plus the exec's, sorted as Go
        sorts a map."""
        for key in filters or {}:
            if key not in ("type", "container", "event", "image", "label", "scope",
                           "daemon", "network", "volume", "plugin", "node", "service",
                           "secret", "config"):
                raise BadFilter(f"invalid filter '{key}'")
        types = (filters or {}).get("type")
        if types and "container" not in types:
            return []
        out = []
        for c in self.containers:
            if "Health" not in c["State"] or c["State"]["Status"] != "running":
                continue
            wanted = (filters or {}).get("container")
            if wanted and not any(w in (c["Id"], c["Name"].lstrip("/")) or
                                  c["Id"].startswith(w) for w in wanted):
                continue
            cmd = " ".join(c["Config"]["Healthcheck"]["Test"][1:])
            for start, end, k in self._probes(c, since_ns, until_ns):
                exec_id = hashlib.sha256(f"{self._seed}-exec-{c['Id']}-{k}".encode()) \
                    .hexdigest()
                base = {**c["Config"]["Labels"], "execID": exec_id,
                        "image": c["Config"]["Image"], "name": c["Name"].lstrip("/")}
                for action, t, extra in ((f"exec_create: /bin/sh -c {cmd}", start, {}),
                                         (f"exec_start: /bin/sh -c {cmd}", start + 39_000,
                                          {}),
                                         ("exec_die", end, {"exitCode": "0"})):
                    if not since_ns <= t <= until_ns:
                        continue
                    attrs = dict(sorted({**base, **extra}.items()))
                    out.append({"Type": "container", "Action": action,
                                "Actor": {"ID": c["Id"], "Attributes": attrs},
                                "scope": "local", "time": t // NS, "timeNano": t})
        events = (filters or {}).get("event")
        if events:
            out = [e for e in out if e["Action"].split(":")[0] in events]
        return sorted(out, key=lambda e: e["timeNano"])

    def _probes(self, c: dict, since_ns: int, until_ns: int):
        """(start, end, k) of nodered's probes overlapping the window; the same schedule
        as `State.Health.Log`."""
        started = parse_time(c["State"]["StartedAt"])
        first = max(1, (since_ns - started) // _PROBE_PERIOD_NS)
        last = (until_ns - started) // _PROBE_PERIOD_NS
        for k in range(first, last + 1):
            start, end = self._probe_times(c, started, k)
            if end >= since_ns and start <= until_ns:
                yield start, end, k

    def list_volumes(self, filters: dict | None = None) -> list[dict]:
        """The `Volumes` of `GET /volumes`."""
        used = {m.get("Name") for c in self.containers for m in c["Mounts"]}
        out = []
        for v in self._volumes:
            tests = {"name": lambda x: x in v["Name"], "driver": lambda x: v["Driver"] == x,
                     "label": lambda x: _label_match(v["Labels"], x),
                     "dangling": lambda x: (v["Name"] not in used) == _truthy(x)}
            for key in filters or {}:
                if key not in tests:
                    raise BadFilter(f"invalid filter '{key}'")
            if all((all if k == "label" else any)(tests[k](x) for x in xs)
                   for k, xs in (filters or {}).items()):
                out.append(copy.deepcopy(v))
        return out

    # -------------------------------------------------------------- daemon views

    def info(self, now: float) -> dict:
        """`GET /info`: the recorded daemon, with this moment's counts and clock."""
        out = copy.deepcopy(self._info)
        states = [c["State"]["Status"] for c in self.containers]
        out["Containers"] = len(states)
        out["ContainersRunning"] = states.count("running")
        out["ContainersPaused"] = states.count("paused")
        out["ContainersStopped"] = len(states) - out["ContainersRunning"] \
            - out["ContainersPaused"]
        out["Images"] = len(self.images)
        wobble = hashlib.sha256(f"{self._seed}-info-{int(now)}".encode()).digest()
        out["NFd"] = 49 + wobble[0] % 5
        out["NGoroutines"] = 68 + wobble[1] % 7
        out["SystemTime"] = go_time(int(now * NS), local=True)
        return out

    def system_df(self, now: float) -> dict:
        """`GET /system/df`, from the same objects as the list views (n=9)."""
        images = self.list_images(shared_size=True)
        containers = [self._summary(d, now, size=True, manifest=False)
                      for d in (self.inspect(c["Id"], now) for c in
                                sorted(self.containers,
                                       key=lambda c: parse_time(c["Created"]),
                                       reverse=True))]
        refs = {}
        for c in self.containers:
            for m in c["Mounts"]:
                if m["Type"] == "volume":
                    refs[m["Name"]] = refs.get(m["Name"], 0) + 1
        volumes = [dict(v, UsageData={"RefCount": refs.get(v["Name"], 0),
                                      "Size": self._df["volume_size"][v["Name"]]})
                   for v in self.list_volumes()]
        layers = self._df["LayersSize"]
        return {
            "LayersSize": layers, "Images": images, "Containers": containers,
            "Volumes": volumes, "BuildCache": [],
            "ImageUsage": {"ActiveCount": sum(i["Containers"] > 0 for i in images),
                           "Items": images, "TotalCount": len(images), "TotalSize": layers},
            "ContainerUsage": {"ActiveCount": sum(c["State"] == "running"
                                                  for c in containers),
                               "Items": containers, "TotalCount": len(containers),
                               "TotalSize": sum(c["SizeRw"] for c in containers)},
            "VolumeUsage": {"ActiveCount": sum(v["UsageData"]["RefCount"] > 0
                                               for v in volumes),
                            "Items": volumes, "TotalCount": len(volumes),
                            "TotalSize": sum(v["UsageData"]["Size"] for v in volumes)},
            "BuildCacheUsage": {},
        }

    # -------------------------------------------------------------- processes

    def processes(self, c: dict, now: float) -> list:
        """The container's processes in the machine's process table: its main process
        and everything under it."""
        table = procs.table(now, self.boot, [], extra=self.container_procs(now))
        mine = {c["State"]["Pid"]}
        grew = True
        while grew:
            more = {p.pid for p in table if p.ppid in mine} - mine
            grew = bool(more)
            mine |= more
        return [p for p in table if p.pid in mine]

    def top(self, c: dict, now: float, ps_args: str = "-ef") -> dict:
        """`GET /containers/<id>/top`: Docker runs `ps` on the host and keeps the
        container's lines, splitting them the way it does (moby's parsePSOutput)."""
        table = procs.table(now, self.boot, [], extra=self.container_procs(now))
        try:
            text, _ = procs.ps(table, ["ps", *ps_args.split()], now, None, None)
        except procs.Unsupported:
            text, _ = procs.ps(table, ["ps", "-ef"], now, None, None)
        lines = text.split("\n")
        titles = lines[0].split()
        pid_col = titles.index("PID")
        pids = {p.pid for p in self.processes(c, now)}
        rows = []
        for line in lines[1:]:
            fields = line.split()
            if fields and fields[pid_col].isdigit() and int(fields[pid_col]) in pids:
                rows.append(fields[:len(titles) - 1] + [" ".join(fields[len(titles) - 1:])])
        return {"Processes": rows, "Titles": titles}

    def stats(self, c: dict, read_ns: int, pre_ns: int | None) -> dict:
        """`GET /containers/<id>/stats`: one sample at read_ns, with the previous one
        at pre_ns (None: the first of a stream, which Docker sends with zeros)."""
        name = _service(c)
        recorded = c["Name"] in self._stats          # one of the three stack containers
        rec = self._stats[c["Name"]] if recorded else _MODELED_STATS

        def cpu(t_ns):
            if t_ns is None:
                return {"cpu_usage": {"total_usage": 0, "usage_in_kernelmode": 0,
                                      "usage_in_usermode": 0},
                        "throttling_data": {"periods": 0, "throttled_periods": 0,
                                            "throttled_time": 0}}
            up = max(t_ns - parse_time(c["State"]["StartedAt"]), 0) / NS
            if recorded:
                burst, rate, per_probe, kernel = _CPU[name]
                total = int((burst + rate * up + per_probe * self._probes_done(c, t_ns))
                            * 1e6) * 1000
            else:                                    # modelled: a near-idle container
                total, kernel = int((0.02 + 2e-5 * up) * 1e6) * 1000, 0.5
            k = int(total * kernel / 1000) * 1000
            system = int(((t_ns / NS - self.boot) * machine.CORES - 8.0) * 100) * 10**7
            return {"cpu_usage": {"total_usage": total, "usage_in_kernelmode": k,
                                  "usage_in_usermode": total - k},
                    "system_cpu_usage": system, "online_cpus": machine.CORES,
                    "throttling_data": {"periods": 0, "throttled_periods": 0,
                                        "throttled_time": 0}}

        link = self._links.get(c["Id"])
        if link:                                     # the container's eth0 is its veth's
            veth = net.link_iface(link, read_ns / NS, self.boot)
            nets = {"eth0": {"rx_bytes": veth.tx[0], "rx_packets": veth.tx[1],
                             "rx_errors": 0, "rx_dropped": 0, "tx_bytes": veth.rx[0],
                             "tx_packets": veth.rx[1], "tx_errors": 0, "tx_dropped": 0}}
        else:                                        # no veth (host network, none)
            nets = {"eth0": {"rx_bytes": 0, "rx_packets": 0, "rx_errors": 0,
                             "rx_dropped": 0, "tx_bytes": 0, "tx_packets": 0,
                             "tx_errors": 0, "tx_dropped": 0}}
        threads = sum(p.nlwp for p in self.processes(c, read_ns / NS))
        return {
            "id": c["Id"], "name": c["Name"], "os_type": "linux",
            "read": go_time(read_ns), "cpu_stats": cpu(read_ns),
            "memory_stats": rec["memory_stats"],
            "networks": nets,
            "pids_stats": {"current": threads, "limit": rec["pids_limit"]},
            "blkio_stats": rec["blkio_stats"], "num_procs": 0, "storage_stats": {},
            "preread": go_time(pre_ns) if pre_ns is not None else "0001-01-01T00:00:00Z",
            "precpu_stats": cpu(pre_ns),
        }

    # -------------------------------------------------------------- logs

    def log_lines(self, c: dict, now_ns: int) -> list[tuple[int, int, str]]:
        """Every line the container has logged up to now_ns, as (Docker's receive time,
        stream: 1 stdout / 2 stderr, text with its newline). Ground Truth's own blocks
        (phase 3), each moved as a whole to this machine's history: the first run's
        startup with the install, then that run's periodic lines until the shutdown
        before this boot, the shutdown, this boot's startup, and periodic lines since."""
        rec = self._logs.get(c["Name"])
        if rec is None:
            # A container created here. Its log is what its command printed: the model's
            # answer, asked for once, when the log is first read after the start, and
            # kept from then on (a log does not change when it is read again).
            started = self._started.get(c["Id"]) or c["State"].get("Status") == "exited"
            if not started:
                return []
            if c["Id"] not in self._program_logs:
                argv = [x for x in (c.get("Path"), *(c.get("Args") or [])) if x]
                if self.program_output is None or not argv:
                    return []
                text, _ = self.program_output(c, argv, bool((c.get("Config") or {}).get("Tty")), "run")
                self.record_program_log(c, text, now_ns)
            return [x for x in self._program_logs[c["Id"]] if x[0] <= now_ns]
        name = _service(c)
        stop_at = parse_time(c["State"]["FinishedAt"])
        start_at = parse_time(c["State"]["StartedAt"])
        out = []
        first = self._move(rec["first"], self.shift_ns, f"{name}-first")
        stop = self._move(rec["stop"], stop_at - rec["stop_anchor"], f"{name}-stop")
        boot = self._move(rec["restart"], start_at - rec["restart_anchor"], f"{name}-boot")
        run_end = stop[0][0] if stop else stop_at
        out += first + self._periodic(name, first, run_end, f"{name}-first")
        out += stop + boot + self._periodic(name, boot, now_ns, f"{name}-boot")
        return [x for x in out if x[0] <= now_ns]

    def _move(self, block: list, delta: int, salt: str) -> list[tuple[int, int, str]]:
        """Ground Truth's lines shifted by delta ns as one block: Docker's receive times,
        the times the services print themselves, and influxd's log ids (a snowflake of
        its start time, so a new start has a new one)."""
        ids = {}
        for t, stream, text in block:
            m = re.search(r'ts=(\S+)Z lvl=info msg="Welcome to InfluxDB" '
                          r'log_id=(\S+)', text)
            if m:                      # the id is minted as influxd starts: its own clock
                printed = parse_time(m.group(1) + "Z") + delta
                ids[m.group(2)] = _snowflake(printed // 1_000_000)
        out = []
        for t, stream, text in block:
            new = t + delta
            text = _retime(text, new, delta)
            for old_id, new_id in ids.items():
                text = text.replace(f"log_id={old_id}", f"log_id={new_id}")
            out.append((new, stream, text))
        return out

    def _periodic(self, name: str, block: list, end: int, salt: str) -> list:
        """What a running service adds after its startup block, until end: mosquitto
        saves its database every 1801 s; influxd checks retention every 30 minutes from
        the moment its retention service starts. nodered prints nothing."""
        out = []
        if name == "mosquitto":
            running = next(x for x in block if x[2].endswith("running\n"))
            sec = int(running[2].split(":")[0])
            k = 1
            while (sec + 1801 * k) * NS < end:
                t = (sec + 1801 * k) * NS + int(self._frac(f"{salt}-{k}") * 0.9 * NS)
                out.append((t, 1, f"{sec + 1801 * k}: Saving in-memory database to "
                                  f"/mosquitto/data//mosquitto.db.\n"))
                k += 1
        elif name == "influxdb":
            anchor = [x for x in block if "Starting retention policy" in x[2]][-1]
            log_id = re.search(r"log_id=(\S+)", anchor[2]).group(1)
            k = 1
            while True:
                t = anchor[0] + 1800 * k * NS + 1_500_000 \
                    + int(self._frac(f"{salt}-{k}") * 1_000_000)
                if t >= end:
                    break
                out += self._retention(t, log_id, f"{salt}-{k}")
                k += 1
        return out

    def _retention(self, t: int, log_id: str, salt: str) -> list[tuple[int, int, str]]:
        """InfluxDB's half-hourly retention check: four lines (phase 1 n=24)."""
        steps = [0, 37_000, 70_000, 105_000]
        prune = f"{0.025 + self._frac(salt + 'p') * 0.01:.3f}ms"
        took = f"{0.12 + self._frac(salt + 'e') * 1.1:.3f}ms"
        base = f"log_id={log_id} service=retention op_name=retention_delete_check"
        msgs = [f'msg="Retention policy deletion check (start)" {base} op_event=start',
                f'msg="Pruning shard groups after retention check (start)" {base} '
                f'op_name=retention_prune_shard_groups op_event=start',
                f'msg="Pruning shard groups after retention check (end)" {base} '
                f'op_name=retention_prune_shard_groups op_event=end op_elapsed={prune}',
                f'msg="Retention policy deletion check (end)" {base} op_event=end '
                f'op_elapsed={took}']
        out = []
        for step, msg in zip(steps, msgs):
            at = t + step
            out.append((at + 60_000, 1, f"ts={_influx_ts(at)} lvl=info {msg}\n"))
        return out


_SNOWFLAKE_DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
_SNOWFLAKE_EPOCH_MS = 1491696000000          # influxdb's pkg/snowflake: 2017-04-09


def _snowflake(ms: int) -> str:
    """influxd's log_id: a snowflake id of its start time, machine 0, sequence 0, in its
    own base 64 (Ground Truth's 15beECsl000 decodes to 2026-09-29T00:35:04.543Z)."""
    n = (ms - _SNOWFLAKE_EPOCH_MS) << 22
    out = ""
    for _ in range(11):
        out = _SNOWFLAKE_DIGITS[n & 0x3F] + out
        n >>= 6
    return out


def _influx_ts(ns: int) -> str:
    return dt.datetime.fromtimestamp(ns // NS, dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S") + f".{ns % NS // 1000:06d}Z"


_TIMES = [
    # influxd: ts=2026-09-29T00:35:04.549190Z (exact, moved by delta)
    (re.compile(r"ts=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6})Z"),
     lambda m, new, delta: "ts=" + _influx_ts(
         int(dt.datetime.fromisoformat(m.group(1) + "+00:00").timestamp()) * NS
         + int(m.group(1)[-6:]) * 1000 + delta)),
    # influxdb's entrypoint: 2026-09-27T22:04:27.<tab> (seconds, UTC)
    (re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.(?=\t)"),
     lambda m, new, delta: dt.datetime.fromtimestamp(
         (new - 100_000) // NS, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")),
    # mosquitto: 1790642102: (Unix seconds)
    (re.compile(r"^\d{10}(?=: )"), lambda m, new, delta: str((new - 100_000) // NS)),
    # Node-RED: 28 Sep 20:35:06 - (local time, the container's TZ)
    (re.compile(r"^\d\d [A-Z][a-z]{2} \d\d:\d\d:\d\d(?= - )"),
     lambda m, new, delta: dt.datetime.fromtimestamp(
         (new - 100_000) // NS, machine.TZ).strftime("%d %b %H:%M:%S")),
]


def _retime(text: str, new: int, delta: int) -> str:
    """The time a service printed in its own line, moved with the line. Second-precision
    stamps follow Docker's receive time (they are printed a few µs before it)."""
    for pattern, fn in _TIMES:
        text = pattern.sub(lambda m: fn(m, new, delta), text)
    return text


def _insert_after(d: dict, after: str, key: str, value) -> dict:
    out = {}
    for k, v in d.items():
        out[k] = v
        if k == after:
            out[key] = value
    return out


def _bridge_mac(ip: str) -> str:
    """The MAC Docker gives a bridge endpoint: 02:42 then the four bytes of its IPv4
    (172.17.0.2 -> 02:42:ac:11:00:02)."""
    return "02:42:" + ":".join(f"{int(o):02x}" for o in ip.split("."))


def _ref_with_tag(ref: str) -> str:
    """How Docker names an unresolved image in a `No such image` message: `:latest` is
    filled in unless the reference already has a tag, a digest or is a bare id."""
    if ":" not in ref.rsplit("/", 1)[-1] and "@" not in ref \
            and not re.fullmatch(r"(sha256:)?[0-9a-f]+", ref):
        return ref + ":latest"
    return ref


def _truthy(v: str) -> bool:
    """Docker's boolValue: anything but these is true."""
    return v.strip().lower() not in ("", "0", "no", "false", "none")


def _label_match(labels: dict, v: str) -> bool:
    key, eq, val = v.partition("=")
    return key in labels and (not eq or labels[key] == val)


def _image_match(img: dict, filters: dict) -> bool:
    for key, values in filters.items():
        if key == "dangling":
            if any(_truthy(v) for v in values):
                return False                     # every image here is tagged
        elif key == "label":
            if not any(_label_match(img["Labels"], v) for v in values):
                return False
        elif key == "reference":
            refs = img["RepoTags"] + [t.split(":")[0] for t in img["RepoTags"]]
            if not any(fnmatch.fnmatchcase(r, v) for r in refs for v in values):
                return False
        elif key not in ("before", "since", "until"):
            raise BadFilter(f"invalid filter '{key}'")
    return True
