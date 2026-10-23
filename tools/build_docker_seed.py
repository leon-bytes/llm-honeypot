#!/usr/bin/env python3
"""Build honeypot/docker_seed.json: the simulated machine's Docker objects at rest.

Source: RECORDED API ANSWERS. Ground Truth's Docker API as read over the network on
2026-09-28, after the 20:34:32 reboot (gt_api_phase1_2026-09.json): the three
containers' inspect documents (n=17, 21, 25), the image list (n=6), the network list
(n=7), the volume list (n=8), plus the daemon's /version (n=2) and /info (n=3), the
disk sizes from /system/df (n=9) and the per-container numbers of /stats that do not
move (n=19, 23, 27: block I/O, the PID limit, the all-zero memory block). Kept
verbatim, with Ground Truth's IDs and times: honeypot/docker.py passes them through
the relay's substitution map (this install's own IDs, identity.py, R3), shifts the
install-time timestamps, fills in the live fields at answer time and derives every
other view from these.

Also from the read-only phase 3 capture (gt_api_phase3_2026-10.json, 2026-10-04),
everything that does not depend on the boot it was taken in (a later one, 23:43 on
2026-09-28): each image's `Manifests` (n=3), inspect (n=6, 9, 12) and history (n=8,
11, 14), and three blocks of each container's full log (n=27, 30, 33): its first run's
startup at the install, and the stop and restart around the 20:34 boot that phases 1
and 2 describe. honeypot/docker.py moves each block to this machine's own times. Phase
3's network and container bodies are not used: their IDs, MACs and IPs are that later
boot's, and the network view is derived from the state instead.

The phase 2 recording is not used: it was taken before the reboot, so its per-boot
values belong to a boot this machine never had.

Run: python3 tools/build_docker_seed.py
"""
import base64
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
API = {e["n"]: e for e in json.load(open(ROOT / "gt_api_phase1_2026-09.json"))}
P3 = {e["n"]: e for e in json.load(open(ROOT / "gt_api_phase3_2026-10.json"))}
NS = 10**9


def body(n, src=API):
    e = src[n]
    assert e["status"] == 200, (n, e["status"])
    return json.loads(e["body"])


def rfc3339_ns(s):
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z$", s)
    import datetime as dt
    whole = dt.datetime.fromisoformat(m.group(1) + "+00:00")
    return int(whole.timestamp()) * NS + int((m.group(2) or "").ljust(9, "0"))


def log_lines(n):
    """A timestamped log body (logs?timestamps=1) -> [[receive ns, stream, text]]."""
    e = P3[n]
    raw = base64.b64decode(e["body_b64"]) if e.get("body_b64") else e["body"].encode()
    out, i = [], 0
    while i < len(raw):
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        stamp, text = raw[i + 8:i + 8 + size].decode().split(" ", 1)
        out.append([rfc3339_ns(stamp), raw[i], text])
        i += 8 + size
    return out


PERIODIC = re.compile(r"Saving in-memory database|deletion check"
                      r"|shard groups after retention")


containers = [body(n) for n in (17, 21, 25)]
assert [c["Name"] for c in containers] == [
    "/iot-stack-nodered-1", "/iot-stack-influxdb-1", "/iot-stack-mosquitto-1"]
volumes = body(8)
assert volumes["Warnings"] is None
df = body(9)
stats = {}
for n in (19, 23, 27):
    st = body(n)
    stats[st["name"]] = {"memory_stats": st["memory_stats"],
                         "pids_limit": st["pids_stats"]["limit"],
                         "blkio_stats": st["blkio_stats"]}
seed = {
    "source": "gt_api_phase1_2026-09.json n=2, 3, 6, 7, 8, 9, 17, 19, 21, 23, 25, 27 "
              "(recorded 2026-09-28)",
    "containers": containers,
    "images": body(6),
    "networks": body(7),
    "volumes": volumes["Volumes"],
    "version": body(2),
    "info": body(3),
    # Sizes keyed by name (image id for images), so the derived /system/df can add them.
    "df": {"LayersSize": df["LayersSize"],
           "image_shared": {i["Id"]: i["SharedSize"] for i in df["Images"]},
           "container_size": {c["Names"][0]: [c["SizeRw"], c["SizeRootFs"]]
                              for c in df["Containers"]},
           "volume_size": {v["Name"]: v["UsageData"]["Size"] for v in df["Volumes"]}},
    "stats": stats,
}

# Phase 3: the images' other views.
manifests = {i["Id"]: i["Manifests"] for i in body(3, P3)}
for m in (m for ms in manifests.values() for m in ms):
    m["ImageData"]["Containers"] = []            # derived from the state at answer time
seed["image_manifests"] = manifests
seed["image_inspect"] = {d["Id"]: d for d in (body(n, P3) for n in (6, 9, 12))}
seed["image_history"] = {body(n - 2, P3)["Id"]: body(n, P3) for n in (8, 11, 14)}

# Phase 3: three blocks of each container's log, with the moment each is anchored to.
# first   - the first run's startup: moves with the install (the containers' Created)
# stop    - the shutdown before the 20:34 boot: moves to this machine's FinishedAt
# restart - the startup at that boot: moves to this machine's StartedAt
logs = {}
for n, c in ((27, containers[0]), (30, containers[1]), (33, containers[2])):
    lines = log_lines(n)
    first_t = lines[0][0]
    started = rfc3339_ns(c["State"]["StartedAt"])
    finished = rfc3339_ns(c["State"]["FinishedAt"])
    logs[c["Name"]] = {
        "first": [x for x in lines
                  if x[0] < first_t + 60 * NS and not PERIODIC.search(x[2])],
        "stop": [x for x in lines if finished - 2 * NS <= x[0] <= finished + NS // 2],
        "stop_anchor": finished,
        "restart": [x for x in lines if started <= x[0] < started + 60 * NS
                    and not PERIODIC.search(x[2])],
        "restart_anchor": started,
    }
seed["logs"] = logs
out = ROOT / "honeypot" / "docker_seed.json"
# The served credentials are site values (honeypot/site.py): written as their @@key@@.
sys.path.insert(0, str(ROOT))
from honeypot.site import SITE                     # noqa: E402
out.write_text(SITE.tokens(json.dumps(seed, indent=1, ensure_ascii=False) + "\n",
                           ["influx_user", "influx_password", "influx_token"]))
print(f"wrote {out.relative_to(ROOT)}: {len(containers)} containers, "
      f"{len(seed['images'])} images, {len(seed['networks'])} networks, "
      f"{len(seed['volumes'])} volumes")
