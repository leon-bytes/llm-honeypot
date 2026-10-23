#!/usr/bin/env python3
"""
capture_docker_api_phase3.py - the gap-filling, READ-ONLY Docker API capture.

Building the fake API (honeypot/dockerapi.py, step 2) found requests that real clients
send but phases 1 and 2 never recorded. This records them from Ground Truth, over the
same `ssh -L` tunnel and with the same lossless helper `one()` as phase 1:

1. `GET /images/json?manifests=1` - what `docker images` sends. Its per-image
   `Manifests` carry the CONTENT SIZE column, which the honeypot shows as 0B.
2. Image inspect (`/images/<ref>/json`, `docker inspect <image>`) and history, and
   network inspect (`/networks/<id>`, `docker network inspect`) - no recording at all.
3. Each container's full log (no `tail`), plain and with timestamps - only `tail=5`
   was recorded, so each service's startup banner is missing.
4. The daemon's recent events (`/events` over the last 10 minutes, bounded) - what
   nodered's health checks report every 30 s.

Plus a few cheap checks of guesses made in step 2: `HEAD /_ping` (the Docker CLI's
first request), `?size=1`, volume inspect, `/plugins`, and an older API version's
answers.

READ-ONLY, AND ONLY REQUESTS THAT SUCCEED. Every request is GET or HEAD (checked
before anything is sent), and each names something that exists, so the daemon
answers 200. That matters: dockerd writes a "Handler for ... returned error" line to
its journal for every error answer (docs/taskB-api.md, phase 1 correction), and a
successful GET leaves no trace. Run it through scripts/gt_capture_api_phase3.sh.
"""
from __future__ import annotations
import argparse
import json
import sys
import time
import urllib.parse

from capture_docker_api import DEFAULT_UA, one

SAFE_METHODS = {"GET", "HEAD"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. http://127.0.0.1:12375 (the tunnel)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--user-agent", default=DEFAULT_UA)
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()
    results = []

    def record(method, path, why):
        if method not in SAFE_METHODS:                  # never, whatever the list says
            sys.exit(f"[phase3] refusing {method} {path}: this capture is read-only")
        rec = {"n": len(results) + 1, "method": method, "path": path, "why": why}
        rec.update(one(args.base, method, path, args.user_agent, args.timeout))
        results.append(rec)
        print(f"  [{rec['n']:2d}] {method:4s} {path[:60]:60s} -> {rec['status']} "
              f"{len(rec['body']):7d}B {rec['elapsed_ms']:6.0f}ms")
        return rec

    def body(rec):
        return json.loads(rec["body"]) if rec["status"] == 200 else []

    print(f"[phase3] {args.base} -> Ground Truth 2375 (read-only, GET/HEAD only)")
    if record("GET", "/_ping", "liveness")["status"] != 200:
        sys.exit("[phase3] /_ping failed - tunnel or daemon not reachable; stopping")
    record("HEAD", "/_ping", "the Docker CLI's first request (header order of a HEAD)")

    # 1. what `docker images` sends (the 0B CONTENT SIZE)
    images = body(record("GET", "/images/json?manifests=1",
                         "docker images: per-image Manifests (content size)"))
    record("GET", "/images/json?all=1&manifests=1", "docker images -a")
    record("GET", "/images/json?shared-size=1", "shared sizes as docker system df -v asks")

    # 2. image and network inspect
    for img in images:
        ref = (img.get("RepoTags") or [img["Id"]])[0]      # unencoded, as the CLI sends it
        record("GET", f"/images/{ref}/json", f"docker image inspect {ref}")
        record("GET", f"/images/{ref}/json?manifests=1", "image inspect with manifests")
        record("GET", f"/images/{ref}/history", f"docker history {ref}")
    for net in body(record("GET", "/networks", "network list, for the ids")):
        record("GET", f"/networks/{net['Id']}", f"docker network inspect {net['Name']}")
        record("GET", f"/networks/{net['Id']}?verbose=true",
               f"network inspect verbose {net['Name']}")

    # 3. full container logs, and inspect with sizes
    containers = body(record("GET", "/containers/json?all=1&size=1", "docker ps -as"))
    for c in containers:
        cid, name = c["Id"], c["Names"][0].lstrip("/")
        record("GET", f"/containers/{cid}/json?size=1", f"docker inspect -s {name}")
        record("GET", f"/containers/{cid}/logs?stdout=1&stderr=1",
               f"docker logs {name}: the whole log")
        record("GET", f"/containers/{cid}/logs?stdout=1&stderr=1&timestamps=1",
               f"docker logs -t {name}")
    volumes = body(record("GET", "/volumes", "volume list, for the names"))
    for vol in (volumes or {}).get("Volumes") or []:
        record("GET", f"/volumes/{vol['Name']}", f"docker volume inspect {vol['Name']}")

    # 4. recent events, in a bounded window so the request returns
    now = int(time.time())
    record("GET", f"/events?since={now - 600}&until={now}",
           "events of the last 10 minutes: the health checks")
    record("GET", f"/events?since={now - 600}&until={now}&filters="
           + urllib.parse.quote(json.dumps({"type": {"container": True}})),
           "the same, filtered as docker stats asks")

    # older clients: does the daemon trim answers for an old API version?
    for path in ("/containers/json", "/images/json", "/info", "/version", "/system/df"):
        record("GET", f"/v1.41{path}", f"{path} as an API 1.41 client sees it")
    record("GET", "/plugins", "plugin list")

    bad = [r for r in results if r["status"] != 200]
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[phase3] wrote {args.out} ({len(results)} requests, "
          f"{len(bad)} not 200{': ' + ', '.join(str(r['n']) for r in bad) if bad else ''})")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
