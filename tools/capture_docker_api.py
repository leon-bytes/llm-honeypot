#!/usr/bin/env python3
"""
capture_docker_api.py - record Ground Truth Pi's Docker Engine API responses.

Task B Phase 1: READ-ONLY. Every request in this script's own request list is a
GET; nothing it sends changes the daemon's state or writes to disk. The
state-changing requests attackers actually use (POST /containers/create with a
host bind-mount, start, exec, delete) are Phase 2, a separate approved run in
tools/capture_docker_api_phase2.py - see TASKS.md.

This module also holds the shared request helper `one()`, which Phase 2 imports
so both phases produce the same record shape. `one()` can send request bodies
for Phase 2's POSTs; that does not make Phase 1 anything other than read-only.

WHY OVER A TUNNEL, NOT ON THE PI: the requests must reach the API over the
network the way an attacker's would, and logging in to the Pi to run curl would
leave login records and change the machine's state. So this runs on the dev machine
against a local port forwarded to the Pi's 2375:

    ssh -f -N -L 12375:REF_IP:2375 lab-dev2
    tools/capture_docker_api.py --base http://127.0.0.1:12375 --out gt_api_phase1.json

(REF_IP: the reference machine's address, ref_ipv4 in site.local.json.)

The request list is grounded in observed attacks on exposed 2375 (Datadog,
Trend Micro, Akamai, Uptycs): recon (/_ping, /version, /info), enumeration
(containers, images, networks, volumes, system/df), per-container inspect / logs
/ top / stats, and the error surfaces a client trips (version too old/new,
missing container, bad path, /swarm on a non-swarm node). Per-container paths
are filled in from the live /containers/json, so the script stays correct if
container IDs change.

Each record keeps method, path, status, reason, response headers and body, and
elapsed_ms - the API-side equivalent of ground_truth_43.json. Bodies are kept
losslessly (see `one()`): non-UTF-8 bytes would otherwise destroy the 8-byte
frame headers on /logs, which the honeypot has to reproduce exactly. Volatile
fields (the Date header, /info counters, stats, timestamps) are recorded as-is;
which ones the scorer must not grade is written up in docs/not-gradable.md.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, sys, time, urllib.parse
import http.client
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from honeypot.site import SITE                              # noqa: E402

# A realistic client fingerprint. The Docker CLI sends this shape; attackers'
# tools send curl/Go-http-client. The daemon does not vary its body on either,
# but recording a plausible one keeps the capture honest.
DEFAULT_UA = "Docker-Client/29.8.1 (linux)"

# Response headers that change every call; kept in the record but listed here so
# the report and the scorer know they are not identity.
VOLATILE_HEADERS = {"date"}


def fixed_requests():
    """Requests that do not depend on what is running. (method, path, why)."""
    return [
        ("GET", "/_ping",                    "liveness probe - the first thing a scanner sends"),
        ("GET", "/version",                  "engine + API version; confirms an exposed daemon"),
        ("GET", "/info",                     "host recon: OS, kernel, #containers, driver, memory"),
        ("GET", "/containers/json",          "running containers - the enumeration step"),
        ("GET", "/containers/json?all=1",    "all containers including stopped"),
        ("GET", "/images/json",              "images present locally (what can be started offline)"),
        ("GET", "/networks",                 "networks - reveals the compose bridge and subnet"),
        ("GET", "/volumes",                  "volumes - named + anonymous"),
        ("GET", "/system/df",                "disk usage across images/containers/volumes"),
        ("GET", "/events?since=0&until=1",   "bounded event window (unbounded would hang)"),
        ("GET", "/swarm",                    "swarm state - 503 on a standalone node"),
        ("GET", "/v1.40/version",            "oldest supported API version - succeeds"),
        ("GET", "/v1.12/version",            "too-old API version - 400 with a text body"),
        ("GET", "/v1.99/version",            "too-new API version - 400 with a JSON body"),
        ("GET", "/containers/deadbeef/json", "inspect a container that does not exist - 404"),
        ("GET", "/nosuchpath",               "unknown path - 404 'page not found'"),
    ]


def per_container_requests(cid, name):
    """Requests an attacker runs against each container it found."""
    lg = f"/containers/{cid}/logs?stdout=1&stderr=1&tail=5"
    return [
        ("GET", f"/containers/{cid}/json",              f"inspect {name}: full config, mounts, network, env"),
        ("GET", f"/containers/{cid}/top",               f"processes inside {name}"),
        ("GET", f"/containers/{cid}/stats?stream=false", f"one-shot resource stats for {name}"),
        ("GET", lg,                                      f"last log lines from {name}"),
    ]


def one(base, method, path, ua, timeout, req_body=None, extra_headers=None):
    """Send one request and record the response losslessly.

    WHY body_b64 EXISTS: the first version of this function kept only
    body.decode("utf-8", errors="replace"), which silently destroyed every byte
    that is not valid UTF-8. That is fatal for /containers/*/logs and for the
    exec stream, whose 8-byte frame headers carry a 4-byte big-endian length:
    any frame with a payload of 128 bytes or more has a length byte >= 0x80,
    which is not valid UTF-8 on its own and came back as U+FFFD. The influxdb
    log record in the first Phase 1 capture lost its very first frame length
    that way. The framing is precisely what the honeypot has to reproduce, so
    the raw bytes are now authoritative:

      body      - UTF-8 with replacement, kept because it is readable
      body_b64  - present whenever the raw bytes do not round-trip through
                  UTF-8; this is the copy to trust for framing
      body_sha256 - always, so a re-recording can be compared byte for byte

    req_body/extra_headers let Phase 2 send POST payloads through the same
    helper, so both phases produce the identical record shape. Phase 1's own
    request list stays read-only; the defaults here reproduce its old behaviour.
    """
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    t0 = time.monotonic()
    # Host header names the Pi's API endpoint, as a request arriving on 2375
    # would, not the local forwarded port.
    headers = {"Host": f"{SITE.ref_ipv4}:2375", "User-Agent": ua, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    payload = None
    if req_body is not None:
        payload = json.dumps(req_body).encode()
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=payload, headers=headers)
        r = conn.getresponse()
        body = r.read()
        elapsed = (time.monotonic() - t0) * 1000
        rec = {"status": r.status, "reason": r.reason,
               "headers": [[k, v] for k, v in r.getheaders()],
               "body": body.decode("utf-8", errors="replace"),
               "body_sha256": hashlib.sha256(body).hexdigest(),
               "elapsed_ms": round(elapsed, 1)}
        if rec["body"].encode("utf-8") != body:      # lossy, so keep the bytes
            rec["body_b64"] = base64.b64encode(body).decode("ascii")
        if payload is not None:
            rec["request_body"] = req_body
        return rec
    except Exception as e:
        return {"status": -1, "reason": f"{type(e).__name__}: {e}",
                "headers": [], "body": "", "body_sha256": "",
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1)}
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="e.g. http://127.0.0.1:12375 (the tunnel)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--user-agent", default=DEFAULT_UA)
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    results, n = [], 0

    def record(method, path, why):
        nonlocal n
        n += 1
        rec = {"n": n, "method": method, "path": path, "why": why}
        rec.update(one(args.base, method, path, args.user_agent, args.timeout))
        results.append(rec)
        vol = " [volatile]" if any(h[0].lower() in VOLATILE_HEADERS for h in rec["headers"]) else ""
        print(f"  [{n:2d}] {method:4s} {path:44.44s} -> {rec['status']} {rec['reason'][:24]:24s}"
              f" {len(rec['body']):6d}B {rec['elapsed_ms']:6.0f}ms{vol}")
        return rec

    # Reachability first: if /_ping is not 200 the tunnel or the daemon is down,
    # and there is no point recording 50 connection errors.
    print(f"[api] {args.base} -> Ground Truth 2375 (read-only)")
    ping = record("GET", "/_ping", "liveness probe - the first thing a scanner sends")
    if ping["status"] != 200:
        sys.exit(f"[api] /_ping returned {ping['status']} {ping['reason']} - "
                 f"tunnel or daemon not reachable; nothing else recorded")

    for method, path, why in fixed_requests()[1:]:   # _ping already done
        record(method, path, why)

    # Discover the live containers and inspect each, so the record matches
    # whatever is actually running.
    live = next((r for r in results if r["path"] == "/containers/json"), None)
    containers = []
    try:
        containers = json.loads(live["body"]) if live else []
    except Exception as e:
        print(f"  [warn] could not parse /containers/json: {e}", file=sys.stderr)
    print(f"[api] {len(containers)} running container(s); inspecting each")
    for c in containers:
        cid = c.get("Id", "")[:12]
        name = (c.get("Names") or ["?"])[0].lstrip("/")
        for method, path, why in per_container_requests(cid, name):
            record(method, path, why)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[api] wrote {args.out} ({len(results)} requests)")


if __name__ == "__main__":
    main()
