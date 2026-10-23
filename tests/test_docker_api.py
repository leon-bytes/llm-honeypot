#!/usr/bin/env python3
"""Host-free tests for the fake Docker API (honeypot/dockerapi.py).

Every one of the 28 read-only requests recorded on Ground Truth (phase 1) is sent over
real HTTP to the listener, with the clock set to the moment of the recording, and the
answer is compared with the recording: status, the header names in order (Date aside),
and the body, byte for byte wherever the body does not depend on the boot.
Run: python3 tests/test_docker_api.py
"""
import base64
import email.utils
import http.client
import json
import pathlib
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from honeypot import identity, net, procs                   # noqa: E402
from honeypot.docker import DockerState, parse_time         # noqa: E402
from honeypot.dockerapi import DockerAPI, serve             # noqa: E402
from honeypot.knowledge import Substitutions                # noqa: E402

from tests import recordings                                # noqa: E402

API = recordings.lazy(lambda: {e["n"]: e for e in recordings.load("gt_api_phase1_2026-09.json")})
P2 = recordings.lazy(lambda: {e["n"]: e for e in recordings.load("gt_api_phase2_2026-09.json")})
P3 = recordings.lazy(lambda: {e["n"]: e for e in recordings.load("gt_api_phase3_2026-10.json")})
GT_BOOT = 1790642072.0

# Bodies that hold no per-boot value: byte for byte. The rest are compared below.
EXACT = {1, 2, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28}


def recorded_body(e) -> bytes:
    return base64.b64decode(e["body_b64"]) if e.get("body_b64") else e["body"].encode()


def p2_body(e) -> bytes:
    """A Phase 2 body: its `body` holds raw bytes as latin-1 when there is no body_b64."""
    return base64.b64decode(e["body_b64"]) if e.get("body_b64") else \
        e["body"].encode("latin-1")


def recorded_at(e) -> float:
    return email.utils.parsedate_to_datetime(dict(e["headers"])["Date"]).timestamp()


def frames(body: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(body):
        n = int.from_bytes(body[i + 4:i + 8], "big")
        out.append((body[i], body[i + 8:i + 8 + n]))
        i += 8 + n
    assert i == len(body), "frames do not tile the body"
    return out


class Clock:
    """A clock the test sets; sleeping moves it on instead of waiting."""

    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class ApiCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clock = Clock(GT_BOOT + 600)
        cls.state = DockerState(GT_BOOT, "test-secret")
        cls.log = []
        cls.srv = serve(DockerAPI(cls.state, cls.clock, cls.clock.sleep), "127.0.0.1", 0,
                        cls.log.append)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, path, method="GET"):
        path = urllib.parse.quote(path, safe="/?&=:")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path)
        r = conn.getresponse()
        body = r.read()
        conn.close()
        return r.status, r.getheaders(), body

    def raw(self, data: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            out = b""
            while chunk := s.recv(65536):
                out += chunk
        return out

    # ---------------------------------------------------------------- the recordings

    def test_every_recorded_request(self):
        for n, e in API.items():
            with self.subTest(n=n, path=e["path"]):
                self.clock.t = recorded_at(e)
                status, headers, body = self.get(e["path"], e["method"])
                self.assertEqual(status, e["status"])
                self.assertEqual([k for k, v in headers], [k for k, v in e["headers"]])
                for (k, v), (rk, rv) in zip(headers, e["headers"]):
                    if k not in ("Date", "Content-Length"):
                        self.assertEqual(v, rv, k)
                want = recorded_body(e)
                if n in EXACT:
                    self.assertEqual(body, want)
                elif e["path"].endswith("/json") or e["path"] in ("/info", "/networks"):
                    self.assertEqual(self._without_live(json.loads(body)),
                                     self._without_live(json.loads(want)))
                elif "/top" in e["path"]:
                    got, rec = json.loads(body), json.loads(want)
                    self.assertEqual(got["Titles"], rec["Titles"])
                    self.assertEqual([p[:3] + p[4:6] + p[7:] for p in got["Processes"]],
                                     [p[:3] + p[4:6] + p[7:] for p in rec["Processes"]])
                elif "/stats" in e["path"]:
                    got, rec = json.loads(body), json.loads(want)
                    self.assertEqual(list(got), list(rec))
                    for k in ("id", "name", "os_type", "memory_stats", "pids_stats",
                              "blkio_stats", "num_procs", "storage_stats"):
                        self.assertEqual(got[k], rec[k], k)
                    gap = got["cpu_stats"]["system_cpu_usage"] \
                        - got["precpu_stats"]["system_cpu_usage"]
                    self.assertAlmostEqual(gap / 1e9, 4.0, delta=0.05)
                elif "/logs" in e["path"]:          # influxdb: ids and µs are its own
                    def shape(b):
                        return [(s, p.split(b" lvl=")[1].split(b" log_id=")[0])
                                for s, p in frames(b)]
                    self.assertEqual(shape(body), shape(want))
                else:
                    self.fail(f"n={n} not compared")

    @staticmethod
    def _without_live(doc):
        if isinstance(doc, list):                 # /networks: the bridge is per boot
            return [dict(n, Created=None) if n["Name"] == "bridge" else n for n in doc]
        doc = dict(doc)
        for k in ("NFd", "NGoroutines", "SystemTime"):
            doc.pop(k, None)
        if "State" in doc:
            doc["State"] = {k: v for k, v in doc["State"].items()
                            if k not in ("StartedAt", "FinishedAt")}
            if "Health" in doc["State"]:
                doc["State"]["Health"] = dict(doc["State"]["Health"], Log=None)
        return doc

    def test_stats_waits_for_two_samples(self):
        """One-shot stats take 1-2 s on the real daemon (n=19: 1005 ms, n=23: 1984 ms)."""
        self.clock.t = GT_BOOT + 5000.3
        t0 = self.clock.t
        self.get("/containers/iot-stack-mosquitto-1/stats?stream=false")
        self.assertTrue(1.0 <= self.clock.t - t0 <= 2.0)

    # ---------------------------------------------------------------- beyond them

    def test_head_ping(self):
        status, headers, body = self.get("/_ping", "HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(dict(headers)["Content-Length"], "0")
        self.assertEqual([k for k, v in headers][-1], "Date")

    def test_unknown_routes_and_methods(self):
        """Docker's notFoundHandler for anything without a route, including the
        state-changing ones not built yet (start/exec/stop/wait/delete)."""
        for method, path in (("GET", "/v1.56/nosuch"), ("DELETE", "/version"),
                             ("POST", "/containers/abc/pause"), ("GET", "/containers/json/")):
            status, headers, body = self.get(path, method)
            self.assertEqual((status, body), (404, b'{"message":"page not found"}\n'), path)
            self.assertEqual([k for k, v in headers], ["Content-Type", "Date",
                                                       "Content-Length"])

    def test_versions(self):
        for path, status in (("/v1.40/containers/json", 200), ("/v1.56/info", 200),
                             ("/v1.39/version", 400), ("/v1.57/version", 400)):
            self.assertEqual(self.get(path)[0], status, path)

    def test_bad_request_line(self):
        """What Go answers to a request it cannot parse, then hangs up."""
        out = self.raw(b"GARBAGE\r\n\r\n")
        self.assertEqual(out, b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; "
                              b"charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request")

    def test_chunked_and_keep_alive(self):
        """Long bodies are chunked; the connection stays open for the next request."""
        out = self.raw(b"GET /containers/json HTTP/1.1\r\nHost: x\r\n\r\n"
                       b"GET /_ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        first, rest = out.split(b"\r\n0\r\n\r\n", 1)
        self.assertIn(b"Transfer-Encoding: chunked\r\n", first)
        self.assertTrue(rest.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertTrue(rest.endswith(b"\r\n\r\nOK"))

    def test_filters(self):
        self.clock.t = GT_BOOT + 600
        q = "/containers/json?filters=" + json.dumps(
            {"label": ["com.docker.compose.project=iot-stack"]})
        self.assertEqual(len(json.loads(self.get(q)[2])), 3)
        q = "/containers/json?filters=" + json.dumps({"status": {"exited": True}})
        self.assertEqual(json.loads(self.get(q)[2]), [])
        q = "/containers/json?filters=" + json.dumps({"name": ["nodered"]})
        self.assertEqual([c["Names"] for c in json.loads(self.get(q)[2])],
                         [["/iot-stack-nodered-1"]])
        q = "/containers/json?filters=" + json.dumps({"bogus": ["x"]})
        status, _, body = self.get(q)
        self.assertEqual((status, body), (400, b'{"message":"invalid filter \'bogus\'"}\n'))
        q = "/images/json?filters=" + json.dumps({"reference": ["influxdb"]})
        self.assertEqual([i["RepoTags"] for i in json.loads(self.get(q)[2])],
                         [["influxdb:2.7-alpine"]])

    def test_logs_parameters(self):
        self.clock.t = GT_BOOT + 5000
        status, headers, body = self.get(
            "/containers/iot-stack-mosquitto-1/logs?stdout=1&tail=2&timestamps=1")
        lines = [p for s, p in frames(body)]
        self.assertEqual(len(lines), 2)
        stamp = lines[0].split(b" ")[0].decode()
        self.assertRegex(stamp, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z$")
        self.assertEqual(self.get("/containers/iot-stack-mosquitto-1/logs")[:3:2],
                         (400, b'{"message":"Bad parameters: you must choose at least one '
                               b'stream"}\n'))
        errs = frames(self.get("/containers/iot-stack-mosquitto-1/logs?stderr=1")[2])
        self.assertEqual({s for s, p in errs}, {2})          # mosquitto's "Info: running"
        self.assertTrue(all(b"Info: running" in p or b"Restored" in p for s, p in errs))
        since = GT_BOOT + 3000
        body = self.get(f"/containers/iot-stack-mosquitto-1/logs?stdout=1&since={since}")[2]
        self.assertEqual([p.split(b":")[0] for s, p in frames(body)], [b"1790645704"])

    def test_logs_follow_and_events_end(self):
        """Live streams end when their window does (R9); follow sends new lines."""
        self.clock.t = GT_BOOT + 1800
        until = GT_BOOT + 1840
        body = self.get(f"/containers/iot-stack-mosquitto-1/logs?stdout=1&follow=1"
                        f"&tail=0&until={until}")[2]
        self.assertEqual([p.split(b":")[0] for s, p in frames(body)], [b"1790643903"])
        self.clock.t = GT_BOOT + 600
        status, headers, body = self.get(f"/events?until={GT_BOOT + 640}")
        self.assertEqual(status, 200)
        self.assertEqual(dict(headers)["Content-Type"], "application/jsonl")
        actions = [json.loads(x)["Action"].split(":")[0] for x in body.splitlines()]
        self.assertIn(len(actions), (3, 6))                   # a probe every ~30.1 s
        self.assertEqual(actions, ["exec_create", "exec_start", "exec_die"] *
                         (len(actions) // 3))

    def test_volume_inspect(self):
        status, _, body = self.get("/volumes/iot-stack_influxdb-data")
        self.assertEqual(json.loads(body), next(
            v for v in json.loads(recorded_body(API[8]))["Volumes"]
            if v["Name"] == "iot-stack_influxdb-data"))
        self.assertEqual(self.get("/volumes/nope")[:3:2],
                         (404, b'{"message":"get nope: no such volume"}\n'))

    def test_requests_are_logged(self):
        self.get("/version")
        # the listener logs just after the answer has gone out: give it a moment
        for _ in range(100):
            if self.log and self.log[-1]["path"] == "/version":
                break
            time.sleep(0.01)
        entry = self.log[-1]
        self.assertEqual((entry["event"], entry["method"], entry["path"], entry["status"]),
                         ("docker_api", "GET", "/version", 200))


class Phase3Case(ApiCase):
    """The gaps step 2 left, filled from the read-only phase 3 capture (2026-10-04). It
    was taken on a later boot of Ground Truth (23:43 on 2026-09-28), so per-boot values
    (the default bridge, endpoints, MACs, container IPs) are compared by shape only."""

    def p3(self, n, path=None):
        e = P3[n]
        self.clock.t = recorded_at(e)
        status, headers, body = self.get(path or e["path"], e["method"])
        self.assertEqual(status, e["status"], e["path"])
        self.assertEqual([k for k, v in headers], [k for k, v in e["headers"]], e["path"])
        return body, recorded_body(e)

    def test_images_with_manifests(self):
        """`docker images`' request, with the content sizes it shows (gap 1)."""
        for n in (3, 4, 5):
            got, want = self.p3(n)
            self.assertEqual(got, want, P3[n]["path"])

    def test_image_inspect_and_history(self):
        for n in range(6, 15):
            got, want = self.p3(n)
            self.assertEqual(got, want, P3[n]["path"])
        status, _, body = self.get("/images/alpine/json")
        self.assertEqual((status, body),
                         (404, b'{"message":"No such image: alpine:latest"}\n'))
        for ref in ("influxdb:2.7-alpine", "docker.io/library/influxdb:2.7-alpine",
                    "sha256:58fcaaf4577e", "58fcaaf4577e"):
            self.assertEqual(self.get(f"/images/{ref}/json")[0], 200, ref)

    def test_network_inspect(self):
        for n in range(16, 24):
            bridge = json.loads(recorded_body(P3[n]))["Name"] == "bridge"
            # the default bridge's id is per boot: ask for it by name
            got, want = (json.loads(x) for x in self.p3(n, "/networks/bridge" if bridge
                                                        else None))
            self.assertEqual(list(got), list(want))
            if want["Name"] in ("none", "host", "iot-stack_default"):
                for k in want:
                    if k != "Containers":
                        self.assertEqual(got[k], want[k], (want["Name"], k))
            self.assertEqual(got["Status"], want["Status"], want["Name"])
            self.assertEqual(sorted(c["Name"] for c in got["Containers"].values()),
                             sorted(c["Name"] for c in want["Containers"].values()))
            for c in got["Containers"].values():
                self.assertEqual(list(c), ["Name", "EndpointID", "MacAddress",
                                           "IPv4Address", "IPv6Address"])

    def test_small_checks(self):
        """HEAD /_ping, volume inspect and /plugins as recorded; ?size=1 in Go's order."""
        for n in (1, 2, 35, 36, 37, 38, 39, 47):
            got, want = self.p3(n)
            self.assertEqual(got, want, P3[n]["path"])
        got, want = (json.loads(x) for x in self.p3(24))
        self.assertEqual([list(c) for c in got], [list(c) for c in want])
        got, want = (json.loads(x) for x in self.p3(25))
        self.assertEqual(list(got), list(want))

    def test_full_logs(self):
        """The first run's startup is Ground Truth's own (unshifted here, so to the
        nanosecond, influxd's log ids included); the 20:34 boot's startup has the same
        lines and streams at this boot's times."""
        for n, first, boot_text in ((27, 32, "Welcome to Node-RED"),
                                    (30, 45, "found existing boltdb"),
                                    (33, 11, "Info: running mosquitto")):
            got, want = (frames(x) for x in self.p3(n))
            self.assertEqual(got[:first], want[:first], P3[n]["path"])

            def boot_run(fr):
                i = next(i for i, (s, p) in enumerate(fr)
                         if p.startswith(b"2026-09-29T00:3") and boot_text.encode() in p)
                return [(s, p.split(b" ", 1)[1]) for s, p in fr[i:i + 8]]

            def plain(fr):
                # times, and influxd's log id, which is minted from its start time
                return [(s, re.sub(rb"log_id=\S+", b"", re.sub(
                    rb"^(\d{10}|\d\d \w{3} [\d:]{8}|ts=\S+|\S+\.\t)", b"", p)))
                        for s, p in fr]
            self.assertEqual(plain(boot_run(got)), plain(boot_run(want)), P3[n]["path"])

    def test_events(self):
        """nodered's health checks, three events each, shaped as recorded (gap 4)."""
        want = [json.loads(x) for x in recorded_body(P3[40]).splitlines()]
        self.clock.t = GT_BOOT + 4000
        got = [json.loads(x) for x in self.get(
            f"/events?since={GT_BOOT + 3700}&until={GT_BOOT + 3800}")[2].splitlines()]
        self.assertGreaterEqual(len(got), 9)
        self.assertEqual(len(got) % 3, 0)
        for g, w in zip(got, want):
            self.assertEqual(list(g), list(w))
            self.assertEqual(g["Action"], w["Action"])
            self.assertEqual(sorted(g["Actor"]["Attributes"]),
                             sorted(w["Actor"]["Attributes"]))
            self.assertEqual(list(g["Actor"]["Attributes"]),
                             sorted(g["Actor"]["Attributes"]))
        state = DockerState(GT_BOOT, "test-secret")
        log = state.inspect("iot-stack-nodered-1", GT_BOOT + 3800)["State"]["Health"]["Log"]
        creates = {e["timeNano"] for e in got if e["Action"].startswith("exec_create")}
        from honeypot.docker import parse_time
        self.assertTrue({parse_time(p["Start"]) for p in log} & creates)


class StateChangeCase(unittest.TestCase):
    """Shared harness for the state-changing routes (create, start, ...): a fresh server
    per test so a mutated container does not leak into another test or the replays."""

    def setUp(self):
        self.clock = Clock(GT_BOOT + 600)
        self.state = DockerState(GT_BOOT, "test-secret")
        self.srv = serve(DockerAPI(self.state, self.clock, self.clock.sleep),
                         "127.0.0.1", 0)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def req(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=json.dumps(body).encode() if body else None,
                     headers={"Content-Type": "application/json"} if body else {})
        r = conn.getresponse()
        out = (r.status, r.read())
        conn.close()
        return out

    def body(self, n):
        return P2[n]["request_body"]

    def create(self, n=8):
        """Create a container from phase-2 request n and return its id."""
        return json.loads(self.req("POST", "/containers/create", self.body(n))[1])["Id"]


class CreateCase(StateChangeCase):
    """`POST /containers/create` (R23-R25): the container is added to the shared state in
    the `created` state and every read-only surface stays consistent with it."""

    def test_unknown_image_is_404(self):
        """n=7: create from an image that was never pulled, byte for byte as recorded."""
        status, body = self.req("POST", "/containers/create", self.body(7))
        self.assertEqual((status, body), (P2[7]["status"], P2[7]["body"].encode()))

    def test_create_adds_a_created_container(self):
        """n=8: 201 with a fresh id; the container is then `created`, not running, and
        reflects the request — the host bind and the image's two anonymous volumes."""
        status, body = self.req("POST", "/containers/create", self.body(8))
        self.assertEqual(status, 201)
        doc = json.loads(body)
        self.assertEqual(list(doc), ["Id", "Warnings"])
        self.assertRegex(doc["Id"], r"^[0-9a-f]{64}$")
        self.assertEqual(doc["Warnings"], [])
        cid = doc["Id"]

        got = json.loads(self.req("GET", f"/containers/{cid}/json")[1])
        self.assertEqual(got["State"]["Status"], "created")
        self.assertFalse(got["State"]["Running"])
        self.assertEqual((got["State"]["Pid"], got["State"]["StartedAt"]),
                         (0, "0001-01-01T00:00:00Z"))
        self.assertEqual(got["Path"], "/bin/sh")
        self.assertEqual(got["Args"], ["-c", "cat /mnt/etc/hostname; sleep 300"])
        self.assertEqual(got["HostConfig"]["Binds"], ["/:/mnt:ro"])
        bind = next(m for m in got["Mounts"] if m["Type"] == "bind")
        self.assertEqual((bind["Source"], bind["Destination"], bind["Mode"], bind["RW"],
                          bind["Propagation"]), ("/", "/mnt", "ro", False, "rslave"))
        anon = [m for m in got["Mounts"] if m["Type"] == "volume"]
        self.assertEqual(sorted(m["Destination"] for m in anon),
                         ["/mosquitto/data", "/mosquitto/log"])

    def test_created_container_is_consistent_across_surfaces(self):
        """R11: a created container hides from `docker ps`, shows in `ps -a` as Created,
        its anonymous volumes appear in /volumes, and /system/df and /info agree."""
        before_vols = len(json.loads(self.req("GET", "/volumes")[1])["Volumes"])
        cid = json.loads(self.req("POST", "/containers/create", self.body(8))[1])["Id"]

        running = json.loads(self.req("GET", "/containers/json")[1])
        self.assertNotIn(cid, [c["Id"] for c in running])
        allc = json.loads(self.req("GET", "/containers/json?all=1")[1])
        entry = next(c for c in allc if c["Id"] == cid)
        self.assertEqual((entry["State"], entry["Status"]), ("created", "Created"))

        vols = json.loads(self.req("GET", "/volumes")[1])["Volumes"]
        self.assertEqual(len(vols), before_vols + 2)

        df = self.req("GET", "/system/df")
        self.assertEqual(df[0], 200)
        self.assertIn(cid, [c["Id"] for c in json.loads(df[1])["Containers"]])

        info = json.loads(self.req("GET", "/info")[1])
        self.assertEqual((info["Containers"], info["ContainersRunning"],
                          info["ContainersStopped"]), (4, 3, 1))

    def test_top_and_stats_on_a_created_container(self):
        """A container that is not running: `/top` is a 409; one sample of `/stats` is a
        200 with empty stats, at once (moby daemon/stats.go at docker-v29.8.1, read
        2026-10-13; neither is in a recording). Until then both were 409 here."""
        cid = json.loads(self.req("POST", "/containers/create", self.body(8))[1])["Id"]
        self.assertEqual(self.req("GET", f"/containers/{cid}/top")[0], 409)
        status, body = self.req("GET", f"/containers/{cid}/stats?stream=false")[:2]
        self.assertEqual(status, 200)
        doc = json.loads(body)
        self.assertEqual((doc["id"], doc["read"], doc["preread"], doc["num_procs"]),
                         (cid, "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", 0))
        self.assertEqual((doc["memory_stats"], doc["pids_stats"], doc["storage_stats"]),
                         ({}, {}, {}))
        self.assertNotIn("networks", doc)
        # the same key order as a real sample (gt_api_phase1), minus what is empty
        self.assertEqual(list(doc), ["id", "name", "os_type", "read", "cpu_stats",
                                     "memory_stats", "pids_stats", "blkio_stats", "num_procs",
                                     "storage_stats", "preread", "precpu_stats"])

    def test_a_request_for_an_old_version_gets_that_versions_layout(self):
        """Phase 3 n=42-46: `/v1.41/…` on the real daemon. The same keys in the same
        order at every level, for all four recorded requests; and the current layout
        still for a request without a version and for one from v1.44 on."""
        def layout(x):
            if isinstance(x, dict):
                return {k: layout(v) for k, v in x.items()}
            return [layout(x[0])] if isinstance(x, list) and x else None

        def order(x):
            if isinstance(x, dict):
                return [(k, order(v)) for k, v in x.items()]
            return [order(x[0])] if isinstance(x, list) and x else None

        for n in (42, 43, 44, 46):
            e = P3[n]
            status, body = self.req("GET", e["path"])[:2]
            self.assertEqual(status, 200)
            got, want = json.loads(body), json.loads(e["body"])
            self.assertEqual(layout(got), layout(want), e["path"])
            self.assertEqual(order(got), order(want), e["path"])
        new = json.loads(self.req("GET", "/images/json")[1])[0]
        self.assertIn("Descriptor", new)
        self.assertNotIn("VirtualSize", new)
        newer = json.loads(self.req("GET", "/v1.44/images/json")[1])[0]
        self.assertNotIn("VirtualSize", newer)
        old = json.loads(self.req("GET", "/v1.43/images/json")[1])[0]
        self.assertEqual(old["VirtualSize"], old["Size"])
        self.assertEqual(self.req("GET", "/v1.41/version")[1], self.req("GET", "/version")[1])

    def test_a_pull_names_the_image_once_however_the_client_spells_it(self):
        """The recorded request is `fromImage=alpine`; the docker client sends the
        normalised `docker.io/library/alpine`. Both name the same reference."""
        import re as _re
        want = json.loads(P2[6]["body"])["message"]
        port = _re.compile(r"\]:\d+->")
        for name in ("alpine", "docker.io/library/alpine", "library/alpine"):
            got = self.state.pull_error(name, "latest")
            self.assertEqual(port.sub("]:N->", got), port.sub("]:N->", want), name)
        self.assertIn('"docker.io/nodered/node-red:4.1"',
                      self.state.pull_error("docker.io/nodered/node-red", "4.1"))
        self.assertNotIn("docker.io/docker.io", self.state.pull_error("docker.io/library/alpine", ""))

    def test_several_label_filters_must_all_match(self):
        """`label` values are not alternatives (moby's MatchKVList): compose asks for
        its project's label and others together, and another project's name must find
        nothing."""
        def ids(*labels):
            f = json.dumps({"label": {l: True for l in labels}})
            return json.loads(self.req("GET", "/containers/json?filters=" + urllib.parse.quote(f))[1])
        self.assertEqual(len(ids("com.docker.compose.project=iot-stack")), 3)
        self.assertEqual(len(ids("com.docker.compose.project=iot-stack",
                                 "com.docker.compose.service=nodered")), 1)
        self.assertEqual(ids("com.docker.compose.project=nosuch",
                             "com.docker.compose.oneoff=False"), [])

    def test_privileged_flags_are_reflected(self):
        """R25: whatever the attacker sent, not a fixed set."""
        cid = json.loads(self.req("POST", "/containers/create", self.body(16))[1])["Id"]
        hc = json.loads(self.req("GET", f"/containers/{cid}/json")[1])["HostConfig"]
        self.assertEqual((hc["Privileged"], hc["PidMode"]), (True, "host"))
        self.assertEqual(hc["Binds"], ["/:/host:ro"])

    def test_name_query_and_conflict(self):
        status, body = self.req("POST", "/containers/create?name=myctr",
                                {"Image": "eclipse-mosquitto:2"})
        self.assertEqual(status, 201)
        got = json.loads(self.req("GET", "/containers/myctr/json")[1])
        self.assertEqual(got["Name"], "/myctr")
        again = self.req("POST", "/containers/create?name=myctr",
                         {"Image": "eclipse-mosquitto:2"})
        self.assertEqual(again[0], 409)

    def test_empty_config_is_400(self):
        self.assertEqual(self.req("POST", "/containers/create", {})[0], 400)

    def test_logs_on_created_container_are_empty_not_a_crash(self):
        """A container created through the API has no recorded log: `docker logs` must
        return an empty stream, not crash on the missing entry."""
        cid = self.create()
        status, body = self.req("GET", f"/containers/{cid}/logs?stdout=1&stderr=1")
        self.assertEqual((status, body), (200, b""))


class CreateFromTheDockerClientCase(StateChangeCase):
    """The docker client sends every field of the request, the empty ones as "" or null
    (2026-10-13: seen when the shell's `docker create` was checked against the real
    client). The daemon fills what is empty from the image, by the rules of its merge()
    (moby daemon/commit.go and daemon/create.go at docker-v29.8.1). Before, a null
    `Cmd` meant "no command" here and a container listed with an empty COMMAND."""

    CLIENT = json.loads((ROOT / "honeypot" / "docker_client.json").read_text())["create_body"]

    def made(self, image, **change):
        body = json.loads(json.dumps(self.CLIENT))
        body["Image"] = image
        host = change.pop("HostConfig", {})
        body.update(change)
        body["HostConfig"].update(host)
        status, answer = self.req("POST", "/containers/create", body)
        self.assertEqual(status, 201, answer)
        return json.loads(self.req("GET", f"/containers/{json.loads(answer)['Id']}/json")[1])

    def test_what_the_request_leaves_empty_is_the_images(self):
        image = json.loads(self.req("GET", "/images/nodered/node-red:4.1/json")[1])["Config"]
        doc = self.made("nodered/node-red:4.1")
        cfg = doc["Config"]
        for key in ("User", "WorkingDir", "Entrypoint", "Cmd", "Env", "ExposedPorts"):
            self.assertEqual(cfg[key], image.get(key), key)       # node-red has no Cmd
        self.assertEqual(cfg["User"], "node-red")
        self.assertEqual(doc["Path"], "./entrypoint.sh")
        listed = json.loads(self.req("GET", "/containers/json?all=1")[1])[0]
        self.assertEqual(listed["Command"], "./entrypoint.sh")

    def test_the_images_volumes_are_made_though_the_client_sends_an_empty_set(self):
        doc = self.made("eclipse-mosquitto:2")
        self.assertEqual(sorted(m["Destination"] for m in doc["Mounts"]),
                         ["/mosquitto/data", "/mosquitto/log"])
        self.assertEqual(doc["Path"], "/docker-entrypoint.sh")
        self.assertEqual(doc["Args"], ["/usr/sbin/mosquitto", "-c", "/mosquitto/config/mosquitto.conf"])

    def test_a_command_replaces_the_images_command_and_keeps_its_entrypoint(self):
        doc = self.made("eclipse-mosquitto:2", Cmd=["sleep", "5"])
        self.assertEqual((doc["Path"], doc["Args"]), ("/docker-entrypoint.sh", ["sleep", "5"]))

    def test_an_entrypoint_drops_the_images_command(self):
        doc = self.made("influxdb:2.7-alpine", Entrypoint=["sh"])
        self.assertEqual((doc["Path"], doc["Args"], doc["Config"]["Cmd"]), ("sh", [], None))

    def test_the_requests_variables_come_first_and_replace_the_images_by_name(self):
        image = json.loads(self.req("GET", "/images/influxdb:2.7-alpine/json")[1])["Config"]["Env"]
        name = image[-1].split("=")[0]
        env = self.made("influxdb:2.7-alpine", Env=["A=1", name + "=mine"])["Config"]["Env"]
        self.assertEqual(env[:2], ["A=1", name + "=mine"])
        self.assertEqual(env[2:], image[:-1])

    def test_ports_and_labels_join_the_images_in_key_order(self):
        doc = self.made("eclipse-mosquitto:2", ExposedPorts={"9000/udp": {}, "80/tcp": {}},
                        Labels={"zz": "1", "aa": "2"})
        self.assertEqual(list(doc["Config"]["ExposedPorts"]), ["1883/tcp", "80/tcp", "9000/udp"])
        labels = list(doc["Config"]["Labels"])
        self.assertEqual(labels, sorted(labels))
        self.assertLessEqual({"aa", "zz"}, set(labels))

    def test_nothing_to_run_is_refused(self):
        body = json.loads(json.dumps(self.CLIENT))
        body.update(Image="nodered/node-red:4.1", Entrypoint=[""])     # `--entrypoint ""`
        status, answer = self.req("POST", "/containers/create", body)
        self.assertEqual((status, json.loads(answer)), (400, {"message": "no command specified"}))
        self.assertEqual(len(json.loads(self.req("GET", "/containers/json?all=1")[1])), 3)

    def test_published_ports_show_once_it_runs(self):
        """NOT RECORDED on the reference machine (docker.py, _publish_ports): the
        daemon's documented behaviour."""
        doc = self.made("eclipse-mosquitto:2", ExposedPorts={"80/tcp": {}}, HostConfig={
            "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}],
                             "1883/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]}})
        self.assertEqual(doc["NetworkSettings"]["Ports"], {})
        self.assertEqual(self.req("POST", f"/containers/{doc['Id']}/start")[0], 204)
        ports = json.loads(self.req("GET", f"/containers/{doc['Id']}/json")[1])["NetworkSettings"]["Ports"]
        self.assertEqual(ports, {
            "1883/tcp": [{"HostIp": "127.0.0.1", "HostPort": "32768"}],
            "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}, {"HostIp": "::", "HostPort": "8080"}]})
        listed = json.loads(self.req("GET", "/containers/json")[1])[0]["Ports"]
        self.assertIn({"IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}, listed)
        self.assertEqual(self.req("POST", f"/containers/{doc['Id']}/stop?t=0")[0], 204)
        self.assertEqual(json.loads(self.req("GET", f"/containers/{doc['Id']}/json")[1])
                         ["NetworkSettings"]["Ports"], {})

    def test_an_exposed_port_that_is_not_published_lists_by_itself(self):
        doc = self.made("eclipse-mosquitto:2")
        self.req("POST", f"/containers/{doc['Id']}/start")
        got = json.loads(self.req("GET", f"/containers/{doc['Id']}/json")[1])
        self.assertEqual(got["NetworkSettings"]["Ports"], {"1883/tcp": None})
        self.assertEqual(json.loads(self.req("GET", "/containers/json")[1])[0]["Ports"],
                         [{"PrivatePort": 1883, "Type": "tcp"}])

    def test_the_hosts_network_publishes_nothing(self):
        doc = self.made("eclipse-mosquitto:2", HostConfig={"NetworkMode": "host"})
        self.req("POST", f"/containers/{doc['Id']}/start")
        got = json.loads(self.req("GET", f"/containers/{doc['Id']}/json")[1])
        self.assertEqual(got["NetworkSettings"]["Ports"], {})


class StartCase(StateChangeCase):
    """`POST /containers/<id>/start` (R23): the created container becomes running with a
    real Pid in the shared process table, filled timestamps and a bridge endpoint, and
    every read-only surface agrees."""

    def start(self, cid):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", f"/containers/{cid}/start")
        r = conn.getresponse()
        out = (r.status, dict(r.getheaders()), r.read())
        conn.close()
        return out

    def test_start_is_204_then_304_and_unknown_is_404(self):
        cid = self.create()
        status, headers, body = self.start(cid)
        self.assertEqual((status, body), (204, b""))
        # 204: Go's four headers plus Date, no Content-Type or Content-Length.
        self.assertEqual([k for k in headers if k != "Date"],
                         ["Api-Version", "Docker-Experimental", "Ostype", "Server"])
        self.assertNotIn("Content-Length", headers)
        self.assertEqual(self.start(cid)[0], 304)                 # already running
        self.assertEqual(self.req("POST", "/containers/nope/start")[0], 404)

    def test_running_state_pid_and_timestamp(self):
        cid = self.create()
        self.clock.t = GT_BOOT + 700
        self.start(cid)
        s = json.loads(self.req("GET", f"/containers/{cid}/json")[1])["State"]
        self.assertEqual((s["Status"], s["Running"]), ("running", True))
        self.assertGreater(s["Pid"], 1399)                        # the collision-free band
        self.assertEqual(s["StartedAt"], "2026-09-29T00:46:12Z")  # the clock at start
        # now shows in `docker ps` (running only), as Up something
        ps = json.loads(self.req("GET", "/containers/json")[1])
        self.assertIn(cid, [c["Id"] for c in ps])
        self.assertTrue(next(c for c in ps if c["Id"] == cid)["Status"].startswith("Up"))

    def test_pid_is_in_the_shared_process_table(self):
        """docker top shows the container's main process; host ps shows the shim and the
        main process; and docker top's pids are a subset of host ps (R15)."""
        cid = self.create()
        self.clock.t = GT_BOOT + 700
        self.start(cid)
        main_pid = json.loads(self.req("GET", f"/containers/{cid}/json")[1])["State"]["Pid"]
        top = json.loads(self.req("GET", f"/containers/{cid}/top")[1])
        pidc = top["Titles"].index("PID")
        top_pids = {int(r[pidc]) for r in top["Processes"]}
        self.assertEqual(top_pids, {main_pid})                    # the container's sh
        host = procs.table(GT_BOOT + 700, GT_BOOT, [],
                           extra=self.state.container_procs(GT_BOOT + 700))
        host_pids = {p.pid for p in host}
        self.assertTrue(top_pids <= host_pids)
        self.assertTrue(any(p.comm == "containerd-shim" and cid in p.args for p in host))

    def test_bridge_endpoint_is_assigned_and_network_inspect_agrees(self):
        cid = self.create()
        self.start(cid)
        ep = json.loads(self.req("GET", f"/containers/{cid}/json")[1]
                        )["NetworkSettings"]["Networks"]["bridge"]
        self.assertEqual(ep["IPAddress"], "172.17.0.2")
        self.assertEqual(ep["IPPrefixLen"], 16)
        self.assertEqual(ep["Gateway"], "172.17.0.1")
        self.assertEqual(ep["MacAddress"], "02:42:ac:11:00:02")   # derived from the IP
        self.assertRegex(ep["EndpointID"], r"^[0-9a-f]{64}$")
        ni = json.loads(self.req("GET", "/networks/bridge")[1])
        self.assertEqual([v["IPv4Address"] for v in ni["Containers"].values()],
                         ["172.17.0.2/16"])
        self.assertEqual(ni["Status"]["IPAM"]["Subnets"]["172.17.0.0/16"]["IPsInUse"], 4)

    def test_stats_on_a_started_container_is_modelled_not_a_crash(self):
        cid = self.create()
        self.clock.t = GT_BOOT + 700
        self.start(cid)
        self.clock.t = GT_BOOT + 760
        st = json.loads(self.req("GET", f"/containers/{cid}/stats?stream=false")[1])
        self.assertEqual(list(st), ["id", "name", "os_type", "read", "cpu_stats",
                                    "memory_stats", "networks", "pids_stats",
                                    "blkio_stats", "num_procs", "storage_stats",
                                    "preread", "precpu_stats"])
        self.assertGreater(st["cpu_stats"]["cpu_usage"]["total_usage"], 0)
        self.assertEqual(st["pids_stats"], {"current": 1, "limit": 9578})
        # Its eth0 is the host veth's other end: what the host sends, it receives.
        read = parse_time(st["read"]) / 1e9                   # the moment the stats are of
        veth = net.link_iface(self.state.host_links()[-1], read, GT_BOOT)
        self.assertEqual(st["networks"]["eth0"]["rx_bytes"], veth.tx[0])
        self.assertEqual(st["networks"]["eth0"]["tx_packets"], veth.rx[1])
        self.assertGreater(veth.tx[0], 0)

    def test_info_counts_follow_the_start(self):
        cid = self.create()
        before = json.loads(self.req("GET", "/info")[1])
        self.assertEqual((before["ContainersRunning"], before["ContainersStopped"]), (3, 1))
        self.start(cid)
        after = json.loads(self.req("GET", "/info")[1])
        self.assertEqual((after["ContainersRunning"], after["ContainersStopped"]), (4, 0))


class ExecCase(StateChangeCase):
    """`POST /containers/<id>/exec` + `POST /exec/<id>/start` (R23), verified against the
    Phase 2 recordings: `id` inside the container (n=12/13) and `cat /mnt/etc/os-release`
    reading the host through the bind mount (n=14/15)."""

    def running_container(self):
        cid = self.create(8)
        self.req("POST", f"/containers/{cid}/start")
        return cid

    def exec_create(self, cid, cmd):
        return json.loads(self.req("POST", f"/containers/{cid}/exec",
                                   {"AttachStdout": True, "AttachStderr": True,
                                    "Cmd": cmd})[1])["Id"]

    def raw_start(self, exec_id):
        """Drive exec start over a socket: the response is hijacked (no Content-Length or
        chunking), so read to EOF."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            b = json.dumps({"Detach": False, "Tty": False}).encode()
            s.sendall(f"POST /exec/{exec_id}/start HTTP/1.1\r\nHost: x\r\nContent-Length: "
                      f"{len(b)}\r\nConnection: close\r\n\r\n".encode() + b)
            out = b""
            while chunk := s.recv(65536):
                out += chunk
        head, _, body = out.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        headers = [tuple(x.split(": ", 1)) for x in lines[1:] if ": " in x]
        return lines[0], headers, body

    def test_exec_create_is_201_with_an_id(self):
        cid = self.running_container()
        status, body = self.req("POST", f"/containers/{cid}/exec",
                                {"AttachStdout": True, "AttachStderr": True, "Cmd": ["id"]})
        self.assertEqual(status, 201)
        doc = json.loads(body)
        self.assertEqual(list(doc), ["Id"])
        self.assertRegex(doc["Id"], r"^[0-9a-f]{64}$")

    def test_exec_create_on_non_running_is_409(self):
        cid = self.create(8)                         # created, never started
        self.assertEqual(self.req("POST", f"/containers/{cid}/exec", {"Cmd": ["id"]})[0],
                         409)

    def model_says(self, text, code=0):
        """A stand-in for the model (DockerState.program_output); records what it is asked."""
        self.asked = []

        def answer(c, argv, tty, kind):
            self.asked.append((c["Id"], argv, tty, kind))
            return text, code
        self.state.program_output = answer

    def test_exec_start_id_matches_recording(self):
        """n=13: hijacked raw stream, Go's header order, no Date/Content-Length, and the
        output framed as recorded. The output itself is the model's (here a stand-in that
        says what the recording holds): the program's output is in no state."""
        cid = self.running_container()
        self.model_says(p2_body(P2[13])[8:].decode().rstrip("\n"))
        eid = self.exec_create(cid, ["id"])
        status, headers, body = self.raw_start(eid)
        self.assertEqual(status, "HTTP/1.1 200 OK")
        self.assertEqual(headers, [("Content-Type", "application/vnd.docker.raw-stream"),
                                   ("Api-Version", "1.56"), ("Docker-Experimental", "false"),
                                   ("Ostype", "linux"), ("Server", "Docker/29.8.1 (linux)")])
        self.assertNotIn("Date", [k for k, v in headers])
        self.assertNotIn("Content-Length", [k for k, v in headers])
        self.assertEqual(body, p2_body(P2[13]))
        self.assertEqual(self.asked, [(cid, ["id"], False, "exec")])

    def test_exec_start_cat_host_file_matches_recording(self):
        """n=15: `cat /mnt/etc/os-release` through the bind mount, framed as recorded."""
        cid = self.running_container()
        self.model_says(p2_body(P2[15])[8:].decode().rstrip("\n"))
        eid = self.exec_create(cid, ["cat", "/mnt/etc/os-release"])
        self.assertEqual(self.raw_start(eid)[2], p2_body(P2[15]))
        self.assertEqual(self.asked, [(cid, ["cat", "/mnt/etc/os-release"], False, "exec")])

    def test_exec_exit_status_is_the_answers(self):
        cid = self.running_container()
        self.model_says("cat: can't open '/nope': No such file or directory", 1)
        eid = self.exec_create(cid, ["cat", "/nope"])
        self.raw_start(eid)
        self.assertEqual(self.state._execs[eid]["exit"], 1)

    def test_no_stored_exec_answers(self):
        """Without a model nothing is printed, also for the recorded attack's commands:
        no answer is stored and looked up by its command (removed 2026-10-15), and the
        recorded texts are nowhere in the honeypot's code."""
        cid = self.running_container()
        self.assertEqual(self.raw_start(self.exec_create(cid, ["id"]))[2], b"")
        code = "".join(f.read_text() for f in (ROOT / "honeypot").glob("*.py"))
        for n in (13, 15):
            first = p2_body(P2[n])[8:].decode().splitlines()[0]
            self.assertNotIn(first, code)
        self.assertNotIn("cat /mnt/etc/hostname; sleep 300", code)

    def test_a_started_containers_log_is_asked_once(self):
        """The recorded attack's container (n=8) prints the host's name: its log is the
        model's answer for its command, asked for when the log is first read, then kept."""
        cid = self.running_container()
        self.model_says("raspberrypi")
        self.clock.t += 1
        for _ in range(2):
            status, body = self.req("GET", f"/containers/{cid}/logs?stdout=1&stderr=1")
            self.assertEqual((status, body), (200, p2_body(P2[11])))
        self.assertEqual(self.asked, [(cid, ["/bin/sh", "-c", "cat /mnt/etc/hostname; sleep 300"],
                                       False, "run")])

    def test_unknown_exec_id_is_404(self):
        self.assertEqual(self.req("POST", "/exec/deadbeef/start", {"Detach": False}),
                         (404, b'{"message":"No such exec instance: deadbeef"}\n'))


class StopWaitCase(StateChangeCase):
    """`POST /containers/<id>/stop` + `/wait` (R23), verified against Phase 2 n=19/20: the
    stop takes the timeout (SIGTERM ignored by the shell PID 1, then SIGKILL) and wait
    returns 137 - the consistency pair - and the stopped container leaves every running
    surface."""

    def running_container(self):
        cid = self.create(8)
        self.req("POST", f"/containers/{cid}/start")
        return cid

    def test_stop_waits_the_timeout_then_204(self):
        cid = self.running_container()
        before = self.clock.t
        self.assertEqual(self.req("POST", f"/containers/{cid}/stop")[0], 204)
        self.assertGreaterEqual(self.clock.t - before, 10.0)     # ~10 s, then SIGKILL
        # a shorter timeout is honoured
        cid2 = self.running_container()
        before = self.clock.t
        self.req("POST", f"/containers/{cid2}/stop?t=2")
        self.assertLess(self.clock.t - before, 5.0)

    def test_wait_returns_137_chunked(self):
        cid = self.running_container()
        self.req("POST", f"/containers/{cid}/stop")
        # raw socket: wait is chunked (the daemon finishes the response at exit)
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(f"POST /containers/{cid}/wait HTTP/1.1\r\nHost: x\r\n"
                      f"Connection: close\r\n\r\n".encode())
            out = b""
            while chunk := s.recv(65536):
                out += chunk
        head, _, _ = out.partition(b"\r\n\r\n")
        self.assertIn(b"Transfer-Encoding: chunked", head)
        self.assertIn(b"Content-Type: application/json", head)
        # body via http.client (de-chunked) matches the recording byte for byte
        self.assertEqual(self.req("POST", f"/containers/{cid}/wait")[1], p2_body(P2[20]))

    def test_stopped_container_leaves_every_running_surface(self):
        cid = self.running_container()
        self.req("POST", f"/containers/{cid}/stop")
        doc = json.loads(self.req("GET", f"/containers/{cid}/json")[1])
        self.assertEqual((doc["State"]["Status"], doc["State"]["ExitCode"]), ("exited", 137))
        self.assertEqual(doc["State"]["Pid"], 0)
        self.assertEqual(doc["NetworkSettings"]["Networks"]["bridge"]["IPAddress"], "")
        self.assertEqual(doc["NetworkSettings"]["SandboxKey"], "")
        self.assertNotIn(cid, [c["Id"] for c in
                               json.loads(self.req("GET", "/containers/json")[1])])
        allc = json.loads(self.req("GET", "/containers/json?all=1")[1])
        self.assertTrue(next(c for c in allc if c["Id"] == cid)["Status"]
                        .startswith("Exited (137)"))
        self.assertEqual(json.loads(self.req("GET", "/networks/bridge")[1])["Containers"], {})
        self.assertEqual(self.req("GET", f"/containers/{cid}/top")[0], 409)
        info = json.loads(self.req("GET", "/info")[1])
        self.assertEqual((info["ContainersRunning"], info["ContainersStopped"]), (3, 1))

    def test_stop_again_is_304_and_unknown_is_404(self):
        cid = self.running_container()
        self.req("POST", f"/containers/{cid}/stop")
        self.assertEqual(self.req("POST", f"/containers/{cid}/stop")[0], 304)
        self.assertEqual(self.req("POST", "/containers/nope/stop")[0], 404)


class DeleteCase(StateChangeCase):
    """`DELETE /containers/<id>` (R23-R24): removes the container and, with `?v=1`, the
    anonymous volumes it made, restoring the pre-attack set."""

    def snapshot(self):
        """The observable state, for the round-trip check."""
        def ids(path):
            return sorted(c["Id"] for c in json.loads(self.req("GET", path)[1]))
        return {
            "containers": sorted(c["Name"] for c in self.state.containers),
            "volumes": sorted(v["Name"] for v in self.state._volumes),
            "running": ids("/containers/json"),
            "bridge": json.loads(self.req("GET", "/networks/bridge")[1])["Containers"],
            "procs": sorted((p.pid, p.args)
                            for p in self.state.container_procs(self.clock.t)),
            "df": (sorted(self.state._df["container_size"]),
                   sorted(self.state._df["volume_size"])),
        }

    def test_delete_created_then_404_on_second_delete(self):
        cid = self.create(16)                        # the privileged one, never started
        self.assertEqual(self.req("DELETE", f"/containers/{cid}?v=1")[0], 204)
        self.assertEqual(self.req("DELETE", f"/containers/{cid}?v=1"),
                         (404, f'{{"message":"No such container: {cid}"}}\n'.encode()))

    def test_running_needs_force(self):
        cid = self.create(8)
        self.req("POST", f"/containers/{cid}/start")
        self.assertEqual(self.req("DELETE", f"/containers/{cid}")[0], 409)
        self.assertEqual(self.req("DELETE", f"/containers/{cid}?force=1")[0], 204)
        self.assertNotIn(cid, [c["Id"] for c in self.state.containers])

    def test_v1_removes_anonymous_volumes_only(self):
        before = {v["Name"] for v in self.state._volumes}
        cid = self.create(8)                         # picks up two anonymous volumes
        self.assertEqual(len({v["Name"] for v in self.state._volumes} - before), 2)
        self.req("DELETE", f"/containers/{cid}?v=1")
        # back to exactly the seed volumes (named/other-referenced ones untouched)
        self.assertEqual({v["Name"] for v in self.state._volumes}, before)

    def test_without_v_keeps_the_anonymous_volumes(self):
        before = {v["Name"] for v in self.state._volumes}
        cid = self.create(8)
        self.req("DELETE", f"/containers/{cid}")     # no ?v
        self.assertEqual(len({v["Name"] for v in self.state._volumes} - before), 2)

    def test_full_attack_round_trips_to_the_pre_attack_set(self):
        """The whole Phase 2 sequence (create/start/exec/stop/delete ?v=1) leaves the
        state byte-identical to before it ran: containers, volumes, the process table and
        the bridge endpoints (R11)."""
        pre = self.snapshot()
        probe = self.create(8)
        self.req("POST", f"/containers/{probe}/start")
        for cmd in (["id"], ["cat", "/mnt/etc/os-release"]):
            eid = json.loads(self.req("POST", f"/containers/{probe}/exec",
                                      {"AttachStdout": True, "Cmd": cmd})[1])["Id"]
            self.req("POST", f"/exec/{eid}/start", {"Detach": False})
        priv = self.create(16)
        self.req("DELETE", f"/containers/{priv}?v=1")
        self.req("POST", f"/containers/{probe}/stop")
        self.req("POST", f"/containers/{probe}/wait")
        self.req("DELETE", f"/containers/{probe}?v=1")
        self.assertEqual(self.snapshot(), pre)


class ImagesCreateCase(StateChangeCase):
    """`POST /images/create` (R2, R23): the pull fails after ~5 s with the DNS error."""

    def test_pull_fails_500_matching_recording(self):
        before = self.clock.t
        status, body = self.req("POST", "/images/create?fromImage=alpine&tag=latest")
        self.assertEqual(status, 500)
        self.assertGreaterEqual(self.clock.t - before, 5.0)   # the resolver's retries
        # byte for byte but the volatile source UDP port (this state carries no subs, so
        # the addresses are Ground Truth's, as recorded)
        blank = lambda s: re.sub(rb"::af2\]:\d+", b"::af2]:PORT", s)
        self.assertEqual(blank(body), blank(p2_body(P2[6])))


class NoRealDaemonCase(unittest.TestCase):
    """R26: the fake API never talks to a Docker daemon. Neither module may open a
    client connection of any kind or name the daemon's socket."""

    def test_sources(self):
        for name in ("dockerapi.py", "docker.py"):
            src = (ROOT / "honeypot" / name).read_text()
            for bad in ("docker.sock", "AF_UNIX", ".connect(", "create_connection",
                        "http.client", "urllib.request", "import requests", "subprocess",
                        "os.system", "/var/run/docker"):
                self.assertNotIn(bad, src, f"{name}: {bad}")


class SubstitutedCase(unittest.TestCase):
    """Through the relay's substitution map: no Ground Truth ID on the wire (R3)."""

    def test_no_ground_truth_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            subs = Substitutions(identity.pairs(tmp, GT_BOOT, "x"))
        clock = Clock(GT_BOOT + 4000)
        api = DockerAPI(DockerState(GT_BOOT, "x", subs), clock, clock.sleep)
        text = b""
        for e in API.values():
            path = subs(e["path"])
            a = api.route(e["method"], path)
            text += a.body or b"".join(a.stream or [])
        for gt in [*identity.INSTALL.values(), *identity.BOOT.values()]:
            self.assertNotIn(gt.encode(), text)
            if len(gt) == 64:
                self.assertNotIn(gt[:12].encode(), text)


if __name__ == "__main__":
    unittest.main()
