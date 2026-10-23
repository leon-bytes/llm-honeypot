"""The fake Docker Engine API on port 2375: read-only requests, answered from the shared
Docker state (docker.py) and nothing else.

There is no Docker client, socket path or proxy anywhere in this module, and there must
never be one (R26): every answer is built from the DockerState the shell's
`docker` commands read too (R11).

What a client sees is copied from Ground Truth's recordings (gt_api_phase1_2026-09.json):
- The status line and header set of each kind of answer, in Go's order (R7). They are
  not all the same: only /_ping carries Builder-Version, Cache-Control, Pragma and
  Swarm; a rejected API version drops Docker-Experimental; an unknown path gets just
  three headers.
- Go's choice between Content-Length and chunked: a body of up to 2048 bytes written
  in one go gets a length, anything longer or streamed is chunked.
- The bodies: Go's JSON (compact, `<` and `&` not escaped, a newline at the end) and,
  for logs, the multiplexed stream (R6).
- The version rules (R8): /v1.40 to /v1.56 work, older is a plain-text 400, newer a
  JSON 400.
- One-shot stats take 1-2 s, as the daemon waits for its next sample (n=19, 23, 27).

State-changing requests: `POST /containers/create` adds the container to the shared
DockerState in the `created` state (R23-R25), `POST /containers/<id>/start` moves it to
`running` (a real Pid in the shared process table, StartedAt filled, a bridge endpoint;
R23), answering 204 or 304, and `POST /containers/<id>/exec` + `POST /exec/<id>/start`
register and run an exec, the latter answering on a hijacked raw stream (R6 framing),
`POST /containers/<id>/stop` SIGKILLs the probe after its timeout (204 after ~10 s) and
`POST /containers/<id>/wait` streams the exit code (137), `DELETE /containers/<id>`
removes it (with `?v=1`, its anonymous volumes too), putting the state back to its
pre-attack set, and `POST /images/create` fails the pull with the DNS error (R2) after
~5 s. The whole Phase 2 attacker path is now answered from the shared state.
"""
from __future__ import annotations
import email.utils
import json
import logging
import re
import select
import socket
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .docker import NS, BadFilter, DockerState, _ref_with_tag, go_time, parse_time

log = logging.getLogger("dockerapi")

API_VERSION = (1, 56)
MIN_VERSION = (1, 40)
CHUNK_AFTER = 2048           # Go's bufferBeforeChunkingSize
STREAM_LIMIT_S = 3600        # a stream nobody closes is closed after an hour

_STD = [("Api-Version", "1.56"), ("Content-Type", None), ("Docker-Experimental", "false"),
        ("Ostype", "linux"), ("Server", "Docker/29.8.1 (linux)")]
_PING = [("Api-Version", "1.56"), ("Builder-Version", "2"),
         ("Cache-Control", "no-cache, no-store, must-revalidate"),
         ("Docker-Experimental", "false"), ("Ostype", "linux"), ("Pragma", "no-cache"),
         ("Server", "Docker/29.8.1 (linux)"), ("Swarm", "inactive")]
_TOO_OLD = [("Api-Version", "1.56"), ("Content-Type", "text/plain; charset=utf-8"),
            ("Ostype", "linux"), ("Server", "Docker/29.8.1 (linux)"),
            ("X-Content-Type-Options", "nosniff")]
_TOO_NEW = [("Api-Version", "1.56"), ("Content-Type", "application/json"),
            ("Ostype", "linux"), ("Server", "Docker/29.8.1 (linux)")]
_SWARM = ("This node is not a swarm manager. Use \"docker swarm init\" or \"docker swarm "
          "join\" to connect this node to swarm and try again.")

JSON, STREAM = "application/json", "application/vnd.docker.multiplexed-stream"
RAW_STREAM = "application/vnd.docker.raw-stream"
# The hijacked response of `POST /exec/<id>/start` (phase 2 n=13/15): Content-Type first,
# no Date and no Content-Length, then the framed output, then the connection closes.
_RAW = [("Content-Type", RAW_STREAM), ("Api-Version", "1.56"),
        ("Docker-Experimental", "false"), ("Ostype", "linux"),
        ("Server", "Docker/29.8.1 (linux)")]


def go_json(obj) -> bytes:
    """Go's json.Encoder as Docker uses it: compact, HTML not escaped, newline."""
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def frame(payload: bytes, stream: int = 1) -> bytes:
    """One frame of Docker's multiplexed stream (R6): stream byte, three zeros, a
    big-endian length, the bytes."""
    return bytes([stream, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


def _bool(q: dict, key: str, default: bool = False) -> bool:
    if key not in q:
        return default
    return q[key].strip().lower() not in ("", "0", "no", "false", "none")


def _filters(q: dict) -> dict:
    """Docker's `filters` parameter: {"key": {"value": true}} or {"key": ["value"]}."""
    raw = q.get("filters", "")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError:
        raise BadFilter("invalid filter: " + raw) from None
    return {k: list(v) if isinstance(v, (dict, list)) else [str(v)]
            for k, v in parsed.items()}


def _unix(v: str | None) -> float | None:
    """`since`/`until`: Unix seconds with an optional fraction (or RFC 3339)."""
    if v in (None, ""):
        return None
    try:
        return float(v)
    except ValueError:
        return parse_time(v) / NS


class Answer:
    """A response: status, headers before Date, and a body that is either bytes or a
    generator of byte chunks (streamed, always chunked)."""

    def __init__(self, status: int, headers: list, body=b"", ctype: str = JSON,
                 stream=None, after_date: list | None = None, raw: bool = False):
        self.status, self.body, self.stream = status, body, stream
        self.headers = [(k, ctype if v is None else v) for k, v in headers]
        self.after_date = after_date          # e.g. /_ping's sniffed Content-Type
        self.raw = raw                        # a hijacked stream: headers as given, then
        #                                       raw bytes, no Date/Content-Length, close


def _json(status: int, obj, headers=_STD) -> Answer:
    return Answer(status, headers, go_json(obj))


def _msg(status: int, message: str) -> Answer:
    return _json(status, {"message": message})


def not_found() -> Answer:
    """No route: moby's notFoundHandler, outside every middleware (n=16)."""
    return Answer(404, [("Content-Type", JSON)], go_json({"message": "page not found"}))


# A body-less answer (204 No Content, 304 Not Modified): the standard header set minus
# Content-Type, and no Content-Length, exactly as the daemon sends them (phase 2 n=10).
_EMPTY = [("Api-Version", "1.56"), ("Docker-Experimental", "false"), ("Ostype", "linux"),
          ("Server", "Docker/29.8.1 (linux)")]


def _empty(status: int) -> Answer:
    return Answer(status, _EMPTY, body=None)


# How long the real daemon took over the requests that make it do work (phase 2: create
# 184 and 198 ms, start 192 ms, running a command 35 and 36 ms, delete 57 and 66 ms).
# The emulated API waits as long: an answer in a millisecond is as much a tell as a
# slow one, and a client that asks for a container's log right after starting it must
# find the first line there, as on the real machine.
_TOOK = {"create": 0.19, "start": 0.19, "exec": 0.035, "delete": 0.06}



# ------------------------------------------------------------------ old API versions
# A request that names an old version of the API (`/v1.41/containers/json`) gets that
# version's layout from the real daemon, not today's. Recorded for four requests at
# v1.41 (phase 3 n=42-46); until 2026-10-13 the emulated API answered them with the
# current layout. What the recording shows, and nothing more:
#   /containers/json   no ImageManifestDescriptor, no Health
#   /images/json       VirtualSize (equal to Size) instead of Descriptor
#   /info              the two BridgeNf* flags, `Expected` beside every commit ID, two
#                      AllowNondistributable* keys; no Containerd, no FirewallBackend,
#                      no `status` in a runtime; and every key in alphabetical order
#   /system/df         no *Usage summaries, VirtualSize in every image, no
#                      ImageManifestDescriptor in a container; alphabetical as well
# The layout is known for v1.41 only. It is applied up to v1.43, the last version before
# VirtualSize was dropped (v1.44); from v1.44 on the current layout is sent, which for
# the versions in between is an approximation nobody has recorded.
OLD_LAYOUT_UP_TO = (1, 43)


def _sorted(x):
    if isinstance(x, dict):
        return {k: _sorted(x[k]) for k in sorted(x)}
    return [_sorted(i) for i in x] if isinstance(x, list) else x


def _old_containers(doc):
    return [{k: v for k, v in c.items() if k not in ("ImageManifestDescriptor", "Health")}
            for c in doc]


def _old_image(im: dict, keep_descriptor: bool = False) -> dict:
    out = {k: v for k, v in im.items() if keep_descriptor or k != "Descriptor"}
    out["VirtualSize"] = im.get("Size")
    return out


def _old_info(doc):
    doc = {k: v for k, v in doc.items() if k not in ("Containerd", "FirewallBackend")}
    doc["BridgeNfIptables"] = doc["BridgeNfIp6tables"] = False
    for key in ("ContainerdCommit", "RuncCommit", "InitCommit"):
        if isinstance(doc.get(key), dict):
            doc[key] = {**doc[key], "Expected": doc[key].get("ID")}
    if isinstance(doc.get("RegistryConfig"), dict):
        doc["RegistryConfig"] = {**doc["RegistryConfig"],
                                 "AllowNondistributableArtifactsCIDRs": None,
                                 "AllowNondistributableArtifactsHostnames": None}
    if isinstance(doc.get("Runtimes"), dict):
        doc["Runtimes"] = {name: {k: v for k, v in rt.items() if k != "status"}
                           for name, rt in doc["Runtimes"].items()}
    return _sorted(doc)


def _old_df(doc):
    doc = {k: v for k, v in doc.items() if not k.endswith("Usage")}
    doc["Images"] = [_old_image(im, keep_descriptor=True) for im in doc.get("Images") or []]
    doc["Containers"] = [{k: v for k, v in c.items() if k != "ImageManifestDescriptor"}
                         for c in doc.get("Containers") or []]
    return _sorted(doc)


_OLD_LAYOUT = {"/containers/json": _old_containers,
               "/images/json": lambda doc: [_old_image(im) for im in doc],
               "/info": _old_info, "/system/df": _old_df}


class DockerAPI:
    """Routes one request to an answer. No I/O of its own besides waiting, so the
    tests can drive it directly."""

    def __init__(self, docker: DockerState, clock=time.time, sleep=time.sleep):
        self.d, self.clock, self.sleep = docker, clock, sleep

    def route(self, method: str, target: str, alive=lambda: True, body: bytes = b"") \
            -> Answer:
        parts = urllib.parse.urlsplit(target)
        path = parts.path
        q = {k: v[-1] for k, v in urllib.parse.parse_qs(parts.query,
                                                         keep_blank_values=True).items()}
        m = re.match(r"^/v([0-9.]+)(/.*)$", path)
        version = None
        if m:
            version, path = m.group(1), m.group(2)
        handler, args = self._match(method, path)
        if handler is None:
            return not_found()
        if version is not None:
            try:
                v = tuple(int(x) for x in version.split("."))
            except ValueError:
                return not_found()
            if v < MIN_VERSION:
                return Answer(400, _TOO_OLD, (
                    f"client version {version} is too old. Minimum supported API version "
                    f"is 1.40, please upgrade your client to a newer version\n").encode())
            if v > API_VERSION:
                return Answer(400, _TOO_NEW, go_json({
                    "message": f"client version {version} is too new. Maximum supported "
                               f"API version is 1.56"}))
        try:
            if handler in (self.create, self.exec_create, self.exec_start):
                return handler(q, body, *args)       # these read the request body
            answer = handler(method, q, alive, *args)
            if version is not None and v <= OLD_LAYOUT_UP_TO and path in _OLD_LAYOUT \
                    and answer.status == 200 and answer.stream is None:
                answer.body = go_json(_OLD_LAYOUT[path](json.loads(answer.body)))
            return answer
        except BadFilter as e:
            return _msg(400, str(e))

    # -------------------------------------------------------------- routing

    def _match(self, method: str, path: str):
        routes = [
            (("GET", "HEAD"), r"/_ping", self.ping),
            (("GET",), r"/version", lambda *a: _json(200, self.d.version)),
            (("GET",), r"/info", lambda m, q, al: _json(200, self.d.info(self.clock()))),
            (("GET",), r"/containers/json", self.containers),
            (("POST",), r"/containers/create", self.create),
            (("POST",), r"/containers/([^/]+)/start", self.start),
            (("POST",), r"/containers/([^/]+)/exec", self.exec_create),
            (("POST",), r"/exec/([^/]+)/start", self.exec_start),
            (("POST",), r"/containers/([^/]+)/stop", self.stop),
            (("POST",), r"/containers/([^/]+)/wait", self.wait),
            (("DELETE",), r"/containers/([^/]+)", self.delete),
            (("GET",), r"/containers/([^/]+)/json", self.inspect),
            (("GET",), r"/containers/([^/]+)/top", self.top),
            (("GET",), r"/containers/([^/]+)/stats", self.stats),
            (("GET",), r"/containers/([^/]+)/logs", self.logs),
            (("POST",), r"/images/create", self.images_create),
            (("GET",), r"/images/json", self.images),
            (("GET",), r"/images/(.+)/json", self.image),
            (("GET",), r"/images/(.+)/history", self.history),
            (("GET",), r"/networks/([^/]+)", self.network),
            (("GET",), r"/networks", self.networks),
            (("GET",), r"/volumes", self.volumes),
            (("GET",), r"/volumes/([^/]+)", self.volume),
            (("GET",), r"/system/df", lambda m, q, al: _json(200, self.d.system_df(
                self.clock()))),
            (("GET",), r"/events", self.events),
            (("GET",), r"/plugins", lambda *a: _json(200, [])),
            (("GET",), r"/(swarm|nodes|services|tasks|secrets|configs)",
             lambda *a: _msg(503, _SWARM)),
        ]
        for methods, pattern, handler in routes:
            m = re.fullmatch(pattern, path)
            if m and method in methods:
                return handler, m.groups()
        return None, ()

    # -------------------------------------------------------------- handlers

    def ping(self, method, q, alive):
        if method == "HEAD":     # the handler sets both, so they sort with the rest
            hs = sorted(_PING + [("Content-Length", "0"),
                                 ("Content-Type", "text/plain; charset=utf-8")])
            return Answer(200, hs, None)
        return Answer(200, _PING, b"OK",
                      after_date=[("Content-Type", "text/plain; charset=utf-8")])

    def containers(self, method, q, alive):
        try:
            limit = int(q.get("limit", "-1") or "-1")
        except ValueError:
            return _msg(400, f"strconv.Atoi: parsing {q['limit']!r}: invalid syntax")
        return _json(200, self.d.list_containers(
            self.clock(), all=_bool(q, "all"), limit=limit, size=_bool(q, "size"),
            filters=_filters(q)))

    def create(self, q, body):
        """`POST /containers/create` (R23-R25): add the container to the shared state in
        the `created` state and answer 201 with its id, exactly as the daemon does. No
        container is ever started here — that is a later route — and nothing but the
        in-memory DockerState is touched (R26)."""
        try:
            config = json.loads(body or b"{}")
        except ValueError as e:
            return _msg(400, f"invalid JSON: {e}")
        if not isinstance(config, dict) or not config.get("Image"):
            return _msg(400, "Config cannot be empty in order to create a container")
        name = q.get("name")
        # The daemon looks the image up before it looks at the name (moby
        # daemon/create.go at docker-v29.8.1: GetImage, then newContainer), so a bad
        # name on a missing image is a 404 for the image. Its message quotes the allowed
        # characters without the `+` of the pattern (daemon/names).
        if name is not None and not re.fullmatch(r"/?[a-zA-Z0-9][a-zA-Z0-9_.-]+", name) \
                and self.d.find_image(str(config["Image"])) is not None:
            return _msg(400, f'Invalid container name ({name}), only '
                             r'[a-zA-Z0-9][a-zA-Z0-9_.-] are allowed')
        doc, err = self.d.create_container(config, name, self.clock())
        if err:
            kind, detail = err
            if kind == "no_image":
                return _msg(404, f"No such image: {detail}")
            if kind == "no_command":
                return _msg(400, "no command specified")
            taken, holder = detail          # the daemon names the container that has it
            return _msg(409, f'Conflict. The container name "/{taken}" is already in use '
                             f'by container "{holder}". You have to remove (or rename) '
                             f'that container to be able to reuse that name.')
        self.sleep(_TOOK["create"])
        return _json(201, {"Id": doc["Id"], "Warnings": []})

    def start(self, method, q, alive, ref):
        """`POST /containers/<id>/start` (R23): move the container to `running` and
        answer 204, or 304 if it was already running — the daemon's own codes. Only the
        shared DockerState changes; nothing is executed (R26)."""
        c, err = self._container(ref)
        if err:
            return err
        result = self.d.start_container(c, self.clock())
        if result not in ("running", "already"):
            # The daemon refuses and leaves the container `created` with the error in
            # its state (docker.py, start_container). A missing network is a 404.
            return _msg(404, result)
        if result == "running":
            self.sleep(_TOOK["start"])
        return _empty(204 if result == "running" else 304)

    def exec_create(self, q, body, ref):
        """`POST /containers/<id>/exec` (R23): register an exec on a running container and
        answer 201 with its id. Nothing runs until `/exec/<id>/start`."""
        c, err = self._container(ref)
        if err:
            return err
        if c["State"]["Status"] != "running":
            # moby daemon/errors.go, errNotRunning, at docker-v29.8.1 (not recorded)
            return _msg(409, f"container {c['Id']} is not running")
        try:
            cfg = json.loads(body or b"{}")
        except ValueError as e:
            return _msg(400, f"invalid JSON: {e}")
        return _json(201, {"Id": self.d.exec_create(c, cfg)})

    def exec_start(self, q, body, exec_id):
        """`POST /exec/<id>/start` (R23): run the exec and stream its output back on a
        hijacked connection (R6 framing unless the exec asked for a TTY). `Detach` runs it
        and returns 200 with no stream. Produced from the shared state only (R26)."""
        try:
            cfg = json.loads(body or b"{}")
        except ValueError:
            cfg = {}
        res = self.d.exec_start(exec_id)
        if res is None:
            return _msg(404, f"No such exec instance: {exec_id}")
        rec, stdout, stderr = res
        self.sleep(_TOOK["exec"])
        if cfg.get("Detach"):
            return _empty(200)
        out = b""
        if rec["tty"]:                               # a TTY stream is not framed
            out = (stdout if rec["stdout"] else b"") + (stderr if rec["stderr"] else b"")
        else:
            if rec["stdout"] and stdout:
                out += frame(stdout, 1)
            if rec["stderr"] and stderr:
                out += frame(stderr, 2)
        return Answer(200, _RAW, body=out, raw=True)

    def stop(self, method, q, alive, ref):
        """`POST /containers/<id>/stop` (R23): SIGTERM, then after the stop timeout
        SIGKILL - the probe's `sh` PID 1 ignores SIGTERM, so this takes ~10 s before the
        204, the consistency pair of wait's 137 (phase 2 n=19). 304 if already stopped."""
        c, err = self._container(ref)
        if err:
            return err
        if c["State"]["Status"] != "running":
            return _empty(304)
        try:
            timeout = int(q.get("t") or q.get("timeout") or 10)
        except ValueError:
            timeout = 10
        self.sleep(max(timeout, 0) + 0.25)           # the ignored SIGTERM, then SIGKILL
        self.d.stop_container(c, self.clock())
        return _empty(204)

    def wait(self, method, q, alive, ref):
        """`POST /containers/<id>/wait` (R23): block until the container is not running,
        then stream its exit code (chunked, as the daemon sends a response it only
        finishes once the container stops; phase 2 n=20: `{"StatusCode":137}`)."""
        c, err = self._container(ref)
        if err:
            return err
        start = self.clock()
        while c["State"]["Status"] == "running" and alive() \
                and self.clock() - start < STREAM_LIMIT_S:
            self.sleep(0.1)
        return Answer(200, _STD, stream=iter([go_json({"StatusCode": c["State"]["ExitCode"]})]))

    def delete(self, method, q, alive, ref):
        """`DELETE /containers/<id>` (R23-R24): remove the container, and with `?v=1` its
        anonymous volumes, putting the state back to its pre-attack set. A running
        container needs `?force=1` (else 409); deleting it again is 404 (phase 2 n=18,
        21). Only the shared state changes (R26)."""
        c, err = self._container(ref)
        if err:
            return err
        if c["State"]["Status"] == "running" and not _bool(q, "force"):
            return _msg(409, f"You cannot remove a running container {c['Id']}. Stop the "
                             f"container before attempting removal or force remove")
        self.d.delete_container(c, _bool(q, "v") or _bool(q, "volumes"))
        self.sleep(_TOOK["delete"])
        return _empty(204)

    def _container(self, ref):
        c = self.d.find(urllib.parse.unquote(ref))
        return c, (None if c else _msg(404, f"No such container: "
                                            f"{urllib.parse.unquote(ref)}"))

    def _not_running(self, c):
        """Docker's 409 for `/top` and `/stats` on a container that is not running — the
        state a just-created, never-started container is in."""
        if c["State"]["Status"] != "running":
            # moby daemon/container/container.go, GetRunningTask, at docker-v29.8.1
            return _msg(409, f"container {c['Id']} is not running")
        return None

    def inspect(self, method, q, alive, ref):
        c, err = self._container(ref)
        return err or _json(200, self.d.inspect(c["Id"], self.clock(),
                                                size=_bool(q, "size")))

    def top(self, method, q, alive, ref):
        c, err = self._container(ref)
        return err or self._not_running(c) or _json(
            200, self.d.top(c, self.clock(), q.get("ps_args") or "-ef"))

    def stats(self, method, q, alive, ref):
        c, err = self._container(ref)
        if err:
            return err
        if not _bool(q, "stream", True) and c["State"]["Status"] != "running":
            # Not a 409 as for /top: asked for one sample of a container that is not
            # running, the daemon answers at once with empty stats (moby
            # daemon/stats.go at docker-v29.8.1; not recorded on Ground Truth). It is
            # what `docker stats -a --no-stream` shows as a row of zeros.
            zero = {"cpu_usage": {"total_usage": 0, "usage_in_kernelmode": 0,
                                  "usage_in_usermode": 0},
                    "throttling_data": {"periods": 0, "throttled_periods": 0,
                                        "throttled_time": 0}}
            return _json(200, {
                "id": c["Id"], "name": c["Name"], "os_type": "linux",
                "read": "0001-01-01T00:00:00Z", "cpu_stats": zero, "memory_stats": {},
                "pids_stats": {}, "blkio_stats": dict.fromkeys(
                    ("io_service_bytes_recursive", "io_serviced_recursive",
                     "io_queue_recursive", "io_service_time_recursive",
                     "io_wait_time_recursive", "io_merged_recursive", "io_time_recursive",
                     "sectors_recursive")),
                "num_procs": 0, "storage_stats": {}, "preread": "0001-01-01T00:00:00Z",
                "precpu_stats": zero})
        if err := self._not_running(c):
            return err
        if not _bool(q, "stream", True) or _bool(q, "one-shot"):
            if _bool(q, "one-shot"):            # no waiting, no previous sample
                return _json(200, self.d.stats(c, int(self.clock() * NS), None))
            # The daemon samples once a second and needs two samples: 1-2 s.
            up = self.clock() - self.d.boot
            self.sleep(2.0 - (up % 1.0))
            now = int(self.clock() * NS)
            return _json(200, self.d.stats(c, now, now - 1_001_500_000))

        def gen():
            pre = None
            start = self.clock()
            while alive() and self.clock() - start < STREAM_LIMIT_S:
                now = int(self.clock() * NS)
                yield go_json(self.d.stats(c, now, pre))
                pre = now
                self.sleep(1.0)
        return Answer(200, _STD, stream=gen())

    def logs(self, method, q, alive, ref):
        c, err = self._container(ref)
        if err:
            return err
        out, errs = _bool(q, "stdout"), _bool(q, "stderr")
        if not (out or errs):
            return _msg(400, "Bad parameters: you must choose at least one stream")
        since, until = _unix(q.get("since")), _unix(q.get("until"))
        stamps, follow = _bool(q, "timestamps"), _bool(q, "follow")
        tail = q.get("tail", "all")

        def select_lines(lines):
            if tail not in ("", "all"):
                try:
                    n = int(tail)
                except ValueError:
                    n = -1
                if n >= 0:
                    lines = lines[-n:] if n else []
            return [x for x in lines
                    if (since is None or x[0] >= since * NS)
                    and (until is None or x[0] <= until * NS)]

        def render(t, stream, text):
            if stamps:
                text = f"{go_time(t, fixed=True)} {text}"
            return frame(text.encode(), stream)

        def wanted(stream):
            return out if stream == 1 else errs

        def gen():
            now = int(self.clock() * NS)
            sent = now
            lines = [x for x in self.d.log_lines(c, now) if wanted(x[1])]
            for t, stream, text in select_lines(lines):
                yield render(t, stream, text)
            if not follow:
                return
            start = self.clock()
            while alive() and self.clock() - start < STREAM_LIMIT_S:
                if until is not None and self.clock() > until:
                    return
                self.sleep(1.0)
                now = int(self.clock() * NS)
                for t, stream, text in self.d.log_lines(c, now):
                    if sent < t <= now and wanted(stream):
                        yield render(t, stream, text)
                sent = now
        return Answer(200, _STD, ctype=STREAM, stream=gen())

    def images_create(self, method, q, alive):
        """`POST /images/create` (R2, R23): the pull fails - the lab has no internet and
        nothing is cached - after the resolver gives up (~5 s), with the DNS failure in
        the 500 body. This is where the attacker lands right before the `No such image`
        create. Built from the shared state's substitution, never a real pull (R26)."""
        self.sleep(5.0)                              # the resolver's retries, then failure
        return _json(500, {"message": self.d.pull_error(q.get("fromImage", ""),
                                                        q.get("tag", ""))})

    def images(self, method, q, alive):
        return _json(200, self.d.list_images(_filters(q), _bool(q, "shared-size"),
                                             _bool(q, "manifests")))

    def _image(self, ref):
        ref = urllib.parse.unquote(ref)
        img = self.d.find_image(ref)
        if img is None:
            return None, _msg(404, f"No such image: {_ref_with_tag(ref)}")
        return img, None

    def image(self, method, q, alive, ref):
        img, err = self._image(ref)
        return err or _json(200, self.d.image_inspect(img, _bool(q, "manifests")))

    def history(self, method, q, alive, ref):
        img, err = self._image(ref)
        return err or _json(200, self.d.image_history(img))

    def network(self, method, q, alive, ref):
        ref = urllib.parse.unquote(ref)
        n = self.d.find_network(ref)
        return _json(200, self.d.network_inspect(n)) if n else _msg(
            404, f"network {ref} not found")

    def networks(self, method, q, alive):
        return _json(200, self.d.list_networks(_filters(q)))

    def volumes(self, method, q, alive):
        return _json(200, {"Volumes": self.d.list_volumes(_filters(q)), "Warnings": None})

    def volume(self, method, q, alive, name):
        v = self.d.find_volume(urllib.parse.unquote(name))
        return _json(200, v) if v else _msg(
            404, f"get {urllib.parse.unquote(name)}: no such volume")

    def events(self, method, q, alive):
        """The daemon's events (docker.py `events`: nodered's health checks). With
        `since`, the past ones first, as far back as the daemon's memory of its last
        256 events reaches; then, unless `until` has passed, new ones as they happen
        until it does or the client hangs up (R9: a window in the past returns at once,
        n=10)."""
        since, until = _unix(q.get("since")), _unix(q.get("until"))
        filters = _filters(q)
        now = self.clock()
        self.d.events(0, 0, filters)                    # rejects a bad filter up front

        def past():
            if since is None:
                return []
            end = min(until if until is not None else now, now)
            recent = self.d.events(int((now - 3600) * NS), int(now * NS), filters)[-256:]
            return [e for e in recent if since * NS <= e["timeNano"] <= end * NS]

        def gen():
            for e in past():
                yield go_json(e)
            if until is not None and until <= now:
                return
            sent = int(now * NS)
            start = self.clock()
            while alive() and self.clock() - start < STREAM_LIMIT_S:
                self.sleep(0.5)
                t = self.clock()
                stop = until is not None and t >= until
                upto = int(min(t, until) * NS) if until is not None else int(t * NS)
                for e in self.d.events(sent + 1, upto, filters):
                    yield go_json(e)
                sent = upto
                if stop:
                    return
        return Answer(200, _STD, ctype="application/jsonl", stream=gen())


# ------------------------------------------------------------------ the HTTP side


def make_handler(api: DockerAPI, record=lambda entry: None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 300

        def handle_one_request(self):
            try:
                self.raw_requestline = self.rfile.readline(65537)
                if not self.raw_requestline:
                    self.close_connection = True
                    return
                if len(self.raw_requestline) > 65536 or not self.parse_request():
                    if len(self.raw_requestline) > 65536:
                        self.send_error(400)
                    return
                self._serve()
                self.wfile.flush()
            except (TimeoutError, ConnectionError, OSError):
                self.close_connection = True

        def send_error(self, code, message=None, explain=None):
            """Go's own answer to a request it cannot parse, then hang up."""
            phrase = HTTPStatus(code).phrase if code in HTTPStatus._value2member_map_ \
                else "Bad Request"
            try:
                self.wfile.write(f"HTTP/1.1 {code} {phrase}\r\nContent-Type: text/plain; "
                                 f"charset=utf-8\r\nConnection: close\r\n\r\n"
                                 f"{code} {phrase}".encode())
            except OSError:
                pass
            self.close_connection = True

        def _alive(self) -> bool:
            """False once the client has hung up (for streams)."""
            try:
                r, _, _ = select.select([self.connection], [], [], 0)
                if r and not self.connection.recv(1, socket.MSG_PEEK):
                    return False
            except OSError:
                return False
            return True

        def _serve(self):
            t0 = time.monotonic()
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n > 0 else b""
            try:
                a = api.route(self.command, self.path, self._alive, body)
            except Exception:
                log.exception("docker api request failed: %s %s", self.command, self.path)
                a = _msg(500, "internal server error")
            http10 = self.request_version == "HTTP/1.0"
            wants_close = self.headers.get("Connection", "").lower() == "close"
            date = ("Date", email.utils.formatdate(usegmt=True))
            headers = list(a.headers)
            if a.raw:                                # hijacked stream (exec): no Date,
                self._serve_raw(a, body, t0)         # no Content-Length, then close
                return
            if a.body is None:                       # HEAD: headers only
                headers.append(date)
                body_bytes, chunked = b"", False
            elif a.stream is None and len(a.body) <= CHUNK_AFTER:
                headers += [date, ("Content-Length", str(len(a.body)))]
                headers += a.after_date or []
                body_bytes, chunked = a.body, False
            else:
                headers.append(date)
                if not http10:
                    headers.append(("Transfer-Encoding", "chunked"))
                body_bytes, chunked = a.body, not http10
            if http10 and (a.stream is not None or a.body and len(a.body) > CHUNK_AFTER):
                self.close_connection = True         # HTTP/1.0: the end is the hang-up
            if wants_close:
                headers.append(("Connection", "close"))
                self.close_connection = True
            head = f"HTTP/1.1 {a.status} {HTTPStatus(a.status).phrase}\r\n" + "".join(
                f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
            sent = 0
            self.wfile.write(head.encode())
            if self.command != "HEAD":
                chunks = a.stream if a.stream is not None else [body_bytes]
                for piece in chunks:
                    if not piece:
                        continue
                    self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n"
                                     if chunked else piece)
                    self.wfile.flush()
                    sent += len(piece)
                if chunked:
                    self.wfile.write(b"0\r\n\r\n")
            self._record(a.status, sent, body, t0)

        def _serve_raw(self, a, body, t0):
            """A hijacked response (exec start): the headers as given, then the raw frames,
            then the connection closes - the daemon does not send Date, Content-Length or
            chunked framing here, and the client reads to EOF."""
            out = a.body if isinstance(a.body, (bytes, bytearray)) else \
                b"".join(a.stream or [])
            head = f"HTTP/1.1 {a.status} {HTTPStatus(a.status).phrase}\r\n" + "".join(
                f"{k}: {v}\r\n" for k, v in a.headers) + "\r\n"
            self.wfile.write(head.encode())
            if self.command != "HEAD":
                self.wfile.write(out)
            self.close_connection = True
            self._record(a.status, len(out), body, t0)

        def _record(self, status, sent, body, t0):
            record({"event": "docker_api", "src_ip": self.client_address[0],
                    "src_port": self.client_address[1], "method": self.command,
                    "path": self.path, "status": status, "bytes": sent,
                    "user_agent": self.headers.get("User-Agent", ""),
                    "request_body": body[:4096].decode("utf-8", "replace"),
                    "elapsed_ms": round((time.monotonic() - t0) * 1000, 1)})

        def log_message(self, fmt, *args):
            log.debug("%s " + fmt, self.address_string(), *args)

    return Handler


def serve(api: DockerAPI, bind: str, port: int, record=lambda entry: None):
    srv = ThreadingHTTPServer((bind, port), make_handler(api, record))
    srv.daemon_threads = True
    return srv
