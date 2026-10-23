"""The shell's `docker` commands, answered from the fake API.

This is the shell side of the cross-surface consistency claim (R10, R11). It is a port
of what the real client does, not a separate renderer: for each command line it asks
THE FAKE API ITSELF, in process, the very requests the real docker client would send
(`GET /containers/json?all=1&filters=…`), and formats the JSON that comes back the way
the client does. So the shell cannot show anything the API does not: whatever a
container list, a filter, an inspect document or a log looks like over HTTP is what the
shell prints. Like the API, it never runs a real `docker` (R26).

Answered here, with every flag (PATHS below; aliases such as `docker container ls`
included): `ps`, `images`, `inspect`, `logs` (since 2026-10-08) and, since 2026-10-13,
the other read-only commands: `network ls|inspect`, `volume ls|inspect`, `version`,
`info`, `system df`, `top`, `stats`, `container inspect`, `image inspect`, and from the
compose plugin `compose ls`, `compose ps`, `compose version`. An unknown flag, a missing
argument or a bad template gets the client's own error text, not a model's guess; a
valid `--format` template is evaluated (gotemplate.py). Four commands that CHANGE state
are answered here too, by the same API calls the client makes, so that what the shell
did is what both surfaces then show: `start`, `stop`, `rm` and `pull` (which fails, as
on a machine without internet). `run` and `create` are answered here when the image
is not on the machine, which without internet always ends in the same pull error, and,
with one of the three images that are on it, `create` and `run -d` with the common
flags (_local_image): the container is made by the API's own create and start.
Every other `docker …` line (run without -d, which would show the container's own
output; create and run with a flag outside that list; exec, kill, restart, network and
volume changes, compose up, …) still raises Unsupported and goes to the model: a
model's answer to those changes nothing in the shared state.

Checked against the real client: Ground Truth's exact docker-ce-cli 29.8.1 and its
compose plugin 5.5.1, run against this fake API (tools/docker_cli_oracle.py), case by
case in tests/test_dockercli.py. What the client knows by itself (help texts, its half
of `version` and `info`) is recorded from it in docker_help.json and docker_client.json
(tools/build_docker_client_data.py).

Known limits. `docker inspect -f`: the real client evaluates a template against its own
Go structures first and against the raw JSON only if that fails. The two differ when a
template prints a whole object instead of a field: `{{.Mounts}}` shows `[{bind  /root…}]`
there and `[map[Destination:… ]]` here. Fields, `json`, `range`, `index`, `len` and the
default (no template) are exact. `docker logs -f` and `docker stats` without
`--no-stream` print what is there once and return, where the real ones keep going.
`docker info` lists its runtimes in the order the real client happens to print them in
(Go does not fix it). `docker compose ps --format json` goes to the model.
"""
from __future__ import annotations
import copy
import datetime as dt
import functools
import json
import pathlib
import re
import urllib.parse

from . import gotemplate, machine
from .docker import human_duration
from .gotemplate import Num, Obj, Template, TemplateError

API_VERSION = "v1.56"


def _data(name: str) -> dict:
    path = pathlib.Path(__file__).parent / name
    return json.loads(path.read_text()) if path.exists() else {}


# Recorded from the real client (tools/build_docker_client_data.py).
_HELP = _data("docker_help.json")
_CLIENT = _data("docker_client.json")

# Every command path answered here -> the method of _Client that answers it.
PATHS = {
    ("ps",): "ps", ("container", "ls"): "ps", ("container", "list"): "ps",
    ("container", "ps"): "ps",
    ("images",): "images", ("image", "ls"): "images", ("image", "list"): "images",
    ("inspect",): "inspect", ("container", "inspect"): "container_inspect",
    ("image", "inspect"): "image_inspect",
    ("logs",): "logs", ("container", "logs"): "logs",
    ("network", "ls"): "network_ls", ("network", "list"): "network_ls",
    ("network", "inspect"): "network_inspect",
    ("volume", "ls"): "volume_ls", ("volume", "list"): "volume_ls",
    ("volume", "inspect"): "volume_inspect",
    ("version",): "version", ("info",): "info", ("system", "info"): "info",
    ("system", "df"): "system_df",
    ("stats",): "stats", ("container", "stats"): "stats",
    ("top",): "top", ("container", "top"): "top",
    # These four change the shared state, through the same API calls the client makes.
    ("start",): "start", ("container", "start"): "start",
    ("stop",): "stop", ("container", "stop"): "stop",
    ("rm",): "rm", ("container", "rm"): "rm",
    ("pull",): "pull", ("image", "pull"): "pull",
    # Only for an image that is not on the machine (the pull fails, as it must without
    # internet); with a local image they go to the model.
    ("run",): "run", ("container", "run"): "run",
    ("create",): "create", ("container", "create"): "create",
    # Only where the shared state alone decides the answer: no such container, or one
    # that is not running. What a program prints inside a container is the model's.
    ("exec",): "exec", ("container", "exec"): "exec",
}
# Spellings the client accepts and its help does not list: not answered here, but not
# an unknown command either.
_UNLISTED = {"remove", "list", "ps", "rmi", "images"}
GROUPS = ("container", "image", "network", "system", "volume")
COMPOSE_PROJECT_DIR = "/root/iot-stack"
COMPOSE_FILE = COMPOSE_PROJECT_DIR + "/docker-compose.yml"


def _usage(path: str) -> str:
    """`docker ps [OPTIONS]`: the first line of the command's own help."""
    return _HELP[path].split("\n")[0].removeprefix("Usage:  ")


# `docker run image cmd` in the foreground made, started and ended in code (shell.py's
# code_scope "docker_run_foreground"); off, the whole line is the model's, as before.
RUN_ATTACHED = lambda: True       # shell.set_scope: the switch docker_run_foreground


class Unsupported(Exception):
    """A `docker` line this module does not render; the shell falls back to the model."""


class ModelOutput(Unsupported):
    """The state change is done here; what the program prints is the model's. `after`
    is called with the answer's exit status, the time and the answer's text once the model
    has answered."""

    def __init__(self, why: str, after):
        super().__init__(why)
        self.after = after


class _Exit(Exception):
    """The client stops with this text and exit status."""

    def __init__(self, text: str, code: int):
        super().__init__(text)
        self.text, self.code = text, code


def render(docker, argv: list[str], sess, now: float) -> tuple[str, int]:
    """`argv` is the whole command (argv[0] == 'docker'). Returns (output, exit) or
    raises Unsupported. The output is stdout and stderr as the terminal shows them,
    without the final newline. A command that takes time on the real machine
    (`docker stats` waits for two samples) adds that to `sess.delay`."""
    if len(argv) < 2:
        raise Unsupported("docker with no subcommand")
    client = _Client(docker, now, sess)
    try:
        if argv[1] == "compose":
            text, code = client.compose(argv[2:])
        else:
            path, rest = _resolve(argv[1:])
            client.path = " ".join(path)
            text, code = getattr(client, PATHS[path])(rest)
    except _Exit as e:
        text, code = e.text, e.code
    if client.delay and hasattr(sess, "delay"):
        sess.delay += client.delay
    return text.removesuffix("\n"), code


def _resolve(words: list[str]) -> tuple[tuple, list[str]]:
    """(command path, the arguments after it). `docker network` alone prints the
    group's help; a subcommand the group does not have gets the client's error; one it
    has but that is not answered here raises Unsupported."""
    first = words[0]
    if first in GROUPS:
        if len(words) == 1 or words[1] == "--help":
            raise _Exit(_HELP[first], 0)
        if (first, words[1]) in PATHS:
            return (first, words[1]), words[2:]
        if words[1].startswith("-"):
            raise Unsupported(f"{first} {words[1]}")
        known = re.findall(r"(?m)^  (\S+)", _HELP[first].split("Commands:")[1])
        if words[1] not in known and words[1] not in _UNLISTED:
            usage = "docker volume COMMAND" if first == "volume" else f"docker {first}"
            raise _Exit(f"docker: unknown command: docker {first} {words[1]}\n\nUsage:  {usage}"
                        f"\n\nRun 'docker {first} --help' for more information\n", 1)
        raise Unsupported(f"{first} {words[1]}")
    if (first,) in PATHS:
        return (first,), words[1:]
    raise Unsupported(first)


# ------------------------------------------------------------------ flags (spf13/pflag)

def _usage_error(sub: str, message: str) -> _Exit:
    return _Exit(f"{message}\n\nUsage:  {_usage(sub)}\n\nRun 'docker {sub} --help' for more "
                 f"information\n", 125)


def _parse(sub: str, rest: list[str], spec: dict, interspersed: bool = True) -> tuple[dict, list[str]]:
    """Flags the way cobra/pflag reads them: `-aq`, `-n 2`, `-n2`, `--last=2`, `--last 2`,
    `--all=false`, flags after operands, `--` ends them. `spec` maps the long name to
    (short letter or '', kind) with kind bool | str | int | list."""
    short = {s: name for name, (s, _) in spec.items() if s}
    opts = {name: ([] if kind == "list" else False if kind == "bool" else None)
            for name, (_, kind) in spec.items()}
    operands, i = [], 0

    def label(name):
        s = spec[name][0]
        return f'"-{s}, --{name}"' if s else f'"--{name}"'

    def store(name, value):
        kind = spec[name][1]
        if kind == "bool":
            if value not in ("1", "0", "t", "f", "T", "F", "true", "false", "TRUE", "FALSE",
                             "True", "False"):
                raise _usage_error(sub, f'invalid argument "{value}" for {label(name)} flag: '
                                        f'strconv.ParseBool: parsing "{value}": invalid syntax')
            opts[name] = value in ("1", "t", "T", "true", "TRUE", "True")
        elif kind == "int":
            if not re.fullmatch(r"[-+]?\d+", value):
                raise _usage_error(sub, f'invalid argument "{value}" for {label(name)} flag: '
                                        f'strconv.ParseInt: parsing "{value}": invalid syntax')
            opts[name] = int(value)
        elif kind == "list":
            opts[name].append(value)
        else:
            opts[name] = value

    while i < len(rest):
        a = rest[i]
        i += 1
        if a == "--":
            operands += rest[i:]
            break
        if a == "--help":
            raise _Exit(_HELP[sub], 0)
        if a.startswith("--"):
            name, eq, value = a[2:].partition("=")
            if name not in spec:
                raise _usage_error(sub, f"unknown flag: --{name}")
            if spec[name][1] == "bool":
                if eq:
                    store(name, value)
                else:
                    opts[name] = True
                continue
            if not eq:
                if i >= len(rest):
                    raise _usage_error(sub, f"flag needs an argument: --{name}")
                value = rest[i]
                i += 1
            store(name, value)
        elif a.startswith("-") and len(a) > 1:
            letters = a[1:]
            for k, ch in enumerate(letters):
                if ch == "h":
                    raise _Exit("Flag shorthand -h has been deprecated, use --help\n"
                                + _HELP[sub], 0)
                if ch not in short:
                    raise _usage_error(sub, f"unknown shorthand flag: '{ch}' in -{letters[k:]}")
                name = short[ch]
                if spec[name][1] == "bool":
                    opts[name] = True
                    continue
                value = letters[k + 1:]
                if value.startswith("="):
                    value = value[1:]
                elif not value:
                    if i >= len(rest):
                        raise _usage_error(sub, f"flag needs an argument: '{ch}' in -{ch}")
                    value = rest[i]
                    i += 1
                store(name, value)
                break
        else:
            if not interspersed:              # `docker run`: after the image, the
                operands += rest[i - 1:]      # rest belongs to the container's command
                break
            operands.append(a)
    return opts, operands


def _spec_from_help(path: str) -> dict:
    """The flags of a command, read off its own help text: `-d, --detach` is a switch,
    `--name string` takes a value. For the commands with a hundred flags."""
    spec = {}
    for m in re.finditer(r"(?m)^\s+(?:-(\w), )?--([\w-]+)( [a-z][\w-]*)?\s{2,}\S", _HELP[path]):
        spec[m.group(2)] = (m.group(1) or "", "list" if m.group(3) else "bool")
    if "network" in spec:                 # spellings the client accepts and does not list
        spec.update({"net": ("", "list"), "net-alias": ("", "list"), "dns-opt": ("", "list")})
    return spec


# ------------------------------------------------------------------ tables (text/tabwriter)

def _tabwriter(lines: list[str], minwidth: int = 10, padding: int = 3) -> str:
    """Go's tabwriter as docker sets it up (minimum cell width 10, padding 3; `top`,
    `version` and compose use others): cells end at a tab; a column is as wide as its
    widest cell plus the padding; the last cell of a line is not padded."""
    rows = [line.split("\t") for line in lines]
    widths = {}
    for r in rows:
        for i, cell in enumerate(r[:-1]):
            widths[i] = max(widths.get(i, 0), len(cell) + padding, minwidth)
    return "\n".join("".join(cell.ljust(widths[i]) if i < len(r) - 1 else cell
                             for i, cell in enumerate(r)) for r in rows)


def _human_size(n) -> str:
    """go-units HumanSizeWithPrecision(n, 3): SI, three significant figures (57MB)."""
    size, units = float(n), ["B", "kB", "MB", "GB", "TB", "PB"]
    i = 0
    while size >= 1000 and i < len(units) - 1:
        size, i = size / 1000, i + 1
    return f"{size:.3g}{units[i]}"


def _size4(n) -> str:
    """go-units HumanSize: SI, four significant figures (1.816GB)."""
    size, units = float(n), ["B", "kB", "MB", "GB", "TB", "PB"]
    i = 0
    while size >= 1000 and i < len(units) - 1:
        size, i = size / 1000, i + 1
    return f"{size:.4g}{units[i]}"


def _bytes_size(n) -> str:
    """go-units BytesSize: binary units, four significant figures (7.874GiB)."""
    size, units = float(n), ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    i = 0
    while size >= 1024 and i < len(units) - 1:
        size, i = size / 1024, i + 1
    return f"{size:.4g}{units[i]}"


def _natural_key(name: str):
    """fvbommel/sortorder NaturalLess, which the client sorts volume names with: runs
    of digits compare as numbers and sort before other characters."""
    def less(a: str, b: str) -> bool:
        i = j = 0
        while i < len(a) and j < len(b):
            da, db = a[i].isdigit() and a[i].isascii(), b[j].isdigit() and b[j].isascii()
            if da != db:
                return da
            if not da:
                if a[i] != b[j]:
                    return a[i] < b[j]
                i, j = i + 1, j + 1
                continue
            while i < len(a) and a[i] == "0":
                i += 1
            while j < len(b) and b[j] == "0":
                j += 1
            ni, nj = i, j
            while i < len(a) and a[i].isdigit() and a[i].isascii():
                i += 1
            while j < len(b) and b[j].isdigit() and b[j].isascii():
                j += 1
            if i - ni != j - nj:
                return i - ni < j - nj
            if a[ni:i] != b[nj:j]:
                return a[ni:i] < b[nj:j]
            if ni != nj:
                return ni < nj
        return len(a) < len(b)
    return functools.cmp_to_key(lambda a, b: -1 if less(a, b) else (1 if less(b, a) else 0))(name)


def _go_time(rfc3339: str) -> str:
    """Go's time.String() of an RFC 3339 time, in the machine's zone:
    `2026-10-11 18:31:18.865782573 -0400 EDT`."""
    m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?(Z|[-+]\d\d:\d\d)",
                     rfc3339)
    if not m:
        return rfc3339
    y, mo, d, h, mi, sec, frac, zone = m.groups()
    offset = dt.timezone.utc if zone == "Z" else dt.timezone(
        (1 if zone[0] == "+" else -1) * dt.timedelta(hours=int(zone[1:3]), minutes=int(zone[4:])))
    local = dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec),
                        tzinfo=offset).astimezone(machine.TZ)
    return (local.strftime("%Y-%m-%d %H:%M:%S") + (frac or "").rstrip("0").rstrip(".")
            + local.strftime(" %z %Z"))


def _local_time(epoch: float) -> str:
    """Go's `2006-01-02 15:04:05 -0700 MST` in the machine's zone."""
    return dt.datetime.fromtimestamp(int(epoch), machine.TZ).strftime("%Y-%m-%d %H:%M:%S %z %Z")


def _ellipsis(text: str, width: int) -> str:
    return text if len(text) <= width else text[:width - 1] + "…"


def _method(fn):
    fn.takes_args = True
    return fn


# ------------------------------------------------------------------ the client

class _Client:
    def __init__(self, docker, now: float, sess):
        from .dockerapi import DockerAPI                 # here: dockerapi imports docker.py
        # Where the daemon waits (one-shot stats wait for a second sample), nothing waits
        # here: the API's clock moves on instead, and the wait is reported as `delay`.
        self._clock = now
        self.api = DockerAPI(docker, clock=lambda: self._clock, sleep=self._waited)
        self.docker, self.now, self.sess = docker, now, sess
        self.path = ""               # the command as typed: `ps`, `container ls`, …
        self.delay = 0.0             # seconds the real command takes beyond an instant
        # The client's stdout is a terminal unless the session has none or the command
        # is the left side of a pipe.
        self.tty = bool(sess.terminal) and not getattr(sess, "piped", False)

    def _waited(self, seconds: float):
        self._clock += seconds
        self.delay = max(self.delay, self._clock - self.now)

    # -- talking to the API, as the real client does

    def get(self, path: str, query: dict | None = None):
        """(status, body bytes). Query keys go out sorted, as Go's url.Values does."""
        q = urllib.parse.urlencode(sorted((query or {}).items()))
        answer = self.api.route("GET", f"/{API_VERSION}{path}" + (f"?{q}" if q else ""))
        body = b"".join(answer.stream) if answer.stream is not None else answer.body
        return answer.status, bytes(body or b"")

    @staticmethod
    def daemon_error(body: bytes) -> str:
        try:
            return "Error response from daemon: " + json.loads(body)["message"]
        except (ValueError, KeyError, TypeError):
            return "Error response from daemon: " + body.decode("utf-8", "replace").strip()

    def send(self, method: str, path: str, query: dict | None = None, body=None):
        """A request that changes state (POST, DELETE): (status, body bytes)."""
        q = urllib.parse.urlencode(sorted((query or {}).items()))
        answer = self.api.route(method, f"/{API_VERSION}{path}" + (f"?{q}" if q else ""),
                                body=json.dumps(body).encode() if body is not None else b"")
        body = b"".join(answer.stream) if answer.stream is not None else answer.body
        return answer.status, bytes(body or b"")

    def get_json(self, path: str, query: dict | None = None):
        status, body = self.get(path, query)
        if status >= 400:
            raise _Exit(self.daemon_error(body) + "\n", 1)
        return gotemplate.loads(body.decode())

    def wrong_args(self, what: str, see: str = "Run") -> _Exit:
        """cobra's complaint about the number of arguments."""
        return _Exit(f"docker: 'docker {self.path}' {what}\n\nUsage:  {_usage(self.path)}\n\n"
                     f"{see} 'docker {self.path} --help' for more information\n", 1)

    @staticmethod
    def filters(values: list[str], sub: str) -> dict:
        """`-f key=value` as the client sends it: {"key": {"value": true}}."""
        out = {}
        for v in values:
            key, eq, value = v.partition("=")
            if not eq:
                raise _Exit(f"invalid argument \"{v}\" for \"-f, --filter\" flag: bad format of "
                            f"filter (expected name=value)\n\nUsage:  {_usage(sub)}\n\nRun "
                            f"'docker {sub} --help' for more information\n", 125)
            out.setdefault(key.strip(), {})[value.strip()] = True
        return out

    # -- docker ps

    def ps(self, rest):
        opts, operands = _parse(self.path, rest, {
            "all": ("a", "bool"), "filter": ("f", "list"), "format": ("", "str"),
            "last": ("n", "int"), "latest": ("l", "bool"), "no-trunc": ("", "bool"),
            "quiet": ("q", "bool"), "size": ("s", "bool")})
        if operands:
            raise self.wrong_args("accepts no arguments")
        fmt, trunc, warning = opts["format"], not opts["no-trunc"], ""
        if opts["quiet"]:
            if fmt:
                warning = ("WARNING: Ignoring custom format, because both --format and --quiet "
                           "are set.\n")
            fmt = "{{.ID}}"
        elif not fmt or fmt == "table":
            fmt = ("table {{.ID}}\t{{.Image}}\t{{.Command}}\t{{.RunningFor}}\t{{.Status}}\t"
                   "{{.Ports}}\t{{.Names}}" + ("\t{{.Size}}" if opts["size"] else ""))
        table, template = self._template(fmt, "failed to parse template: ")
        # The client runs the template once on nothing, to learn whether it asks for the
        # size; a template that fails does so here, before any request.
        asked = []
        if template is not None:
            try:
                template.render(self._container({}, trunc, asked))
            except TemplateError as e:
                raise _Exit(f"failed to execute template: {e}\n", 1)
        query = {}
        if opts["all"]:
            query["all"] = "1"
        limit = 1 if opts["latest"] else opts["last"]
        if limit is not None and limit > 0:
            query["limit"] = str(limit)
        if opts["size"] or asked:
            query["size"] = "1"
        f = self.filters(opts["filter"], self.path)
        if f:
            query["filters"] = json.dumps(f, sort_keys=True, separators=(",", ":"))
        containers = self.get_json("/containers/json", query)
        rows = [self._container(c, trunc, []) for c in containers]
        text, code = self._emit(fmt, table, template, rows, _PS_HEADERS,
                                "*formatter.ContainerContext")
        return warning + text, code

    def _container(self, c: dict, trunc: bool, asked: list) -> Obj:
        """The client's ContainerContext for one entry of GET /containers/json."""
        def size():
            asked.append(True)
            rw, root = c.get("SizeRw"), c.get("SizeRootFs")
            text = _human_size(Num(rw).value if rw is not None else 0)
            if root is not None and Num(root).value > 0:
                text += f" (virtual {_human_size(Num(root).value)})"
            return text

        def mounts():
            names = []
            for m in c.get("Mounts") or []:
                name = m.get("Name") or m.get("Source") or ""
                names.append(_ellipsis(name, 15) if trunc else name)
            return ",".join(names)

        def platform():
            p = (c.get("ImageManifestDescriptor") or {}).get("platform")
            if not p:
                return None
            return _Platform(p)

        labels = c.get("Labels") or {}
        created = Num(c["Created"]).value if "Created" in c else 0
        command = c.get("Command", "")
        return Obj("*formatter.ContainerContext", {
            "ID": lambda: c.get("Id", "")[:12] if trunc else c.get("Id", ""),
            "Names": lambda: ",".join(n.lstrip("/") for n in c.get("Names") or []),
            "Image": lambda: c.get("Image", ""),
            "Command": lambda: '"' + (_ellipsis(command, 20) if trunc else command) + '"',
            "CreatedAt": lambda: _local_time(created),
            "RunningFor": lambda: human_duration(max(self.now - created, 0)) + " ago",
            "Ports": lambda: _ports(c.get("Ports") or []),
            "State": lambda: c.get("State", ""),
            "Status": lambda: c.get("Status", ""),
            "Size": size,
            "Labels": lambda: ",".join(sorted(f"{k}={v}" for k, v in labels.items())),
            "Label": _method(lambda name: labels.get(name, "")),
            "Mounts": mounts,
            "LocalVolumes": lambda: str(sum(1 for m in c.get("Mounts") or []
                                            if m.get("Driver") == "local")),
            "Networks": lambda: ",".join(sorted(((c.get("NetworkSettings") or {})
                                                 .get("Networks") or {}))),
            "Platform": platform,
            "HealthStatus": lambda: (c.get("Health") or {}).get("Status") or "none",
        })

    # -- docker images

    def images(self, rest):
        opts, operands = _parse(self.path, rest, {
            "all": ("a", "bool"), "digests": ("", "bool"), "filter": ("f", "list"),
            "format": ("", "str"), "no-trunc": ("", "bool"), "quiet": ("q", "bool"),
            "tree": ("", "bool")})
        if len(operands) > 1:
            raise self.wrong_args("requires at most 1 argument")
        f = self.filters(opts["filter"], self.path)
        if operands:
            f.setdefault("reference", {})[operands[0]] = True
        query = {}
        if opts["all"]:
            query["all"] = "1"
        if f:
            query["filters"] = json.dumps(f, sort_keys=True, separators=(",", ":"))
        classic = opts["quiet"] or opts["no-trunc"] or opts["digests"] or opts["format"] is not None
        if opts["tree"]:
            for name, shown in (("format", "format"), ("quiet", "quiet"),
                                ("no-trunc", "no-trunc"), ("digests", "show-digest")):
                if opts[name]:
                    raise _Exit(f"--{shown} is not yet supported with --tree\n", 1)
        if not classic:
            query["manifests"] = "1"
            return self._image_list(self.get_json("/images/json", query), opts["tree"]), 0

        fmt, trunc, warning = opts["format"], not opts["no-trunc"], ""
        if fmt is not None and fmt != "table":
            pass                              # for images a format wins over --quiet
        elif opts["quiet"]:
            fmt = "{{.ID}}"
        else:
            fmt = ("table {{.Repository}}\t{{.Tag}}\t"
                   + ("{{.Digest}}\t" if opts["digests"] else "")
                   + "{{.ID}}\t{{.CreatedSince}}\t{{.Size}}")
        table, template = self._template(fmt, "template parsing error: ")
        rows = []
        for im in self.get_json("/images/json", query):
            refs = im.get("RepoTags") or ["<none>:<none>"]
            digests = {d.split("@")[0]: d.split("@")[1] for d in im.get("RepoDigests") or []
                       if "@" in d}
            for ref in refs:
                repo, _, tag = ref.rpartition(":")
                show = opts["digests"] or ".Digest" in fmt       # the client's own test
                rows.append(self._image(im, repo, tag, trunc,
                                        digests.get(repo, "<none>") if show else "<none>"))
        try:
            text, code = self._emit(fmt, table, template, rows, _IMAGE_HEADERS,
                                    "*formatter.imageContext")
            return warning + text, code
        except _Exit as e:
            if e.text.startswith("failed to execute template: "):
                e.text = "template parsing error: " + e.text[len("failed to execute template: "):]
            raise

    def _image(self, im: dict, repo: str, tag: str, trunc: bool, digest: str) -> Obj:
        created = Num(im.get("Created", "0")).value
        shared, containers = Num(im.get("SharedSize", "-1")).value, Num(im.get("Containers", "-1")).value
        size = Num(im.get("Size", "0")).value
        ident = im.get("Id", "")
        return Obj("*formatter.imageContext", {
            "ID": lambda: ident.removeprefix("sha256:")[:12] if trunc else ident,
            "Repository": lambda: repo, "Tag": lambda: tag, "Digest": lambda: digest,
            "CreatedSince": lambda: human_duration(max(self.now - created, 0)) + " ago",
            "CreatedAt": lambda: _local_time(created),
            "Size": lambda: _human_size(size),
            "Containers": lambda: "N/A" if containers < 0 else str(containers),
            "SharedSize": lambda: "N/A" if shared < 0 else _size4(shared),
            "UniqueSize": lambda: "N/A" if shared < 0 else _size4(size - shared),
        })

    def _image_list(self, images: list, tree: bool) -> str:
        """Docker 29's default view: IMAGE, ID, DISK USAGE, CONTENT SIZE, EXTRA, sorted by
        name; on a terminal in colour, under a legend pushed to the right edge. With
        --tree, one more line per platform under each image."""
        tty = self.tty
        groups = []                      # (name, id, disk, content, in use, [children])
        for im in images:
            manifests = [m for m in im.get("Manifests") or [] if m.get("Kind") == "image"]
            content = sum(Num((m.get("Size") or {}).get("Content", "0")).value
                          for m in manifests if m.get("Available"))
            in_use = Num(im.get("Containers", "0")).value > 0 or any(
                (m.get("ImageData") or {}).get("Containers") for m in manifests)
            kids = []
            for m in manifests:
                platform = _Platform((m.get("ImageData") or {}).get("Platform") or {})
                size = m.get("Size") or {}
                kids.append(("└─ " + platform.go_string(), m.get("ID", "").removeprefix("sha256:")[:12],
                             _human_size(Num(size.get("Total", "0")).value),
                             _human_size(Num(size.get("Content", "0")).value),
                             bool((m.get("ImageData") or {}).get("Containers"))))
            for ref in im.get("RepoTags") or ["<untagged>"]:
                groups.append((ref, im["Id"].removeprefix("sha256:")[:12],
                               _human_size(Num(im.get("Size", "0")).value), _human_size(content),
                               in_use, kids))
        groups.sort(key=lambda g: g[0])
        w_name = max([len(g[0]) for g in groups] + [len("IMAGE")]
                     + ([len(k[0]) + 4 for g in groups for k in g[5]] if tree else []))
        bold = "\x1b[1m" if tty else ""

        def paint(code: str, text: str) -> str:
            return f"\x1b[{code}m{text}\x1b[0m" if tty else text

        def line(name, ident, disk, content, extra, kind):
            first = {"head": paint("39", bold + name), "image": paint("34", bold + name),
                     "child": paint("39", name)}[kind]
            b = bold if kind == "head" else ""
            return "   ".join([first + " " * (w_name - len(name)),
                               paint("39", b + ident) + " " * (12 - len(ident)),
                               " " * (10 - len(disk)) + paint("39", b + disk),
                               " " * (12 - len(content)) + paint("39", b + content)]) + "   " + extra

        used = "\x1b[38;5;0m\x1b[48;5;14m U \x1b[0m  " if tty else "U    "
        out = [line("IMAGE", "ID", "DISK USAGE", "CONTENT SIZE", paint("39", bold + "EXTRA"), "head")]
        for name, ident, disk, content, in_use, kids in groups:
            out.append(line(name, ident, disk, content, used if in_use else "     ", "image"))
            if tree:
                out += [line(k[0], k[1], k[2], k[3], used if k[4] else "     ", "child") for k in kids]
                out.append("")
        if tty:
            legend = ("\x1b[1m\x1b[106m\x1b[30mi\x1b[0m\x1b[0m \x1b[96mInfo → \x1b[0m\x1b[0m "
                      "\x1b[38;5;0m\x1b[48;5;14m U \x1b[0m In Use")
            out.insert(0, " " * max(self.sess.cols - len("i Info →   U  In Use"), 0) + legend)
        return "\n".join(out) + "\n"

    # -- templates and tables, shared by ps and images

    @staticmethod
    def _template(fmt: str, parse_prefix: str):
        """(is a table, Template or None for the `json` format)."""
        table = fmt.startswith("table")
        body = fmt[len("table"):].strip() if table else fmt
        if body == "json":
            return table, None
        body = body.replace("\\t", "\t").replace("\\n", "\n")
        try:
            return table, Template(body)
        except TemplateError as e:
            raise _Exit(f"{parse_prefix}{e}\n", 1)

    @staticmethod
    def _emit(fmt, table, template, rows, headers, typename,
              failed="failed to execute template: "):
        if template is None:                               # --format json: every field
            return "".join(gotemplate.go_json(r) + "\n" for r in rows), 0
        try:
            lines = [template.render(r) for r in rows]
            if not table:
                return "".join(line + "\n" for line in lines), 0
            head = template.render(Obj(typename, {
                k: (v if getattr(v, "takes_args", False) else (lambda v=v: v))
                for k, v in headers.items()}))
        except TemplateError as e:
            raise _Exit(f"{failed}{e}\n", 1)
        return _tabwriter([head] + lines) + "\n", 0

    # -- docker inspect

    _KINDS = ("config", "container", "image", "network", "node", "plugin", "secret", "service",
              "task", "volume")

    def inspect(self, rest):
        opts, refs = _parse(self.path, rest, {"format": ("f", "str"), "size": ("s", "bool"),
                                               "type": ("", "str")})
        kind = opts["type"]
        if refs and kind is not None and kind not in self._KINDS:
            raise _Exit(f'unknown type: "{kind}": must be one of '
                        + ", ".join(f'"{k}"' for k in self._KINDS) + "\n", 1)
        return self._inspect(refs, kind, opts["format"], opts["size"])

    def container_inspect(self, rest):
        opts, refs = _parse(self.path, rest, {"format": ("f", "str"), "size": ("s", "bool")})
        return self._inspect(refs, "container", opts["format"], opts["size"])

    def image_inspect(self, rest):
        opts, refs = _parse(self.path, rest, {"format": ("f", "str"), "platform": ("", "str")})
        if opts["platform"] is not None:
            raise Unsupported("image inspect --platform")
        return self._inspect(refs, "image", opts["format"], False)

    def network_inspect(self, rest):
        opts, refs = _parse(self.path, rest, {"format": ("f", "str"), "verbose": ("v", "bool")})
        return self._inspect(refs, "network", opts["format"], False,
                             {"verbose": "true"} if opts["verbose"] else None)

    def volume_inspect(self, rest):
        opts, refs = _parse(self.path, rest, {"format": ("f", "str")})
        return self._inspect(refs, "volume", opts["format"], False)

    def _inspect(self, refs, kind, fmt, size, query=None):
        if not refs:
            raise self.wrong_args("requires at least 1 argument", "See")
        template = None
        if fmt and fmt != "json":
            try:
                template = Template(fmt)
            except TemplateError as e:
                raise _Exit(f"template parsing error: {e}\n", 64)
        found, lines, errors, warnings = [], [], [], []
        for ref in refs:
            doc, raw, err, what = self._find(ref, kind, size, query)
            if err:
                errors.append(err)
                continue
            if size and what != "container":
                warnings.append(f"WARNING: --size ignored for {what}")
            if template is None:
                found.append(raw)
                continue
            try:
                lines.append(template.render(_typed(doc)))
            except TemplateError:
                # The client tries its own structures first and, if the template fails
                # on them, the raw JSON; the error shown is the raw one.
                try:
                    lines.append(template.render(doc))
                except TemplateError as e:
                    errors.append(f"template parsing error: {e}")
        if template is not None:
            # With nothing to show, the client still ends the (empty) output line.
            out = "".join(l + "\n" for l in lines) or ("\n" if errors else "")
        elif fmt == "json":
            out = "[" + ",".join(json.dumps(d, ensure_ascii=False, separators=(",", ":"))
                                 for d in found) + "]\n"
        else:
            out = json.dumps(found, indent=4, ensure_ascii=False) + "\n"
        return ("".join(w + "\n" for w in warnings) + out
                + "".join(e + "\n" for e in errors)), (1 if errors else 0)

    def _find(self, ref: str, kind, size: bool, query=None):
        """(document for templates, document for printing, error, what it is). Without
        --type the client asks for a container, an image, a network and a volume of that
        name, in that order."""
        quoted = urllib.parse.quote(ref, safe=":@")
        paths = {"container": (f"/containers/{quoted}/json", {"size": "1"} if size else None),
                 "image": (f"/images/{quoted}/json", None),
                 "network": (f"/networks/{quoted}", query),
                 "volume": (f"/volumes/{quoted}", None)}
        order = [kind] if kind else ["container", "image", "network", "volume"]
        for k in order:
            if k not in paths:
                break
            status, body = self.get(*paths[k])
            if status == 200:
                return gotemplate.loads(body.decode()), json.loads(body), None, k
            if kind:
                return None, None, self.daemon_error(body), k
        return None, None, f"error: no such object: {ref}", None

    # -- docker logs

    def logs(self, rest):
        opts, refs = _parse(self.path, rest, {
            "details": ("", "bool"), "follow": ("f", "bool"), "since": ("", "str"),
            "tail": ("n", "str"), "timestamps": ("t", "bool"), "until": ("", "str")})
        if len(refs) != 1:
            raise self.wrong_args("requires 1 argument")
        c = self.get_json(f"/containers/{urllib.parse.quote(refs[0], safe=':@')}/json")
        query = {"stdout": "1", "stderr": "1"}
        for name in ("since", "until"):
            if opts[name]:
                query[name] = _timestamp(opts[name], self.now, name)
        if opts["timestamps"]:
            query["timestamps"] = "1"
        if opts["details"]:
            query["details"] = "1"
        if opts["tail"] is not None and opts["tail"] != "all":
            query["tail"] = opts["tail"]
        # `follow` is not passed on: the relay answers a command and returns, it cannot
        # sit and wait as `docker logs -f` does.
        status, body = self.get(f"/containers/{c['Id']}/logs", query)
        if status >= 400:
            raise _Exit(self.daemon_error(body) + "\n", 1)
        return _demultiplex(body), 0


    # -- docker network ls, docker volume ls

    def _list(self, rest, spec, default, quiet, rows_of, headers, typename):
        """The shape `network ls` and `volume ls` share: flags, a filter, a table or a
        template. Unlike `docker ps`, a format wins over --quiet."""
        opts, operands = _parse(self.path, rest, spec)
        if operands:
            raise self.wrong_args("accepts no arguments")
        fmt = opts["format"]
        if fmt is None or fmt == "table":
            fmt = quiet if opts["quiet"] else default
        table, template = self._template(fmt, "template parsing error: ")
        query = {}
        f = self.filters(opts["filter"], self.path)
        if f:
            query["filters"] = json.dumps(f, sort_keys=True, separators=(",", ":"))
        rows = rows_of(query, not opts.get("no-trunc"))
        return self._emit(fmt, table, template, rows, headers, typename,
                          "template parsing error: ")

    def network_ls(self, rest):
        def rows(query, trunc):
            nets = sorted(self.get_json("/networks", query), key=lambda n: n.get("Name", ""))
            return [self._network(n, trunc) for n in nets]
        return self._list(rest, {"filter": ("f", "list"), "format": ("", "str"),
                                 "no-trunc": ("", "bool"), "quiet": ("q", "bool")},
                          "table {{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}", "{{.ID}}", rows,
                          _NETWORK_HEADERS, "*network.networkContext")

    @staticmethod
    def _network(n: dict, trunc: bool) -> Obj:
        labels = n.get("Labels") or {}
        flag = lambda key: (lambda: "true" if n.get(key) else "false")      # noqa: E731
        return Obj("*network.networkContext", {
            "ID": lambda: n.get("Id", "")[:12] if trunc else n.get("Id", ""),
            "Name": lambda: n.get("Name", ""), "Driver": lambda: n.get("Driver", ""),
            "Scope": lambda: n.get("Scope", ""),
            "IPv4": flag("EnableIPv4"), "IPv6": flag("EnableIPv6"), "Internal": flag("Internal"),
            "Labels": lambda: ",".join(f"{k}={v}" for k, v in sorted(labels.items())),
            "Label": _method(lambda name: labels.get(name, "")),
            "CreatedAt": lambda: _go_time(n.get("Created", "")),
        })

    def volume_ls(self, rest):
        def rows(query, trunc):
            vols = self.get_json("/volumes", query).get("Volumes") or []
            return [self._volume(v) for v in sorted(vols, key=lambda v: _natural_key(v["Name"]))]
        return self._list(rest, {"cluster": ("", "bool"), "filter": ("f", "list"),
                                 "format": ("", "str"), "quiet": ("q", "bool")},
                          "table {{.Driver}}\t{{.Name}}", "{{.Name}}", rows,
                          _VOLUME_HEADERS, "*formatter.volumeContext")

    @staticmethod
    def _volume(v: dict) -> Obj:
        labels = v.get("Labels") or {}
        usage = v.get("UsageData") or {}
        return Obj("*formatter.volumeContext", {
            "Name": lambda: v.get("Name", ""), "Driver": lambda: v.get("Driver", ""),
            "Scope": lambda: v.get("Scope", ""), "Mountpoint": lambda: v.get("Mountpoint", ""),
            "Labels": lambda: ",".join(f"{k}={val}" for k, val in sorted(labels.items())),
            "Label": _method(lambda name: labels.get(name, "")),
            "Links": lambda: str(Num(usage["RefCount"]).value) if "RefCount" in usage else "N/A",
            "Size": lambda: _size4(Num(usage["Size"]).value) if "Size" in usage else "N/A",
            "Availability": lambda: "N/A", "Group": lambda: "N/A", "Status": lambda: "N/A",
        })

    # -- docker version, docker info

    def _client_template(self, rest, typename, name=""):
        """`-f` as `version` and `info` take it: (the format or None, a Template or
        None). Their template errors come after an empty line and carry the template's
        name."""
        opts, operands = _parse(self.path, rest, {"format": ("f", "str")})
        if operands:
            raise self.wrong_args("accepts no arguments")
        fmt = opts["format"]
        if not fmt or fmt == "json":
            return fmt, None
        try:
            return fmt, Template(fmt)
        except TemplateError as e:
            raise _Exit(f"template parsing error: {self._named(e, name)}\n", 64)

    @staticmethod
    def _named(error, name: str) -> str:
        return str(error).replace("template: :", f"template: {name}:", 1) \
                         .replace('executing ""', f'executing "{name}"', 1)

    def _client_render(self, template, doc: dict, typename: str, name=""):
        top = Obj(typename, {k: (lambda v=v: v) for k, v in doc.items()})
        try:
            return template.render(top) + "\n", 0
        except TemplateError as e:
            return f"\n{self._named(e, name)}\n", 1

    def version(self, rest):
        fmt, template = self._client_template(rest, "system.versionInfo", "version")
        api = self.get_json("/version")
        server = {k: api[k] for k in _CLIENT["version_server_keys"] if k in api}
        # The client rewrites a component's build time the way it prints its own
        # (Go's ANSIC); the server's top-level BuildTime stays as sent.
        for comp in server.get("Components") or []:
            built = (comp.get("Details") or {}).get("BuildTime")
            m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(?:Z|[-+]\d\d:\d\d)",
                             built or "")
            if m:
                t = dt.datetime(*map(int, m.groups()))
                comp["Details"]["BuildTime"] = t.strftime("%a %b ") + f"{t.day:2d}" + t.strftime(" %H:%M:%S %Y")
        client = gotemplate.loads(json.dumps(_CLIENT["version_client"]))
        doc = {"Client": client, "Server": server}
        if fmt == "json":
            return gotemplate.go_json(doc) + "\n", 0
        if template is not None:
            return self._client_render(template, doc, "system.versionInfo", "version")

        def block(indent, pairs):
            return [f"{indent}{label}:".ljust(20) + str(value) for label, value in pairs]

        out = [f"Client: {client['Platform']['Name']}"] + block(" ", [
            ("Version", client["Version"]), ("API version", client["ApiVersion"]),
            ("Go version", client["GoVersion"]), ("Git commit", client["GitCommit"]),
            ("Built", client["BuildTime"]), ("OS/Arch", f"{client['Os']}/{client['Arch']}"),
            ("Context", client["Context"])])
        out += ["", f"Server: {server['Platform']['Name']}"]
        for comp in server.get("Components") or []:
            d = comp.get("Details") or {}
            out.append(f" {comp['Name']}:")
            if comp["Name"] == "Engine":
                out += block("  ", [
                    ("Version", comp["Version"]),
                    ("API version", f"{d.get('ApiVersion')} (minimum version {d.get('MinAPIVersion')})"),
                    ("Go version", d.get("GoVersion")), ("Git commit", d.get("GitCommit")),
                    ("Built", d.get("BuildTime")), ("OS/Arch", f"{d.get('Os')}/{d.get('Arch')}"),
                    ("Experimental", d.get("Experimental"))])
            else:
                out += block("  ", [("Version", comp["Version"])] + sorted(d.items()))
        return "\n".join(out) + "\n", 0

    def info(self, rest):
        fmt, template = self._client_template(rest, "system.dockerInfo")
        api = self.get_json("/info")
        doc = {k: api[k] for k in _CLIENT["info_keys"] if k in api}
        doc["ClientInfo"] = client = gotemplate.loads(json.dumps(_CLIENT["info_client"]))
        if fmt == "json":
            return gotemplate.go_json(doc) + "\n", 0
        if template is not None:
            return self._client_render(template, doc, "system.dockerInfo")
        yes = lambda v: "true" if v else "false"                              # noqa: E731
        out = [f"Client: {client['Platform']['Name']}", f" Version:    {client['Version']}",
               f" Context:    {client['Context']}", f" Debug Mode: {yes(client['Debug'])}"]
        if client.get("Plugins"):
            out.append(" Plugins:")
            for plug in client["Plugins"]:
                out += [f"  {plug['Name']}: {plug['ShortDescription']} ({plug['Vendor']})",
                        f"    Version:  {plug['Version']}", f"    Path:     {plug['Path']}"]
        n = lambda key: Num(doc[key]).value if isinstance(doc.get(key), str) else doc.get(key)  # noqa: E731
        out += ["", "Server:", f" Containers: {n('Containers')}", f"  Running: {n('ContainersRunning')}",
                f"  Paused: {n('ContainersPaused')}", f"  Stopped: {n('ContainersStopped')}",
                f" Images: {n('Images')}", f" Server Version: {doc['ServerVersion']}",
                f" Storage Driver: {doc['Driver']}"]
        out += [f"  {k}: {v}" for k, v in doc.get("DriverStatus") or []]
        out += [f" Logging Driver: {doc['LoggingDriver']}", f" Cgroup Driver: {doc['CgroupDriver']}",
                f" Cgroup Version: {doc['CgroupVersion']}", " Plugins:"]
        plugins = doc.get("Plugins") or {}
        out += [f"  {kind}: {' '.join(plugins.get(kind) or [])}" for kind in ("Volume", "Network", "Log")]
        if doc.get("CDISpecDirs"):
            out += [" CDI spec directories:"] + [f"  {d}" for d in doc["CDISpecDirs"]]
        out.append(f" Swarm: {(doc.get('Swarm') or {}).get('LocalNodeState', '')}")
        # Go prints a map's keys in no fixed order here; the recording has them sorted.
        out += [" Runtimes: " + " ".join(sorted(doc.get("Runtimes") or {})),
                f" Default Runtime: {doc['DefaultRuntime']}", f" Init Binary: {doc['InitBinary']}",
                f" containerd version: {doc['ContainerdCommit']['ID']}",
                f" runc version: {doc['RuncCommit']['ID']}", f" init version: {doc['InitCommit']['ID']}"]
        if doc.get("SecurityOptions"):
            out.append(" Security Options:")
            for option in doc["SecurityOptions"]:
                pairs = [kv.partition("=") for kv in option.split(",")]
                out.append(f"  {pairs[0][2]}")
                out += [f"   {k.capitalize()}: {v}" for k, _, v in pairs[1:]]
        out += [f" Kernel Version: {doc['KernelVersion']}", f" Operating System: {doc['OperatingSystem']}",
                f" OSType: {doc['OSType']}", f" Architecture: {doc['Architecture']}",
                f" CPUs: {n('NCPU')}", f" Total Memory: {_bytes_size(n('MemTotal'))}",
                f" Name: {doc['Name']}", f" ID: {doc['ID']}", f" Docker Root Dir: {doc['DockerRootDir']}",
                f" Debug Mode: {yes(doc.get('Debug'))}", f" Experimental: {yes(doc.get('ExperimentalBuild'))}"]
        cidrs = (doc.get("RegistryConfig") or {}).get("InsecureRegistryCIDRs") or []
        if cidrs:
            out += [" Insecure Registries:"] + [f"  {c}" for c in cidrs]
        out.append(f" Live Restore Enabled: {yes(doc.get('LiveRestoreEnabled'))}")
        firewall = doc.get("FirewallBackend") or {}
        if firewall.get("Driver"):
            out.append(f" Firewall Backend: {firewall['Driver']}")
            out += [f"  {k}: {v}" for k, v in firewall.get("Info") or []]
        out.append("")
        out += list(doc.get("Warnings") or [])
        return "\n".join(out) + "\n", 0

    # -- docker system df

    def system_df(self, rest):
        opts, operands = _parse(self.path, rest, {"format": ("", "str"), "verbose": ("v", "bool")})
        if operands:
            raise self.wrong_args("accepts no arguments")
        df = self.get_json("/system/df", {"verbose": "1"} if opts["verbose"] else None)
        num = lambda v: Num(v).value if isinstance(v, str) else (v or 0)        # noqa: E731

        def usage(key, items_key):
            u = df.get(key) or {}
            return {k: num(u.get(k)) for k in ("TotalCount", "ActiveCount", "TotalSize", "Reclaimable")}

        if opts["verbose"]:
            return self._df_verbose(df, opts["format"])
        fmt = opts["format"]
        if fmt is None or fmt == "table":
            fmt = "table {{.Type}}\t{{.TotalCount}}\t{{.Active}}\t{{.Size}}\t{{.Reclaimable}}"
        table, template = self._template(fmt, "template parsing error: ")
        rows = []
        for label, key, typename in (("Images", "ImageUsage", "*formatter.diskUsageImagesContext"),
                                     ("Containers", "ContainerUsage", "*formatter.diskUsageContainersContext"),
                                     ("Local Volumes", "VolumeUsage", "*formatter.diskUsageVolumesContext"),
                                     ("Build Cache", "BuildCacheUsage", "*formatter.diskUsageBuilderContext")):
            u = usage(key, None)
            total, reclaim = u["TotalSize"], u["Reclaimable"]
            percent = f" ({reclaim * 100 // total}%)" if total > 0 and label != "Build Cache" else ""
            rows.append(Obj(typename, {
                "Type": lambda label=label: label, "TotalCount": lambda u=u: str(u["TotalCount"]),
                "Active": lambda u=u: str(u["ActiveCount"]), "Size": lambda total=total: _size4(total),
                "Reclaimable": lambda reclaim=reclaim, percent=percent: _size4(reclaim) + percent}))
        return self._emit(fmt, table, template, rows, _DF_HEADERS, rows[0].typename,
                          "template parsing error: ")

    def _df_verbose(self, df: dict, fmt):
        if fmt is not None:
            raise Unsupported("system df -v --format")
        num = lambda v: Num(v).value if isinstance(v, str) else (v or 0)        # noqa: E731
        out = ["Images space usage:", ""]
        rows = ["REPOSITORY\tTAG\tIMAGE ID\tCREATED\tSIZE\tSHARED SIZE\tUNIQUE SIZE\tCONTAINERS"]
        for im in df.get("Images") or []:
            for ref in im.get("RepoTags") or ["<none>:<none>"]:
                repo, _, tag = ref.rpartition(":")
                c = self._image(im, repo, tag, True, "<none>").fields
                rows.append("\t".join([repo, tag, c["ID"](), c["CreatedSince"](), c["Size"](),
                                       c["SharedSize"](), c["UniqueSize"](), c["Containers"]()]))
        out += [_tabwriter(rows), "", "Containers space usage:", ""]
        rows = ["CONTAINER ID\tIMAGE\tCOMMAND\tLOCAL VOLUMES\tSIZE\tCREATED\tSTATUS\tNAMES"]
        for c in df.get("Containers") or []:
            f = self._container(c, True, []).fields
            rows.append("\t".join([f["ID"](), f["Image"](), f["Command"](), f["LocalVolumes"](),
                                   _human_size(num(c.get("SizeRw"))), f["RunningFor"](),
                                   f["Status"](), f["Names"]()]))
        out += [_tabwriter(rows), "", "Local Volumes space usage:", ""]
        rows = ["VOLUME NAME\tLINKS\tSIZE"]
        for v in df.get("Volumes") or []:
            f = self._volume(v).fields
            rows.append("\t".join([f["Name"](), f["Links"](), f["Size"]()]))
        cache = df.get("BuildCache") or []
        total = sum(num(b.get("Size")) for b in cache)
        out += [_tabwriter(rows), "", f"Build cache usage: {_size4(total)}", "",
                _tabwriter(["CACHE ID\tCACHE TYPE\tSIZE\tCREATED\tLAST USED\tUSAGE\tSHARED"])]
        if cache:
            raise Unsupported("system df -v with a build cache")
        return "\n".join(out) + "\n", 0

    # -- docker top

    def top(self, rest):
        # No flags of its own: everything after the container is for ps.
        if rest[:1] == ["--help"]:
            raise _Exit(_HELP[self.path], 0)
        if rest and rest[0].startswith("-") and rest[0] != "--":
            _parse(self.path, rest[:1], {})
        if rest[:1] == ["--"]:
            rest = rest[1:]
        if not rest:
            raise self.wrong_args("requires at least 1 argument", "See")
        query = {"ps_args": " ".join(rest[1:])} if rest[1:] else None
        procs = self.get_json(f"/containers/{urllib.parse.quote(rest[0], safe=':@')}/top", query)
        lines = ["\t".join(procs.get("Titles") or [])]
        lines += ["\t".join(row) for row in procs.get("Processes") or []]
        return _tabwriter(lines, 20, 3) + "\n", 0

    # -- docker stats

    def stats(self, rest):
        opts, refs = _parse(self.path, rest, {
            "all": ("a", "bool"), "format": ("", "str"), "no-stream": ("", "bool"),
            "no-trunc": ("", "bool")})
        fmt = opts["format"]
        if fmt is None or fmt == "table":
            fmt = ("table {{.ID}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t"
                   "{{.BlockIO}}\t{{.PIDs}}")
        table, template = self._template(fmt, "template parsing error: ")
        # `follow` without --no-stream is not held open: one sample, as with --no-stream.
        if refs:
            targets = [(r, r) for r in refs]
        else:
            listed = self.get_json("/containers/json", {"all": "1"} if opts["all"] else None)
            targets = [(c["Id"], c["Id"]) for c in listed]
        rows, errors = [], []
        for shown, ref in targets:
            # The client asks for all of them at once: each wait starts from now, so the
            # whole command takes one wait (1 to 2 s), whatever the number of containers.
            self._clock = self.now
            status, body = self.get(f"/containers/{urllib.parse.quote(ref, safe=':@')}/stats",
                                    {"stream": "false"})
            if status >= 400:
                errors.append(self.daemon_error(body))
                continue
            rows.append(self._stat(gotemplate.loads(body.decode()), shown, not opts["no-trunc"]))
        if errors:
            return "".join(e + "\n" for e in errors[:1]), 1
        self._clock = self.now
        return self._emit(fmt, table, template, rows, _STATS_HEADERS, "*container.statsContext",
                          "template parsing error: ")

    @staticmethod
    def _stat(st: dict, shown: str, trunc: bool) -> Obj:
        num = lambda v: Num(v).value if isinstance(v, str) else (v or 0)        # noqa: E731
        cpu, pre = st.get("cpu_stats") or {}, st.get("precpu_stats") or {}
        cpu_delta = num((cpu.get("cpu_usage") or {}).get("total_usage")) \
            - num((pre.get("cpu_usage") or {}).get("total_usage"))
        sys_delta = num(cpu.get("system_cpu_usage")) - num(pre.get("system_cpu_usage"))
        online = num(cpu.get("online_cpus")) or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or [])
        percent = cpu_delta / sys_delta * online * 100.0 if sys_delta > 0 and cpu_delta > 0 else 0.0
        mem = st.get("memory_stats") or {}
        used, limit = num(mem.get("usage")), num(mem.get("limit"))
        inactive = num((mem.get("stats") or {}).get("inactive_file"))
        if 0 < inactive < used:
            used -= inactive
        rx = sum(num(n.get("rx_bytes")) for n in (st.get("networks") or {}).values())
        tx = sum(num(n.get("tx_bytes")) for n in (st.get("networks") or {}).values())
        blk = (st.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []
        read = sum(num(b.get("value")) for b in blk if str(b.get("op", ""))[:1].lower() == "r")
        write = sum(num(b.get("value")) for b in blk if str(b.get("op", ""))[:1].lower() == "w")
        ident = st.get("id", "")
        return Obj("*container.statsContext", {
            "Container": lambda: shown, "Name": lambda: st.get("name", "").lstrip("/"),
            "ID": lambda: ident[:12] if trunc else ident,
            "CPUPerc": lambda: f"{percent:.2f}%",
            "MemUsage": lambda: f"{_bytes_size(used)} / {_bytes_size(limit)}",
            "MemPerc": lambda: f"{(used / limit * 100.0) if limit else 0.0:.2f}%",
            "NetIO": lambda: f"{_human_size(rx)} / {_human_size(tx)}",
            "BlockIO": lambda: f"{_human_size(read)} / {_human_size(write)}",
            "PIDs": lambda: str(num((st.get("pids_stats") or {}).get("current"))),
        })

    # -- docker start | stop | rm | pull: the four that change the shared state

    def _each(self, refs, method, path, query, after_errors=None, quiet_404=False,
              together=False):
        """One request per container, as the client sends them: the name back for each
        that worked, the daemon's error for each that did not. `together`: the client
        sends them all at the same moment (`docker stop a b` takes as long as one
        stop); otherwise one after the other (`docker start a b`)."""
        out, failed = [], []
        for ref in refs:
            if together:
                self._clock = self.now
            status, body = self.send(method, path.format(urllib.parse.quote(ref, safe=":@")), query)
            if status < 400:
                out.append(ref)
            elif not (quiet_404 and status == 404):
                out.append(self.daemon_error(body))
                failed.append(ref)
        self._clock = self.now
        if failed and after_errors:
            out.append(after_errors(failed))
        return "".join(line + "\n" for line in out), (1 if failed else 0)

    def start(self, rest):
        opts, refs = _parse(self.path, rest, {"attach": ("a", "bool"), "detach-keys": ("", "str"),
                                               "interactive": ("i", "bool")})
        if not refs:
            raise self.wrong_args("requires at least 1 argument", "See")
        if opts["attach"] or opts["interactive"]:
            raise Unsupported("start attached to the container's streams")
        return self._each(refs, "POST", "/containers/{}/start", None,
                          lambda failed: "failed to start containers: " + ", ".join(failed))

    def stop(self, rest):
        opts, refs = _parse(self.path, rest, {"signal": ("s", "str"), "timeout": ("t", "int"),
                                               "time": ("", "int")})
        if not refs:
            raise self.wrong_args("requires at least 1 argument", "See")
        note, timeout = "", opts["timeout"]
        if opts["time"] is not None:
            note, timeout = "Flag --time has been deprecated, use --timeout instead\n", opts["time"]
        query = {}
        if opts["signal"]:
            query["signal"] = opts["signal"]
        if timeout is not None:
            query["t"] = str(timeout)
        text, code = self._each(refs, "POST", "/containers/{}/stop", query or None, together=True)
        return note + text, code

    def rm(self, rest):
        opts, refs = _parse(self.path, rest, {"force": ("f", "bool"), "link": ("l", "bool"),
                                               "volumes": ("v", "bool")})
        if not refs:
            raise self.wrong_args("requires at least 1 argument", "See")
        if opts["link"]:
            raise Unsupported("rm --link")
        query = {}
        if opts["force"]:
            query["force"] = "1"
        if opts["volumes"]:
            query["v"] = "1"
        return self._each(refs, "DELETE", "/containers/{}", query or None, quiet_404=opts["force"])

    def pull(self, rest):
        opts, refs = _parse(self.path, rest, {"all-tags": ("a", "bool"), "platform": ("", "str"),
                                               "quiet": ("q", "bool"),
                                               "disable-content-trust": ("", "bool")})
        if len(refs) != 1:
            raise self.wrong_args("requires 1 argument")
        ref = refs[0]
        if opts["all-tags"] or opts["platform"] or "@" in ref or not re.fullmatch(r"[\w./:-]+", ref):
            raise Unsupported("pull with --all-tags, --platform or a digest")
        name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "")
        # The name as the client normalises it before asking (`alpine` is
        # `docker.io/library/alpine`); a name with a registry in it goes out as it is.
        first = name.split("/", 1)[0]
        if "/" in name and ("." in first or ":" in first or first == "localhost"):
            full = name
        else:
            full = "docker.io/" + (name if "/" in name else "library/" + name)
        note = "" if tag or opts["quiet"] else "Using default tag: latest\n"
        status, body = self.send("POST", "/images/create", {"fromImage": full, "tag": tag or "latest"})
        if status >= 400:
            return note + self.daemon_error(body) + "\n", 1
        raise Unsupported("a pull that succeeds")     # there is no registry to pull from

    # -- docker run | create, for an image that is not on the machine

    def exec(self, rest):
        """`docker exec`: decided 2026-10-13. Code answers what follows from the shared
        state and nothing else: the container has to exist and to be running, and the
        refusals are the daemon's own, through the two requests the real client makes
        (an inspect first, so that "No such container" comes before anything else, then
        the exec itself). What the program prints inside a running container is not in
        any state the honeypot keeps: that stays the model's, and changes nothing."""
        opts, words = _parse(self.path, rest, _spec_from_help(self.path), interspersed=False)
        if len(words) < 2:
            raise self.wrong_args("requires at least 2 arguments", "See")
        ref = urllib.parse.quote(words[0], safe=":@")
        status, body = self.get(f"/containers/{ref}/json")
        if status >= 400:
            return self.daemon_error(body) + "\n", 1
        if opts.get("interactive") and opts.get("tty") and not opts.get("detach") \
                and not self.sess.terminal:
            return "cannot attach stdin to a TTY-enabled container because stdin is not a terminal\n", 1
        if json.loads(body)["State"]["Running"]:
            raise Unsupported("exec in a running container: its output is the model's")
        status, body = self.send("POST", f"/containers/{ref}/exec", None,
                                 {"Cmd": words[1:], "AttachStdout": True, "AttachStderr": True})
        if status < 400:
            raise Unsupported("exec that the API accepts")
        return self.daemon_error(body) + "\n", 1

    def run(self, rest):
        return self._run_or_create(rest, "run")

    def create(self, rest):
        return self._run_or_create(rest, "create")

    def _run_or_create(self, rest, verb):
        """The machine has no internet and three images. `docker run alpine` therefore
        ends the same way whatever its flags: the image is not found locally, the pull
        fails after the resolver's five seconds, and the client prints the daemon's
        error. That path is answered here, exactly. With an image that IS on the
        machine, `create` and `run -d` make the container in the shared state, as the
        same request on the API does (_local_image). `run` without -d and with a command
        is made and started here too, and only the program's output is the model's."""
        opts, words = _parse(self.path, rest, _spec_from_help(self.path), interspersed=False)
        if not words:
            raise self.wrong_args("requires at least 1 argument", "See")
        ref = words[0]
        if opts.get("platform") or (opts.get("pull") and opts["pull"] != ["missing"]) \
                or not re.fullmatch(r"(?:[a-z0-9.-]+(?::\d+)?/)?[a-z0-9]+(?:[._/-][a-z0-9]+)*"
                                    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?", ref):
            raise Unsupported(f"{verb} with --platform, --pull or an unusual image name")
        status, _ = self.get(f"/images/{urllib.parse.quote(ref, safe=':@/')}/json")
        if verb == "run" and opts.get("interactive") and opts.get("tty") \
                and not opts.get("detach") and not self.sess.terminal:
            return "cannot attach stdin to a TTY-enabled container because stdin is not a terminal\n", 1
        if status == 200:
            return self._local_image(opts, words, verb)
        name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "")
        tag = tag or "latest"
        first = name.split("/", 1)[0]
        if "/" in name and ("." in first or ":" in first or first == "localhost"):
            full = shown = name
            if first in ("docker.io", "index.docker.io"):
                shown = name.split("/", 1)[1].removeprefix("library/")
                full = "docker.io/" + name.split("/", 1)[1]
        else:
            shown = name.removeprefix("library/")
            full = "docker.io/" + (name if "/" in name else "library/" + name)
        status, body = self.send("POST", "/images/create", {"fromImage": full, "tag": tag})
        if status < 400:
            raise Unsupported("a pull that succeeds")
        head = f"Unable to find image '{shown}:{tag}' locally\n"
        if verb == "create":
            return head + self.daemon_error(body) + "\n", 1
        return head + f"docker: {self.daemon_error(body)}\n\nRun 'docker run --help' for more information\n", 125

    # The flags of create/run the shell turns into a request itself. Any other flag
    # that is set sends the whole command to the model.
    _CREATE_FLAGS = {"name", "env", "volume", "publish", "privileged", "pid", "network", "net",
                     "restart", "rm", "workdir", "user", "hostname", "entrypoint", "label",
                     "interactive", "tty", "init", "read-only", "cap-add", "cap-drop",
                     "detach", "pull"}

    def _local_image(self, opts, words, verb):
        """`docker create` and `docker run -d` with an image that is on the machine. The
        request body is the real client's own (recorded: docker_client.json,
        `create_body`) with what each flag changes in it, measured flag by flag against
        the real client (tools/docker_cli_oracle.py). The fake API then does what it does
        for the same request from the network, so the new container is in `docker ps`
        and on the API alike."""
        detach = verb == "run" and opts.get("detach")
        attached = verb == "run" and not detach
        if attached and not RUN_ATTACHED():
            raise Unsupported("run attached: handed back to the model (config code_scope)")
        if attached and (not words[1:] or opts.get("tty") or opts.get("interactive")):
            # the image's own program (a broker, a server) runs until stopped, and -it
            # is a shell inside the container: neither ends by itself
            raise Unsupported("run attached with the image's own command or a terminal")
        extra = sorted(k for k, v in opts.items() if v and k not in self._CREATE_FLAGS)
        if extra:
            raise Unsupported(f"{verb} with --{extra[0]}")

        def one(key):
            return opts[key][-1] if opts.get(key) else None

        def fail(text):
            return _Exit(f"docker: {text}\n\nRun 'docker {verb} --help' for more information\n", 125)

        body = copy.deepcopy(_CLIENT["create_body"])
        hc = body["HostConfig"]
        body["Image"] = words[0]
        if words[1:]:
            body["Cmd"] = words[1:]
        if detach:
            body["AttachStdout"] = body["AttachStderr"] = False
        if opts.get("interactive"):
            body["OpenStdin"] = True
            if not detach:
                body["AttachStdin"] = body["StdinOnce"] = True
        body["Tty"] = bool(opts.get("tty"))
        if self.sess.terminal:
            hc["ConsoleSize"] = [24, self.sess.cols]

        env = {}                                   # one value per name, the last one
        for e in opts.get("env") or []:
            key, eq, _ = e.partition("=")
            if not key or not eq:                  # `-e NAME` copies the caller's own
                raise Unsupported(f"{verb} -e without a value")
            env[key] = e
        if env:
            body["Env"] = list(env.values())
        for label in opts.get("label") or []:
            key, _, value = label.partition("=")
            if not key:
                raise Unsupported(f"{verb} with an empty label")
            body["Labels"][key] = value
        for v in opts.get("volume") or []:
            if re.fullmatch(r"/[^:]*", v):
                body["Volumes"][v] = {}
            elif re.fullmatch(r"(/[^:]*|[A-Za-z0-9][A-Za-z0-9_.-]+):/[^:]*(:(ro|rw|z|Z))?", v):
                hc["Binds"] = (hc["Binds"] or []) + [v]
            else:
                raise Unsupported(f"{verb} -v in an unusual form")
        for p in opts.get("publish") or []:
            m = re.fullmatch(r"(?:(?:(\d+\.\d+\.\d+\.\d+):)?(\d*):)?(\d+)(?:/(tcp|udp))?", p)
            if not m:
                raise Unsupported(f"{verb} -p in an unusual form")
            port = f"{m.group(3)}/{m.group(4) or 'tcp'}"
            body.setdefault("ExposedPorts", {})[port] = {}
            hc["PortBindings"].setdefault(port, []).append(
                {"HostIp": m.group(1) or "", "HostPort": m.group(2) or ""})

        # Go writes a map with its keys in order, so the client's request has them so.
        for holder, key in ((body, "ExposedPorts"), (body, "Labels"), (body, "Volumes"),
                            (hc, "PortBindings")):
            if holder.get(key):
                holder[key] = dict(sorted(holder[key].items()))
        for key, field in (("user", "User"), ("workdir", "WorkingDir"), ("hostname", "Hostname")):
            if one(key) is not None:
                body[field] = one(key)
        if one("entrypoint") is not None:
            body["Entrypoint"] = [one("entrypoint")]
        hc["Privileged"] = bool(opts.get("privileged"))
        hc["ReadonlyRootfs"] = bool(opts.get("read-only"))
        hc["AutoRemove"] = bool(opts.get("rm"))
        if opts.get("init"):
            hc["Init"] = True
        if one("pid") is not None:
            hc["PidMode"] = one("pid")
        for key, field in (("cap-add", "CapAdd"), ("cap-drop", "CapDrop")):
            caps = {c.upper() if c.upper() == "ALL" or c.upper().startswith("CAP_")
                    else "CAP_" + c.upper() for c in opts.get(key) or []}
            if caps:
                hc[field] = sorted(caps)
        if one("restart") is not None:
            m = re.fullmatch(r"(no|always|unless-stopped|on-failure)(?::(\d+))?", one("restart"))
            if not m or (m.group(2) and m.group(1) != "on-failure"):
                raise Unsupported(f"{verb} with an unusual --restart")
            if hc["AutoRemove"] and m.group(1) != "no":
                raise fail("conflicting options: cannot specify both --restart and --rm")
            hc["RestartPolicy"] = {"Name": m.group(1), "MaximumRetryCount": int(m.group(2) or 0)}
        networks = (opts.get("network") or []) + (opts.get("net") or [])
        if len(networks) > 1:
            raise Unsupported(f"{verb} on more than one network")
        if networks:
            # A network that does not exist is accepted here and refused at start,
            # as by the daemon (docker.py, start_container).
            hc["NetworkMode"] = networks[0]
            body["NetworkingConfig"]["EndpointsConfig"] = {}

        status, answer = self.send("POST", "/containers/create",
                                   {"name": one("name")} if one("name") is not None else None, body)
        if status >= 400:
            if verb == "create":
                return self.daemon_error(answer) + "\n", 1
            raise fail(self.daemon_error(answer))
        cid = json.loads(answer)["Id"]
        if attached:
            # `docker run image cmd`: created and started here, on both surfaces; the
            # program's output is generated; when it is, the container has exited with
            # the answer's status (and is gone again with --rm, anonymous volumes too).
            status, answer = self.send("POST", f"/containers/{cid}/start")
            if status >= 400:
                raise fail(self.daemon_error(answer))
            docker, auto = self.docker, hc["AutoRemove"]

            def after(code: int, now: float, text: str = "") -> None:
                c = docker.find(cid)
                if c is None or c["State"]["Status"] != "running":
                    return
                docker.record_program_log(c, text, int(now * 1e9))   # what it printed is its log
                docker.finish_container(c, now, code)
                if auto:
                    docker.delete_container(c, True)
            raise ModelOutput("run attached: the program's output is the model's", after)
        if detach:
            status, answer = self.send("POST", f"/containers/{cid}/start")
            if status >= 400:
                # the client prints the new container's id whether or not it starts
                raise _Exit(cid + "\n" + fail(self.daemon_error(answer)).args[0], 125)
        return cid + "\n", 0

    # -- docker compose ls | ps | version (the compose plugin, 5.5.1)

    def compose(self, words):
        """Three read-only commands of the plugin. Its global flags come before the
        command: -f/--file, -p/--project-name. Everything else it can do (up, down,
        logs, exec, config, …) goes to the model."""
        files, project, i = [], None, 0
        while i < len(words) and words[i].startswith("-"):
            w = words[i]
            if w == "--help":
                raise _Exit(_HELP["compose"], 0)
            name, eq, value = w.partition("=")
            if name in ("-f", "--file", "-p", "--project-name"):
                if not eq:
                    if i + 1 >= len(words):
                        raise Unsupported("compose: flag without a value")
                    value, i = words[i + 1], i + 1
                if name in ("-f", "--file"):
                    files.append(value)
                else:
                    project = value
            else:
                raise Unsupported(f"compose {w}")
            i += 1
        if i >= len(words):
            raise _Exit(_HELP["compose"], 0)
        sub, rest = words[i], words[i + 1:]
        if sub not in ("ls", "ps", "version"):
            raise Unsupported(f"compose {sub}")
        self.path = f"compose {sub}"
        try:
            return getattr(self, f"compose_{sub}")(rest, files, project)
        except _Exit as e:
            if e.code == 125:                 # the plugin prints the error alone, exit 1
                e.text, e.code = e.text.split("\n")[0] + "\n", 1
            raise

    def _compose_parse(self, rest, spec):
        opts, operands = _parse(self.path, rest, {**spec, "dry-run": ("", "bool")})
        if opts["dry-run"]:
            raise Unsupported("compose --dry-run")
        return opts, operands

    def compose_version(self, rest, files, project):
        opts, operands = self._compose_parse(rest, {"format": ("f", "str"), "short": ("", "bool")})
        if operands:
            raise _Exit(f'unknown command "{operands[0]}" for "docker compose version"\n', 1)
        version = _CLIENT["compose_version"]
        if opts["short"]:
            return version.removeprefix("v") + "\n", 0
        if opts["format"] == "json":
            return json.dumps({"version": version}, separators=(",", ":")) + "\n", 0
        return f"Docker Compose version {version}\n", 0

    def compose_ls(self, rest, files, project):
        opts, operands = self._compose_parse(rest, {
            "all": ("a", "bool"), "filter": ("", "list"), "format": ("", "str"),
            "quiet": ("q", "bool")})
        if operands:
            raise _Exit(f'unknown command "{operands[0]}" for "docker compose ls"\n', 1)
        if opts["format"] not in (None, "table", "json"):
            raise Unsupported("compose ls --format")
        labels = {"com.docker.compose.config-hash": True, "com.docker.compose.project": True}
        query = {"filters": json.dumps({"label": labels}, sort_keys=True, separators=(",", ":"))}
        if opts["all"]:
            query["all"] = "1"
        stacks = {}
        for c in self.get_json("/containers/json", query):
            lab = c.get("Labels") or {}
            entry = stacks.setdefault(lab.get("com.docker.compose.project", ""), {
                "files": lab.get("com.docker.compose.project.config_files", ""), "states": []})
            entry["states"].append(c.get("State", ""))
        wanted = self.filters(opts["filter"], self.path).get("name")
        rows = []
        for name in sorted(stacks):
            if wanted and not any(re.search(w, name) for w in wanted):
                continue
            states = stacks[name]["states"]
            status = ", ".join(f"{st}({states.count(st)})" for st in sorted(set(states)))
            rows.append((name, status, stacks[name]["files"]))
        if opts["quiet"]:
            return "".join(name + "\n" for name, _, _ in rows), 0
        if opts["format"] == "json":
            return json.dumps([{"Name": n, "Status": st, "ConfigFiles": f} for n, st, f in rows],
                              separators=(",", ":"), ensure_ascii=False) + "\n", 0
        return _tabwriter(["NAME\tSTATUS\tCONFIG FILES"] + ["\t".join(r) for r in rows], 20, 3) + "\n", 0

    def _compose_project(self, files, project) -> str:
        """The project a `compose ps` is about: named with -p, or the one whose compose
        file is given with -f or found in the working directory or above it. The
        machine has one compose file; any other file is not something this code knows
        the content of."""
        if project:
            return project
        cwd = getattr(self.sess, "cwd", "/root")
        if files:
            paths = {f if f.startswith("/") else f"{cwd.rstrip('/')}/{f}" for f in files}
            if paths == {COMPOSE_FILE}:
                return "iot-stack"
            raise Unsupported("compose -f with another file")
        if cwd == COMPOSE_PROJECT_DIR or cwd.startswith(COMPOSE_PROJECT_DIR + "/"):
            return "iot-stack"
        raise _Exit("no configuration file provided: not found\n", 1)

    def compose_ps(self, rest, files, project):
        opts, services = self._compose_parse(rest, {
            "all": ("a", "bool"), "filter": ("", "str"), "format": ("", "str"),
            "no-trunc": ("", "bool"), "orphans": ("", "bool"), "quiet": ("q", "bool"),
            "services": ("", "bool"), "status": ("", "list")})
        name = self._compose_project(files, project)
        statuses = list(opts["status"])
        if opts["filter"]:
            key, _, value = opts["filter"].partition("=")
            if key != "status":
                raise Unsupported("compose ps --filter other than status")
            statuses.append(value)
        fmt = opts["format"]
        if fmt == "json" or (fmt and fmt != "table" and not fmt.startswith("table ")):
            raise Unsupported("compose ps --format json or a bare template")
        labels = {"com.docker.compose.config-hash": True,
                  f"com.docker.compose.project={name}": True}
        query = {}
        if opts["all"] or statuses:
            query["all"] = "1"
        else:
            labels["com.docker.compose.oneoff=False"] = True
        query["filters"] = json.dumps({"label": labels}, sort_keys=True, separators=(",", ":"))
        found = self.get_json("/containers/json", query)
        service = lambda c: (c.get("Labels") or {}).get("com.docker.compose.service", "")   # noqa: E731
        if services:
            found = [c for c in found if service(c) in services]
        if statuses:
            found = [c for c in found if c.get("State") in statuses]
        found.sort(key=lambda c: (c.get("Names") or [""])[0])
        if opts["quiet"]:
            return "".join(c["Id"] + "\n" for c in found), 0
        if opts["services"]:
            return "".join(n + "\n" for n in sorted({service(c) for c in found})), 0
        if not fmt or fmt == "table":
            fmt = ("table {{.Name}}\t{{.Image}}\t{{.Command}}\t{{.Service}}\t{{.RunningFor}}\t"
                   "{{.Status}}\t{{.Ports}}")
        table, template = self._template(fmt, "template parsing error: ")
        rows = []
        for c in found:
            row = self._container(c, not opts["no-trunc"], [])
            row.fields.update({"Name": row.fields["Names"], "Service": lambda c=c: service(c),
                               "Project": lambda: name})
            rows.append(row)
        return self._emit(fmt, table, template, rows,
                          {**_PS_HEADERS, "Name": "NAME", "Service": "SERVICE", "Project": "PROJECT"},
                          "*formatter.ContainerContext", "template parsing error: ")


class _Platform(dict):
    """An image's platform: printed `linux/arm64/v8`, marshalled as its JSON object."""

    def go_string(self) -> str:
        return "/".join(str(self[k]) for k in ("os", "architecture", "variant") if self.get(k))


_PS_HEADERS = {"ID": "CONTAINER ID", "Names": "NAMES", "Image": "IMAGE", "Command": "COMMAND",
               "CreatedAt": "CREATED AT", "RunningFor": "CREATED", "Ports": "PORTS",
               "State": "STATE", "Status": "STATUS", "Size": "SIZE", "Labels": "LABELS",
               "Mounts": "MOUNTS", "LocalVolumes": "LOCAL VOLUMES", "Networks": "NETWORKS",
               "Platform": "PLATFORM", "HealthStatus": "HEALTH STATUS",
               "Label": _method(lambda name: name.rsplit(".", 1)[-1].replace("-", " ")
                                .replace("_", " "))}
_NETWORK_HEADERS = {"ID": "NETWORK ID", "Name": "NAME", "Driver": "DRIVER", "Scope": "SCOPE",
                    "IPv4": "IPV4", "IPv6": "IPV6", "Internal": "INTERNAL", "Labels": "LABELS",
                    "CreatedAt": "CREATED AT",
                    "Label": _method(lambda name: name.rsplit(".", 1)[-1].replace("-", " ")
                                     .replace("_", " "))}
_VOLUME_HEADERS = {"Name": "VOLUME NAME", "Driver": "DRIVER", "Scope": "SCOPE",
                   "Mountpoint": "MOUNTPOINT", "Labels": "LABELS", "Links": "LINKS",
                   "Size": "SIZE", "Availability": "AVAILABILITY", "Group": "GROUP",
                   "Status": "STATUS",
                   "Label": _method(lambda name: name.rsplit(".", 1)[-1].replace("-", " ")
                                    .replace("_", " "))}
_DF_HEADERS = {"Type": "TYPE", "TotalCount": "TOTAL", "Active": "ACTIVE", "Size": "SIZE",
               "Reclaimable": "RECLAIMABLE"}
_STATS_HEADERS = {"Container": "CONTAINER", "Name": "NAME", "ID": "CONTAINER ID",
                  "CPUPerc": "CPU %", "MemUsage": "MEM USAGE / LIMIT", "MemPerc": "MEM %",
                  "NetIO": "NET I/O", "BlockIO": "BLOCK I/O", "PIDs": "PIDS"}
_IMAGE_HEADERS = {"ID": "IMAGE ID", "Repository": "REPOSITORY", "Tag": "TAG", "Digest": "DIGEST",
                  "CreatedSince": "CREATED", "CreatedAt": "CREATED AT", "Size": "SIZE",
                  "Containers": "CONTAINERS", "SharedSize": "SHARED SIZE",
                  "UniqueSize": "UNIQUE SIZE"}


def _ports(ports: list) -> str:
    """The PORTS column: the client's DisplayablePorts (docker/cli at v29,
    cli/command/formatter/container.go). Sorted by container port; ports that are not
    published, or are published on their own number, come first, runs of neighbours
    joined into ranges (`1880-1881/tcp`, `127.0.0.1:1883->1883/tcp`); those published
    on another number follow, one by one."""
    def join(ip, port):
        return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

    def group(key, first, last):
        ip, _, kind = key.rpartition("/")
        text = str(first) if first == last else f"{first}-{last}"
        return (f"{join(ip, text)}->{text}" if ip else text) + "/" + kind

    groups, order, out, mapped = {}, [], [], []
    rows = [(int(p["PrivatePort"]), p.get("IP", ""), int(p.get("PublicPort", 0)), p["Type"])
            for p in ports]                    # numbers arrive as written: compare as numbers
    for cur, ip, public, kind in sorted(rows):
        key = kind
        if ip:
            if public != cur:
                mapped.append(f"{join(ip, public)}->{cur}/{kind}")
                continue
            key = ip + "/" + kind
        if key not in groups:
            groups[key] = [cur, cur]
            order.append(key)
        elif cur == groups[key][1] + 1:
            groups[key][1] = cur
        else:
            out.append(group(key, *groups[key]))
            groups[key] = [cur, cur]
    return ", ".join(out + [group(k, *groups[k]) for k in order] + mapped)


class _Doc(dict):
    """An inspect document with the fields the client's Go structure has besides those
    in the JSON (`also`). They are visible to templates and not to `json`."""
    also: dict = {}


def _typed(doc):
    """What the real client's own structures add to a container's raw document for
    templates: `.ID` beside `.Id`, and fields that are left out of the JSON when empty
    but exist, as nil, in the structure (the two sizes, `.State.Health`)."""
    if isinstance(doc, dict) and "Id" in doc and "State" in doc and "Config" in doc:
        top = _Doc(doc)
        top.also = {"ID": doc["Id"], "SizeRw": None, "SizeRootFs": None}
        if isinstance(doc["State"], dict):
            state = _Doc(doc["State"])
            state.also = {"Health": None}
            top["State"] = state
        return top
    if isinstance(doc, dict) and "IPAM" in doc and "Scope" in doc and "Created" in doc:
        top = _Doc(doc)                                # a network: its Created is a Go time
        top["Created"] = _go_time(doc["Created"])
        return top
    if isinstance(doc, dict) and "Mountpoint" in doc and "Driver" in doc:
        top = _Doc(doc)                                # a volume: nil maps print as map[]
        for key in ("Labels", "Options"):
            if top.get(key) is None:
                top[key] = {}
        return top
    if isinstance(doc, dict) and "RepoTags" in doc and isinstance(doc.get("Config"), dict):
        top = _Doc(doc)                                # an image
        config = _Doc(doc["Config"])
        config.also = {"Labels": {}}
        top["Config"] = config
        return top
    return doc


_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
_UNIT_S = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600}


def _timestamp(value: str, now: float, flag: str) -> str:
    """docker's GetTimestamp for --since/--until: a duration back from now, a Unix
    time, or a date in the machine's zone."""
    if _DURATION.fullmatch(value) or (value and "".join(m.group(0) for m in _DURATION.finditer(value)) == value):
        seconds = sum(float(m.group(1)) * _UNIT_S[m.group(2)] for m in _DURATION.finditer(value))
        return str(int(now - seconds))
    if re.fullmatch(r"\d+(\.\d+)?", value):
        return value
    for pattern in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H", "%Y-%m-%d"):
        try:
            t = dt.datetime.strptime(value.replace("Z", "+0000"), pattern)
        except ValueError:
            continue
        if t.tzinfo is None:
            t = t.replace(tzinfo=machine.TZ)
        return f"{int(t.timestamp())}.{t.microsecond * 1000:09d}"
    raise _Exit(f'invalid value for "{flag}": failed to parse value as time or duration: '
                f'"{value}"\n', 1)


def _demultiplex(body: bytes) -> str:
    """The multiplexed log stream as the terminal shows it: every frame's bytes, in
    order, stdout and stderr together."""
    out, i = [], 0
    while i + 8 <= len(body):
        n = int.from_bytes(body[i + 4:i + 8], "big")
        out.append(body[i + 8:i + 8 + n])
        i += 8 + n
    return b"".join(out).decode("utf-8", "replace")
