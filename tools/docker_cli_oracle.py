#!/usr/bin/env python3
"""What does the REAL docker client print? Ground Truth's exact client, asked here.

The shell's `docker ps / images / inspect / logs` are written in Python
(honeypot/dockercli.py) and must print what the real client would print for the same
state, for every flag. This tool is how that is checked without touching Ground Truth:

  - the client is Ground Truth's own: docker-ce-cli 29.8.1 for arm64, the package staged
    in offline/docker-gt/ for the install, unpacked to offline/docker-cli/docker;
  - it runs in the Debian 13 arm64 userland of offline/debian13-arm64 (proot + qemu,
    no root needed; README.md there);
  - it talks to the honeypot's own fake Docker API (honeypot/dockerapi.py), started
    here on a local port with a fixed state. It never sees a real Docker daemon.

So the client is real and the daemon is ours: whatever it prints is, by definition,
what a real `docker` shows for the state the fake API serves. dockercli.py is compared
with it case by case, and the cases are kept as a fixture so the test suite needs
neither the userland nor the client:

  .venv/bin/python tools/docker_cli_oracle.py --write     # rebuild tests/fixtures/docker_cli.json
  .venv/bin/python tools/docker_cli_oracle.py --check     # run every case now and compare with dockercli.py
  .venv/bin/python tools/docker_cli_oracle.py --check -- network     # only the cases starting `docker network`
  .venv/bin/python tools/docker_cli_oracle.py -- ps -a --no-trunc    # ask about one command line

One-time setup of the client (the userland must exist already):
  mkdir -p offline/docker-cli/x && cd offline/docker-cli/x
  ar x ../../docker-gt/docker-ce-cli_29.8.1-1~debian.13~trixie_arm64.deb
  tar -xf data.tar.xz ./usr/bin/docker && cp usr/bin/docker ../docker && cd .. && rm -r x
and of its two plugins (compose, buildx), into offline/docker-cli/cli-plugins/:
  mkdir -p offline/docker-cli/x offline/docker-cli/cli-plugins && cd offline/docker-cli/x
  for d in docker-compose-plugin_5.5.1 docker-buildx-plugin_0.37.1; do
    ar x ../../docker-gt/${d}-1~debian.13~trixie_arm64.deb && tar -xf data.tar.* && rm data.tar.* control.tar.* debian-binary
  done
  cp usr/libexec/docker/cli-plugins/docker-* ../cli-plugins/ && cd .. && rm -r x
The compose project directory the userland sees as /root/iot-stack is written by this
tool from the recorded `cat /root/iot-stack/docker-compose.yml` (gt_docker_shell).
"""
from __future__ import annotations
import argparse
import datetime as dt
import fcntl
import json
import os
import pathlib
import pty
import select
import struct
import subprocess
import sys
import termios
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from honeypot import identity, machine                      # noqa: E402
from honeypot.docker import DockerState                     # noqa: E402
from honeypot.dockerapi import DockerAPI, serve             # noqa: E402

BOX = ROOT / "offline" / "debian13-arm64"
CLIENT = ROOT / "offline" / "docker-cli" / "docker"
# Ground Truth's two client plugins (compose 5.5.1, buildx 0.37.1), unpacked the same
# way from offline/docker-gt/ (docstring above). With them `docker info` lists its
# plugins as on the real machine and `docker compose` is the real one.
PLUGINS = ROOT / "offline" / "docker-cli" / "cli-plugins"
PROJECT = ROOT / "offline" / "docker-cli" / "iot-stack"       # /root/iot-stack in the userland
FIXTURE = ROOT / "tests" / "fixtures" / "docker_cli.json"
SECRET = "oracle"
CLASS_START = dt.date(2026, 11, 2)
UP_FOR_S = 3 * 3600            # the machine booted three hours before "now"
ATTACK_AGO_S = 2.9 * 3600      # the attacker's containers are just under three hours old
# docker says "3 hours" for anything from 2.5 to 3.5 hours. Both ages sit well inside
# that, so the wording does not flip during the minutes it takes to record the cases.

# The attacker's path of gt_api_phase2_2026-09.json, shortened: one container with the
# host mounted, started; one privileged, created and never started; one started and
# stopped again.
ATTACK = [
    ("POST", "/containers/create", {"Image": "eclipse-mosquitto:2",
                                          "Cmd": ["sh", "-c", "cat /mnt/etc/hostname; sleep 300"],
                                          "HostConfig": {"Binds": ["/:/mnt:ro"]}}),
    ("POST", "/containers/{0}/start", None),
    ("POST", "/containers/create?name=probe", {"Image": "influxdb:2.7-alpine", "Cmd": ["id"],
                                               "HostConfig": {"Privileged": True, "PidMode": "host",
                                                              "Binds": ["/:/host:ro"]}}),
    ("POST", "/containers/create?name=old", {"Image": "eclipse-mosquitto:2", "Cmd": ["sleep", "1"]}),
    ("POST", "/containers/{2}/start", None),
    ("POST", "/containers/{2}/stop?t=0", None),
]


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def build(t0: float, scenario: str):
    """The state of a scenario at time t0, and the API in front of it. Used by the
    oracle and, with the recorded t0, by the test that replays the fixture."""
    boot = t0 - UP_FOR_S
    shift = identity.install_shift_ns(SECRET, boot, CLASS_START)
    state = DockerState(boot, SECRET, shift_ns=shift)
    clock = Clock(t0)
    api = DockerAPI(state, clock, clock.sleep)
    if scenario == "attacked":
        clock.t = t0 - ATTACK_AGO_S
        ids = []
        for method, path, body in ATTACK:
            a = api.route(method, path.format(*ids), body=json.dumps(body).encode() if body else b"")
            if "create" in path:
                assert a.status == 201, (path, a.status, a.body)
                ids.append(json.loads(a.body)["Id"])
            clock.t += 2
        clock.t = t0
    return state, api, clock


def _project_dir():
    """/root/iot-stack as the real machine has it, as far as the client reads it: the
    compose file, from the recording."""
    shell = json.loads((ROOT / "gt_docker_shell_2026-09.json").read_text())
    text = next(e["output"] for e in shell if e["command"] == "cat /root/iot-stack/docker-compose.yml")
    (PROJECT / "mosquitto" / "config").mkdir(parents=True, exist_ok=True)
    (PROJECT / "docker-compose.yml").write_text(text + "\n")


class Oracle:
    def __init__(self, scenario: str, t0: float | None = None):
        for need in (BOX / "rootfs", BOX / "proot", BOX / "qemu-aarch64-static", CLIENT,
                     PLUGINS / "docker-compose", PLUGINS / "docker-buildx"):
            if not need.exists():
                sys.exit(f"missing {need}: see this file's docstring and "
                         f"offline/debian13-arm64/README.md")
        _project_dir()
        self.scenario, self.t0 = scenario, t0 or time.time()
        self.state, self.api, self.clock = build(self.t0, scenario)
        self.requests = []          # what the client asked the API, for the curious
        self.srv = serve(self.api, "127.0.0.1", 0, self.requests.append)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _cmd(self, argv, cwd="/root"):
        return [str(BOX / "proot"), "-0", "-q", str(BOX / "qemu-aarch64-static"), "-r",
                str(BOX / "rootfs"), "-b", "/dev", "-b", "/proc", "-b", "/sys",
                "-b", f"{CLIENT}:/usr/bin/docker",
                "-b", f"{PLUGINS}:/usr/libexec/docker/cli-plugins",
                "-b", f"{PROJECT}:/root/iot-stack", "-w", cwd, "/usr/bin/env", "-i",
                "HOME=/root", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "TZ=America/New_York", "LANG=en_GB.UTF-8", "TERM=xterm",
                f"DOCKER_HOST=tcp://127.0.0.1:{self.port}", "docker", *argv]

    def run(self, argv: list[str], tty: bool = False, cols: int = 80, cwd: str = "/root") -> dict:
        """One `docker ARGV`. The API's clock is the real time at this moment, which is
        also the client's own clock; it is returned so the case can be replayed."""
        for _ in range(4):
            now = self.clock.t = time.time()
            if not tty:
                p = subprocess.run(self._cmd(argv, cwd), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
                out, code = p.stdout.decode("utf-8", "replace"), p.returncode
            else:
                out, code = self._run_tty(argv, cols, cwd)
            # proot, the user-space chroot, now and then prints a memory report of its
            # own after the client has ended (seen once in 905 runs, on a loaded
            # machine). It is the emulator's text, not the client's: ask again.
            if "talloc report on" not in out:
                break
        case = {"argv": argv, "tty": tty, "cols": cols, "now": now, "output": out, "exit": code}
        if cwd != "/root":
            case["cwd"] = cwd
        return case

    def _run_tty(self, argv, cols, cwd="/root"):
        pid, fd = pty.fork()
        if pid == 0:
            os.execv(self._cmd(argv, cwd)[0], self._cmd(argv, cwd))
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, cols, 0, 0))
        chunks = []
        while True:
            r, _, _ = select.select([fd], [], [], 120)
            if not r:
                break
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        _, status = os.waitpid(pid, 0)
        return b"".join(chunks).decode("utf-8", "replace").replace("\r\n", "\n"), os.waitstatus_to_exitcode(status)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scenario", default="base", choices=["base", "attacked"])
    ap.add_argument("--tty", action="store_true", help="give the client a terminal")
    ap.add_argument("--cols", type=int, default=80)
    ap.add_argument("--cwd", default="/root", help="the directory the command runs in")
    ap.add_argument("--write", action="store_true", help="rebuild the fixture")
    ap.add_argument("--sequences-only", action="store_true",
                    help="with --write: keep the recorded single cases, record the sequences again")
    ap.add_argument("--check", action="store_true", help="compare dockercli.py with the client now; "
                    "words after `--` limit it to the cases that start with them")
    ap.add_argument("--show", type=int, default=12, help="with --check: how many differences to print")
    ap.add_argument("argv", nargs="*")
    args = ap.parse_args()
    if args.write or args.check:
        from tests.docker_cli_cases import generate, check       # the list of cases lives with the tests
        if args.write:
            return generate(Oracle, FIXTURE, args.sequences_only)
        return check(Oracle, args.show, " ".join(args.argv))
    o = Oracle(args.scenario)
    r = o.run(args.argv, args.tty, args.cols, args.cwd)
    sys.stdout.write(r["output"])
    print(f"[exit {r['exit']}]", file=sys.stderr)
    o.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
