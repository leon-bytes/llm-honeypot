#!/usr/bin/env python3
"""The shell's `docker` commands (honeypot/dockercli.py), checked two ways.

Against Ground Truth's recordings (gt_docker_shell_2026-09.json), and against what
Ground Truth's own docker client prints when it talks to the fake API
(tests/fixtures/docker_cli.json, recorded by tools/docker_cli_oracle.py): several
hundred command lines, every flag of `ps`, `images`, `inspect` and `logs`.

Run: python3 tests/test_dockercli.py
"""
import json
import pathlib
import re
import sys
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT / "tools"))

from honeypot import dockercli, gotemplate                    # noqa: E402
from honeypot.docker import DockerState                       # noqa: E402
from docker_cli_oracle import build                           # noqa: E402
from tests.docker_cli_cases import comparable, ours, replay   # noqa: E402
from honeypot.site import SITE                                # noqa: E402
from tests import recordings                                  # noqa: E402

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# The real client's answers hold the site's values as @@key@@ (honeypot/site.py).
_RECORDED = SITE.load_json(ROOT / "tests" / "fixtures" / "docker_cli.json")
FIXTURE, SEQUENCES = _RECORDED["cases"], _RECORDED["sequences"]

SHELL = recordings.lazy(lambda: {e["n"]: e for e in recordings.load("gt_docker_shell_2026-09.json")})
GT_BOOT = 1790642072.0
NOW = GT_BOOT + 800


def cells(line: str) -> list[str]:
    """A `docker ps` row split into its columns (fields are separated by 2+ spaces; no
    field here has an internal run of two spaces)."""
    return re.split(r"\s{2,}", line.rstrip())


class DockerCliCase(unittest.TestCase):
    def setUp(self):
        self.state = DockerState(GT_BOOT, "test-secret")
        self.sess = SimpleNamespace(terminal=True, cols=200)

    def render(self, *argv):
        return dockercli.render(self.state, ["docker", *argv], self.sess, NOW)

    # ---------------------------------------------------------------- images

    def test_images_matches_recording_byte_for_byte(self):
        """Nothing in `docker images` depends on the clock (ids are content hashes, sizes
        are fixed), so it matches Ground Truth exactly. The recording was made on a
        terminal and stored without the colour codes the client prints there."""
        out, code = self.render("images")
        self.assertIn("\x1b[34m\x1b[1meclipse-mosquitto:2\x1b[0m", out)   # in colour
        self.assertEqual((ANSI.sub("", out), code), (SHELL[3]["output"], 0))

    def test_images_without_a_terminal_has_no_colour_and_no_legend(self):
        for change in ({"terminal": False}, {"piped": True}):     # no terminal, or `| grep`
            sess = SimpleNamespace(terminal=True, cols=200, **{})
            vars(sess).update(change)
            out, code = dockercli.render(self.state, ["docker", "images"], sess, NOW)
            self.assertNotIn("\x1b", out)
            self.assertTrue(out.startswith("IMAGE "), out[:40])

    # ---------------------------------------------------------------- ps

    def test_ps_header_and_stable_columns(self):
        """The header is exact; the id/image/command/ports/names columns match the
        recording (CREATED and STATUS depend on the clock, so they are not compared)."""
        out, _ = self.render("ps")
        got = out.split("\n")
        want = SHELL[1]["output"].split("\n")
        self.assertEqual(got[0], want[0])                    # header, byte for byte
        got_rows = {cells(l)[0]: cells(l) for l in got[1:]}
        for wl in want[1:]:
            w = cells(wl)
            g = got_rows[w[0]]                               # same CONTAINER ID
            self.assertEqual((g[0], g[1], g[2], g[5], g[6]),  # id,image,command,ports,name
                             (w[0], w[1], w[2], w[5], w[6]))

    def test_ps_hides_created_until_started(self):
        cid = self.state.create_container({"Image": "eclipse-mosquitto:2",
                                           "Cmd": ["sleep", "1"]}, None, NOW)[0]["Id"]
        running = [cells(l)[0] for l in self.render("ps")[0].split("\n")[1:]]
        self.assertNotIn(cid[:12], running)                  # created, not running
        all_ids = [cells(l)[0] for l in self.render("ps", "-a")[0].split("\n")[1:]]
        self.assertIn(cid[:12], all_ids)                     # shows with -a, as Created
        row = next(cells(l) for l in self.render("ps", "-a")[0].split("\n")[1:]
                   if cells(l)[0] == cid[:12])
        self.assertIn("Created", row)

    def test_ps_shows_a_started_container_with_up_status_and_ports(self):
        c = self.state.create_container({"Image": "eclipse-mosquitto:2",
                                         "Cmd": ["sleep", "300"]}, None, NOW)[0]
        self.state.start_container(c, NOW)
        line = next(l for l in self.render("ps")[0].split("\n")[1:]
                    if l.startswith(c["Id"][:12]))
        self.assertIn("eclipse-mosquitto:2", line)
        self.assertRegex(line, r"\bUp\b")                    # running, Up … status

    # ---------------------------------------------------------------- inspect

    def test_inspect_is_the_same_document_as_the_api(self):
        """`docker inspect` prints exactly the inspect document the API serves, pretty
        printed - the cross-surface guarantee at the single-container level."""
        out, code = self.render("inspect", "iot-stack-mosquitto-1")
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0], self.state.inspect("iot-stack-mosquitto-1", NOW))
        self.assertTrue(out.startswith("[\n    {\n"))         # Go's 4-space indent

    def test_inspect_matches_recording_shape(self):
        out, _ = self.render("inspect", "iot-stack-influxdb-1")
        got = json.loads(out)[0]
        want = json.loads(SHELL[8]["output"])[0]
        self.assertEqual(list(got), list(want))              # same top-level keys, in order
        self.assertEqual(got["Config"]["Image"], want["Config"]["Image"])

    def test_inspect_unknown_is_the_clients_own_error(self):
        self.assertEqual(self.render("inspect", "nosuch"),
                         ("[]\nerror: no such object: nosuch", 1))

    def test_inspect_finds_images_networks_and_volumes_too(self):
        for ref, key in (("influxdb:2.7-alpine", "RepoTags"), ("iot-stack_default", "IPAM"),
                         ("iot-stack_influxdb-data", "Mountpoint")):
            out, code = self.render("inspect", ref)
            self.assertEqual(code, 0, ref)
            self.assertIn(key, json.loads(out)[0], ref)

    # ---------------------------------------------------------------- logs

    def test_logs_of_a_created_container_is_empty(self):
        cid = self.state.create_container({"Image": "eclipse-mosquitto:2"}, None, NOW)[0]["Id"]
        self.assertEqual(self.render("logs", cid), ("", 0))

    def test_logs_unknown_container_errors(self):
        out, code = self.render("logs", "nope")
        self.assertEqual((out, code),
                         ("Error response from daemon: No such container: nope", 1))

    # ---------------------------------------------------------------- routing

    def test_unhandled_subcommands_are_unsupported(self):
        """What changes the machine's state is not answered here yet (TASKS.md)."""
        for argv in (["run", "eclipse-mosquitto:2"], ["exec", "iot-stack-mosquitto-1", "id"], ["kill", "x"],
                     ["run", "-it", "--rm", "influxdb:2.7-alpine", "sh"],
                     ["create", "--memory", "1g", "influxdb:2.7-alpine"],
                     ["run", "-d", "-e", "HOME", "nodered/node-red:4.1"],
                     ["run", "-d", "-p", "8000-8010:80", "nodered/node-red:4.1"],
                     ["restart", "x"], ["network", "create", "n"], ["volume", "create"],
                     ["compose", "up"], ["start", "-a", "x"], ["container", "remove", "x"]):
            with self.assertRaises(dockercli.Unsupported, msg=argv):
                self.render(*argv)

    def test_the_flag_that_started_this(self):
        """2026-10-08: `docker ps -a --no-trunc` went to the model and came back as an
        empty table, with three containers running."""
        out, code = self.render("ps", "-a", "--no-trunc")
        ids = {c["Id"] for c in self.state.list_containers(NOW, all=True)}
        self.assertEqual(len(ids), 3)
        self.assertEqual({line.split()[0] for line in out.split("\n")[1:]}, ids)


PATHS_THAT_CHANGE_STATE = {"start", "stop", "rm", "pull", "run", "create", "exec"}


class AgainstTheRealClient(unittest.TestCase):
    """Every recorded case: dockercli.py prints what Ground Truth's docker client
    printed for the same state, byte for byte, with the same exit status. The two
    things the real client itself does not fix (the order of `docker info`'s runtimes,
    the traffic counters of a several-container `docker stats`) are compared as
    docker_cli_cases.comparable says."""

    def test_every_case(self):
        states, bad = {}, []
        for case in FIXTURE:
            key = (case["scenario"], case["t0"])
            if key not in states:
                states[key] = build(case["t0"], case["scenario"])
            state, _, clock = states[key]
            try:
                got = ours(state, clock, case)
            except Exception as e:
                got = (f"<{type(e).__name__}: {e}>", -99)
            if (comparable(case, got[0]), got[1]) != (comparable(case, case["output"]), case["exit"]):
                bad.append("docker " + " ".join(case["argv"]))
        self.assertEqual(bad, [])
        self.assertGreater(len(FIXTURE), 900)

    def test_the_cases_cover_every_command_and_both_scenarios(self):
        seen = {(c["scenario"], " ".join(c["argv"][:len(path)]))
                for c in FIXTURE for path in dockercli.PATHS if tuple(c["argv"][:len(path)]) == path}
        for scenario in ("base", "attacked"):
            for path in dockercli.PATHS:
                if path in (("container", "list"), ("container", "ps"), ("image", "list")):
                    continue                     # spellings of `ls`, tried on one scenario
                if PATHS_THAT_CHANGE_STATE & {dockercli.PATHS[path]}:
                    continue                     # checked in the sequences instead
                self.assertIn((scenario, " ".join(path)), seen)
            for sub in ("ls", "ps", "version"):
                self.assertTrue(any(c["scenario"] == scenario and c["argv"][0] == "compose"
                                    and sub in c["argv"] for c in FIXTURE), sub)
        self.assertTrue(any(c["tty"] for c in FIXTURE))
        self.assertTrue(any(c.get("cwd") for c in FIXTURE))

    def test_every_sequence_that_changes_state(self):
        """`start`, `stop`, `rm` and `pull` in sequences on one machine, with listings
        in between: after every step ours prints what the real client printed, so the
        state both arrived at is the same."""
        bad = []
        for seq in SEQUENCES:
            for case, got in replay(build, seq):
                if (comparable(case, got[0]), got[1]) != (comparable(case, case["output"]), case["exit"]):
                    bad.append("docker " + " ".join(case["argv"]))
        self.assertEqual(bad, [])
        steps = [c["argv"][0] for q in SEQUENCES for c in q["steps"]]
        for sub in ("start", "stop", "rm", "pull", "run", "create"):
            self.assertIn(sub, steps)
        self.assertGreater(len(steps), 80)

    def test_run_with_an_image_that_is_not_there_on_a_terminal(self):
        """What a student types first: `docker run --rm -it alpine sh`. On a terminal
        the client goes for the image, which is not there and cannot be pulled."""
        state = DockerState(GT_BOOT, "test-secret")
        sess = SimpleNamespace(terminal=True, cols=120, cwd="/root", delay=0.0)
        out, code = dockercli.render(state, ["docker", "run", "--rm", "-it", "alpine", "sh"], sess, NOW)
        self.assertEqual(code, 125)
        self.assertTrue(out.startswith("Unable to find image 'alpine:latest' locally\ndocker: Error "
                                       "response from daemon: failed to resolve reference "
                                       '"docker.io/library/alpine:latest"'), out[:160])
        self.assertTrue(out.endswith("\n\nRun 'docker run --help' for more information"))
        self.assertEqual(sess.delay, 5.0)                     # the resolver's retries
        self.assertEqual(len(state.list_containers(NOW, all=True)), 3)   # nothing was made

    def test_what_is_not_compared_literally_is_little(self):
        """The masking is for several-container `docker stats` and one line of
        `docker info`, nothing else."""
        masked = [c for c in FIXTURE if comparable(c, c["output"]) != c["output"]]
        for c in masked:
            self.assertTrue("stats" in c["argv"][:2] or "info" in c["argv"][:2], c["argv"])
        self.assertLess(len(masked), 40)


class TheReadOnlyCommands(DockerCliCase):
    """`network`, `volume`, `version`, `info`, `system df`, `stats`, `compose ps`
    against Ground Truth's own recorded shell answers (gt_docker_shell_2026-09.json),
    which the fake API's state is seeded from. Recorded 13 minutes after the boot."""

    def at(self, *argv, cwd="/root"):
        self.sess.cwd, self.sess.delay = cwd, 0.0
        return dockercli.render(self.state, ["docker", *argv], self.sess, NOW)

    def test_network_ls_volume_ls_version_and_df_equal_the_recording(self):
        for n, argv in ((4, ["network", "ls"]), (5, ["volume", "ls"]), (6, ["version"]),
                        (13, ["system", "df"])):
            self.assertEqual(self.at(*argv), (SHELL[n]["output"], 0), argv)

    def test_info_equals_the_recording(self):
        out, code = self.at("info")
        self.assertEqual((out, code), (SHELL[7]["output"], 0))

    def test_stats_equals_the_recording_but_for_the_counters(self):
        """The traffic and block I/O counters grow with time and the CPU share moves;
        everything else is the recording's: the header, the three rows in their order,
        the IDs and names, `0B / 0B` and `0.00%` for memory (this kernel has no memory
        accounting) and the number of processes."""
        out, code = self.at("stats", "--no-stream")
        self.assertEqual(code, 0)
        want = SHELL[12]["output"].split("\n")
        got = out.split("\n")
        self.assertEqual(got[0], want[0])
        self.assertEqual(len(got), len(want))
        for g, w in zip(got[1:], want[1:]):
            g, w = cells(g), cells(w)
            self.assertEqual(len(g), 8)
            for col in (0, 1, 3, 4, 7):          # id, name, memory, memory %, pids
                self.assertEqual(g[col], w[col])
            self.assertRegex(g[2], r"^\d\.\d\d%$")
            for col in (5, 6):
                self.assertRegex(g[col], r"^\d+(\.\d+)?[kM]?B / \d+(\.\d+)?[kM]?B$")
        self.assertTrue(1.0 <= self.sess.delay <= 2.0, self.sess.delay)   # recorded: 2.0 s

    def test_compose_ps_equals_the_recording_but_for_the_clock(self):
        want = SHELL[11]["output"]                       # docker compose -f <file> ps
        for argv, cwd in ((["compose", "-f", "/root/iot-stack/docker-compose.yml", "ps"], "/root"),
                          (["compose", "ps"], "/root/iot-stack"),
                          (["compose", "-p", "iot-stack", "ps"], "/tmp")):
            out, code = self.at(*argv, cwd=cwd)
            self.assertEqual(code, 0)
            clock = lambda t: re.sub(r"Up \d+ minutes", "Up N minutes", t)        # noqa: E731
            self.assertEqual(clock(out), clock(want), argv)
        self.assertEqual(self.at("compose", "ps", cwd="/root"),
                         ("no configuration file provided: not found", 1))

    def test_what_changes_state_still_goes_to_the_model(self):
        for argv in (["run", "eclipse-mosquitto:2"], ["exec", "-it", "iot-stack-influxdb-1", "sh"], ["kill", "x"],
                     ["create", "--cpus", "2", "influxdb:2.7-alpine"],
                     ["network", "create", "n"], ["volume", "rm", "v"], ["system", "prune"],
                     ["compose", "up", "-d"], ["compose", "-p", "iot-stack", "logs"]):
            with self.assertRaises(dockercli.Unsupported, msg=argv):
                self.at(*argv)


class NothingGoesToTheModel(DockerCliCase):
    """No flag combination of the four commands may fall through to the model: that is
    how the shell came to disagree with the API."""

    FLAGS = ["-a", "-q", "-s", "-l", "-n", "2", "--no-trunc", "--format", "{{.ID}}", "-f",
             "status=running", "--filter", "x=y", "--digests", "--tree", "--type", "image",
             "--tail", "3", "-t", "--since", "1h", "--until", "5m", "--details", "--follow",
             "--help", "-h", "--bogus", "-z", "--format", "{{", "--format", "{{.Nope}}",
             "iot-stack-nodered-1", "nosuch", "influxdb:2.7-alpine", "--", "-x=1", "--last=x",
             "--all=false", "--size", "--format", "table {{.Names}}\\t{{.Image}}", "json", ""]

    def test_random_flag_soup_is_always_answered_here(self):
        import random
        rng = random.Random(7)
        for _ in range(3000):
            sub = rng.choice(["ps", "images", "inspect", "logs", "container ls",
                              "image ls", "container logs", "network ls", "network inspect",
                              "volume ls", "volume inspect", "version", "info", "system df",
                              "stats", "container stats", "container inspect"]).split()
            argv = sub + [rng.choice(self.FLAGS) for _ in range(rng.randint(0, 5))]
            self.sess.terminal = rng.random() < 0.5
            try:
                out, code = self.render(*argv)
            except dockercli.Unsupported as e:
                self.fail(f"docker {' '.join(argv)} would go to the model: {e}")
            self.assertIsInstance(out, str)
            self.assertIsInstance(code, int)

    def test_through_the_shell_the_source_is_code(self):
        import tempfile
        from honeypot.relay import Relay
        from tests.test_relay import FakePool
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
            cfg.update(state_dir=tmp + "/state", log=tmp + "/relay.jsonl")
            relay = Relay(cfg, str(ROOT / "honeypot"), pool=FakePool())
            try:
                def run(cmd):
                    resp = relay.handle({"user": "s", "messages": [{"role": "user", "content": cmd}],
                                         "honeypot": {"event": "command"}})[1]
                    return resp["choices"][0]["message"]["content"], resp["honeypot"]
                relay.handle({"user": "s", "messages": [], "honeypot": {"event": "login"}})
                for cmd in ("docker ps -a --no-trunc", "docker ps -q", "docker ps --format '{{.Names}}'",
                            "docker images -q", "docker inspect -f '{{.State.Status}}' iot-stack-nodered-1",
                            "docker logs --tail 2 iot-stack-mosquitto-1", "docker ps --bogus",
                            "docker container ls -a", "docker ps -aq | wc -l", "whoami"):
                    text, ext = run(cmd)
                    self.assertEqual(ext["source"], "builtin", cmd)
                self.assertEqual(run("docker ps -aq | wc -l")[0], "3\n")
                self.assertEqual(run("whoami")[0], run("id -un")[0])
                self.assertEqual(run("docker images | grep influx")[0].count("\x1b"), 0)   # piped
                self.assertEqual(run("docker network ls")[1]["source"], "builtin")  # since 2026-10-13
                # since 2026-10-13 a container made in the shell exists, here and on the API
                text, ext = run("docker run -d --name fromshell -p 8080:80 eclipse-mosquitto:2 sleep 600")
                self.assertEqual(ext["source"], "builtin")
                self.assertRegex(text, r"^[0-9a-f]{64}\n$")
                self.assertEqual(run("docker ps -q | wc -l")[0], "4\n")
                self.assertIn("0.0.0.0:8080->80/tcp", run("docker ps -f name=fromshell")[0])
                self.assertEqual(run("docker rm -f fromshell")[0], "fromshell\n")
                self.assertEqual(run("docker run eclipse-mosquitto:2 id")[1]["source"], "model")   # still the model's
            finally:
                relay._log.close()

    def test_logs_follow_prints_what_is_there_and_returns(self):
        plain = self.render("logs", "--tail", "2", "iot-stack-mosquitto-1")
        self.assertEqual(self.render("logs", "-f", "--tail", "2", "iot-stack-mosquitto-1"), plain)


class GoTemplateCase(unittest.TestCase):
    DOC = gotemplate.loads('{"Name":"/x","N":191635456,"L":["a","b"],"M":{"b":"2","a":"1"},'
                           '"S":{"Up":true,"Pid":7},"E":"<a&b>"}')

    def t(self, source):
        return gotemplate.Template(source).render(self.DOC)

    def test_values_print_as_go_prints_them(self):
        self.assertEqual(self.t("{{.Name}} {{.N}} {{.L}} {{.M}} {{.S.Up}} {{.S.Pid}}"),
                         "/x 191635456 [a b] map[a:1 b:2] true 7")
        self.assertEqual(self.t("{{json .M}}{{json .E}}"), '{"b":"2","a":"1"}"<a&b>"')

    def test_control_flow(self):
        self.assertEqual(self.t("{{range $i, $v := .L}}{{if $i}},{{end}}{{$v}}{{end}}"), "a,b")
        self.assertEqual(self.t("{{range $k, $v := .M}}{{$k}}={{$v}};{{end}}"), "a=1;b=2;")
        self.assertEqual(self.t("{{if .S.Up}}up{{else}}down{{end}}{{with .S}} {{.Pid}}{{end}}"), "up 7")
        self.assertEqual(self.t("{{range .Nothing}}x{{else}}empty{{end}}"
                                .replace(".Nothing", "(index .M \"zz\")")), "empty")
        self.assertEqual(self.t("a {{- 1 -}} b"), "a1b")

    def test_functions(self):
        self.assertEqual(self.t('{{printf "%s:%05d|%-4s|%q" .Name .S.Pid "x" "y"}}'), '/x:00007|x   |"y"')
        self.assertEqual(self.t('{{len .L}} {{index .L 1}} {{join .L "+"}} {{upper .Name}} '
                                '{{eq .S.Pid 7}} {{and .S.Up 0}} {{.S.Pid | printf "%d!"}}'),
                         "2 b a+b /X true 0 7!")

    def test_errors_are_gos_own_words(self):
        for source, message in (
                ("{{.Nope}}", 'template: :1:2: executing "" at <.Nope>: map has no entry for key "Nope"'),
                ("{{.S.Nope.X}}", 'template: :1:4: executing "" at <.S.Nope.X>: map has no entry for key "Nope"'),
                ("{{.Name", "template: :1: unclosed action"),
                ("{{nosuch .Name}}", 'template: :1: function "nosuch" not defined')):
            with self.assertRaises(gotemplate.TemplateError) as cm:
                self.t(source)
            self.assertEqual(str(cm.exception), message)


if __name__ == "__main__":
    unittest.main()
