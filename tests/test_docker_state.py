#!/usr/bin/env python3
"""Host-free tests for the shared Docker state (honeypot/docker.py).

Every view is checked against Ground Truth's recordings: the API's (phase 1) and the
shell's `docker inspect` (gt_docker_shell), so the one state behind both surfaces is
checked against both surfaces of the real machine. Only the per-boot times may differ.
Run: python3 tests/test_docker_state.py
"""
import datetime as dt
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from honeypot import identity, machine, procs                # noqa: E402
from honeypot.docker import (DockerState, go_time, human_duration,  # noqa: E402
                             parse_time)
from honeypot.knowledge import Substitutions                 # noqa: E402
from honeypot.site import SITE                               # noqa: E402
from tests import recordings                                 # noqa: E402


# Ground Truth's boot (2026-09-28 20:34:32 EDT) and the time of each recorded answer.
GT_BOOT = 1790642072.0
LIVE = ("StartedAt", "FinishedAt")


def _load(name):
    return recordings.lazy(lambda: {e["n"]: e for e in recordings.load(name)})


def api(n):
    return json.loads(API[n]["body"])


def recorded_at(n):
    date = dict(API[n]["headers"])["Date"]
    import email.utils
    return email.utils.parsedate_to_datetime(date).timestamp()


def without_live(doc):
    doc = json.loads(json.dumps(doc))
    for k in LIVE:
        doc["State"].pop(k)
    if "Health" in doc["State"]:
        doc["State"]["Health"].pop("Log")
    return doc


API = _load("gt_api_phase1_2026-09.json")
SHELL = _load("gt_docker_shell_2026-09.json")
CORPUS = _load("corpus284_lab_2026-09.json")
GT43 = _load("gt43_lab_2026-09.json")


class DockerStateCase(unittest.TestCase):
    def setUp(self):
        self.d = DockerState(GT_BOOT, "test-secret")

    def test_container_list_derived_from_inspect(self):
        """`/containers/json` is built from the inspect documents and matches the
        recording field for field, `Status` included, at the recording's time."""
        for n, all_ in ((4, False), (5, True)):
            self.assertEqual(self.d.list_containers(recorded_at(n), all=all_), api(n), n)

    def test_inspect_matches_api_and_shell(self):
        """One document per container, equal to both surfaces' recordings apart from
        the per-boot times (R10, R11)."""
        for n, sh in ((17, 10), (21, 8), (25, 9)):
            rec = api(n)
            doc = self.d.inspect(rec["Id"][:12], recorded_at(n))
            self.assertEqual(without_live(doc), without_live(rec), n)
            shell = json.loads(SHELL[sh]["output"])
            self.assertEqual(len(shell), 1)
            self.assertEqual(without_live(doc), without_live(shell[0]), sh)

    def test_influxdb_credentials(self):
        env = self.d.inspect("iot-stack-influxdb-1", GT_BOOT + 600)["Config"]["Env"]
        for kv in (f"DOCKER_INFLUXDB_INIT_USERNAME={SITE.influx_user}",
                   f"DOCKER_INFLUXDB_INIT_PASSWORD={SITE.influx_password}",
                   f"DOCKER_INFLUXDB_INIT_ADMIN_TOKEN={SITE.influx_token}"):
            self.assertIn(kv, env)

    def test_images_networks_volumes(self):
        self.assertEqual(self.d.list_images(), api(6))
        self.assertEqual(self.d.list_volumes(), api(8)["Volumes"])
        nets = self.d.list_networks()
        rec = api(7)
        for got, want in zip(nets, rec):
            if want["Name"] == "bridge":         # recreated at every boot
                self.assertNotEqual(got["Created"], want["Created"])
                got, want = dict(got, Created=None), dict(want, Created=None)
            self.assertEqual(got, want)

    def test_times(self):
        """Created stays at first bring-up; StartedAt follows the boot, in the recorded
        order, with nanoseconds that are this machine's own (R3, R12)."""
        boot = 1791000000.0
        d = DockerState(boot, "test-secret")
        starts = {}
        for c in d.containers:
            name = c["Config"]["Labels"]["com.docker.compose.service"]
            started = parse_time(c["State"]["StartedAt"]) / 1e9
            self.assertTrue(boot + 29.7 <= started < boot + 30.0, name)
            self.assertLess(parse_time(c["State"]["FinishedAt"]) / 1e9, boot)
            self.assertLess(parse_time(c["Created"]) / 1e9, boot - 86400)
            starts[name] = started
        self.assertLess(starts["mosquitto"], starts["influxdb"])
        self.assertLess(starts["influxdb"], starts["nodered"])
        again = DockerState(boot, "test-secret")
        self.assertEqual([c["State"] for c in again.containers],
                         [c["State"] for c in d.containers])       # stable within a boot
        other = DockerState(boot, "another-install")
        self.assertNotEqual(other.containers[0]["State"]["StartedAt"],
                            d.containers[0]["State"]["StartedAt"])
        recorded = {api(n)["State"]["StartedAt"] for n in (17, 21, 25)}
        self.assertFalse(recorded & {c["State"]["StartedAt"] for c in self.d.containers})

    def test_health_log(self):
        """nodered: the last five probes, ~30.1 s apart, all finished; starting before
        the first. The other two have no health check at all."""
        started = parse_time(self.d.find("iot-stack-nodered-1")["State"]["StartedAt"])
        h = self.d.inspect("iot-stack-nodered-1", started / 1e9 + 10)["State"]["Health"]
        self.assertEqual((h["Status"], h["Log"]), ("starting", []))
        self.assertEqual(self.d.list_containers(started / 1e9 + 10)[0]["Status"],
                         "Up 10 seconds (health: starting)")
        now = recorded_at(17)
        log = self.d.inspect("iot-stack-nodered-1", now)["State"]["Health"]["Log"]
        self.assertEqual(len(log), 5)
        starts = [parse_time(p["Start"]) for p in log]
        for a, b in zip(starts, starts[1:]):
            self.assertAlmostEqual((b - a) / 1e9, 30.1, delta=0.01)
        for p in log:
            took = (parse_time(p["End"]) - parse_time(p["Start"])) / 1e6
            self.assertTrue(90 < took < 105, took)
            self.assertTrue(p["Start"].endswith("-04:00"))
        self.assertLess(now - parse_time(log[-1]["End"]) / 1e9, 30.2)
        self.assertEqual(self.d.inspect("iot-stack-nodered-1", now),
                         self.d.inspect("iot-stack-nodered-1", now))
        for name in ("iot-stack-influxdb-1", "iot-stack-mosquitto-1"):
            doc = self.d.inspect(name, now)
            self.assertNotIn("Health", doc["State"])
            self.assertNotIn("Healthcheck", doc["Config"])

    def test_pids_are_the_process_tables(self):
        rows = {r[0]: r for r in procs.SERVICES}
        for c in self.d.containers:
            row = rows[c["State"]["Pid"]]
            self.assertIn(c["Id"], rows[row[1]][4])             # parent is its shim

    def test_find(self):
        nodered = "d139ff53533c7de3002a3a73db79943a968d3ab1da93dd637a4e292bd1ed3334"
        for ref in ("iot-stack-nodered-1", "/iot-stack-nodered-1", nodered, "d139ff53533c",
                    "d1"):
            self.assertEqual(self.d.find(ref)["Id"], nodered, ref)
        self.assertIsNone(self.d.find("d"))                      # d139… and d377…
        self.assertIsNone(self.d.find("D139FF"))                 # ids are lower-case only
        self.assertIsNone(self.d.find("deadbeef"))
        self.assertIsNone(self.d.find(""))

    def test_no_ground_truth_ids_after_substitution(self):
        """Loaded through the relay's substitution map, no Ground Truth install or boot
        ID is left in any view (identity.py, R3)."""
        with tempfile.TemporaryDirectory() as tmp:
            subs = Substitutions(identity.pairs(tmp, GT_BOOT, "test-secret"))
        d = DockerState(GT_BOOT, "test-secret", subs)
        now = GT_BOOT + 3600
        text = json.dumps([d.list_containers(now, all=True), d.list_images(),
                           d.list_networks(), d.list_volumes(), d.info(now),
                           d.system_df(now),
                           [d.inspect(c["Id"], now) for c in d.containers],
                           [d.stats(c, int(now * 1e9), None) for c in d.containers],
                           [d.top(c, now) for c in d.containers],
                           [d.log_lines(c, int(now * 1e9)) for c in d.containers]])
        for gt in [*identity.INSTALL.values(), *identity.BOOT.values()]:
            self.assertNotIn(gt, text)
            if len(gt) == 64:
                self.assertNotIn(gt[:12], text)
        self.assertEqual(d.find(subs(identity.INSTALL["container-nodered"]))["Name"],
                         "/iot-stack-nodered-1")


class InstallShiftCase(unittest.TestCase):
    """The setup day moves as one block to a day of this install's own (identity.py)."""
    CLASS = dt.date(2026, 10, 15)
    LATE_BOOT = dt.datetime(2026, 10, 14, 8, 0, tzinfo=machine.TZ).timestamp()

    def setUp(self):
        # The moment these answers are given: an hour after that boot. Recorded dates
        # are rewritten against the machine's clock (`ls -l` and the age of a file), so
        # it must not lie before the boot the test assumes.
        real = self.real_now = machine.now
        self.addCleanup(lambda: setattr(machine, "now", real))
        machine.now = lambda: dt.datetime.fromtimestamp(self.LATE_BOOT + 3600, machine.TZ)

    def test_window(self):
        for secret in ("a", "b", "c", "d", "e", "f"):
            shift = identity.install_shift_ns(secret, self.LATE_BOOT, self.CLASS)
            created = (parse_time(api(17)["Created"]) + shift) / 1e9
            day = dt.datetime.fromtimestamp(created, machine.TZ).date()
            self.assertIn((self.CLASS - day).days, (2, 3, 4, 5), secret)  # +-2 h may
            self.assertNotEqual(shift % 10**9, 0)                       # cross midnight
            self.assertEqual(identity.install_shift_ns(secret, self.LATE_BOOT, self.CLASS),
                             shift)                                     # fixed per install
        self.assertNotEqual(identity.install_shift_ns("a", self.LATE_BOOT, self.CLASS),
                            identity.install_shift_ns("b", self.LATE_BOOT, self.CLASS))

    def test_never_after_the_boot(self):
        """Booted before the planned day: the setup moves back to fit, whole days."""
        early = dt.datetime(2026, 10, 3, 9, 0, tzinfo=machine.TZ).timestamp()
        planned = identity.install_shift_ns("a", self.LATE_BOOT, self.CLASS)
        shift = identity.install_shift_ns("a", early, self.CLASS)
        self.assertEqual((planned - shift) % (86400 * 10**9), 0)
        d = DockerState(early, "a", shift_ns=shift)
        last_setup_minute = identity._local_ns(dt.date(2026, 9, 27), 23, 59) + shift
        self.assertLess(last_setup_minute / 1e9, early - 3600)
        for c in d.containers:
            self.assertLess(parse_time(c["Created"]) / 1e9, early)
        # The Orchestrator as deployed: booted 2026-09-27 13:06, during Ground Truth's
        # own setup day. The setup goes to an earlier day, never after the start.
        orch = dt.datetime(2026, 9, 27, 13, 6, 6, tzinfo=machine.TZ).timestamp()
        shift = identity.install_shift_ns("a", orch, self.CLASS)
        self.assertLess(shift, 0)
        d = DockerState(orch, "a", shift_ns=shift)
        for c in d.containers:
            self.assertLess(parse_time(c["Created"]), parse_time(c["State"]["StartedAt"]))
        self.assertLess(identity._local_ns(dt.date(2026, 9, 27), 23, 59) + shift,
                        (orch - 3600) * 1e9)

    def test_containers_networks_volumes_move_together(self):
        """Every install-time value moves by the same amount, so order and gaps stay;
        image build times and the per-boot bridge do not move."""
        shift = identity.install_shift_ns("a", self.LATE_BOOT, self.CLASS)
        d = DockerState(self.LATE_BOOT, "a", shift_ns=shift)
        for n, sh in ((17, 10), (21, 8), (25, 9)):
            rec = api(n)
            self.assertEqual(parse_time(d.find(rec["Name"])["Created"]),
                             parse_time(rec["Created"]) + shift)
        for got, want in zip(d.list_networks(), api(7)):
            if want["Name"] != "bridge":
                self.assertEqual(parse_time(got["Created"]),
                                 parse_time(want["Created"]) + shift)
        for got, want in zip(d.list_volumes(), api(8)["Volumes"]):
            t = parse_time(want["CreatedAt"]) + shift
            self.assertEqual(parse_time(got["CreatedAt"]), t - t % 10**9)
        self.assertEqual(d.list_images(), api(6))
        listed = {c["Names"][0]: c["Created"] for c in d.list_containers(self.LATE_BOOT)}
        for n in (17, 21, 25):
            rec = api(n)
            self.assertEqual(listed[rec["Name"]],
                             (parse_time(rec["Created"]) + shift) // 10**9)

    def test_shell_and_api_agree_on_setup_dates(self):
        """The same moments read the same on both surfaces: the recorded `ls -la /`
        (corpus n=105, a retrieval example), /root/iot-stack's files and the logs against the API's
        creation times."""
        shift = identity.install_shift_ns("a", self.LATE_BOOT, self.CLASS)
        d = DockerState(self.LATE_BOOT, "a", shift_ns=shift)
        subs = Substitutions({}, identity.date_rewriters(shift, self.LATE_BOOT))

        def ls_date(ns):
            t = dt.datetime.fromtimestamp(ns // 10**9, machine.TZ)
            return t.strftime("%b %e %H:%M")
        nets = {n["Name"]: parse_time(n["Created"]) for n in d.list_networks()}
        # Docker's own directory /opt/containerd came with the package, the minute the
        # host and none networks were made (both 18:03 on Ground Truth).
        listing = subs(CORPUS[105]["output"])
        opt = next(line for line in listing.splitlines() if line.endswith(" opt"))
        self.assertIn(ls_date(nets["host"]), opt)
        self.assertNotIn("Sep 27", listing)
        # The compose files: written just before the project network.
        files = {p: t for p, kind, t, size in d.stack_files()}
        gap = nets["iot-stack_default"] - files["/root/iot-stack"]
        self.assertTrue(0 < gap < 2 * 10**9)
        first_container = min(parse_time(c["Created"]) for c in d.containers)
        self.assertLess(files["/root/iot-stack"], first_container)
        # Each container's log starts with its first run, seconds after Created (on
        # Ground Truth compose created mosquitto and influxdb 9 s before starting them).
        for c in d.containers:
            first_line = d.log_lines(c, int(self.LATE_BOOT * 1e9))[0][0]
            self.assertTrue(0 < first_line - parse_time(c["Created"]) < 15 * 10**9,
                            c["Name"])

    def test_influx_log_ids_are_this_machines(self):
        """influxd's log ids are snowflakes of its start times: with the install shifted
        and this machine's boot, none is Ground Truth's, and each decodes to the time
        its own Welcome line prints."""
        import re
        from honeypot.docker import _SNOWFLAKE_DIGITS, _SNOWFLAKE_EPOCH_MS
        shift = identity.install_shift_ns("a", self.LATE_BOOT, self.CLASS)
        d = DockerState(self.LATE_BOOT, "a", shift_ns=shift)
        c = d.find("iot-stack-influxdb-1")
        lines = d.log_lines(c, int((self.LATE_BOOT + 4000) * 1e9))
        gt = {"15aEDCa0000", "15aEDHP0000", "15aF9VH0000", "15beECsl000", "15bp0gzG000"}
        welcomes = [re.search(r"ts=(\S+)Z .*Welcome to InfluxDB\" log_id=(\S+)", x[2])
                    for x in lines]
        welcomes = [m for m in welcomes if m]
        self.assertEqual(len(welcomes), 3)          # setup, first run, this boot
        for m in welcomes:
            self.assertNotIn(m.group(2), gt)
            n = 0
            for ch in m.group(2):
                n = n * 64 + _SNOWFLAKE_DIGITS.index(ch)
            self.assertEqual((n >> 22) + _SNOWFLAKE_EPOCH_MS,
                             parse_time(m.group(1) + "Z") // 10**6)
        ids = {i for x in lines for i in re.findall(r"log_id=(\S+)", x[2])}
        self.assertFalse(ids & gt)

    def test_unshifted_matches_ground_truth(self):
        """With no shift the derived dates are Ground Truth's own: /root/iot-stack at
        18:04 as the 43's `ls -al` shows it (n=32), and the corpus untouched."""
        d = DockerState(GT_BOOT, "a")
        t = dict((p, t) for p, k, t, s in d.stack_files())["/root/iot-stack"]
        when = dt.datetime.fromtimestamp(t // 10**9, machine.TZ).strftime("%b %e %H:%M")
        self.assertIn(f"{when} iot-stack", GT43[32]["output"])
        # ... read on the day it was recorded: later, `ls -l` prints the year for the
        # files of April (machine.ls_age_rewriters).
        machine.now = lambda: dt.datetime.fromtimestamp(GT_BOOT + 600, machine.TZ)
        subs = Substitutions({}, identity.date_rewriters(0, GT_BOOT))
        self.assertEqual(subs(CORPUS[105]["output"]), CORPUS[105]["output"])

    def test_through_the_relay(self):
        """End to end: the recorded `ls -la /` the model is shown as an example (corpus
        n=105; the replay tier is off, so the model answers) and the model's facts
        carry the same setup dates as the relay's Docker state."""
        recordings.path("corpus284_lab_2026-09.json")    # the relay shows the corpus as examples
        from honeypot.relay import Relay
        from tests.test_relay import FakePool
        # A real relay takes this computer's own boot time, not LATE_BOOT: its clock must be
        # the real one, or "now" can lie before its boot (found 2026-10-15, when the dev machine
        # had booted after the fixed hour of setUp and every recorded date read as future).
        machine.now = self.real_now
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SITE.load_json(ROOT / "honeypot" / "config.json")
            cfg.update(state_dir=tmp + "/state", log=tmp + "/log/relay.jsonl")
            pool = FakePool()
            r = Relay(cfg, str(ROOT / "honeypot"), pool=pool)
            try:
                def run(cmd):
                    body = {"user": "s", "messages": [{"role": "user", "content": cmd}],
                            "honeypot": {"event": "command"}}
                    return r.handle(body)[1]["choices"][0]["message"]["content"]
                r.handle({"user": "s", "messages": [], "honeypot": {"event": "login"}})
                host = next(n for n in r.docker.list_networks() if n["Name"] == "host")
                when = dt.datetime.fromtimestamp(parse_time(host["Created"]) // 10**9,
                                                 machine.TZ).strftime("%b %e %H:%M")
                run("ls -la /")
                shown = "\n".join(m["content"] for m in pool.calls[-1])
                self.assertIn(f"{when} opt", shown)
                run("ls -la /root/iot-stack")
                prompt = pool.calls[-1][0]["content"]
                for path, kind, t, size in r.docker.stack_files():
                    d = dt.datetime.fromtimestamp(t // 10**9, machine.TZ)
                    self.assertIn(f"{path}{'/' if kind == 'dir' else ''} ", prompt)
                    self.assertIn(f"{d:%b %e %H:%M}", prompt)
            finally:
                r._log.close()


class BootDateCase(unittest.TestCase):
    """Ground Truth's boot-relative dates follow this machine's boot (R5)."""
    BOOT = dt.datetime(2026, 9, 27, 13, 6, 6, tzinfo=machine.TZ).timestamp()

    def subs(self, shift=0):
        return Substitutions({}, identity.date_rewriters(shift, self.BOOT))

    def test_ls_root(self):
        """`ls -la /` (corpus n=105): /dev, /etc, /proc, /sys at the boot minute; /root,
        /run, /tmp as many minutes after it as on Ground Truth."""
        out = self.subs()(CORPUS[105]["output"])
        dates = {line.split()[-1]: " ".join(line.split()[-4:-1]) for line in
                 out.splitlines()[1:]}
        for name in ("dev", "etc", "proc", "sys"):
            self.assertEqual(dates[name], "Sep 27 13:06", name)
        self.assertEqual((dates["root"], dates["run"], dates["tmp"]),
                         ("Sep 27 13:15", "Sep 27 13:15", "Sep 27 13:17"))
        self.assertEqual(dates["var"], "Sep 8 13:07")             # older: untouched

    def test_one_pass(self):
        """A setup day moved onto the boot's own calendar day is not moved twice."""
        out = self.subs(shift=-86400 * 10**9)(CORPUS[105]["output"])
        self.assertIn("Sep 27 13:06 dev", out)
        self.assertIn("Sep 26 18:03 opt", out)

    def test_formats(self):
        s = self.subs()
        self.assertEqual(s("since Mon 2026-09-28 20:34:42 EDT"),
                         "since Sun 2026-09-27 13:06:16 EDT")      # seconds: exact
        self.assertEqual(s("Mon 28 Sep 20:47:12 EDT 2026"), "Sun 27 Sep 13:18:46 EDT 2026")
        self.assertEqual(s("Sep 28 20:46:07 raspberrypi"), "Sep 27 13:17:41 raspberrypi")
        self.assertEqual(s("Sep 28 18:46"), "Sep 28 18:46")       # before the boot

    def test_no_recorded_boot_dates_reach_the_relay(self):
        """No recorded answer the relay can show the model (or replay, if that tier
        is switched on) still carries Ground Truth's boot day."""
        from honeypot.knowledge import Knowledge
        k = Knowledge(str(recordings.path("corpus284_lab_2026-09.json")),
                      str(recordings.path("eval_not_gradable.json")), self.subs())
        for e in k.examples:
            for bad in ("Sep 28 2", "2026-09-28 2", "28 Sep 2"):
                self.assertNotIn(bad, e["output"], e["command"])


class FormatCase(unittest.TestCase):
    def test_go_time_round_trips_recorded_strings(self):
        for n in (17, 21, 25):
            rec = api(n)
            times = [rec["Created"], rec["State"]["StartedAt"], rec["State"]["FinishedAt"]]
            for t in times:
                self.assertEqual(go_time(parse_time(t)), t)
        for p in api(17)["State"]["Health"]["Log"]:          # 8-digit fractions in there
            self.assertEqual(go_time(parse_time(p["Start"]), local=True), p["Start"])
        self.assertEqual(go_time(1790642072 * 10**9), "2026-09-29T00:34:32Z")

    def test_human_duration(self):
        cases = {0.5: "Less than a second", 1: "1 second", 59: "59 seconds",
                 60: "About a minute", 13 * 60: "13 minutes", 85 * 60: "About an hour",
                 89 * 60: "About an hour", 90 * 60: "2 hours", 27 * 3600: "27 hours",
                 6 * 86400: "6 days", 15 * 86400: "2 weeks", 70 * 86400: "2 months",
                 800 * 86400: "2 years"}
        for secs, want in cases.items():
            self.assertEqual(human_duration(secs), want, secs)


if __name__ == "__main__":
    unittest.main()
