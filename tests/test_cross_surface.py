#!/usr/bin/env python3
"""The paper's main claim, as a test (R10, R11): the fake Docker API (port 2375) and the
shell's `docker` commands read one shared state, so they never disagree.

The whole Phase 2 attacker path is driven through the API, and after every step the
shell's `docker ps` / `ps -a` / `inspect` are checked to show exactly what the API shows.
Both surfaces come from the same Relay, which builds one DockerState and hands it to both
the API and the shell - so a divergence here means the two surfaces drifted apart.

Run: python3 tests/test_cross_surface.py
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import test_relay                                            # noqa: E402

from tests import recordings                                 # noqa: E402

P2 = recordings.lazy(lambda: {e["n"]: e for e in recordings.load("gt_api_phase2_2026-09.json")})


class CrossSurfaceCase(test_relay.RelayCase):
    def setUp(self):
        super().setUp()
        self.api = self.relay.docker_api
        self.api.sleep = lambda s: None          # don't really wait out the 10 s stop

    # --- the two surfaces, over the one shared state

    def api_call(self, method, path, body=None):
        a = self.api.route(method, path,
                           body=json.dumps(body).encode() if body is not None else b"")
        return a.status, (a.body if not a.stream else b"".join(a.stream))

    def api_ids(self, show_all):
        _, body = self.api_call("GET", "/containers/json" + ("?all=1" if show_all else ""))
        return sorted(c["Id"][:12] for c in json.loads(body))

    def shell_ids(self, show_all):
        text, meta = self.out("docker ps -a" if show_all else "docker ps")
        self.assertEqual(meta["source"], "builtin")          # code, not the model
        return sorted(m.group(1) for line in text.split("\n")[1:]
                      for m in [re.match(r"([0-9a-f]{12})\b", line)] if m)

    def assert_agree(self, label):
        self.assertEqual(self.shell_ids(False), self.api_ids(False), f"{label}: docker ps")
        self.assertEqual(self.shell_ids(True), self.api_ids(True), f"{label}: docker ps -a")

    # --- the attack

    def test_phase2_attack_keeps_shell_and_api_in_agreement(self):
        self.assert_agree("before")                          # the three stack containers
        self.assertEqual(len(self.api_ids(True)), 3)

        probe = json.loads(self.api_call("POST", "/containers/create",
                                         P2[8]["request_body"])[1])["Id"]
        self.assert_agree("created probe")                   # in ps -a, not in ps

        self.api_call("POST", f"/containers/{probe}/start")
        self.assert_agree("started probe")                   # now in ps too

        # inspect is the very same document on both surfaces
        _, api_body = self.api_call("GET", f"/containers/{probe}/json")
        shell_doc = json.loads(self.out(f"docker inspect {probe}")[0])[0]
        self.assertEqual(shell_doc, json.loads(api_body))

        for cmd in (["id"], ["cat", "/mnt/etc/os-release"]):
            eid = json.loads(self.api_call("POST", f"/containers/{probe}/exec",
                                           {"AttachStdout": True, "Cmd": cmd})[1])["Id"]
            self.api_call("POST", f"/exec/{eid}/start", {"Detach": False})
        self.assert_agree("after exec")

        priv = json.loads(self.api_call("POST", "/containers/create",
                                        P2[16]["request_body"])[1])["Id"]
        self.assert_agree("created privileged")
        self.api_call("DELETE", f"/containers/{priv}?v=1")
        self.assert_agree("deleted privileged")

        self.api_call("POST", f"/containers/{probe}/stop")
        self.assert_agree("stopped probe")                   # out of ps, Exited in ps -a
        self.api_call("POST", f"/containers/{probe}/wait")
        self.api_call("DELETE", f"/containers/{probe}?v=1")
        self.assert_agree("deleted probe")                   # back to the three
        self.assertEqual(len(self.api_ids(True)), 3)

    def test_created_container_shows_in_shell_docker_ps(self):
        """The headline: a container created and started purely through the API appears
        in the shell's `docker ps`, with its image and an Up status."""
        cid = json.loads(self.api_call("POST", "/containers/create",
                                       P2[8]["request_body"])[1])["Id"]
        self.api_call("POST", f"/containers/{cid}/start")
        text, meta = self.out("docker ps")
        self.assertEqual(meta["source"], "builtin")
        line = next(l for l in text.split("\n") if l.startswith(cid[:12]))
        self.assertIn("eclipse-mosquitto:2", line)
        self.assertRegex(line, r"\bUp\b")


class HostNetworkCase(CrossSurfaceCase):
    """A container started through the API gets its veth on the host, so the shell's
    network view (`ip a`, the routes, /proc/net/dev, ifconfig) follows the shared state:
    docker0 comes up with its first port and goes back to NO-CARRIER without one, and a
    stopped container's veth goes. Modelled from the kernel's and Docker's behaviour, not
    recorded (TASKS.md, "host-network view")."""

    def links(self):
        text, meta = self.out("ip -br link")
        self.assertEqual(meta["source"], "builtin")
        return [l.split()[0] for l in text.split("\n") if l.startswith("veth")]

    def docker0(self):
        return next(l for l in self.out("ip a")[0].split("\n") if ": docker0:" in l)

    def route(self, dev):
        return next(l for l in self.out("ip route")[0].split("\n") if f"dev {dev} " in l)

    def test_a_started_container_has_a_veth_and_docker0_follows(self):
        self.assertEqual(len(self.links()), 3)
        self.assertIn("NO-CARRIER", self.docker0())
        self.assertIn("linkdown", self.route("docker0"))

        probe = json.loads(self.api_call("POST", "/containers/create",
                                         P2[8]["request_body"])[1])["Id"]
        self.assertEqual(len(self.links()), 3)               # created is not running
        self.api_call("POST", f"/containers/{probe}/start")
        links = self.links()
        self.assertEqual(len(links), 4)
        ip_a = self.out("ip a")[0]
        new = next(l for l in ip_a.split("\n") if l.startswith("9: veth"))
        self.assertRegex(new, r"^9: veth[0-9a-f]{7}@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> "
                              r"mtu 1500 qdisc noqueue master docker0 state UP group default $")
        self.assertIn("link-netnsid 3", ip_a.split(new)[1].split("\n")[1])
        self.assertIn("state UP", self.docker0())
        self.assertNotIn("NO-CARRIER", self.docker0())
        self.assertNotIn("linkdown", self.route("docker0"))
        name = new.split(":")[1].strip().split("@")[0]
        self.assertIn(name + ":", self.out("cat /proc/net/dev")[0])
        self.assertIn(name + ": flags=4163", self.out("ifconfig")[0])

        self.api_call("POST", f"/containers/{probe}/stop")
        self.assertEqual(self.links(), links[:3] if name not in links[:3] else
                         [l for l in links if l != name])
        self.assertNotIn(name, self.out("ip a")[0])
        self.assertIn("NO-CARRIER", self.docker0())
        self.assertIn("linkdown", self.route("docker0"))
        # the link-local address docker0 got with its first port stays
        d0 = self.out("ip a show docker0")[0]
        self.assertIn("inet6 fe80::", d0)

    def test_a_restarted_stack_container_gets_a_new_veth(self):
        ids = {c["Names"][0]: c["Id"] for c in json.loads(self.api_call(
            "GET", "/containers/json")[1])}
        first = sorted(ids)[0]
        before = self.links()
        self.api_call("POST", f"/containers/{ids[first]}/stop")
        after_stop = self.links()
        self.assertEqual(len(after_stop), 2)
        self.api_call("POST", f"/containers/{ids[first]}/start")
        again = self.links()
        self.assertEqual(len(again), 3)
        gone = (set(before) - set(after_stop)).pop()
        self.assertNotIn(gone, again)                        # a new name, not the old one
        ip_a = self.out("ip a")[0]
        self.assertIn("9: veth", ip_a)                       # the next index, not reused
        self.assertRegex(ip_a.split("9: veth")[1].split("\n")[0], r" master br-[0-9a-f]{12} ")
        self.assertEqual(len(re.findall(r"master (br-[0-9a-f]{12})", ip_a)), 3)
        self.assertEqual(len(set(re.findall(r"master (br-[0-9a-f]{12})", ip_a))), 1)

    def test_the_compose_bridge_loses_carrier_when_its_containers_stop(self):
        for c in json.loads(self.api_call("GET", "/containers/json")[1]):
            self.api_call("POST", f"/containers/{c['Id']}/stop")
        self.assertEqual(self.links(), [])
        br = next(l for l in self.out("ip a")[0].split("\n") if re.search(r": br-[0-9a-f]{12}:", l))
        self.assertIn("NO-CARRIER", br)
        self.assertIn("linkdown", self.route(re.search(r"br-[0-9a-f]{12}", br).group(0)))

    # --- what a program prints inside a container: the model's (2026-10-15)

    def test_exec_output_is_the_models_through_the_shells_path(self):
        """An exec through the API (the user's decision of 15 October): the program's
        output comes from the model, asked the line the shell's `docker exec` would send,
        and the answer is logged like a command."""
        probe = json.loads(self.api_call("POST", "/containers/create?name=probe",
                                         P2[8]["request_body"])[1])["Id"]
        self.api_call("POST", f"/containers/{probe}/start")
        eid = json.loads(self.api_call("POST", f"/containers/{probe}/exec",
                                       {"AttachStdout": True, "AttachStderr": True,
                                        "Cmd": ["cat", "/etc/os-release"]})[1])["Id"]
        n = len(self.pool.calls)
        _, body = self.api_call("POST", f"/exec/{eid}/start", {"Detach": False})
        self.assertEqual(self.pool.calls[n][-1]["content"], "docker exec probe cat /etc/os-release")
        self.assertEqual(body[8:], b"MODEL<docker exec probe cat /etc/os-release>\n")
        self.assertEqual(body[:1], b"\x01")                 # a stdout frame
        with open(self.relay._log.name) as f:
            rows = [json.loads(l) for l in f if '"container_output"' in l]
        self.assertEqual((rows[-1]["kind"], rows[-1]["command"], rows[-1]["source"]),
                         ("exec", "docker exec probe cat /etc/os-release", "model"))

    def test_an_api_containers_log_is_the_models_and_the_same_on_both_surfaces(self):
        probe = json.loads(self.api_call("POST", "/containers/create?name=probe",
                                         P2[8]["request_body"])[1])["Id"]
        self.api_call("POST", f"/containers/{probe}/start")
        _, api_log = self.api_call("GET", f"/containers/{probe}/logs?stdout=1&stderr=1")
        line = self.pool.calls[-1][-1]["content"]
        self.assertTrue(line.startswith("docker run --name probe -v /:/mnt:ro "), line)
        self.assertTrue(line.endswith("/bin/sh -c 'cat /mnt/etc/hostname; sleep 300'"), line)
        self.assertEqual(api_log[8:].decode(), f"MODEL<{line}>\n")
        n = len(self.pool.calls)
        self.assertEqual(self.out("docker logs probe")[0], f"MODEL<{line}>")
        self.assertEqual(len(self.pool.calls), n)           # asked once, then it is the log


if __name__ == "__main__":
    import unittest
    unittest.main()
