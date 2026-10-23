#!/usr/bin/env python3
"""
measure_deployed_api.py - the emulated Docker API of the DEPLOYED honeypot against the
recordings of the reference machine, and the shell against the API while the recorded
attack runs.

Three measurements, all over the network, on the honeypot only:

  1. Every recorded read-only request (28 of gt_api_phase1, 47 of gt_api_phase3) is
     sent to the honeypot's API again, and its answer is compared with the recording:
     the status line, the headers, the body.
  2. The 26 recorded state-changing requests (gt_api_phase2: the failed pull, a
     container with the host mounted, two commands run in it, a privileged container,
     the teardown) are sent in the recorded order, with the honeypot's own container and
     exec IDs where the recording has the reference machine's, and compared the same way.
  3. At eight checkpoints of that attack, from before it to after the last deletion,
     the shell is asked the questions the API has just answered, and the two are
     compared pair by pair (`docker ps -q --no-trunc` against `GET /containers/json`,
     and so on). A pair counts only if the shell's answer was computed in code.
  4. The other direction: a container is made, stopped and removed in the shell, and
     after each step the API is asked the same way (three more checkpoints, reported
     apart from the eight).

How a body is compared. The honeypot shows its own addresses and IDs, so the recorded
body is first rewritten with the build's identity file (as the scorer does for the
shell), and the IDs created during this run stand in for the recorded ones. Then:

  identical        the same bytes
  same structure   both are JSON with the same keys, list lengths and value types
                   everywhere; the values that differ are listed by their path
                   (timestamps, counters, per-boot values: for the write-up to explain)
  different        anything else

SAFETY. This tool sends state-changing requests. It can only ever reach the honeypot:
it opens its own SSH tunnels to the alias `lab-orch` (the Orchestrator's loopback ports
2375 and 8000) and has no option to name another host. It never contacts Ground Truth.
The attack is torn down at the end, also after an error.

  .venv/bin/python tools/measure_deployed_api.py --label build-1013 \
      --identity res_relay_identity_build-1013_2026-10-13.json

Writes res_api_<phase>_<label>.json (the honeypot's answers, in the recordings' shape)
and res_apicompare_<label>.json (the comparison, read by tools/eval_harness.py).
"""
from __future__ import annotations
import argparse
import base64
import collections
import email.utils
import json
import pathlib
import re
import socket
import subprocess
import sys
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from capture_docker_api import one, DEFAULT_UA               # noqa: E402  (the recorder itself)
from relay_client import Client                              # noqa: E402
from honeypot.site import SITE                      # noqa: E402  (site.local.json)

HONEYPOT = "lab-orch"            # the only host this tool talks to. Not an option.


PAUSE_S = 15        # before each request whose answer a model node writes (8 at least)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Tunnels:
    """Local ports forwarded to the honeypot's loopback API and relay."""

    def __init__(self):
        self.api_port, self.relay_port = free_port(), free_port()
        self.proc = subprocess.Popen(
            ["ssh", "-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
             "-L", f"{self.api_port}:127.0.0.1:2375", "-L", f"{self.relay_port}:127.0.0.1:8000",
             HONEYPOT])
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", self.api_port), timeout=1).close()
                return
            except OSError:
                if self.proc.poll() is not None:
                    sys.exit("the SSH tunnel to the honeypot did not open")
                time.sleep(0.25)
        sys.exit("the SSH tunnel to the honeypot did not open in time")

    def close(self):
        self.proc.terminate()


def raw(e: dict) -> bytes:
    if e.get("body_b64"):
        return base64.b64decode(e["body_b64"])
    try:
        return e["body"].encode("latin-1")       # phase 2 keeps raw bytes this way
    except UnicodeEncodeError:
        return e["body"].encode("utf-8")


def frames_ok(body: bytes) -> bool:
    i = 0
    while i + 8 <= len(body):
        if body[i] not in (0, 1, 2) or body[i + 1:i + 4] != b"\0\0\0":
            return False
        i += 8 + int.from_bytes(body[i + 4:i + 8], "big")
    return i == len(body)


def _key(item):
    """What a list of objects is sorted by before comparing: Docker returns networks,
    volumes and their kin in no fixed order (eval_not_gradable.json says the same)."""
    if isinstance(item, dict):
        for k in ("Name", "Id", "ID", "id"):
            if isinstance(item.get(k), str):
                return (k, item[k])
        if isinstance(item.get("Names"), list) and item["Names"]:
            return ("Names", str(item["Names"][0]))
    return ("", "")


def shape_diff(a, b, path="", why=None) -> tuple[bool, list[str]]:
    """(same structure?, the paths of the leaves whose values differ). `why` collects
    the reason for every structural difference."""
    why = why if why is not None else []
    if a is None or b is None:
        return True, ([] if a == b else [path or "."])       # null against a value: a leaf
    if type(a) is not type(b) and not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
        why.append(f"{path or '.'}: {type(a).__name__} against {type(b).__name__}")
        return False, [path or "."]
    if isinstance(a, dict):
        same, leaves = True, []
        if set(a) != set(b):
            why.append(f"{path or '.'}: keys only in the recording {sorted(set(a) - set(b))[:6]}, "
                       f"only in the honeypot {sorted(set(b) - set(a))[:6]}")
            same = False
        for k in a:
            if k in b:
                s, l = shape_diff(a[k], b[k], f"{path}.{k}" if path else k, why)
                same, leaves = same and s, leaves + l
        return same, leaves
    if isinstance(a, list):
        if len(a) != len(b):
            why.append(f"{path or '.'}: {len(a)} entries against {len(b)}")
            return False, [path or "."]
        if a and all(_key(x)[0] for x in a + b):
            a, b = sorted(a, key=_key), sorted(b, key=_key)
        same, leaves = True, []
        for x, y in zip(a, b):
            s, l = shape_diff(x, y, f"{path}[]", why)
            same, leaves = same and s, leaves + l
        return same, leaves
    return True, ([] if a == b else [path or "."])


def frames(body: bytes) -> list[tuple[int, int]]:
    out, i = [], 0
    while i + 8 <= len(body):
        n = int.from_bytes(body[i + 4:i + 8], "big")
        out.append((body[i], n))
        i += 8 + n
    return out


def generic(path: str) -> str:
    """A leaf path with its IDs and names taken out, to count kinds of difference."""
    path = re.sub(r"\.[0-9a-f]{64}\b", ".<id>", path)
    return re.sub(r"\.(iot-stack_default|bridge|host|none)\b", ".<network>", path)


def compare(rec: dict, got: dict, rewrite) -> dict:
    """One honeypot answer against the recorded one."""
    want_body, got_body = rewrite(raw(rec)), raw(got)
    names = lambda hs: [k for k, _ in hs]                                    # noqa: E731
    skip = ("Date", "Content-Length")
    headers_same = names(rec["headers"]) == names(got["headers"]) and all(
        v == rewrite(rv.encode()).decode() for (k, v), (_, rv) in zip(got["headers"], rec["headers"])
        if k not in skip)
    out = {"n": rec["n"], "method": rec["method"], "path": rec["path"],
           "status_same": rec["status"] == got["status"], "status": [rec["status"], got["status"]],
           "header_names_same": names(rec["headers"]) == names(got["headers"]),
           "headers_same": headers_same, "leaves": []}
    ctype = dict(got["headers"]).get("Content-Type", "")
    stream = "multiplexed" in ctype or "raw-stream" in ctype
    if stream:
        out["framing_ok"] = frames_ok(got_body)
    if want_body == got_body:
        out["body"] = "identical"
        return out
    out["why"] = why = []
    if stream:
        # A log or the output of a command: the same number of frames on the same
        # streams (stdout, stderr) is the same structure; the text in them is content.
        fa, fb = frames(want_body), frames(got_body)
        if [s for s, _ in fa] == [s for s, _ in fb]:
            out["body"], out["leaves"] = "same structure", ["<the text of a stream frame>"]
        elif len(fa) > 20 and len(fb) > 20 and {s for s, _ in fa} == {s for s, _ in fb}:
            # A whole log, without `tail`: how many lines it has depends on how long the
            # container has been running. Both are long, well-formed and use the same
            # streams; the number of lines is content, like a timestamp.
            out["body"] = "same structure"
            out["leaves"] = ["<the text of a stream frame>", "<the number of lines of a whole log>"]
        else:
            out["body"] = "different"
            why.append(f"{len(fa)} frames against {len(fb)}, or on other streams")
        return out
    try:
        a, b = json.loads(want_body), json.loads(got_body)
    except ValueError:
        try:                    # a stream of JSON lines (events)
            a = [json.loads(l) for l in want_body.splitlines() if l.strip()]
            b = [json.loads(l) for l in got_body.splitlines() if l.strip()]
            if not a and not b:
                raise ValueError
        except ValueError:
            out["body"] = "different"
            why.append("not JSON on one side, and not the same bytes")
            return out
    same, leaves = shape_diff(a, b, "", why)
    out["body"] = "same structure" if same else "different"
    out["leaves"] = sorted({generic(l) for l in leaves})
    return out


def boot_pairs(recordings: list[dict], base: str, rewrite) -> dict:
    """IDs this one recording has and the identity file does not: the recordings were
    made in three different boots of the reference machine, and the default bridge
    network gets a new ID at every boot. Matched by name with the honeypot's own."""
    pairs = {}
    live = {n["Name"]: n["Id"] for n in json.loads(raw(one(base, "GET", "/networks", DEFAULT_UA, 30.0)))}
    for rec in recordings:
        if rec["path"].split("?")[0] == "/networks" and rec["status"] == 200:
            for n in json.loads(rewrite(raw(rec))):
                if n["Name"] in live and n["Id"] != live[n["Name"]]:
                    pairs[n["Id"]] = live[n["Name"]]
                    pairs[n["Id"][:12]] = live[n["Name"]][:12]
    return pairs


def with_pairs(rewrite, pairs: dict):
    def f(body: bytes) -> bytes:
        body = rewrite(body)
        for old, new in sorted(pairs.items(), key=lambda kv: -len(kv[0])):
            body = body.replace(old.encode(), new.encode())
        return body
    return f


# ------------------------------------------------------------------ the three measurements

def window_now(rec: dict, path: str) -> str:
    """An `/events` request asks about a window of time, and the daemon keeps only its
    most recent events. The recording asked about the ten minutes before it was made;
    asked today with the recorded numbers, any daemon answers with nothing. So the
    window is moved to end as long before now as it ended before the recording."""
    m = re.search(r"since=(\d+)&until=(\d+)", path)
    if not m or int(m.group(1)) < 1_000_000_000:        # `since=0&until=1`: asked as it is
        return path
    recorded_at = email.utils.parsedate_to_datetime(dict(rec["headers"])["Date"]).timestamp()
    shift = int(time.time() - recorded_at)
    return path.replace(m.group(0), f"since={int(m.group(1)) + shift}&until={int(m.group(2)) + shift}")


def read_only(base: str, recordings: list[dict], rewrite_path, rewrite) -> tuple[list, list]:
    answers, results = [], []
    for rec in recordings:
        path = window_now(rec, rewrite_path(rec["path"]))
        got = {"n": rec["n"], "method": rec["method"], "path": path, "why": rec.get("why"),
               **one(base, rec["method"], path, DEFAULT_UA, 30.0)}
        answers.append(got)
        results.append(compare(rec, got, rewrite))
        r = results[-1]
        print(f"  [{rec['n']:2d}] {rec['method']:4s} {path[:58]:58s} {got['status']} "
              f"{'ok ' if r['status_same'] and r['headers_same'] else 'DIFF'} {r['body']}", flush=True)
    return answers, results


PAIRS = ("running containers", "all containers", "inspect of every container", "images",
         "networks", "volumes", "container counts in info", "database credentials")


def checkpoint(label: str, base: str, shell) -> dict:
    """Every shell/API pair at this moment: {pair: (agree, shell answer computed in code)}."""
    def api(path):
        r = one(base, "GET", path, DEFAULT_UA, 30.0)
        return json.loads(raw(r))

    def sh(cmd):
        text, ext = shell(cmd)
        return text.strip("\n"), ext["source"] == "builtin"

    out = {}
    text, code = sh("docker ps -q --no-trunc")
    out[PAIRS[0]] = (sorted(text.split()) == sorted(c["Id"] for c in api("/containers/json")), code)
    text, code = sh("docker ps -aq --no-trunc")
    everything = api("/containers/json?all=1")
    out[PAIRS[1]] = (sorted(text.split()) == sorted(c["Id"] for c in everything), code)
    agree, coded = True, True
    for c in everything:
        for _ in range(2):          # a health probe may land between the two questions
            doc = api(f"/containers/{c['Id']}/json")
            text, code = sh(f"docker inspect {c['Id']}")
            try:
                same = json.loads(text)[0] == doc
            except (ValueError, IndexError):
                same = False
            if same:
                break
        agree, coded = agree and same, coded and code
    out[PAIRS[2]] = (agree, coded)
    text, code = sh("docker images -q --no-trunc")
    out[PAIRS[3]] = (sorted(set(text.split())) == sorted({i["Id"] for i in api("/images/json")}), code)
    text, code = sh("docker network ls -q --no-trunc")
    out[PAIRS[4]] = (sorted(text.split()) == sorted(n["Id"] for n in api("/networks")), code)
    text, code = sh("docker volume ls -q")
    out[PAIRS[5]] = (sorted(text.split()) == sorted(v["Name"] for v in api("/volumes")["Volumes"]), code)
    info = api("/info")
    text, code = sh("docker info --format '{{.Containers}} {{.ContainersRunning}} {{.ContainersStopped}} {{.Images}}'")
    out[PAIRS[6]] = (text == f"{info['Containers']} {info['ContainersRunning']} "
                             f"{info['ContainersStopped']} {info['Images']}", code)
    text, code = sh("docker inspect -f '{{json .Config.Env}}' iot-stack-influxdb-1")
    env = api("/containers/iot-stack-influxdb-1/json")["Config"]["Env"]
    try:
        out[PAIRS[7]] = (json.loads(text) == env and any("INIT_ADMIN_TOKEN" in e for e in env), code)
    except ValueError:
        out[PAIRS[7]] = (False, code)
    bad = [k for k, (a, c) in out.items() if not (a and c)]
    print(f"  checkpoint {label:22s} {len(out) - len(bad)}/{len(out)} pairs agree"
          + (f"   NOT: {bad}" if bad else ""), flush=True)
    return {"label": label, "pairs": {k: {"agree": a, "computed": c} for k, (a, c) in out.items()}}


def attack(base: str, recordings: list[dict], rewrite, shell) -> tuple[list, list, list]:
    """The recorded state-changing run, with this run's IDs, and the checkpoints."""
    ids = {}                        # the recording's ID (full and 12 characters) -> this run's
    created = []

    def here(text: str) -> str:
        for old, new in sorted(ids.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(old, new)
        return text

    def rewrite_run(body: bytes) -> bytes:
        body = rewrite(body)
        for old, new in sorted(ids.items(), key=lambda kv: -len(kv[0])):
            body = body.replace(old.encode(), new.encode())
        return body

    answers, results, checkpoints = [], [], []
    # What a program prints inside a container is the model's (since 2026-10-15): an
    # exec's start and the log of the container the attack made reach a model node, so
    # they are paced like every model run (docs/jetson-stability.md).
    reaches_model = lambda method, path: (method == "POST" and re.fullmatch(r"/exec/[0-9a-f]+/start", path)) \
        or (method == "GET" and any(path.startswith(f"/containers/{c[:12]}") and "/logs" in path
                                     for c in created))
    marks = {5: "before the attack", 8: "container created", 10: "container started",
             15: "commands run in it", 16: "privileged one created", 18: "privileged one deleted",
             19: "container stopped", 22: "container deleted"}
    try:
        for rec in recordings:
            path = here(rec["path"])
            model = bool(reaches_model(rec["method"], path.split("?")[0]))
            if model:
                time.sleep(PAUSE_S)
            got = {"n": rec["n"], "stage": rec["stage"], "method": rec["method"], "path": path,
                   "why": rec.get("why"), "model": model,
                   **one(base, rec["method"], path, DEFAULT_UA, 60.0, req_body=rec.get("request_body"))}
            if rec.get("request_body") is not None:
                got["request_body"] = rec["request_body"]
            if rec["status"] == 201 and got["status"] == 201:       # a container or an exec was made
                old, new = json.loads(raw(rec))["Id"], json.loads(raw(got))["Id"]
                ids[old] = new
                if rec["path"] == "/containers/create":
                    ids[old[:12]] = new[:12]
                    created.append(new)
            answers.append(got)
            results.append(compare(rec, got, rewrite_run))
            results[-1]["model"] = model
            r = results[-1]
            print(f"  [{rec['n']:2d}] {rec['method']:6s} {path[:56]:56s} {got['status']} "
                  f"{'ok ' if r['status_same'] and r['headers_same'] else 'DIFF'} {r['body']}", flush=True)
            if rec["n"] in marks:
                checkpoints.append(checkpoint(marks[rec["n"]], base, shell))
    finally:
        for cid in created:                 # whatever happened, leave nothing behind
            one(base, "POST", f"/containers/{cid}/stop?t=0", DEFAULT_UA, 60.0)
            one(base, "DELETE", f"/containers/{cid}?v=1&force=1", DEFAULT_UA, 60.0)
    return answers, results, checkpoints


def from_the_shell(base: str, shell) -> list:
    """The other direction (since 2026-10-13, when the shell's `docker run -d` began to
    make its container in the shared state): a container is made, stopped and removed
    IN THE SHELL, and after each step the API is asked. Uses a local image and a name
    of this run's own; whatever happens, the container is removed through the API."""
    name = f"xsurface-{uuid.uuid4().hex[:8]}"
    checkpoints = []
    try:
        for label, cmd in (
                ("made in the shell", f"docker run -d --name {name} -p 8081:80 -e XSURFACE=1 "
                                      f"eclipse-mosquitto:2 sleep 600"),
                ("stopped in the shell", f"docker stop -t 0 {name}"),
                ("removed in the shell", f"docker rm -v {name}")):
            text, ext = shell(cmd)
            print(f"  $ {cmd}\n    -> {text.strip()[:70]}  [{ext['source']}]", flush=True)
            listed = [c for c in json.loads(raw(one(base, "GET", "/containers/json?all=1", DEFAULT_UA, 30.0)))
                      if "/" + name in c["Names"]]
            want = {"made in the shell": "running", "stopped in the shell": "exited",
                    "removed in the shell": None}[label]
            point = checkpoint(label, base, shell)
            point["command"], point["computed"] = cmd, ext["source"] == "builtin"
            point["api_shows"] = listed[0]["State"] if listed else None
            point["api_as_expected"] = point["api_shows"] == want
            checkpoints.append(point)
    finally:
        one(base, "DELETE", f"/containers/{name}?v=1&force=1", DEFAULT_UA, 60.0)
    return checkpoints


def summary(results: list[dict]) -> dict:
    leaves = collections.Counter(l for r in results for l in r["leaves"])
    framed = [r for r in results if "framing_ok" in r]
    return {"requests": len(results), "status_same": sum(r["status_same"] for r in results),
            "headers_same": sum(r["headers_same"] for r in results),
            "body_identical": sum(r["body"] == "identical" for r in results),
            "body_same_structure": sum(r["body"] == "same structure" for r in results),
            "body_different": sum(r["body"] == "different" for r in results),
            "streams": len(framed), "streams_framed_ok": sum(r["framing_ok"] for r in framed),
            "differing_leaves": dict(leaves.most_common())}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--label", required=True)
    ap.add_argument("--identity", required=True, help="this build's identity file")
    ap.add_argument("--skip-attack", action="store_true", help="read-only requests only")
    args = ap.parse_args()
    subs = sorted(json.load(open(args.identity))["substitutions"].items(), key=lambda kv: -len(kv[0]))

    def rewrite(body: bytes) -> bytes:
        for old, new in subs:
            body = body.replace(old.encode(), new.encode())
        return body

    tunnels = Tunnels()
    base = f"http://127.0.0.1:{tunnels.api_port}"
    out = {"label": args.label, "identity": pathlib.Path(args.identity).name, "phases": {}}
    try:
        ping = one(base, "GET", "/_ping", DEFAULT_UA, 10.0)
        if ping["status"] != 200:
            sys.exit(f"the honeypot's API does not answer: {ping}")
        before = one(base, "GET", "/containers/json?all=1", DEFAULT_UA, 30.0)
        if len(json.loads(raw(before))) != 3:
            sys.exit("the honeypot does not show exactly its three containers: someone else's "
                     "containers are there; not starting")
        for phase, name in (("phase1", "gt_api_phase1_2026-09.json"), ("phase3", "gt_api_phase3_2026-10.json")):
            print(f"== read-only requests of {name}")
            recs = json.load(open(ROOT / name))
            rw = with_pairs(rewrite, boot_pairs(recs, base, rewrite))
            answers, results = read_only(base, recs, lambda p: rw(p.encode()).decode(), rw)
            (ROOT / f"res_api_{phase}_{args.label}.json").write_text(json.dumps(answers, indent=1) + "\n")
            out["phases"][phase] = {"summary": summary(results), "results": results}
        if not args.skip_attack:
            print("== the recorded attack, with the shell asked at eight checkpoints")
            client = Client(f"http://127.0.0.1:{tunnels.relay_port}", SITE.lab_jump)
            sid = f"xsurface-{uuid.uuid4().hex[:8]}"
            client.send(sid, event="login")

            def shell(cmd):
                text, ext, _ = client.send(sid, cmd)
                return text, ext
            recs = json.load(open(ROOT / "gt_api_phase2_2026-09.json"))
            answers, results, checkpoints = attack(
                base, recs, with_pairs(rewrite, boot_pairs(recs, base, rewrite)), shell)
            print("== and the other way: a container made, stopped and removed in the shell")
            shell_points = from_the_shell(base, shell)
            client.send(sid, event="logout")
            (ROOT / f"res_api_phase2_{args.label}.json").write_text(json.dumps(answers, indent=1) + "\n")
            out["phases"]["phase2"] = {"summary": summary(results), "results": results}
            pairs = [(c["label"], k, v) for c in checkpoints for k, v in c["pairs"].items()]
            out["cross_surface"] = {
                "checkpoints": checkpoints, "pairs_total": len(pairs),
                "pairs_agree": sum(v["agree"] and v["computed"] for _, _, v in pairs),
                "pairs_computed": sum(v["computed"] for _, _, v in pairs),
                "transport": "shell through the answer engine's interface (the front end is not "
                             "deployed yet), API over HTTP"}
            shell_pairs = [v for c in shell_points for v in c["pairs"].values()]
            out["cross_surface"]["from_shell"] = {
                "checkpoints": shell_points, "pairs_total": len(shell_pairs),
                "pairs_agree": sum(v["agree"] and v["computed"] for v in shell_pairs),
                "steps_as_expected": sum(c["api_as_expected"] and c["computed"] for c in shell_points)}
            after = one(base, "GET", "/containers/json?all=1", DEFAULT_UA, 30.0)
            out["restored"] = len(json.loads(raw(after))) == 3
    finally:
        tunnels.close()
    (ROOT / f"res_apicompare_{args.label}.json").write_text(json.dumps(out, indent=1) + "\n")
    print()
    for phase, d in out["phases"].items():
        s = d["summary"]
        print(f"{phase}: {s['requests']} requests; status {s['status_same']}, headers {s['headers_same']}, "
              f"body identical {s['body_identical']}, same structure {s['body_same_structure']}, "
              f"different {s['body_different']}; streams framed {s['streams_framed_ok']}/{s['streams']}")
    if "cross_surface" in out:
        x = out["cross_surface"]
        print(f"cross-surface: {x['pairs_agree']} of {x['pairs_total']} pairs agree at "
              f"{len(x['checkpoints'])} checkpoints; state restored: {out['restored']}")
        f = x["from_shell"]
        print(f"from the shell: {f['steps_as_expected']} of {len(f['checkpoints'])} steps show on the API "
              f"as expected; {f['pairs_agree']} of {f['pairs_total']} pairs agree")
    print(f"saved to res_apicompare_{args.label}.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
