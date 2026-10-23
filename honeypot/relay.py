"""The relay's HTTP side: an OpenAI-compatible endpoint Cowrie sends every command to.

The request and response format is in docs/relay-protocol.md.

Run (from the directory holding this package):
  python3 -m honeypot.relay --config honeypot/config.json
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import logging
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import identity, machine
from .docker import DockerState
from .dockerapi import DockerAPI, serve as serve_docker_api
from . import backend
from .backend import Backend, Pool
from .knowledge import Knowledge, Substitutions
from .session import SessionStore
from .shell import Shell
from .site import SITE
from . import shell as shell_mod

log = logging.getLogger("relay")
# The answer modes a session can be given (honeypot.mode); /health lists them, so that a
# measurement asking for one an older relay does not know stops instead of measuring the
# wrong thing ("scope_off": since 2026-10-15).
ANSWER_MODES = ("normal", "model_only", "scope_off")
MODEL_NAME = "raspberrypi-shell"


class Relay:
    def __init__(self, cfg: dict, base_dir: str, pool=None):
        def path(p):
            return p if os.path.isabs(p) else os.path.join(base_dir, p)

        state_dir = path(cfg.get("state_dir", "relay-state"))
        # The same boot time at every start in one boot, or the per-boot values below
        # would change with a restart (machine.pinned_boot_time).
        boot = machine.pinned_boot_time(state_dir)
        secret = identity.secret(state_dir)
        # This install's setup day, a few days before the class (identity.py).
        self.install_shift_ns = identity.install_shift_ns(
            secret, boot, dt.date.fromisoformat(cfg.get("class_start", "2026-11-02")))
        # Ground Truth's addresses (config) and its per-boot values (net.py, R3) become
        # this machine's, in every answer (code or generated) and in every example
        # shown to the model.
        # ... and so do its install- and boot-specific IDs (identity.py, R3), and the
        # dates of its setup day and of its boot.
        subs = Substitutions(identity.all_pairs(cfg.get("substitutions", {}), state_dir,
                                                boot, secret),
                             identity.date_rewriters(self.install_shift_ns, boot))
        # The replay tier (a recorded answer looked up by the exact command text) is off
        # unless the config turns it on: it is the caching ruled out for the study.
        # The class build only (decided 2026-10-15): the corpus entries withheld because they
        # overlap test answers are shown to the model again, once the paper's last
        # measurement is taken. /health says so, and every measuring tool refuses such a relay.
        self.withheld_shown = bool(cfg.get("class_show_withheld", False))
        self.knowledge = Knowledge(path(cfg["corpus"]), path(cfg["not_gradable"]), subs,
                                   replay=cfg.get("replay_tier", False),
                                   hidden=() if self.withheld_shown else cfg.get("hidden_examples", ()))
        self.pool = pool or Pool([Backend(**b) for b in cfg["backends"]],
                                 cfg.get("answer_deadline_s", 25.0),
                                 cfg.get("first_token_s", 10.0),
                                 cfg.get("connect_s", 1.5), cfg.get("stall_s", 6.0),
                                 cfg.get("node_rest_ratio", 0.0),
                                 cfg.get("node_spread", False),
                                 cfg.get("loop_stop_s", 0.0))
        # Containers, images, networks, volumes: one state for the shell's `docker` and
        # the fake API on 2375 (R11).
        self.docker = DockerState(boot, secret, subs, self.install_shift_ns)
        self.docker_api = DockerAPI(self.docker)
        self.store = SessionStore(state_dir,
                                  cfg.get("initial_last_login", {}), boot)
        self.shell = Shell(self.knowledge, self.pool, self.store, boot,
                           cfg.get("k_examples", 6), self.docker)
        self.shell.line_bound = bool(cfg.get("line_bound", False))
        self.docker.program_output = self._program_output
        shell_mod.set_scope(cfg.get("code_scope"))
        self.api_key = cfg.get("api_key")
        # "model_only" sends every line to the model (code still keeps the state): for
        # measuring the model on its own. Per request: honeypot.mode.
        self.answer_mode = cfg.get("answer_mode", "normal")
        self.dst = (cfg.get("dst_ip", SITE.hp_ipv4), cfg.get("dst_port", 22))
        log_path = path(cfg.get("log", "relay-logs/relay.jsonl"))
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        self._log = open(log_path, "a", encoding="utf-8", buffering=1)
        self._log_lock = threading.Lock()
        self._session_locks: dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()
        # The commands of each session that have arrived and are not answered yet (one
        # being answered, others waiting their turn): what a Ctrl-C stops.
        self._unanswered: dict[str, list[backend.Cancel]] = {}

    def record(self, entry: dict) -> None:
        with self._log_lock:
            self._log.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _program_output(self, c: dict, argv: list, tty: bool, kind: str) -> tuple[str, int]:
        """The fake API's output of a program inside a container (DockerState
        .program_output): the model's, through the shell's path; logged like a command."""
        t0 = time.monotonic()
        ans, line = self.shell.container_output(c, argv, tty, kind)
        self.record({"ts": machine.now().isoformat(timespec="milliseconds"),
                     "event": "container_output", "kind": kind, "container": c.get("Name"),
                     "command": line, "output": ans.output, "exit_code": ans.exit_code,
                     "source": ans.source, "elapsed_ms": round((time.monotonic() - t0) * 1000),
                     "meta": ans.meta})
        return ans.output, ans.exit_code

    def _lock_for(self, sid: str) -> threading.Lock:
        with self._locks_lock:
            return self._session_locks.setdefault(sid, threading.Lock())

    def handle(self, body: dict) -> tuple[int, dict]:
        """One chat-completions request -> (HTTP status, response body)."""
        if body.get("stream"):
            return 400, _error("stream is not supported; send stream=false")
        hp = body.get("honeypot") or {}
        sid = str(body.get("user") or hp.get("session") or "")
        if not sid:
            return 400, _error("missing `user`: the Cowrie session id")
        event = hp.get("event", "command")
        if event not in ("login", "command", "logout", "exec", "interrupt"):
            return 400, _error(f"unknown honeypot.event {event!r}")
        command = _last_user_text(body.get("messages") or [])

        t0 = time.monotonic()
        cancel = None
        if event == "interrupt":
            # Ctrl-C. Before waiting for the session: stop the answer that is being
            # generated (its connection is shut, so the Jetson stops too) and give up
            # the lines typed before it that are still waiting their turn, as a terminal
            # throws away what was typed ahead.
            with self._locks_lock:
                for c in self._unanswered.get(sid, ()):
                    c.fire()
        elif event == "command":
            cancel = backend.Cancel()
            with self._locks_lock:
                self._unanswered.setdefault(sid, []).append(cancel)
        try:
            return self._handle(body, hp, sid, event, command, t0, cancel)
        finally:
            if cancel is not None:
                with self._locks_lock:
                    left = self._unanswered.get(sid, [])
                    if cancel in left:
                        left.remove(cancel)
                    if not left:
                        self._unanswered.pop(sid, None)

    def _handle(self, body: dict, hp: dict, sid: str, event: str, command: str,
                t0: float, cancel: "backend.Cancel | None") -> tuple[int, dict]:
        with self._lock_for(sid):
            sess = self.store.get(sid)
            if event in ("login", "exec") or sess is None:
                if sess is not None:
                    self.store.close(sid)
                sess, prev = self.store.open(
                    sid, hp.get("username", "root"), hp.get("src_ip", "127.0.0.1"),
                    int(hp.get("src_port", 0)), hp.get("dst_ip", self.dst[0]),
                    int(hp.get("dst_port", self.dst[1])), terminal=event != "exec")
                if event == "command":
                    log.warning("session %s sent a command before logging in", sid)
            if event in ("login", "exec") or "mode" in hp:   # set once, kept for the session
                mode = hp.get("mode", self.answer_mode)
                if mode in ANSWER_MODES:
                    sess.mode = mode
            if "hide_examples" in hp:        # measurement only (docs/relay-protocol.md)
                try:
                    sess.hide_examples = frozenset(int(n) for n in hp["hide_examples"][:400])
                except (TypeError, ValueError):
                    pass
            if "cols" in hp:
                try:
                    sess.cols = max(int(hp["cols"]), 20)
                    sess.cols_known = True
                except (TypeError, ValueError):
                    pass
            if "rows" in hp:
                try:
                    sess.rows = max(int(hp["rows"]), 2)
                except (TypeError, ValueError):
                    pass
            if event == "login":
                last = f"Last login: {prev}\r\n" if prev else ""
                content, code, source, close, meta = (
                    machine.MOTD + last + machine.AFTER_LAST_LOGIN, 0, "login", False, None)
            elif event == "logout":
                content, code, source, close, meta = "", 0, "logout", True, None
            elif event == "interrupt":
                # Ctrl-C at the prompt (relay-protocol.md): nothing printed here, the
                # prompt that comes back is PS1 again.
                a = self.shell.interrupt(sess)
                content, code, source, close, meta = "", a.exit_code, a.source, False, None
            elif event == "exec":
                # One command, no terminal, then the connection ends (relay-protocol.md).
                a = self.shell.run(sess, command)
                content = a.output + ("\n" if a.newline else "") if a.output or a.blank else ""
                code, source, close, meta = a.exit_code, a.source, True, a.meta
            else:
                backend.CURRENT.cancel = cancel
                try:
                    if cancel is not None and cancel.fired:    # given up while it waited
                        raise backend.Cancelled()
                    a = self.shell.run(sess, command)
                    content = a.output + ("\n" if a.newline else "") if a.output or a.blank else ""
                    code, source, close, meta = a.exit_code, a.source, a.close, a.meta
                except backend.Cancelled:
                    # Nothing is printed for it; the `interrupt` request that follows
                    # sets $? and brings the prompt. Cowrie has moved on already.
                    sess.last_exit = 130
                    content, code, source, close, meta = "", 130, "interrupted", False, None
                finally:
                    backend.CURRENT.cancel = None
            if event in ("command", "exec"):
                self.store.count_traffic(command, content)
            if close:
                self.store.close(sid)
            ms = round((time.monotonic() - t0) * 1000)
            ext = {"exit_code": code, "cwd": sess.cwd,
                   "prompt": sess.prompt() if sess.terminal else "",
                   "source": source, "close_session": close, "elapsed_ms": ms}
            self.record({"ts": machine.now().isoformat(timespec="milliseconds"),
                         "session": sid, "src_ip": sess.src_ip, "event": event,
                         "command": command if event in ("command", "exec") else None,
                         "output": content, **ext, "meta": meta})
        return 200, {
            "id": f"chatcmpl-{uuid.uuid4().hex[:24]}", "object": "chat.completion",
            "created": int(time.time()), "model": MODEL_NAME,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "honeypot": ext,
        }


def _error(msg: str) -> dict:
    return {"error": {"message": msg, "type": "invalid_request_error"}}


def _last_user_text(messages: list) -> str:
    for m in reversed(messages):
        if m.get("role") == "user":
            c = m.get("content", "")
            if isinstance(c, list):          # content parts
                c = "".join(p.get("text", "") for p in c if isinstance(p, dict))
            return str(c)
    return ""


def make_handler(relay: Relay):
    class Handler(BaseHTTPRequestHandler):
        server_version = "relay"
        sys_version = ""

        def _send(self, status: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            # The server closes every connection after its answer (HTTP/1.0), and says
            # so: Twisted's client (Cowrie) keeps an HTTP/1.0 connection without this
            # header for reuse, and a request sent within a millisecond of the last
            # answer (a command typed right after Ctrl-C, pasted lines) went out on the
            # connection being closed and was lost (found 2026-10-15).
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def _authorised(self) -> bool:
            if not relay.api_key:
                return True
            return self.headers.get("Authorization", "") == f"Bearer {relay.api_key}"

        def do_GET(self):
            if self.path.rstrip("/") == "/v1/models":
                self._send(200, {"object": "list", "data": [
                    {"id": MODEL_NAME, "object": "model", "owned_by": "honeypot"}]})
            elif self.path.rstrip("/") == "/health":
                self._send(200, {"ok": True, "sessions": len(relay.store.active()),
                                 "withheld_shown": relay.withheld_shown,
                                 "modes": list(ANSWER_MODES),
                                 "backends": [{"name": b.name, "up": not b.down,
                                               "thinks": b.thinks}
                                              for b in relay.pool.backends]})
            else:
                self._send(404, _error("not found"))

        def do_POST(self):
            if self.path.rstrip("/") != "/v1/chat/completions":
                return self._send(404, _error("not found"))
            if not self._authorised():
                return self._send(401, _error("bad api key"))
            try:
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, _error("body is not JSON"))
            try:
                status, resp = relay.handle(body)
            except Exception as e:
                log.exception("request failed")
                status, resp = 500, _error(f"relay error: {e}")
            self._send(status, resp)

        def log_message(self, fmt, *args):
            log.debug("%s " + fmt, self.address_string(), *args)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="The honeypot relay (OpenAI-compatible).")
    ap.add_argument("--config", default="honeypot/config.json")
    ap.add_argument("--bind", help="override the config's bind address")
    ap.add_argument("--port", type=int, help="override the config's port")
    ap.add_argument("--no-keep-warm", action="store_true")
    ap.add_argument("--example-site", action="store_true",
                    help="run on site.example.json's made-up values (no real lab)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if SITE.is_example and not args.example_site:
        # A deploy without the local file would serve made-up addresses: refuse.
        ap.error(f"no site.local.json next to honeypot/ (site values: {SITE.path}); "
                 "copy it there, or pass --example-site to run on the made-up values")
    cfg = SITE.load_json(args.config)
    relay = Relay(cfg, os.path.dirname(os.path.abspath(args.config)))
    if not args.no_keep_warm:
        relay.pool.keep_warm(messages=relay.shell.warm_messages)
    relay.pool.watch()          # brings a Jetson that was down back into use
    bind, port = args.bind or cfg.get("bind", "127.0.0.1"), args.port or cfg.get("port", 8000)
    srv = ThreadingHTTPServer((bind, port), make_handler(relay))
    api_cfg = cfg.get("docker_api")
    if api_cfg:
        def record(entry):
            relay.record({"ts": machine.now().isoformat(timespec="milliseconds"), **entry})
        api = serve_docker_api(relay.docker_api, api_cfg["bind"], api_cfg["port"], record)
        threading.Thread(target=api.serve_forever, name="docker-api", daemon=True).start()
        log.info("fake Docker API on %s:%d", api_cfg["bind"], api_cfg["port"])
    log.info("relay on %s:%d, replay tier %s (%d cached answers), %d examples, backends: %s",
             bind, port, "ON" if relay.knowledge.replay else "off",
             len(relay.knowledge.cache), len(relay.knowledge.examples),
             ", ".join(b.name for b in relay.pool.backends))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
