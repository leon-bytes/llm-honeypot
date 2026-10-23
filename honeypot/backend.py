"""The Jetsons: OpenAI-compatible model servers (ollama today), called with urllib."""
from __future__ import annotations
import http.client
import json
import logging
import re
import socket
import threading
import time
import urllib.parse
import urllib.request

log = logging.getLogger("relay.backend")


# A model that has no example for a command can start counting: `lsusb` became
# "Bus 002 002 ... 0424:0001", "Bus 002 003 ... 0424:0002", ... until the deadline, and
# `hostnamectl` "IDN RFC 5675: (none)", "IDN RFC 5676: ...". The fine-tuned 1.7B did so
# on 5 of 5 runs of `lsusb` (build-1019-ft, 2026-10-19). A run of LOOP_RUN lines that
# are the same except for numbers, each of which is the one before plus 1 (decimal or
# hex), or LOOP_RUN numbers in one line that count up the same way, is such a loop.
# Pool(loop_stop_s=...) stops an answer there, once it has run that long (config
# `loop_stop_s`; 0 = off): a real listing of that shape (`ls -1 /dev`: tty0..tty63)
# that the model writes in time is left alone. Real machines count too (`ram0`..,
# `NUMA node0`.., `kcompactd0`..): the longest such run in all recorded answers of the
# reference machine is 10 lines (`cat /proc/partitions`), so LOOP_RUN is 12 and none of
# them is ever cut (tests/test_relay.py, TestLoopStop).
LOOP_RUN = 12


def enough_lines(text: str, max_lines: int) -> int | None:
    """Where to cut `text` if it already holds `max_lines` whole lines of output, else None.

    The command fixes how many lines it can print (`head -5`: shell.line_limit); a model
    that goes on writes lines no real program prints (30 lines for `head -5`, until the
    25 s deadline). The model sometimes puts an echoed `$ command` / `# command` line or a
    ``` fence before the output, which clean() drops; one more line is allowed for it, so
    the cut is never early (clean() then keeps at most max_lines)."""
    t = text.lstrip("\n")
    first = t.split("\n", 1)[0]
    extra = 1 if first.startswith(("$ ", "# ", "```")) else 0
    need = max_lines + extra
    pos = len(text) - len(t)
    for _ in range(need):
        nl = text.find("\n", pos)
        if nl < 0:
            return None
        pos = nl + 1
    return pos
_NUM = re.compile(r"[0-9A-Fa-f]*[0-9][0-9A-Fa-f]*")


def _plus_one(a: str, b: str) -> bool:
    for base in (10, 16):
        try:
            if int(b, base) - int(a, base) == 1:
                return True
        except ValueError:
            pass
    return False


def _counts_on(a: str, b: str) -> bool:
    """Is line b line a with one or more numbers each one higher, and nothing else?"""
    if _NUM.sub("#", a) != _NUM.sub("#", b):
        return False
    pairs = [(x, y) for x, y in zip(_NUM.findall(a), _NUM.findall(b)) if x != y]
    return bool(pairs) and all(_plus_one(x, y) for x, y in pairs)


def counting_loop(text: str) -> int | None:
    """Where to cut `text` if it ends in a counting loop (see LOOP_RUN), else None."""
    lines = text.split("\n")
    whole = lines[:-1]                       # the last one is not finished yet
    run = 1
    for i in range(len(whole) - 1, 0, -1):
        if not _counts_on(whole[i - 1], whole[i]):
            break
        run += 1
        if run >= LOOP_RUN:
            return len(text) - len(lines[-1])        # after the last whole line
    last = lines[-1] if lines[-1] else (whole[-1] if whole else "")
    nums = list(_NUM.finditer(last))
    if lines[-1] and nums and nums[-1].end() == len(last):
        nums.pop()                           # may be only the first digits of a number
    run = 1
    for i in range(len(nums) - 1, 0, -1):
        a, b = nums[i - 1], nums[i]
        sep = last[a.end():b.start()]
        if not sep or sep.strip(" ,;:") != "" or not _plus_one(a.group(), b.group()):
            break
        if i < len(nums) - 1 and sep != last[b.end():nums[i + 1].start()]:
            break
        run += 1
        if run >= LOOP_RUN:
            return len(text) - len(last) + nums[-1].end() if lines[-1] else len(text)
    return None


class Stalled(Exception):
    """A Jetson that went silent in the middle of an answer. Carries what had arrived,
    in case no other Jetson can give a whole one."""

    def __init__(self, text: str, meta: dict):
        super().__init__("no token for too long in the middle of an answer")
        self.text, self.meta = text, meta


class Thinking(Exception):
    """A model that began a reasoning block instead of the answer: Qwen3's `<think>`
    (in the text, or in the separate `reasoning` field ollama and llama-server use for a
    model whose template supports thinking). Every model here runs with thinking off,
    so this means a wrong template on that node: the generation is stopped at once
    rather than waited for, and the pool asks another node (Pool.complete)."""


class Cancelled(Exception):
    """The attacker gave the command up (Ctrl-C) while its answer was being generated."""


class Cancel:
    """The stop switch of one command (docs/relay-protocol.md, "Ctrl-C"). The request
    that brings the Ctrl-C fires it from its own thread; the thread that is waiting for
    the model's tokens is woken by its connection being shut down, which also makes the
    Jetson stop generating. Nothing polls, so no answer is slower for it."""

    def __init__(self):
        self.fired = False
        self._sock = None
        self._lock = threading.Lock()

    def attach(self, sock) -> None:
        with self._lock:
            self._sock = sock
            if self.fired:
                self._shut()

    def detach(self) -> None:
        with self._lock:
            self._sock = None

    def fire(self) -> None:
        with self._lock:
            self.fired = True
            self._shut()

    def _shut(self) -> None:
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


# .cancel: the Cancel of the command the current thread is answering, set by the relay
# around Shell.run. Thread-local, so nothing between the relay and the Jetson has to
# pass it on.
CURRENT = threading.local()


class Backend:
    def __init__(self, name: str, base_url: str, model: str, api_key: str = "ollama",
                 timeout: float = 25.0, max_tokens: int = 1024, roles: list | None = None):
        self.name, self.base_url, self.model = name, base_url.rstrip("/"), model
        self.roles = list(roles or ["state"])
        self.api_key, self.timeout, self.max_tokens = api_key, timeout, max_tokens
        # Set when a request to it failed; cleared only by a successful probe or answer.
        # No attacker's command is sent to a Jetson that is down (Pool.complete).
        self.down = False
        # Not given a command before this moment (time.monotonic): the rest after a
        # generated answer, if the pool is told to give one (Pool.rest_ratio).
        self.rest_until = 0.0
        # Answers it is generating right now, and when it finished the last one
        # (time.monotonic): what Pool.spread chooses by.
        self.busy, self.last_end = 0, 0.0
        # Set when its model began to think (Thinking); cleared by an answer without.
        # Not cleared by the probe, which asks for one token and cannot tell.
        self.thinks = False

    def reachable(self, connect_s: float) -> bool:
        """Does anything accept a connection there? A cheap first check for the probe."""
        u = urllib.parse.urlsplit(self.base_url)
        try:
            socket.create_connection((u.hostname, u.port or 80), timeout=connect_s).close()
            return True
        except OSError:
            return False

    def body(self, messages: list[dict], stream: bool, max_tokens: int | None = None) -> dict:
        """The request for one answer: the same for an attacker's command, the probe and
        tools/measure_node_model.py, which renders it on a node to check the prompt."""
        # reasoning_effort "none": thinking off, asked of the server too (ollama turns it
        # into think=false, and into enable_thinking=false for a template of the model's
        # own). The prompt already ends in an empty reasoning block where the model has
        # one; for a model without (Qwen2.5) it changes nothing (tried on ollama 0.34.0,
        # the Jetsons' version, 2026-10-14).
        b = {"model": self.model, "messages": messages, "temperature": 0,
             "max_tokens": max_tokens or self.max_tokens, "stream": stream,
             "reasoning_effort": "none"}
        if stream:
            b["stream_options"] = {"include_usage": True}
        return b

    def chat(self, messages: list[dict], max_tokens: int | None = None,
             timeout: float | None = None) -> dict:
        body = json.dumps(self.body(messages, False, max_tokens)).encode()
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body,
                                     headers={"Content-Type": "application/json",
                                              "Authorization": f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
            return json.load(r)

    def stream(self, messages: list[dict], deadline: float, first_token_s: float,
               connect_s: float | None = None, stall_s: float | None = None,
               loop_stop_s: float = 0.0, max_lines: int | None = None) -> tuple[str, dict]:
        """Stream one answer and keep whatever has arrived by `deadline` (monotonic).

        Raises if the connection is not made within `connect_s` (a machine that is off
        or hung: on the lab network a live one answers in a millisecond), or if nothing
        arrives within `first_token_s` (model not loaded, HTTP error), so the pool can
        try the next Jetson. Once text is flowing, running out of time is not a failure:
        the text so far comes back with finish_reason "deadline", and closing the
        connection stops the generation. But a Jetson that sends nothing for `stall_s`
        in the middle of an answer has died (it sends about 20 tokens a second): that
        raises Stalled, with the text so far. A model that starts to think raises
        Thinking as soon as the first characters show it (one token for Qwen3), and
        closing the connection stops it. With `loop_stop_s`, an answer still running
        after that many seconds that ends in a counting loop (counting_loop) is cut there,
        with finish_reason "loop", and closing the connection stops it. With `max_lines`
        (config `line_bound`, the command fixes the line count), an answer that holds that
        many whole lines is cut there with finish_reason "lines" (enough_lines)."""
        u = urllib.parse.urlsplit(self.base_url)
        conn_cls = (http.client.HTTPSConnection if u.scheme == "https"
                    else http.client.HTTPConnection)
        conn = conn_cls(u.hostname, u.port, timeout=min(connect_s or first_token_s,
                                                        first_token_s))
        body = json.dumps(self.body(messages, True))
        parts: list[str] = []
        finish, usage = None, {}
        t0, first = time.monotonic(), None          # for the first token's delay (reading)
        head = ""               # the answer's first characters, until they rule out <think>
        cancel = getattr(CURRENT, "cancel", None)
        if cancel is not None and cancel.fired:
            raise Cancelled()
        try:
            conn.connect()
            if cancel is not None:
                cancel.attach(conn.sock)
            conn.sock.settimeout(first_token_s)
            conn.request("POST", f"{u.path}/chat/completions", body=body,
                         headers={"Content-Type": "application/json",
                                  "Authorization": f"Bearer {self.api_key}"})
            r = conn.getresponse()
            if r.status != 200:
                raise RuntimeError(f"HTTP {r.status}: {r.read(300)!r}")
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    finish = "deadline"
                    break
                # Before the first token, allow first_token_s; after it, the time left,
                # but no silence longer than stall_s.
                wait = min(left, first_token_s) if not parts else min(left, stall_s or left)
                conn.sock.settimeout(wait)
                try:
                    raw = r.readline()
                except TimeoutError:
                    if not parts:
                        raise
                    if deadline - time.monotonic() > 0.05:      # silence, not the deadline
                        raise Stalled("".join(parts), {
                            "finish_reason": "deadline", "stalled": True,
                            "prompt_tokens": None, "completion_tokens": None})
                    finish = "deadline"
                    break
                if not raw:
                    break
                line = raw.strip()
                if not line.startswith(b"data:"):
                    continue
                data = line[5:].strip()
                if data == b"[DONE]":
                    break
                ev = json.loads(data)
                usage = ev.get("usage") or usage
                for ch in ev.get("choices") or []:
                    delta = ch.get("delta") or {}
                    if delta.get("reasoning") or delta.get("reasoning_content"):
                        raise Thinking("the model sent reasoning (thinking is on)")
                    parts.append(delta.get("content") or "")
                    if first is None and parts[-1]:
                        first = time.monotonic() - t0
                    if head is not None and parts[-1]:
                        head = (head + parts[-1]).lstrip()
                        if head.startswith("<think>"):
                            raise Thinking("the answer began with <think> (thinking is on)")
                        if head and not "<think>".startswith(head):
                            head = None             # not a reasoning block: no more checks
                    finish = ch.get("finish_reason") or finish
                if loop_stop_s and parts and time.monotonic() - t0 >= loop_stop_s:
                    text = "".join(parts)
                    cut = counting_loop(text)
                    if cut is not None:
                        parts, finish = [text[:cut]], "loop"
                        break
                if max_lines and parts:
                    text = "".join(parts)
                    cut = enough_lines(text, max_lines)
                    if cut is not None:
                        parts, finish = [text[:cut]], "lines"
                        break
        except Exception:
            if cancel is not None and cancel.fired:     # the shut connection, not a fault
                raise Cancelled() from None
            raise
        finally:
            if cancel is not None:
                cancel.detach()
            conn.close()
        if cancel is not None and cancel.fired:
            raise Cancelled()
        return "".join(parts), {"finish_reason": finish,
                                "prompt_tokens": usage.get("prompt_tokens"),
                                "completion_tokens": usage.get("completion_tokens"),
                                "first_token_ms": round(first * 1000) if first is not None else None,
                                "total_ms": round((time.monotonic() - t0) * 1000)}


class Pool:
    """Routes each model request by role (decided 2026-10-02): the Jetsons that serve the
    role first, then the spare (Jetson 4, the untuned base model), then any other. Roles
    in config.json: `state` (Jetson 1), `docker` (Jetson 3 once it exists; Jetson 1 until
    then), `errors` (Jetson 2, stretch goal), `spare` (Jetson 4).

    A Jetson that failed is marked down and gets no attacker's command until a probe in
    the background has seen it answer again (since 2026-10-08). Before that it was
    retried every 30 s by whatever command came next, and a hung Jetson made that command
    wait the full first-token time, 10 s (Jetson 1, 2026-10-06 and 2026-10-08)."""

    PROBE_EVERY_S = 15
    REST_MAX_S = 20.0

    def __init__(self, backends: list[Backend], answer_deadline_s: float = 25.0,
                 first_token_s: float = 10.0, connect_s: float = 1.5, stall_s: float = 6.0,
                 rest_ratio: float = 0.0, spread: bool = False, loop_stop_s: float = 0.0):
        if not backends:
            raise ValueError("no backends configured")
        self.backends = backends
        self.answer_deadline_s, self.first_token_s = answer_deadline_s, first_token_s
        self.connect_s, self.stall_s = connect_s, stall_s
        # Cut an answer that is still running after this many seconds and ends in a
        # counting loop (config `loop_stop_s`, 0 = off; counting_loop).
        self.loop_stop_s = max(float(loop_stop_s or 0.0), 0.0)
        # A rest after each generated answer, as a multiple of the time the answer took
        # (config `node_rest_ratio`; 0 = none, the default). On 2026-10-13 a node that had
        # survived 300 answers with pauses froze after 46 without any, with its memory
        # flat (docs/jetson-stability.md). With a ratio of 2 a node works a third of the
        # time at most, which is the load it is known to survive. While one node rests
        # the next is asked; if all rest, the command waits for the first to be ready.
        # Someone typing never meets it; a script gets slower answers, not a dead node.
        self.rest_ratio = max(float(rest_ratio or 0.0), 0.0)
        # Spread the generated answers over the nodes that run the same model (config
        # `node_spread`): each answer goes to a node that is generating nothing, and of
        # those to the one that has been idle longest. No answer waits and none is
        # slower; two people at once are answered by two nodes instead of queueing on
        # one. A script that sends commands without pauses then loads each of n nodes
        # 1/n of the time instead of one node all of the time, which is what froze
        # Jetson 1 on 2026-10-13 (docs/jetson-stability.md). Nodes with another model
        # (a role's fine-tuned one) are not mixed in: they stay behind, as failover.
        self.spread = bool(spread)
        self._lock = threading.Lock()

    def _order(self, role: str) -> list[Backend]:
        first = [b for b in self.backends if role in b.roles]
        spare = [b for b in self.backends if "spare" in b.roles and b not in first]
        rest = [b for b in self.backends if b not in first and b not in spare]
        ring = first + spare + rest
        # With every Jetson down there is nothing to lose by trying them all: each costs
        # at most connect_s if it is still dead.
        up = [b for b in ring if not b.down] or ring
        # A node whose model thinks would cost the reading of the prompt and then be
        # stopped: it is not asked while another can answer. With none left, one is
        # asked, so a node whose template was put right comes back by itself.
        up = [b for b in up if not b.thinks] or up[:1]
        if self.spread:
            with self._lock:
                same = sorted((b for b in up if b.model == up[0].model),
                              key=lambda b: (b.busy, b.last_end))    # ties: the role order
            up = same + [b for b in up if b not in same]
        return up

    def complete(self, sid: str, messages: list[dict], role: str = "state",
                 max_lines: int | None = None) -> tuple[str, dict]:
        """The model's text and what to log about it. Raises if every backend failed.

        The whole answer, failover included, must fit in answer_deadline_s; an answer
        cut short there comes back with finish_reason "deadline". If a Jetson dies in
        the middle of an answer, the next one is asked for a whole answer; what the dead
        one had sent is used only if nobody else answers."""
        order = self._order(role)
        rested = 0.0
        if self.rest_ratio:
            now = time.monotonic()
            ready = [b for b in order if b.rest_until <= now]
            if not ready:                      # every node is resting: wait for the first
                rested = max(min(b.rest_until for b in order) - now, 0.0)
                time.sleep(rested)
                now = time.monotonic()
                ready = [b for b in order if b.rest_until <= now + 0.01]
            order = ready + [b for b in order if b not in ready]
        deadline = time.monotonic() + self.answer_deadline_s
        last_err, partial = None, None
        for b in order:
            if deadline - time.monotonic() < 1:
                break
            t0 = time.monotonic()
            with self._lock:
                b.busy += 1
            try:
                text, meta = b.stream(messages, deadline, self.first_token_s,
                                      self.connect_s, self.stall_s, self.loop_stop_s,
                                      max_lines)
            except Cancelled:                # Ctrl-C: nobody else is asked, nothing is down
                raise
            except Thinking as e:            # alive, but a wrong template: not marked down
                b.thinks = True
                log.error("backend %s: model %s thinks (%s); fix its template "
                          "(docs/finetuning-on-the-5090.md, step 14)", b.name, b.model, e)
                last_err = e
                continue
            except Stalled as e:
                b.down = True
                log.warning("backend %s went silent in the middle of an answer", b.name)
                partial = partial or (e.text, {"backend": b.name, "role": role,
                                               "model_ms": round((time.monotonic() - t0) * 1000),
                                               **e.meta})
                last_err = e
                continue
            except Exception as e:           # network, no first token, bad JSON: next
                b.down = True
                log.warning("backend %s failed: %s", b.name, e)
                last_err = e
                continue
            finally:
                with self._lock:
                    b.busy -= 1
                    b.last_end = time.monotonic()
            b.down = b.thinks = False
            took = time.monotonic() - t0
            out = {"backend": b.name, "role": role, "model_ms": round(took * 1000), **meta}
            if self.rest_ratio:
                b.rest_until = time.monotonic() + min(took * self.rest_ratio, self.REST_MAX_S)
                out["rested_ms"] = round(rested * 1000)
            return text, out
        if partial:
            return partial
        raise RuntimeError(f"all backends failed: {last_err or 'out of time'}")

    def probe_once(self, load_timeout_s: float = 120.0) -> list[str]:
        """Check every Jetson that is down; mark up those that answer. Returns their
        names. Two steps: does anything accept a connection (connect_s), then does the
        model give a token (long timeout: it may have to be loaded first, ~30 s)."""
        back = []
        for b in self.backends:
            if not b.down or not b.reachable(self.connect_s):
                continue
            try:
                b.chat([{"role": "user", "content": "ok"}], max_tokens=1, timeout=load_timeout_s)
            except Exception as e:
                log.info("probe: %s accepts connections but does not answer yet: %s", b.name, e)
                continue
            b.down = False
            back.append(b.name)
            log.warning("backend %s is back", b.name)
        return back

    def watch(self) -> threading.Thread:
        """The background probe: every PROBE_EVERY_S, try the Jetsons that are down."""
        def loop():
            while True:
                time.sleep(self.PROBE_EVERY_S)
                try:
                    self.probe_once()
                except Exception:
                    log.exception("probe failed")
        t = threading.Thread(target=loop, name="probe", daemon=True)
        t.start()
        return t

    def keep_warm(self, every_s: float = 240.0, messages=None) -> threading.Thread:
        """ollama unloads an idle model after 5 minutes by default, and loading
        qwen2.5:3b on a Jetson takes ~30 s (measured 2026-09-29), which an attacker
        would notice. A one-token request every 4 minutes keeps it loaded; it gets a
        long timeout so that the first one can do the loading. A Jetson that fails it is
        marked down; the probe (watch) brings it back.
        `messages` (a function returning the request's messages, Shell.warm_messages)
        makes the ping the shared beginning of the real prompts, so that the node's
        cache still holds it for the next answer; without it the ping is a bare "ok"."""
        def loop():
            while True:
                for b in self.backends:
                    if b.down and not b.reachable(self.connect_s):
                        continue                 # dead: the probe's business, not ours
                    try:
                        b.chat(messages() if messages else [{"role": "user", "content": "ok"}],
                               max_tokens=1, timeout=120)
                        b.down = False
                    except Exception as e:
                        b.down = True
                        log.warning("keep-warm %s failed: %s", b.name, e)
                time.sleep(every_s)
        t = threading.Thread(target=loop, name="keep-warm", daemon=True)
        t.start()
        return t
