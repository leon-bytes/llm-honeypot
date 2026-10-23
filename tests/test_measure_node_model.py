#!/usr/bin/env python3
"""tools/measure_node_model.py against a stand-in ollama (no lab): it refuses a model
that would think, stops when one starts to, and compares each prompt's length with the
PC's count for the same record (thinking off, 2026-10-14).
Run: python3 tests/test_measure_node_model.py
"""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import measure_node_model as mnm                  # noqa: E402

# The guide's Modelfile template for a Qwen3 (docs/finetuning-on-the-5090.md, step 14).
GOOD_Q3 = ("{{- range .Messages }}<|im_start|>{{ .Role }}\n{{ .Content }}<|im_end|>\n"
           "{{ end }}<|im_start|>assistant\n<think>\n\n</think>\n\n")
NO_BLOCK = ("{{- range .Messages }}<|im_start|>{{ .Role }}\n{{ .Content }}<|im_end|>\n"
            "{{ end }}<|im_start|>assistant\n")


class FakeOllama:
    def __init__(self, show: dict, tokens: list[str], prompt_tokens: int = 2000,
                 rendered: str = "PROMPT"):
        cfg = self
        self.show, self.tokens, self.prompt_tokens, self.posts = show, tokens, prompt_tokens, []
        self.rendered = rendered

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _json(self, obj):
                b = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                if self.path == "/api/tags":
                    self._json({"models": [{"name": "ft:latest"}]})
                elif self.path == "/api/ps":
                    self._json({"models": []})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
                cfg.posts.append((self.path, body))
                if self.path == "/api/show":
                    return self._json(cfg.show)
                if self.path == "/api/generate":
                    return self._json({"done": True})
                if body.get("_debug_render_only"):
                    return self._json({"_debug_info": {"rendered_template": cfg.rendered}})
                if not body.get("stream"):
                    return self._json({"choices": [{"message": {"content": "o"}}]})
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()

                def w(b):
                    self.wfile.write(b"%x\r\n" % len(b) + b + b"\r\n")
                    self.wfile.flush()
                try:
                    for tok in cfg.tokens:
                        w(b"data: " + json.dumps({"choices": [{"delta": {"content": tok}}]}).encode()
                          + b"\n\n")
                    w(b"data: " + json.dumps({"choices": [{"delta": {}, "finish_reason": "stop"}],
                                              "usage": {"prompt_tokens": cfg.prompt_tokens,
                                                        "completion_tokens": len(cfg.tokens)}}).encode()
                      + b"\n\n")
                    w(b"data: [DONE]\n\n")
                    self.wfile.write(b"0\r\n\r\n")
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.handle_error = lambda *a: None       # the client hung up: what it should do
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def show(template, arch="qwen3", caps=("completion",)):
    return {"template": template, "capabilities": list(caps),
            "model_info": {"general.architecture": arch}}


class TestTemplateCheck(unittest.TestCase):
    def test_what_is_refused(self):
        self.assertIsNone(mnm.template_problem(show(GOOD_Q3)))
        self.assertIsNone(mnm.template_problem(show(NO_BLOCK, arch="qwen2")))   # Qwen2.5
        self.assertIn("block", mnm.template_problem(show(NO_BLOCK)))
        self.assertIn("can think", mnm.template_problem(show(GOOD_Q3, caps=("completion", "thinking"))))
        pen = show(NO_BLOCK, arch="qwen2")
        pen["model_info"]["general.sampling.penalty_repeat"] = 1.05
        self.assertIn("penalty", mnm.template_problem(pen))
        pen["model_info"]["general.sampling.penalty_repeat"] = 1.0
        pen["model_info"]["general.sampling.top_k"] = 20               # no matter when greedy
        self.assertIsNone(mnm.template_problem(pen))


class TestARun(unittest.TestCase):
    META = {"source": "corpus", "n": 1}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = pathlib.Path(self.tmp.name)
        (d / "data").mkdir()
        (d / "evals").mkdir()
        (d / "data" / "val.jsonl").write_text(json.dumps({"meta": self.META, "messages": [
            {"role": "system", "content": "s"}, {"role": "user", "content": "pwd"},
            {"role": "assistant", "content": "/root"}]}) + "\n")
        (d / "evals" / "base-q3.json").write_text(json.dumps(
            {"answers": [{"meta": self.META, "prompt_tokens": 2000,
                          "prompt_sha256": hashlib.sha256(b"PROMPT").hexdigest()}]}))

    def run_tool(self, fake, *extra):
        self.addCleanup(fake.close)
        d = self.tmp.name
        p = subprocess.run([sys.executable, str(ROOT / "tools" / "measure_node_model.py"),
                            "--node", "lab-j1", "--model", "ft", "--no-tunnel", "--port",
                            str(fake.port), "--data", f"{d}/data", "--expect-dir", f"{d}/evals",
                            "--out-dir", d, *extra], capture_output=True, text=True, timeout=60)
        reports = list(pathlib.Path(d).glob("res_nodemodel_*.json"))
        return p, (json.loads(reports[0].read_text()) if reports else None)

    def test_a_model_that_would_think_is_not_measured(self):
        fake = FakeOllama(show(NO_BLOCK), ["/root"])
        p, rep = self.run_tool(fake)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("WILL THINK", p.stdout)
        self.assertIsNone(rep)
        self.assertFalse([b for path, b in fake.posts if path.endswith("/chat/completions")])

    def test_check_only_generates_nothing(self):
        fake = FakeOllama(show(GOOD_Q3), ["/root"])
        p, rep = self.run_tool(fake, "--check-only")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("thinking off, template fine", p.stdout)
        self.assertIn("1 of 1 prompts byte for byte as in training", p.stdout)
        posts = [(path, b.get("_debug_render_only"), b.get("reasoning_effort")) for path, b in fake.posts]
        self.assertEqual(posts, [("/api/show", None, None),
                                 ("/v1/chat/completions", True, "none"),   # the relay's request
                                 ("/api/generate", None, None)])           # unloaded again

    def test_a_node_that_renders_another_prompt_fails_the_check(self):
        p, _ = self.run_tool(FakeOllama(show(GOOD_Q3), ["/root"], rendered="PROMPT "), "--check-only")
        self.assertEqual(p.returncode, 1)
        self.assertIn("0 of 1 prompts byte for byte as in training (DIFFERENT", p.stdout)

    def test_the_prompt_lengths_are_compared_with_the_pc(self):
        p, rep = self.run_tool(FakeOllama(show(GOOD_Q3), ["/", "root"]))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual((rep["prompts"]["compared"], rep["prompts"]["differ"]), (1, 0))
        self.assertEqual((rep["prompts"]["rendered"]["same"], rep["prompts"]["rendered"]["differ"]), (1, 0))
        self.assertEqual(rep["report"]["all"]["exact"], 1)
        self.assertIn("1 of 1 the same as on the PC", p.stdout)

    def test_without_pc_reports_the_fingerprints_beside_the_data_are_used(self):
        d = pathlib.Path(self.tmp.name)
        (d / "evals" / "base-q3.json").unlink()
        (d / "data" / "prompt_fingerprints.json").write_text(json.dumps({"qwen3": [
            {"meta": self.META, "prompt_tokens": 2000,
             "prompt_sha256": hashlib.sha256(b"PROMPT").hexdigest()}], "qwen2": []}))
        p, _ = self.run_tool(FakeOllama(show(GOOD_Q3), ["/root"]), "--check-only")
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("1 of 1 prompts byte for byte as in training", p.stdout)

    def test_a_different_prompt_is_reported(self):
        p, rep = self.run_tool(FakeOllama(show(GOOD_Q3), ["/root"], prompt_tokens=1990))
        self.assertEqual(rep["prompts"]["differ"], 1)
        self.assertIn("DIFFERENT", p.stdout)

    def test_a_model_that_starts_to_think_stops_the_run(self):
        p, rep = self.run_tool(FakeOllama(show(GOOD_Q3), ["<think>", "\nhm"]))
        self.assertIn("the model thinks", p.stdout)
        self.assertIsNone(rep)


if __name__ == "__main__":
    unittest.main()
