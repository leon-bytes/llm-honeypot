#!/usr/bin/env python3
"""Host-free tests for the Docker API recorder's lossless body capture.

These guard the defect found in the first Phase 1 capture: bodies were stored
only as UTF-8-with-replacement, which destroys any byte that is not valid UTF-8.
Docker's stream framing puts a 4-byte big-endian length in every 8-byte frame
header, so a frame carrying 128 bytes or more has a length byte >= 0x80 - not
valid UTF-8 on its own, and it came back as U+FFFD. The influxdb log record lost
its first frame length exactly that way, and that framing is the thing the
honeypot has to reproduce byte for byte.

No lab host is touched: a throwaway HTTP server on localhost stands in for the
Docker daemon.

Run: python3 tests/test_api_capture.py
"""
import base64
import json
import pathlib
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from capture_docker_api import one                      # noqa: E402
try:                                                    # not in the shared repository:
    from capture_docker_api_phase2 import demux         # noqa: E402  it writes to the reference machine
except ImportError:
    demux = None
from check_api_framing import walk                      # noqa: E402


def frame(stream, payload):
    """Build one Docker stream frame: stream byte, three zeros, 4-byte BE length."""
    return bytes([stream, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


# A short frame (length byte < 0x80, survives even a lossy recorder) followed by
# a long one (length 0x0134 = 308, whose high byte 0x01 is fine but whose low
# byte 0x34 is not the problem - the killer is a length like 200 -> 0xC8).
SHORT = frame(1, b"raspberrypi\n")
LONG = frame(1, b"x" * 200)              # length 200 -> 0x00 0x00 0x00 0xC8
STDERR = frame(2, b"a warning\n")
STREAM_BODY = SHORT + LONG + STDERR


class Handler(BaseHTTPRequestHandler):
    def _respond(self):
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.docker.multiplexed-stream")
            self.send_header("Content-Length", str(len(STREAM_BODY)))
            self.end_headers()
            self.wfile.write(STREAM_BODY)
        elif self.path == "/echo":
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n)
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    do_GET = do_POST = do_DELETE = _respond

    def log_message(self, *a):
        pass                                     # keep the test output clean


class RecorderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Handler)
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, path, **kw):
        return one(self.base, "GET", path, "test-agent", 10.0, **kw)

    # ---- the defect this file exists for -------------------------------------

    def test_stream_body_is_kept_losslessly(self):
        rec = self.get("/stream")
        self.assertEqual(rec["status"], 200)
        self.assertIn("body_b64", rec,
                      "a body with non-UTF-8 bytes must be kept as base64")
        self.assertEqual(base64.b64decode(rec["body_b64"]), STREAM_BODY,
                         "the recorded bytes must be byte-for-byte what the server sent")

    def test_frame_lengths_survive(self):
        # The regression in one line: walk the frames from the recorded record.
        rec = self.get("/stream")
        raw = base64.b64decode(rec["body_b64"])
        frames, err = walk(raw)
        self.assertIsNone(err, f"framing damaged: {err}")
        self.assertEqual([(1, 12), (1, 200), (2, 10)], frames)

    def test_text_only_copy_would_have_lost_the_long_frame(self):
        # Proof that the old behaviour was lossy, so this test fails loudly if
        # someone "simplifies" the recorder back to text-only.
        rec = self.get("/stream")
        lossy = rec["body"].encode("utf-8")
        self.assertNotEqual(lossy, STREAM_BODY)
        self.assertIn("�", rec["body"])
        _, err = walk(lossy)
        self.assertIsNotNone(err, "the text-only copy should NOT parse as valid framing")

    def test_sha256_is_over_the_raw_bytes(self):
        import hashlib
        rec = self.get("/stream")
        self.assertEqual(rec["body_sha256"], hashlib.sha256(STREAM_BODY).hexdigest())

    def test_demux_splits_stdout_and_stderr(self):
        if demux is None:
            self.skipTest("tools/capture_docker_api_phase2.py is not here (kept out of the shared repository)")
        out, err = demux(self.get("/stream"))
        self.assertEqual(out, "raspberrypi\n" + "x" * 200)
        self.assertEqual(err, "a warning\n")

    # ---- plain bodies keep working exactly as Phase 1 recorded them ----------

    def test_clean_utf8_body_has_no_b64(self):
        rec = self.get("/nope")
        self.assertEqual(rec["status"], 404)
        self.assertNotIn("body_b64", rec,
                         "a body that round-trips must not carry a redundant base64 copy")

    def test_record_shape_matches_phase1(self):
        rec = self.get("/nope")
        for k in ("status", "reason", "headers", "body", "body_sha256", "elapsed_ms"):
            self.assertIn(k, rec)
        self.assertIsInstance(rec["headers"], list)

    # ---- POST support, which Phase 2 needs ----------------------------------

    def test_post_sends_json_and_records_the_request_body(self):
        payload = {"Image": "eclipse-mosquitto:2",
                   "HostConfig": {"Binds": ["/:/mnt:ro"]}}
        rec = one(self.base, "POST", "/echo", "test-agent", 10.0, req_body=payload)
        self.assertEqual(rec["status"], 201)
        self.assertEqual(json.loads(rec["body"]), payload,
                         "the server should have received exactly the JSON we sent")
        self.assertEqual(rec["request_body"], payload,
                         "the request body belongs in the record, for the paper")

    def test_get_sends_no_request_body_field(self):
        self.assertNotIn("request_body", self.get("/nope"))

    def test_connection_failure_is_recorded_not_raised(self):
        rec = one("http://127.0.0.1:1", "GET", "/_ping", "test-agent", 2.0)
        self.assertEqual(rec["status"], -1)
        self.assertIn("body_sha256", rec)


class FramingWalkerTests(unittest.TestCase):
    """The checker must actually catch damage, not just wave things through."""

    def test_clean_stream_parses(self):
        frames, err = walk(STREAM_BODY)
        self.assertIsNone(err)
        self.assertEqual(len(frames), 3)

    def test_replacement_char_in_length_is_caught(self):
        damaged = STREAM_BODY.replace(b"\xc8", "�".encode())
        _, err = walk(damaged)
        self.assertIsNotNone(err)

    def test_truncated_payload_is_caught(self):
        _, err = walk(STREAM_BODY[:-4])
        self.assertIsNotNone(err)
        self.assertIn("remain", err)

    def test_bad_stream_byte_is_caught(self):
        _, err = walk(b"\x09\x00\x00\x00\x00\x00\x00\x01a")
        self.assertIsNotNone(err)
        self.assertIn("stream byte", err)

    def test_nonzero_reserved_bytes_are_caught(self):
        _, err = walk(b"\x01\x00\x01\x00\x00\x00\x00\x01a")
        self.assertIsNotNone(err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
