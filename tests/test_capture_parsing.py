#!/usr/bin/env python3
"""Host-free tests for capture_session_v3.parse_capture.

Each test guards one of the three sentinel defects found in the April data.
Run: python3 tests/test_capture_parsing.py
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import capture_session_v3 as cap

S = "__Xdeadbeef01__"


def stream(cmd, output, code):
    """Build the raw terminal stream one command produces.

    The terminal echoes the instrumented line first (with a literal "$?", which
    is why the marker regex requires digits), then the output, then the marker.
    """
    return f"{cmd}; echo {S}$?\r\n" + (f"{output}\r\n" if output else "") + f"{S}{code}\r\n"


class ExitCodes(unittest.TestCase):
    """Defect 1: the marker was SENT+"0", so only exit code 0 ever matched."""

    def test_zero(self):
        text, code = cap.parse_capture(stream("whoami", "root", 0), S)
        self.assertEqual((text, code), ("root", 0))

    def test_nonzero_codes_are_parsed(self):
        for c in (1, 2, 4, 42, 127, 255):
            with self.subTest(code=c):
                raw = stream("junkcommand", "-bash: junkcommand: command not found", c)
                text, code = cap.parse_capture(raw, S)
                self.assertEqual(code, c)
                self.assertEqual(text, "-bash: junkcommand: command not found")

    def test_marker_regex_matches_any_exit_code(self):
        # The read loop stops on this pattern; if it did not match, the command
        # would burn the full --timeout (the ~20,600 ms entries in April's data).
        import re
        pat = re.compile(re.escape(S) + r'(\d+)')
        for c in (0, 1, 127):
            self.assertTrue(pat.search(f"{S}{c}\r\n"), f"no match for exit {c}")

    def test_missing_marker_gives_minus_one(self):
        text, code = cap.parse_capture("hostname; echo " + S + "$?\r\nraspberrypi\r\n", S)
        self.assertEqual(code, -1)


class SentinelInOutput(unittest.TestCase):
    """Defect 3: output was cut at the FIRST sentinel occurrence."""

    def test_output_containing_sentinel_survives(self):
        # What `history | head -5` looks like when earlier lines hold a sentinel.
        out = "\r\n".join([
            "    1  uname -a",
            f"    2  df -h; echo {S}$?",
            "    3  whoami",
            f"    4  ls; echo {S}$?",
            "    5  free -m",
        ])
        text, code = cap.parse_capture(stream("history | head -5", out, 0), S)
        self.assertEqual(code, 0)
        self.assertEqual(len(text.split("\n")), 5, f"truncated: {text!r}")
        self.assertIn("free -m", text)

    def test_sentinel_with_digits_in_output_uses_last_match(self):
        # A pathological case: the output ends in something marker-shaped.
        out = f"some log line {S}7"
        text, code = cap.parse_capture(stream("cat log", out, 0), S)
        self.assertEqual(code, 0)
        self.assertIn("some log line", text)

    def test_bash_history_read_is_not_truncated(self):
        out = "\r\n".join([f"uname -a; echo {S}$?", "df -h", "whoami"])
        text, _ = cap.parse_capture(stream("cat /root/.bash_history", out, 0), S)
        self.assertEqual(len(text.split("\n")), 3, f"truncated: {text!r}")


class EchoStripping(unittest.TestCase):
    def test_echoed_command_line_is_dropped(self):
        text, _ = cap.parse_capture(stream("hostname", "raspberrypi", 0), S)
        self.assertEqual(text, "raspberrypi")
        self.assertNotIn("echo", text)

    def test_banner_before_echo_is_dropped(self):
        raw = "Linux raspberrypi 6.12.0\r\nLast login: Sun Sep 27 14:03:34 2026\r\n" \
              + stream("whoami", "root", 0)
        text, code = cap.parse_capture(raw, S)
        self.assertEqual((text, code), ("root", 0))

    def test_no_echo_falls_back_to_full_body(self):
        # If the terminal does not echo, keep the output rather than losing it.
        raw = f"raspberrypi\r\n{S}0\r\n"
        text, code = cap.parse_capture(raw, S)
        self.assertEqual((text, code), ("raspberrypi", 0))

    def test_empty_output(self):
        text, code = cap.parse_capture(stream("touch junk.txt", "", 0), S)
        self.assertEqual((text, code), ("", 0))


class Normalisation(unittest.TestCase):
    """Behaviour that must not regress from the original script."""

    def test_ansi_escapes_removed(self):
        out = "\x1B[0m\x1B[01;34mjunkdir\x1B[0m  junk.txt"
        text, _ = cap.parse_capture(stream("ls", out, 0), S)
        self.assertEqual(text, "junkdir  junk.txt")

    def test_crlf_becomes_lf_and_trailing_newlines_stripped(self):
        text, _ = cap.parse_capture(stream("df -h", "line1\r\nline2", 0), S)
        self.assertEqual(text, "line1\nline2")
        self.assertNotIn("\r", text)

    def test_multiline_output_preserved(self):
        out = "\r\n".join(f"row {i}" for i in range(20))
        text, _ = cap.parse_capture(stream("ps -aux", out, 0), S)
        self.assertEqual(len(text.split("\n")), 20)


class Prologue(unittest.TestCase):
    def test_default_prologue_unsets_histfile(self):
        # The point of the prologue: bash reads HISTFILE at startup and writes it
        # back at exit, so unsetting it keeps reads truthful and writes nothing.
        self.assertEqual(cap.DEFAULT_PROLOGUE, "unset HISTFILE")
        self.assertNotIn("/dev/null", cap.DEFAULT_PROLOGUE)
        self.assertNotIn("history -c", cap.DEFAULT_PROLOGUE)

    def test_stray_prologue_echo_is_dropped(self):
        # If the prologue echo races past the drain, it lands before the command
        # echo and must not end up in the recorded output.
        raw = "unset HISTFILE\r\n" + stream("whoami", "root", 0)
        text, code = cap.parse_capture(raw, S)
        self.assertEqual((text, code), ("root", 0))


class PromptTerminated(unittest.TestCase):
    """--end prompt (2026-10-13), for the honeypot: the command is sent as it is and the
    answer ends at the next prompt. The bytes are what Cowrie sends (two carriage
    returns per line, the bracketed-paste switch before each prompt)."""

    P = "\x1b[?2004hroot@raspberrypi:~# "

    def test_the_answer_lies_between_the_echo_and_the_prompt(self):
        raw = "uname -a\r\nLinux raspberrypi 6.12\r\r\n" + self.P
        self.assertEqual(cap.parse_prompt_capture(raw), "Linux raspberrypi 6.12")

    def test_nothing_printed(self):
        self.assertEqual(cap.parse_prompt_capture("touch x\r\n" + self.P), "")

    def test_several_lines_and_a_prompt_that_follows_the_directory(self):
        raw = "cd /tmp; ls\r\na\r\r\nb\r\r\n\x1b[?2004hroot@raspberrypi:/tmp# "
        self.assertEqual(cap.parse_prompt_capture(raw), "a\nb")

    def test_a_line_that_only_looks_like_a_prompt_inside_the_answer_stays(self):
        raw = "cat notes\r\nroot@raspberrypi:~# ls\r\r\nmore\r\r\n" + self.P
        self.assertEqual(cap.parse_prompt_capture(raw), "root@raspberrypi:~# ls\nmore")

    def test_the_end_is_found_only_at_a_prompt(self):
        clean = lambda raw: cap.PROMPT_RE.search(cap.ANSI.sub("", raw))    # noqa: E731
        self.assertTrue(clean("ls\r\niot-stack\r\r\n" + self.P))
        self.assertFalse(clean("ls\r\niot-stack\r\r\n"))
        self.assertFalse(clean("echo x\r\nuser@host:~# not the end\r\r\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
