#!/usr/bin/env python3
"""The prior-system run with --examples (tools/run43_prior_shellm.py) builds its prompts
from the relay's own examples. No test answer and no Ground Truth address may be in them.
Needs the team-only recordings and site.local.json (skipped otherwise).
Run: python3 tests/test_prior_shellm.py
"""
import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from honeypot.site import SITE                    # noqa: E402
from tests import recordings                      # noqa: E402

spec = importlib.util.spec_from_file_location("run43_prior_shellm",
                                              ROOT / "tools" / "run43_prior_shellm.py")
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)

SYSTEM = "PERSONALITY TEXT"
# A one-line test answer that a corpus recording of a different command also holds, which the
# relay shows its own model the same way: echo $PATH (n=20) and `printenv PATH`.
KNOWN_SAME_LINE = {20}


class TestExamplePrompts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gt = recordings.load("gt43_lab_2026-09.json")
        cls.ex = prior.relay_examples([g["command"] for g in cls.gt])
        cls.prompts = [prior.with_examples(SYSTEM, e["block"]) for e in cls.ex]

    def test_all_43_built_and_most_have_examples(self):
        self.assertEqual(len(self.prompts), 43)
        self.assertGreaterEqual(sum(1 for e in self.ex if e["block"]), 35)
        for p, e in zip(self.prompts, self.ex):
            self.assertTrue(p.startswith(SYSTEM))
            if e["block"]:
                self.assertIn(prior.EXAMPLES_TITLE, p)

    def test_no_test_answer_in_any_prompt(self):
        big = [g for g in self.gt if len(g["output"].strip()) >= 20]
        self.assertGreater(len(big), 15)
        for g in big:
            ans = g["output"].strip()
            for i, p in enumerate(self.prompts):
                if "\n" in ans:
                    self.assertNotIn(ans, p, (g["n"], g["command"], i))
                elif g["n"] not in KNOWN_SAME_LINE:    # one line: it may sit inside a longer file (the PATH in sudoers)
                    self.assertNotIn(ans, [ln.strip() for ln in p.split("\n")],
                                     (g["n"], g["command"], i))

    def test_no_distinctive_multiline_answer_line_run(self):
        # three lines in a row of a test answer, as the relay's own hidden_examples rule
        for g in self.gt:
            lines = [ln for ln in g["output"].split("\n")]
            for i in range(len(lines) - 2):
                chunk = "\n".join(lines[i:i + 3])
                if len(chunk.strip()) < 40:
                    continue
                for p in self.prompts:
                    self.assertNotIn(chunk, p, (g["n"], g["command"]))

    def test_withheld_corpus_entries_absent(self):
        for e in self.ex:
            self.assertFalse({42, 233, 262, 263, 264} & set(e["n"]))
        corpus = {e["n"]: e for e in recordings.load("corpus284_lab_2026-09.json")}
        for n in (42, 233, 262, 263, 264):
            for p in self.prompts:
                self.assertNotIn(corpus[n]["output"].strip()[:200], p)

    def test_no_reference_address(self):
        # the lab resolver (SITE.lab_resolver6) is lab infrastructure, the honeypot's too
        for v in (SITE.ref_ipv4, SITE.ref_ipv6, SITE.ref_ipv6_slaac, SITE.ref_ipv6_link,
                  SITE.ref_mac_eth, SITE.ref_mac_wlan):
            for p in self.prompts:
                self.assertNotIn(v, p)


if __name__ == "__main__":
    unittest.main()
