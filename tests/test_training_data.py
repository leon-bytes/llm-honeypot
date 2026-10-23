#!/usr/bin/env python3
"""The fine-tuning data never contains the 43, nor Ground Truth's identity.

Builds the data (all three sources: corpus, debian, code) into a temporary directory
and checks every record. Run:
  python3 tests/test_training_data.py
"""
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import build_training_data as btd                  # noqa: E402
from honeypot import machine, net                  # noqa: E402
from tests.test_relay import wrong_zone_labels     # noqa: E402

from honeypot.site import SITE                     # noqa: E402
from tests import recordings                       # noqa: E402

# The training data is built from the team-only recordings: without them (a fresh clone
# with the example site values) this whole module is skipped.
GT43 = recordings.load("gt43_lab_2026-09.json")
CORPUS = {e["n"]: e for e in recordings.load("corpus284_lab_2026-09.json")}
CFG = SITE.load_json(ROOT / "honeypot" / "config.json")
EXAMPLES = "Real examples from this exact machine:"


def shown_examples(record) -> list[str]:
    """The commands of the recordings a record's prompt shows as examples."""
    system = record["messages"][0]["content"]
    if EXAMPLES not in system:
        return []
    return [line[2:] for line in system.split(EXAMPLES)[1].split("\n") if line.startswith("$ ")]


class TestTrainingData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real_clock = (machine.now, machine.boot_time)
        cls.tmp = tempfile.TemporaryDirectory()
        out = pathlib.Path(cls.tmp.name)
        cls.manifest = btd.build(2, out, code_session_count=20)
        cls.records = {}
        for name in ("train", "val"):
            with open(out / f"{name}.jsonl") as f:
                cls.records[name] = [json.loads(l) for l in f]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def all_records(self):
        return self.records["train"] + self.records["val"]

    def by_source(self, source, name=None):
        pool = self.records[name] if name else self.all_records()
        return [r for r in pool if r["meta"]["source"] == source]

    # ---- the rules, for every source

    def test_no_test_command_is_trained_or_held_back(self):
        test_cmds = {btd.norm_cmd(e["command"]) for e in GT43}
        for r in self.all_records():
            self.assertNotIn(btd.norm_cmd(r["messages"][1]["content"]), test_cmds, r["meta"])

    def test_no_output_shares_lines_with_a_test_answer(self):
        test_windows = set().union(*(btd.windows(e["output"]) for e in GT43))
        for r in self.all_records():
            for m in r["messages"]:                    # targets AND everything in the prompt
                self.assertFalse(btd.windows(m["content"]) & test_windows, r["meta"])

    def test_no_test_command_appears_anywhere_in_a_prompt(self):
        """Not as an example and not among the session's earlier commands."""
        test_cmds = {btd.norm_cmd(e["command"]) for e in GT43}
        for r in self.all_records():
            for line in r["messages"][0]["content"].split("\n"):
                if line.startswith("$ "):
                    self.assertNotIn(btd.norm_cmd(line[2:]), test_cmds, r["meta"])

    def test_passwd_and_os_release_pieces_are_out(self):
        for n in (262, 263, 264):
            self.assertIn(str(n), self.manifest["excluded"])
        for r in self.all_records():
            for cmd in shown_examples(r):
                for n in (262, 263, 264):
                    self.assertNotEqual(cmd, CORPUS[n]["command"], r["meta"])

    def test_no_ground_truth_identity(self):
        from honeypot import identity
        gt = list(CFG["substitutions"]) + [net.GT_DOCKER0_MAC, net.GT_BR_MAC] + \
            list(identity.INSTALL.values()) + list(identity.BOOT.values()) + \
            [x for pair in net.GT_VETHS for x in pair]
        for r in self.all_records():
            text = json.dumps(r["messages"]).lower()
            for g in gt:
                self.assertNotIn(g.lower(), text, (g, r["meta"]))

    def test_held_back_examples_are_never_trained_or_retrieved(self):
        val = set(self.manifest["examples"]["val"])
        self.assertTrue(val)
        self.assertFalse(val & set(self.manifest["examples"]["train"]))
        val_cmds = {CORPUS[n]["command"] for n in val}
        for r in self.all_records():                   # in no prompt at all, of any source
            self.assertFalse(val_cmds & set(shown_examples(r)), r["meta"])
        d = self.manifest["sources"]["debian"]["examples"]
        self.assertTrue(d["val"])
        self.assertFalse(set(d["val"]) & set(d["train"]))
        held = {r["meta"]["n"] for r in self.records["val"]}
        self.assertFalse(held & {r["meta"]["n"] for r in self.records["train"]})
        train_sessions = {r["meta"]["session"] for r in self.by_source("code", "train")}
        val_sessions = {r["meta"]["session"] for r in self.by_source("code", "val")}
        self.assertTrue(val_sessions)
        self.assertFalse(train_sessions & val_sessions)

    def test_no_record_is_shown_a_recording_of_its_own_command(self):
        for r in self.all_records():
            cmd = btd.norm_cmd(r["messages"][1]["content"])
            self.assertNotIn(cmd, {btd.norm_cmd(c) for c in shown_examples(r)}, r["meta"])

    def test_every_zone_label_follows_the_zone_rules(self):
        """Contexts fall on both sides of 2026-11-01; no prompt and no target may say EDT
        for a winter time or EST for a summer one."""
        summer = winter = 0
        for r in self.all_records():
            system = r["messages"][0]["content"]
            summer += " EDT 2026" in system
            winter += " EST 2026" in system
            for m in r["messages"]:
                self.assertEqual(wrong_zone_labels(m["content"])[1], [], r["meta"])
        self.assertGreater(summer, 50)
        self.assertGreater(winter, 50)

    # ---- the sources

    def test_all_three_sources_are_there(self):
        for name in ("train", "val"):
            got = self.manifest["records_by_source"][name]
            for source in ("corpus", "debian", "code"):
                self.assertGreater(got.get(source, 0), 0, (name, source))
            self.assertEqual(sum(got.values()), len(self.records[name]))

    def test_debian_texts_are_new_commands_from_matching_packages(self):
        corpus_cmds = {btd.norm_cmd(e["command"]) for e in CORPUS.values()}
        with open(btd.DEBIAN_TEXTS) as f:
            texts = {e["n"]: e for e in json.load(f)}
        gt = {}
        with open(ROOT / "offline" / "gt-installed.txt") as f:
            for line in f:
                p = line.split()
                if len(p) >= 2:
                    gt[p[0].split(":")[0]] = p[1]
        for r in self.by_source("debian"):
            e = texts[r["meta"]["n"]]
            self.assertNotIn(btd.norm_cmd(e["command"]), corpus_cmds)
            self.assertEqual(r["messages"][1]["content"], e["command"])
            self.assertEqual(r["messages"][2]["content"], e["output"])      # nothing to substitute
            self.assertTrue(e["packages"])
            for pkg, version in e["packages"].items():
                self.assertEqual(gt.get(pkg), version, (e["command"], pkg))
            self.assertNotIn("command not found", e["output"])

    def test_code_answers_are_what_the_relay_computes(self):
        """Spot check through a relay of our own: a session's first `export` and `echo`
        of it, and that state-changing lines have empty answers."""
        code = self.by_source("code")
        self.assertGreater(len(code), 100)
        for r in code:
            cmd, target = r["messages"][1]["content"], r["messages"][2]["content"]
            first = cmd.split()[0]
            if first in ("cd", "export", "unset", "touch", "mkdir") and r["meta"]["exit_code"] == 0 \
                    and ";" not in cmd and "|" not in cmd:
                self.assertEqual(target, "", cmd)
            if cmd == "pwd":
                self.assertIn(f"current directory {target},", r["messages"][0]["content"])
            if cmd == "date":
                self.assertIn(f"- date prints: {target}\n", r["messages"][0]["content"])
            if cmd == "echo $USER":
                self.assertEqual(target, "root")
        self.assertTrue(any(r["messages"][1]["content"] == "date" for r in code))

    def test_code_sessions_show_the_codes_answers_as_history(self):
        """Later prompts of a generated session show what code answered, not the empty
        reply of the stand-in model."""
        seen = 0
        for r in self.by_source("code"):
            system = r["messages"][0]["content"]
            if "This session so far" in system and "\n$ pwd\n/" in system:
                seen += 1
        self.assertGreater(seen, 3)

    def test_the_clock_is_put_back(self):
        self.assertEqual((machine.now, machine.boot_time), self.real_clock)


class TestEvaluationCleansLikeTheRelay(unittest.TestCase):
    """tools/finetune/eval_heldback.py carries a copy of the relay's clean(), so that it
    runs on the training PC without the repository. The two must not drift apart."""

    def test_the_copy_equals_the_relays_clean(self):
        import re
        from honeypot.shell import clean
        src = (ROOT / "tools" / "finetune" / "eval_heldback.py").read_text()
        ns = {"re": re}
        exec(src[src.index("def relay_clean"):src.index("def main")], ns)
        for text, line in (("```\nabc  \n```", "ls"), ("$ ls\nfoo \nroot@raspberrypi:~# ", "ls"),
                           ("\nx\n\n", "pwd"), ("```bash\na\nb\n```\n", "x"), ("", "true"),
                           ("# id\nuid=0(root)", "id"), ("a  \n b\t\nroot@raspberrypi:/etc# ", "cat x"),
                           ("<think>\nhm\n</think>\n\n  PID TTY", "ps"), ("<think>\ncut off", "ls"),
                           ("why</think>\nroot", "whoami"), ("\n<think></think>\n```\nx\n```", "x")):
            self.assertEqual(ns["relay_clean"](text, line), clean(text, line), (text, line))


class TestTrainingDataIsReproducible(unittest.TestCase):
    def test_the_same_seed_builds_the_same_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = pathlib.Path(tmp) / "a", pathlib.Path(tmp) / "b"
            for out in (a, b):
                btd.build(1, out, debian_variants=0, code_session_count=3)
            for name in ("train.jsonl", "val.jsonl"):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(), name)


class TestFrozenHeldBack(unittest.TestCase):
    """`--frozen-val`: an earlier set's held-back records are kept byte for byte, and no
    training record holds one of their corpus examples or Debian commands, nor is word
    for word one of them (the go/no-go stays comparable across data sets)."""

    def test_held_back_records_are_kept_and_never_trained(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = pathlib.Path(tmp) / "first", pathlib.Path(tmp) / "second"
            btd.build(1, first, debian_variants=0, code_session_count=6)
            btd.build(2, second, debian_variants=1, code_session_count=12, frozen_val=first)
            self.assertEqual((first / "val.jsonl").read_bytes(), (second / "val.jsonl").read_bytes())
            val = [json.loads(l) for l in open(second / "val.jsonl")]
            train = [json.loads(l) for l in open(second / "train.jsonl")]
            corpus_ns = {r["meta"]["n"] for r in val if r["meta"]["source"] == "corpus"}
            held = {btd.norm_cmd(r["messages"][-2]["content"]) for r in val
                    if r["meta"]["source"] in ("corpus", "debian")}
            whole = {json.dumps(r["messages"]) for r in val}
            for r in train:
                self.assertNotIn(json.dumps(r["messages"]), whole)
                if r["meta"]["source"] == "corpus":
                    self.assertNotIn(r["meta"]["n"], corpus_ns)
                else:
                    self.assertNotIn(btd.norm_cmd(r["messages"][-2]["content"]), held, r["meta"])


if __name__ == "__main__":
    unittest.main()
