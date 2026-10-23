"""compare_evals.py --choose: the go rule and the rule for the 3B or the 1.7B, fixed
before any run (the user, 2026-10-14; docs/finetuning-on-the-5090.md, "Go/no-go"), with
"not slower" judged per token (the user, 2026-10-15)."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "finetune" / "compare_evals.py"
RECORDS = {"corpus": 18, "debian": 66, "code": 85}


def report(exact: dict, ms=None, speed=None) -> dict:
    """A report of eval_heldback.py's shape: exact (and exact_rs) per source."""
    rep, total = {}, 0
    for s, n in RECORDS.items():
        e = exact[s]
        total += e
        rep[s] = {"records": n, "exact": e, "exact_rs": e, "exact_pct": round(100 * e / n, 1),
                  "exact_rs_pct": round(100 * e / n, 1), "lines_pct": 0.0}
    n = sum(RECORDS.values())
    rep["all"] = {"records": n, "exact": total, "exact_rs": total,
                  "exact_pct": round(100 * total / n, 1),
                  "exact_rs_pct": round(100 * total / n, 1), "lines_pct": 0.0}
    out = {"model": "m", "adapter": None, "report": rep}
    if ms is not None:
        # reading and writing tokens/s; by default the base model's, or faster in proportion
        read, write = speed or (1000 * 5000 / ms, 20 * 5000 / ms)
        out["timing"] = {"total_ms_median": ms, "reading_tokens_per_s": round(read, 1),
                         "writing_tokens_per_s": round(write, 1)}
    return out


BASE = report({"corpus": 6, "debian": 30, "code": 40}, ms=5000)


class ChooseCase(unittest.TestCase):
    def pick(self, big: dict, small: dict, base: dict = BASE) -> str:
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for name, r in (("base", base), ("big", big), ("small", small)):
                p = pathlib.Path(d) / f"{name}.json"
                p.write_text(json.dumps(r))
                paths.append(str(p))
            run = subprocess.run([sys.executable, str(TOOL), "--choose", *paths],
                                 capture_output=True, text=True)
        return run.stdout.strip().splitlines()[-1]

    def test_smaller_wins_when_close(self):
        big = report({"corpus": 12, "debian": 50, "code": 70}, ms=5000)
        small = report({"corpus": 11, "debian": 47, "code": 70}, ms=3100)   # 4 behind
        self.assertEqual(self.pick(big, small), "1.7b")

    def test_bigger_wins_when_clearly_better(self):
        big = report({"corpus": 12, "debian": 50, "code": 70}, ms=5000)
        small = report({"corpus": 10, "debian": 47, "code": 70}, ms=3100)   # 5 behind
        self.assertEqual(self.pick(big, small), "3b")

    def test_no_speed_gain_means_better_one(self):
        big = report({"corpus": 12, "debian": 50, "code": 70}, ms=5000)
        small = report({"corpus": 12, "debian": 49, "code": 70}, ms=4200)   # only 16% faster
        self.assertEqual(self.pick(big, small), "3b")
        small = report({"corpus": 12, "debian": 50, "code": 70}, ms=4200)   # equal: the 1.7B
        self.assertEqual(self.pick(big, small), "1.7b")

    def test_go_rule_gates_each(self):
        big = report({"corpus": 12, "debian": 50, "code": 70}, ms=5000)
        weak = report({"corpus": 5, "debian": 60, "code": 70}, ms=3100)     # corpus below base
        self.assertEqual(self.pick(big, weak), "3b")
        slow = report({"corpus": 12, "debian": 50, "code": 70}, ms=5300)    # 6% slower per token
        self.assertEqual(self.pick(slow, weak), "no-go")
        little = report({"corpus": 7, "debian": 33, "code": 45}, ms=3100)   # under +10 points
        self.assertEqual(self.pick(slow, little), "no-go")
        self.assertEqual(self.pick(slow, big), "1.7b")

    def test_not_slower_is_per_token(self):
        weak = report({"corpus": 5, "debian": 60, "code": 70}, ms=3100)     # corpus below base
        # longer answers, so 20% more time per answer, at the base model's speed: a go
        full = report({"corpus": 12, "debian": 50, "code": 70}, ms=6000, speed=(1000, 20))
        self.assertEqual(self.pick(full, weak), "3b")
        # the same answers, writing 6% slower per token: no go
        slow = report({"corpus": 12, "debian": 50, "code": 70}, ms=5000, speed=(1000, 18.8))
        self.assertEqual(self.pick(slow, weak), "no-go")
        # reading 6% slower per token: no go
        slow = report({"corpus": 12, "debian": 50, "code": 70}, ms=5000, speed=(940, 20))
        self.assertEqual(self.pick(slow, weak), "no-go")
        # within 5%: a go
        near = report({"corpus": 12, "debian": 50, "code": 70}, ms=5000, speed=(960, 19.2))
        self.assertEqual(self.pick(near, weak), "3b")

    def test_needs_speed_when_both_go(self):
        big = report({"corpus": 12, "debian": 50, "code": 70})
        small = report({"corpus": 11, "debian": 47, "code": 70})
        self.assertEqual(self.pick(big, small, report({"corpus": 6, "debian": 30, "code": 40})),
                         "undecided")


def answers(right: dict) -> dict:
    """A report with answers: right[source] is the set of record numbers it gets exact."""
    out = []
    for s, n in RECORDS.items():
        out += [{"meta": {"source": s, "n": i}, "exact": i in right.get(s, set())} for i in range(n)]
    rep = {s: {"records": n, "exact": len(right.get(s, set()))} for s, n in RECORDS.items()}
    return {"model": "m", "adapter": None, "report": rep, "answers": out}


class SpecialistsCase(unittest.TestCase):
    """--specialists (2026-10-15): each record routed to the specialist of its kind,
    against the generalist; clearly better or worse at 5 of the 84 corpus+debian records."""

    def verdict(self, gen, corpus, debian, code):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for i, r in enumerate((gen, corpus, debian, code)):
                p = pathlib.Path(d) / f"{i}.json"
                p.write_text(json.dumps(r))
                paths.append(str(p))
            run = subprocess.run([sys.executable, str(TOOL), "--specialists", *paths],
                                 capture_output=True, text=True)
        return run.stdout.strip().splitlines()[-1]

    def test_the_kind_decides_which_specialist_counts(self):
        gen = answers({"corpus": {0, 1}, "debian": set(range(30))})
        # the corpus specialist is right on 4 more corpus records but useless on debian;
        # only its corpus answers count, so 4 more is no clear difference
        corpus = answers({"corpus": {0, 1, 2, 3, 4, 5}})
        debian = answers({"debian": set(range(30))})
        self.assertEqual(self.verdict(gen, corpus, debian, answers({})), "no-difference")
        debian = answers({"debian": set(range(31))})                     # one more: 5 in all
        self.assertEqual(self.verdict(gen, corpus, debian, answers({})), "specialists")

    def test_code_records_do_not_count(self):
        gen = answers({"debian": set(range(30))})
        code = answers({"code": set(range(85))})
        self.assertEqual(self.verdict(gen, answers({}), answers({"debian": set(range(30))}), code),
                         "no-difference")

    def test_clearly_worse(self):
        gen = answers({"debian": set(range(30))})
        self.assertEqual(self.verdict(gen, answers({}), answers({"debian": set(range(25))}), answers({})),
                         "generalist")


if __name__ == "__main__":
    unittest.main()
