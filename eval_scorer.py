#!/usr/bin/env python3
"""
eval_scorer.py - score honeypot run files (relay format or the older pipeline format).

  python eval_scorer.py --file RUN.json [--file RUN2.json] \
      --real-key real --model-key model --verdict-key none [--identity identity.json] [--out results/]

The expected answer is read from --real-key inside each file (no separate ground-truth file).
Needs eval_honeypot.py next to it (all grading logic lives there).
Skip/stateful groups come from eval_not_gradable.json if found (cwd or next to this script),
otherwise the built-in skip list is used.
Extra columns used when present: tier (code vs model answers), real_exit_code / model_exit_code,
elapsed_ms. Exit codes are reported as a separate stat; the headline is text-only.
"""
import argparse, csv, json, os, statistics, sys
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval_honeypot as H

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", action="append", required=True)
    ap.add_argument("--real-key", default="real")
    ap.add_argument("--model-key", default="model")
    ap.add_argument("--verdict-key", default="none")
    ap.add_argument("--rules")
    ap.add_argument("--identity")
    ap.add_argument("--baseline", action="store_true",
                    help="run is the REAL machine (human baseline): ignore --identity, since the real "
                         "machine correctly shows its own addresses")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()

    skip, skip_src = H.load_rules(a.rules)
    subs = {}
    if a.baseline and a.identity:
        print("--baseline: ignoring --identity (the real machine shows its own addresses)")
        a.identity = None
    if a.identity:
        subs = {k: v for k, v in json.load(open(a.identity))["substitutions"].items() if v != "REPLACE_ME"}
    leak = [k for k, v in subs.items() if k != v]
    os.makedirs(a.out, exist_ok=True)
    if not a.identity:
        print("no --identity: identity substitution/leak check OFF")
    summ = []
    for path in a.file:
        name = os.path.splitext(os.path.basename(path))[0]
        data = json.load(open(path))
        rows = []
        for e in data:
            g = {"n": e["n"], "command": e["command"], "output": e[a.real_key]}
            run = {"model": e[a.model_key], "ms": e.get("ms", e.get("elapsed_ms", "")),
                   "examples": e.get("examples"), "empty_reason": e.get("empty_reason", "")}
            r = H.grade(g, run, subs, leak, skip)
            r["answer_tier"] = e.get("tier", "")
            rc, mc = e.get("real_exit_code"), e.get("model_exit_code")
            r["exit_ok"] = "" if rc is None or mc is None else (rc == mc)
            rows.append(r)
        # pair check: tests 24/25 (ps) and 26/27 (uptime) are the same command run twice because the
        # live value must CHANGE between calls. If the real answers differ but the model repeats itself,
        # the live value is frozen.
        byn = {e["n"]: e for e in data}
        rb = {r["n"]: r for r in rows}
        for p1, p2 in ((24, 25), (26, 27)):
            if p1 in byn and p2 in byn:
                ra, rb2 = H.norm(byn[p1][a.real_key]), H.norm(byn[p2][a.real_key])
                ma, mb2 = H.norm(byn[p1][a.model_key]), H.norm(byn[p2][a.model_key])
                if ra != rb2 and ma == mb2:
                    for k in (p1, p2):
                        if rb[k]["outcome"] == "PASS":
                            rb[k].update(outcome="FAIL", tier="", reason="live_value_frozen")
        if a.verdict_key != "none":
            for r in rows:
                hv = str(byn[r["n"]].get(a.verdict_key, "")).strip().upper()
                r["human_pass"] = hv in ("PASSED", "PASS", "MATCH", "EXACT", "SEMANTIC", "OK", "TRUE")
                r["agrees"] = r["human_pass"] == (r["outcome"] == "PASS")
        with open(os.path.join(a.out, name + "_per_test.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

        def t(sel):
            r = [x for x in rows if sel(x)]
            return f"{sum(x['outcome'] == 'PASS' for x in r)}/{len(r)}"
        core = lambda x: x["group"] == "CORE"
        print("=" * 66); print(name, f"(mode: {data[0].get('answer_mode', '?')}, build: {data[0].get('build', '?')})")
        print(f"  HEADLINE core stateless : {t(core)}   (excl. empty-expected: {t(lambda x: core(x) and 'empty_expected' not in x['tags'])})")
        print(f"  stateful group          : {t(lambda x: x['group'] == 'STATEFUL')}")
        print(f"  skip group (structural) : {t(lambda x: x['group'] == 'SKIP')}")
        tiers = sorted({x["answer_tier"] for x in rows if x["answer_tier"]})
        if len(tiers) > 1:
            for tr in tiers:
                print(f"  answered by '{tr}' (all groups) : {t(lambda x, tr=tr: x['answer_tier'] == tr)}   core only: {t(lambda x, tr=tr: core(x) and x['answer_tier'] == tr)}")
        print("  tiers passed (core)     :", dict(Counter(x["tier"] for x in rows if core(x) and x["outcome"] == "PASS")))
        print("  failures by reason, core:", dict(Counter(x["reason"] for x in rows if core(x) and x["outcome"] == "FAIL")))
        if a.verdict_key != "none":
            ag = [r for r in rows if r["agrees"]]
            print(f"  AGREEMENT with human verdicts : {len(ag)}/{len(rows)}   (human passed {sum(r['human_pass'] for r in rows)}, scorer passed {sum(r['outcome'] == 'PASS' for r in rows)})")
            for r in rows:
                if not r["agrees"]:
                    print(f"     disagree n={r['n']} {r['command'][:30]!r}: human={'PASS' if r['human_pass'] else 'FAIL'} scorer={r['outcome']} {r['reason']}")
        ex = [x for x in rows if x["exit_ok"] != ""]
        bad = [x["n"] for x in ex if x["exit_ok"] is False]
        if ex: print(f"  exit code agrees        : {len(ex) - len(bad)}/{len(ex)}   mismatched n: {bad}")
        ms = [float(x["ms"]) for x in rows if x["ms"] != ""]
        if ms: print(f"  latency ms              : median {statistics.median(ms):.0f}, max {max(ms):.0f}")
        summ.append(dict(file=name, core=t(core), stateful=t(lambda x: x["group"] == "STATEFUL"),
                         skip=t(lambda x: x["group"] == "SKIP"), exit_mismatch=len(bad) if ex else ""))
    with open(os.path.join(a.out, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summ[0])); w.writeheader(); w.writerows(summ)
    print("\nwrote per-test CSVs + summary.csv to", a.out)


if __name__ == "__main__":
    main()