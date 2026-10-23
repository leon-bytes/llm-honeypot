#!/usr/bin/env python3
"""Put reports of eval_heldback.py side by side: the base model and checkpoints.

Needs nothing but Python. With two reports it lists the totals per source, and the
records one model got exactly right and the other did not, so the numbers can be read
against real answers. With more than two it prints one line per report (the base model
and the three methods), which is the table for the go/no-go.

With --winner and the reports of the methods (not the base model's) it prints the name
of the method that won, by a rule fixed before any run (2026-10-14): the most exact
answers on the corpus and debian records together (the kinds of command the model
answers in normal mode; the code records reach it only if a code_scope switch is
turned off); if equal, the most exact answers on all records; if equal, the lower
best held-back loss of the run; if still equal, the first named. The reasons go to the
screen, the name alone to the last line, for run_finetune_plan.sh.

With --choose and three reports (the base model, the 3B winner, the 1.7B challenger),
it applies the go rule to each and then the rule for the 3B or the 1.7B, both fixed
before any run (the user, 2026-10-14; docs/finetuning-on-the-5090.md, "Go/no-go").
Meant for the board measurement's reports from Jetson 1 (tools/measure_node_model.py),
which carry the speed; on the PC's reports the speed conditions print as not measured. Go, per
model against the base model: no source worse on exact_rs, all records up by at least
GO_POINTS on exact_rs, and (when measured) not slower per token: its median reading speed
and its median writing speed (tokens/s) each at most SLOWER_OK below the base model's
(the user, 2026-10-15, after the PC's results and before any board measurement: a
fine-tuned model that writes the whole answer where the base model wrote a shorter one
takes longer per answer without being slower). Reading the wrong answers (the third go condition) stays a person's
job; it is printed as a reminder. Then: the 1.7B, unless it is clearly worse, which
means the 3B winner gets at least CLEARLY_WORSE more of the corpus and debian records
exactly right. If the 1.7B is not at least FASTER_BY faster on the node, speed is no
reason and the one with more corpus and debian records exactly right is taken (equal:
the 1.7B). The verdict goes to the last line: 3b, 1.7b or no-go.

With --specialists and four reports (the generalist, then the specialists for corpus,
debian and code; the specialist experiment, the user, 2026-10-15) it routes every
held-back record to the specialist of its own kind (perfect routing: the best case for
specialists) and compares with the generalist, record by record. The rule, fixed before
any specialist was trained: the specialists are clearly better if they get at least
CLEARLY_WORSE more of the corpus and debian records exactly right than the generalist,
clearly worse if they get that many fewer, and otherwise no clear difference. It also
prints what each specialist gets right on the kinds it was not trained on (what a
failover to it would give). The verdict goes to the last line: specialists, generalist
or no-difference.

Run: python compare_evals.py ~/ai/finetuning/honeypot/evals/base.json ~/ai/finetuning/honeypot/evals/lora.json
     python compare_evals.py ~/ai/finetuning/honeypot/evals/base.json ~/ai/finetuning/honeypot/evals/lora.json \
         ~/ai/finetuning/honeypot/evals/qlora.json ~/ai/finetuning/honeypot/evals/dora.json
     python compare_evals.py --choose res_nodemodel_<base>.json res_nodemodel_<3b>.json res_nodemodel_<1.7b>.json
"""
import collections
import json
import os
import sys

GO_POINTS = 10.0         # all records, exact_rs, points above the base model
SLOWER_OK = 0.05         # reading and writing speed on the node, share below the base model's
CLEARLY_WORSE = 5        # corpus+debian records the 3B must get right beyond the 1.7B
FASTER_BY = 0.20         # the 1.7B's median answer time at least this share below the 3B's


def table(paths: list[str]) -> int:
    reports = [(p, json.load(open(os.path.expanduser(p), encoding="utf-8"))) for p in paths]
    sources = sorted(reports[0][1]["report"], key=lambda k: (k == "all", k))
    print(f"{'report':28} " + " ".join(f"{s + ' exact':>14} {s + ' lines':>13}" for s in sources))
    for path, r in reports:
        name = os.path.basename(path).removesuffix(".json")[:28]
        cells = []
        for s in sources:
            x = r["report"].get(s)
            cells.append(f"{x['exact_pct']:13.1f}% {x['lines_pct']:12.1f}%" if x else " " * 28)
        print(f"{name:28} " + " ".join(cells))
    base = reports[0][1]["report"]["all"]
    print(f"\nagainst the first report ({os.path.basename(paths[0])}), all records, exact:")
    for path, r in reports[1:]:
        gain = r["report"]["all"]["exact_pct"] - base["exact_pct"]
        print(f"   {os.path.basename(path):28} {gain:+.1f} points")
    return 0


def winner(paths: list[str]) -> int:
    rows = []
    for order, path in enumerate(paths):
        r = json.load(open(os.path.expanduser(path), encoding="utf-8"))
        rep = r["report"]
        seen = sum(rep.get(s, {}).get("exact", 0) for s in ("corpus", "debian"))
        loss = float("inf")
        if r.get("adapter"):
            log = os.path.join(os.path.dirname(os.path.normpath(r["adapter"])), "log.jsonl")
            if os.path.exists(log):
                with open(log, encoding="utf-8") as f:
                    done = [json.loads(l) for l in f if '"done"' in l]
                if done:
                    loss = done[-1].get("best_heldback_loss", loss)
        name = os.path.basename(path).removesuffix(".json")
        rows.append(((-seen, -rep["all"]["exact"], loss, order), name, seen, rep["all"]["exact"], loss))
    rows.sort()
    for key, name, seen, total, loss in rows:
        print(f"   {name:20} corpus+debian exact {seen:3}   all exact {total:3}   "
              f"best held-back loss {loss:.4f}", file=sys.stderr)
    print(f"winner: {rows[0][1]}", file=sys.stderr)
    print(rows[0][1])
    return 0


def seen_exact(rep: dict) -> int:
    return sum(rep.get(s, {}).get("exact", 0) for s in ("corpus", "debian"))


def median_ms(r: dict):
    return (r.get("timing") or {}).get("total_ms_median")


def speeds(r: dict):
    """Median reading and writing speed on the node (tokens/s), or None when not measured."""
    t = r.get("timing") or {}
    read, write = t.get("reading_tokens_per_s"), t.get("writing_tokens_per_s")
    return (read, write) if read and write else None


def go(base: dict, r: dict) -> list[str]:
    """The go conditions that fail, as sentences; empty when it is a go."""
    fails = []
    for s, b in base["report"].items():
        x = r["report"].get(s)
        if s != "all" and x and x["exact_rs"] < b["exact_rs"]:
            fails.append(f"{s} worse than the base model ({x['exact_rs']} < {b['exact_rs']} exact_rs)")
    gain = r["report"]["all"]["exact_rs_pct"] - base["report"]["all"]["exact_rs_pct"]
    if gain < GO_POINTS:
        fails.append(f"all records up {gain:+.1f} points, needs {GO_POINTS:+.0f}")
    sb, sr = speeds(base), speeds(r)
    if sb and sr:
        for what, b, x in (("reading", sb[0], sr[0]), ("writing", sb[1], sr[1])):
            if x < b * (1 - SLOWER_OK):
                fails.append(f"slower than the base model on the node, {what} {x:.1f} tokens/s "
                             f"against {b:.1f} (median)")
    return fails


def choose(paths: list[str]) -> int:
    if len(paths) != 3:
        sys.exit("--choose needs three reports: the base model, the 3B winner, the 1.7B challenger")
    base, big, small = (json.load(open(os.path.expanduser(p), encoding="utf-8")) for p in paths)
    say = lambda s: print(s, file=sys.stderr)     # noqa: E731
    ok = {}
    for tag, r in (("3b", big), ("1.7b", small)):
        fails = go(base, r)
        ok[tag] = not fails
        say(f"{tag:5} {'go' if ok[tag] else 'NO GO'}" + ("".join(f"\n      - {f}" for f in fails)))
        if speeds(r) is None or speeds(base) is None:
            say("      - speed per token not measured in these reports (the node reports have it)")
        else:
            mb, mr = median_ms(base), median_ms(r)
            say(f"      speed per token, reading {speeds(r)[0]} against {speeds(base)[0]} tokens/s, "
                f"writing {speeds(r)[1]} against {speeds(base)[1]}"
                + (f"; median answer time {mr:.0f} ms against {mb:.0f} (for information)"
                   if mb and mr else ""))
    say("      (go also needs a person to read the wrong answers: nothing alarming, such as "
        "an invented answer that looks real)")
    if not ok["3b"] and not ok["1.7b"]:
        say("verdict: no-go, the base model stays")
        print("no-go")
        return 0
    if ok["3b"] != ok["1.7b"]:
        pick = "3b" if ok["3b"] else "1.7b"
        say(f"verdict: {pick}, the only one that is a go")
        print(pick)
        return 0
    sb, ss = seen_exact(big["report"]), seen_exact(small["report"])
    tb, ts = median_ms(big), median_ms(small)
    say(f"corpus+debian exact: 3b {sb}, 1.7b {ss}; median answer time: 3b "
        f"{tb if tb is not None else '?'} ms, 1.7b {ts if ts is not None else '?'} ms")
    if tb is None or ts is None:
        say("speed not measured: the rule needs the board measurement's reports; no verdict")
        print("undecided")
        return 1
    if ts > tb * (1 - FASTER_BY):
        pick = "3b" if sb > ss else "1.7b"
        say(f"the 1.7B is not {FASTER_BY:.0%} faster, so speed is no reason: the one with more "
            f"exact corpus+debian answers (equal: the 1.7B). verdict: {pick}")
    elif sb - ss >= CLEARLY_WORSE:
        pick = "3b"
        say(f"the 1.7B is faster but clearly worse (the 3B gets {sb - ss} more right; clearly "
            f"worse is {CLEARLY_WORSE} or more). verdict: 3b")
    else:
        pick = "1.7b"
        say(f"the 1.7B is faster and not clearly worse (the 3B gets {sb - ss:+d} more right; "
            f"clearly worse is {CLEARLY_WORSE} or more). verdict: 1.7b")
    print(pick)
    return 0


def key(meta: dict) -> str:
    return json.dumps(meta, sort_keys=True)


def specialists(paths: list[str]) -> int:
    if len(paths) != 4:
        sys.exit("--specialists needs four reports: the generalist, then the corpus, debian "
                 "and code specialists")
    gen, *specs = (json.load(open(os.path.expanduser(p), encoding="utf-8")) for p in paths)
    kinds = ("corpus", "debian", "code")
    say = lambda s: print(s, file=sys.stderr)     # noqa: E731
    by = [{key(a["meta"]): a for a in r["answers"]} for r in specs]
    routed, g_right, pairs = {}, {}, {}
    for a in gen["answers"]:
        src = a["meta"].get("source", "corpus")
        sa = by[kinds.index(src)].get(key(a["meta"]))
        if sa is None:
            sys.exit(f"a {src} record is missing from the {src} specialist's report")
        routed[src] = routed.get(src, 0) + sa["exact"]
        g_right[src] = g_right.get(src, 0) + a["exact"]
        d = pairs.setdefault(src, [0, 0])
        d[0] += sa["exact"] and not a["exact"]
        d[1] += a["exact"] and not sa["exact"]
    n = collections.Counter(a["meta"].get("source", "corpus") for a in gen["answers"])
    say(f"{'kind':8} {'records':>7} {'generalist':>11} {'specialist':>11}   only the specialist / only the generalist")
    for src in kinds:
        say(f"{src:8} {n[src]:7} {g_right.get(src, 0):11} {routed.get(src, 0):11}   "
            f"{pairs.get(src, [0, 0])[0]} / {pairs.get(src, [0, 0])[1]}")
    say("each specialist on every kind (exact), the kinds it was not trained on in brackets:")
    for kind, r in zip(kinds, specs):
        rep = r["report"]
        say(f"   {kind:7} " + "  ".join(f"{s} {rep[s]['exact']}/{rep[s]['records']}" if s == kind
                                       else f"({s} {rep[s]['exact']}/{rep[s]['records']})" for s in kinds))
    gs = g_right.get("corpus", 0) + g_right.get("debian", 0)
    ss = routed.get("corpus", 0) + routed.get("debian", 0)
    say(f"corpus+debian exact: generalist {gs}, specialists {ss} (of {n['corpus'] + n['debian']}); "
        f"clearly is {CLEARLY_WORSE} or more")
    verdict = "specialists" if ss - gs >= CLEARLY_WORSE else "generalist" if gs - ss >= CLEARLY_WORSE \
        else "no-difference"
    say(f"verdict: {verdict}")
    print(verdict)
    return 0


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--specialists":
        return specialists(sys.argv[2:])
    if len(sys.argv) >= 3 and sys.argv[1] == "--winner":
        return winner(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "--choose":
        return choose(sys.argv[2:])
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    if len(sys.argv) > 3:
        return table(sys.argv[1:])
    a, b = (json.load(open(os.path.expanduser(p), encoding="utf-8")) for p in sys.argv[1:])
    print(f"A = {a['adapter'] or a.get('model') or 'base model'}\n"
          f"B = {b['adapter'] or b.get('model') or 'base model'}\n")
    print(f"{'source':8} {'records':>7} {'exact A':>9} {'exact B':>9} {'no-space A':>11} "
          f"{'no-space B':>11} {'lines A':>8} {'lines B':>8}")
    for key in sorted(a["report"], key=lambda k: (k == "all", k)):
        x, y = a["report"][key], b["report"].get(key)
        if y is None:
            continue
        print(f"{key:8} {x['records']:7} {x['exact_pct']:8.1f}% {y['exact_pct']:8.1f}% "
              f"{x['exact_rs_pct']:10.1f}% {y['exact_rs_pct']:10.1f}% "
              f"{x['lines_pct']:7.1f}% {y['lines_pct']:7.1f}%")
    by = {json.dumps(r["meta"], sort_keys=True): r for r in b["answers"]}
    gained = [r for r in a["answers"] if not r["exact"]
              and by.get(json.dumps(r["meta"], sort_keys=True), {}).get("exact")]
    lost = [r for r in a["answers"] if r["exact"]
            and not by.get(json.dumps(r["meta"], sort_keys=True), {"exact": True})["exact"]]
    print(f"\nB right where A was wrong: {len(gained)}")
    for r in gained[:15]:
        print(f"   {r['meta'].get('source', '?'):7} {r['command'][:70]}")
    print(f"B wrong where A was right: {len(lost)}")
    for r in lost[:15]:
        print(f"   {r['meta'].get('source', '?'):7} {r['command'][:70]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
