"""Promotion gate for honeypot model arms (paired, seed-averaged, cluster bootstrap).

Each arm and its control are lists of bench runs (final/<run>.jsonl, one per seed). Records
pair by position within each test set (all arms see the same commands). A record's score is its
exact-match averaged over seeds. Primary metric: the mean of the four per-set exact rates
(val restricted to commands unseen in the original training set). The 95% CI comes from
resampling source clusters (meta n) within each set, paired across arms.

Epoch 2: the primary metric is the mean over val (unseen), test2 and gt43. test3 comes from the
same session generator as the state training data and saturates near 99%, so it is a guard
instead: an arm may not lose more than 3 points there (CI lower bound > -3).

PROMOTED: primary delta CI lower bound > 0, no primary set's CI upper bound < 0, test3 guard holds.
REJECTED: primary delta CI upper bound < 0, or point delta <= 0.
otherwise INCONCLUSIVE (needs more seeds or a split).
"""

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gt_score import normalise

SETS = ["val", "test2", "test3", "gt43"]
PRIMARY = ["val", "test2", "gt43"]
GUARD, GUARD_MARGIN = "test3", -0.03
B = 4000


def load_run(final_dir, run, gt_skip, val_unseen):
    rows = [
        json.loads(line)
        for line in (Path(final_dir) / f"{run}.jsonl").read_text().splitlines()
    ]
    by_set = {s: [] for s in SETS}
    for r in rows:
        by_set[r["set"].split("_")[0]].append(
            r
        )  # layout variants are named e.g. val_cache
    out = {}
    for s in SETS:
        recs = []
        for i, r in enumerate(by_set[s]):
            if s == "gt43":
                n = int(r["n"])
                if n in gt_skip:
                    continue
                exact = normalise(n, r["pred"]) == normalise(n, r["gold"])
            elif s == "val" and i not in val_unseen:
                continue
            else:
                exact = r["exact"]
            recs.append(
                {
                    "i": i,
                    "cluster": r["n"],
                    "command": r["command"],
                    "exact": float(exact),
                    "prompt_n": r["prompt_n"],
                    "predicted_n": r["predicted_n"],
                    "ms": r["ms"],
                }
            )
        out[s] = recs
    return out


def seed_mean(runs):
    """Average per-record scores over seed runs; records must align."""
    merged = {}
    for s in SETS:
        base = runs[0][s]
        for other in runs[1:]:
            assert [r["command"] for r in other[s]] == [r["command"] for r in base], (
                f"{s} misaligned"
            )
        merged[s] = [
            dict(
                r,
                exact=sum(run[s][k]["exact"] for run in runs) / len(runs),
                ms=sum(run[s][k]["ms"] for run in runs) / len(runs),
            )
            for k, r in enumerate(base)
        ]
    return merged


def rate(recs):
    return sum(r["exact"] for r in recs) / len(recs)


def compare(control, arm, rng):
    for s in SETS:
        assert [r["command"] for r in control[s]] == [r["command"] for r in arm[s]], (
            f"{s} misaligned"
        )
    clusters = {s: sorted({r["cluster"] for r in control[s]}) for s in SETS}
    index = {s: {} for s in SETS}
    for s in SETS:
        for k, r in enumerate(control[s]):
            index[s].setdefault(r["cluster"], []).append(k)
    point = {s: rate(arm[s]) - rate(control[s]) for s in SETS}
    boots = {s: [] for s in SETS + ["primary"]}
    for _ in range(B):
        prim = 0.0
        for s in SETS:
            ks = [
                k
                for c in (rng.choice(clusters[s]) for _ in clusters[s])
                for k in index[s][c]
            ]
            d = sum(arm[s][k]["exact"] - control[s][k]["exact"] for k in ks) / len(ks)
            boots[s].append(d)
            prim += d / len(PRIMARY) if s in PRIMARY else 0.0
        boots["primary"].append(prim)
    ci = {
        k: (sorted(v)[int(0.025 * B)], sorted(v)[int(0.975 * B)])
        for k, v in boots.items()
    }
    point["primary"] = sum(point[s] for s in PRIMARY) / len(PRIMARY)
    if (
        ci["primary"][0] > 0
        and all(ci[s][1] >= 0 for s in PRIMARY)
        and ci[GUARD][0] > GUARD_MARGIN
    ):
        verdict = "PROMOTED"
    elif ci["primary"][1] < 0 or point["primary"] <= 0:
        verdict = "REJECTED"
    else:
        verdict = "INCONCLUSIVE"
    return point, ci, verdict


def speed(m):
    allr = [r for s in SETS for r in m[s]]
    n = len(allr)
    return {
        "prompt_tokens": sum(r["prompt_n"] for r in allr) / n,
        "output_tokens": sum(r["predicted_n"] for r in allr) / n,
        "ms_b200": sum(r["ms"] for r in allr) / n,
    }


def demo():
    rng = random.Random(0)
    mk = lambda xs: {
        s: [
            {"cluster": str(i % 7), "command": str(i), "exact": float(x)}
            for i, x in enumerate(xs)
        ]
        for s in SETS
    }
    same = mk([1, 0] * 40)
    assert compare(same, same, rng)[2] == "REJECTED"  # zero delta never promotes
    better = mk([1] * 80)
    assert compare(same, better, rng)[2] == "PROMOTED"


if __name__ == "__main__":
    demo()
    final_dir, rules_path, train_path, val_path, spec = sys.argv[1:6]
    rules = json.loads(Path(rules_path).read_text())["ground_truth_43"]
    # n=16 "which pwd" leaked into the container data before the leak fix; n=8 and 9 (cat/more junk.txt)
    # need the file content, which the prompt never contains (no history, Changed lists only the name).
    gt_skip = {int(n) for n, r in rules.items() if r.get("grade") == "skip"} | {
        8,
        9,
        16,
    }
    train_cmds = {
        json.loads(line)["messages"][1]["content"]
        for line in Path(train_path).read_text().splitlines()
    }
    val_unseen = {
        i
        for i, line in enumerate(Path(val_path).read_text().splitlines())
        if json.loads(line)["messages"][1]["content"] not in train_cmds
    }
    rng = random.Random(20261016)
    # spec: "arm_name=runA,runB:control=runC,runD;..."
    for item in spec.split(";"):
        arm_part, ctrl_part = item.split(":")
        arm_name, arm_runs = arm_part.split("=")
        ctrl_name, ctrl_runs = ctrl_part.split("=")
        arm = seed_mean(
            [load_run(final_dir, r, gt_skip, val_unseen) for r in arm_runs.split(",")]
        )
        ctrl = seed_mean(
            [load_run(final_dir, r, gt_skip, val_unseen) for r in ctrl_runs.split(",")]
        )
        point, ci, verdict = compare(ctrl, arm, rng)
        row = {
            "arm": arm_name,
            "control": ctrl_name,
            "seeds": len(arm_runs.split(",")),
            "verdict": verdict,
            "primary_arm": sum(rate(arm[s]) for s in PRIMARY) / len(PRIMARY),
            "primary_control": sum(rate(ctrl[s]) for s in PRIMARY) / len(PRIMARY),
            "delta": {
                k: [round(point[k], 4), round(ci[k][0], 4), round(ci[k][1], 4)]
                for k in point
            },
            "per_set_arm": {s: round(rate(arm[s]), 4) for s in SETS},
            "speed_arm": speed(arm),
            "speed_control": speed(ctrl),
        }
        print(json.dumps(row))
