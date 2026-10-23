#!/usr/bin/env python3
"""side_build_compare.py - latency side builds against their same-night baseline (the
latency plan of 2026-10-22): the 43 (core passed per mode), the generated answers' times
in the runs of the 43, and the leave-one-out `none` run (corpus commands the model
answers, recordings shown): byte-exact count and times. Reads the run files only; uses
the harness's own scoring (tools/eval_harness.py), writes nothing into paper/.

  .venv/bin/python tools/side_build_compare.py build-1022-base build-1022-k3 build-1022-fast \\
      --out res_side_builds_2026-10-22.json
"""
from __future__ import annotations
import argparse
import json
import pathlib
import statistics
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import eval_harness as H  # noqa: E402


def summary(label: str) -> dict:
    t = H.the43(label)
    core = {}
    for mode in ("normal", "model-only"):
        core[mode] = [H.group_counts(r["rows"])["CORE"] for r in t.get(mode, [])]
    g = H.generated_times(label)
    out = {"label": label, "commit": H.build_commit(label), "core": core,
           "generated_43": {k: g[k] for k in g if k != "ms"}}
    files = [f for f in H.newest(f"res_loo_none_{label}*.json")]
    if files:
        ident = H.newest(f"res_relay_identity_{label}*.json")
        subs = H.substituter(ident[-1] if ident else None)
        rows = json.load(open(files[-1]))
        model = [e for e in rows if e.get("tier") != "code"]
        ms = [e["elapsed_ms"] for e in model if e.get("elapsed_ms") is not None]
        exact = sum(H.measures(subs(e["real"]), e["model"])["byte_exact"] for e in rows)
        out["loo_none"] = {"file": pathlib.Path(files[-1]).name, "n": len(rows),
                           "model_n": len(model), "byte_exact": exact,
                           "median": statistics.median(ms) if ms else None,
                           "p90": H.quantile(ms, 0.90) if ms else None,
                           "over5_pct": H.pct(sum(x > 5000 for x in ms), len(ms)) if ms else None,
                           "cut": sum(x >= 24900 for x in ms)}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("labels", nargs="+")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = [summary(lb) for lb in a.labels]
    for r in res:
        g, lo = r["generated_43"], r.get("loo_none") or {}
        print(f"{r['label']} ({r['commit']}): core normal {r['core']['normal']} "
              f"model-only {r['core']['model-only']}")
        if g.get("n"):
            print(f"   the 43, generated n={g['n']}: median {g['median']:.0f} ms, p90 {g['p90']:.0f} ms, "
                  f">5 s {g['over5_pct']:.0f}%, cut {g['cut']}")
        if lo:
            print(f"   leave-one-out none: {lo['byte_exact']}/{lo['n']} byte-exact; model n={lo['model_n']} "
                  f"median {lo['median']:.0f} ms, p90 {lo['p90']:.0f} ms, >5 s {lo['over5_pct']:.0f}%, "
                  f"cut {lo['cut']}")
    if a.out:
        json.dump(res, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
