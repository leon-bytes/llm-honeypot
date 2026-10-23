#!/usr/bin/env python3
"""
build_scorer_identity.py - the identity file for the scorer (`eval_scorer.py --identity`).

The honeypot shows its own addresses, MACs and Docker IDs where the recordings show
Ground Truth's (R1, R3), so a correct answer differs from the recording in exactly those
values. The scorer rewrites the expected answer with this file before comparing, and
treats a Ground Truth value in a honeypot answer as a leak:

  {"substitutions": {"<Ground Truth's value>": "<the honeypot's value>", ...}}

It is the relay's own literal substitution map (identity.all_pairs), read off the
deployed relay, because the per-install IDs come from a secret kept on the Orchestrator
and the per-boot ones from its boot time. Only the resulting values leave the
Orchestrator, and they are what any login to the honeypot is shown; the secret stays
where it is. The command below only reads there (python3 -B: not even bytecode).

**One file per boot time the relay ran with.** A reboot gives new bridge and veth MACs,
endpoint, sandbox and default-bridge IDs, so rebuild it after one and score a run file
only with the identity file of the boot it was made in (`relay_boot` is in the file).

The boot time is the one the relay keeps in relay-state/boot.json (since 2026-10-06;
machine.pinned_boot_time). Before that the relay read /proc/stat at every start, and
the kernel's value moved with a clock correction: from 13:06:06 to 13:05:56 between
2026-10-05 and 2026-10-06, with no reboot, so the relay restarted that morning took new
per-boot values. For run files older than such a move, give the boot time the relay
had then with --boot (epoch seconds): the two run files of 2026-10-05 need
--boot 1790528766.

Not covered: dates. The relay also moves Ground Truth's setup day and boot-relative
times (identity.date_rewriters), which no fixed list of pairs can express. Among the 43
those only appear where the rules file masks timestamps anyway (n=30, 32).

  python3 tools/build_scorer_identity.py --label pre-freeze
  python3 eval_scorer.py --file RUN.json --identity res_relay_identity_pre-freeze_<date>.json

The file name starts with res_ like the run files it belongs with: generated, git-ignored.
"""
from __future__ import annotations
import argparse
import datetime
import json
import subprocess
import sys

# Runs on the Orchestrator, in ~/honeypot, against the deployed package.
REMOTE = r'''
import json, os
from honeypot import identity, machine
cfg_path = os.path.abspath("honeypot/config.json")
try:                    # a deploy with the site file (2026-10-16 on): values filled in
    from honeypot.site import SITE
    cfg = SITE.load_json(cfg_path)
except ImportError:     # an older deploy: the values are in its config
    cfg = json.load(open(cfg_path))
state = cfg.get("state_dir", "relay-state")
if not os.path.isabs(state):
    state = os.path.join(os.path.dirname(cfg_path), state)
# Read the secret directly: identity.secret() would make a new one if it were missing.
secret = json.load(open(os.path.join(state, "install.json")))["secret"]
boot = BOOT or machine.pinned_boot_time(state, write=False)
print(json.dumps({"boot": boot, "pairs": identity.all_pairs(
    cfg.get("substitutions", {}), state, boot, secret)}))
'''


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", default="lab-orch", help="SSH alias of the Orchestrator")
    ap.add_argument("--label", required=True, help="build label, e.g. pre-freeze or frozen")
    ap.add_argument("--boot", type=int, help="the boot time the relay ran with, in epoch "
                    "seconds, if not the Orchestrator's current one")
    ap.add_argument("--out", help="default: res_relay_identity_<label>_<date>.json")
    args = ap.parse_args()

    r = subprocess.run(["ssh", "-o", "BatchMode=yes", args.host, "cd ~/honeypot && python3 -B -"],
                       input=f"BOOT = {args.boot!r}\n" + REMOTE, capture_output=True,
                       text=True, timeout=60)
    if r.returncode:
        print(r.stderr, file=sys.stderr)
        return 1
    got = json.loads(r.stdout)
    pairs = got["pairs"]
    same = [k for k, v in pairs.items() if k == v]
    clash = sorted(set(pairs) & set(pairs.values()))
    if same or clash:
        print(f"refusing: unchanged values {same}, values that are also keys {clash}",
              file=sys.stderr)
        return 1
    boot = datetime.datetime.fromtimestamp(got["boot"]).astimezone()
    today = datetime.date.today().isoformat()
    out = args.out or f"res_relay_identity_{args.label}_{today}.json"
    doc = {
        "note": ("For eval_scorer.py --identity. Ground Truth's value -> the honeypot's own: "
                 "addresses and hardware MACs, per-boot network values, Docker IDs (each "
                 "64-character ID also in its 12-character short form). Valid for run files "
                 "made while the relay ran with the boot time below; rebuild after a reboot "
                 "with tools/build_scorer_identity.py. Dates the honeypot moves are not in "
                 "here."),
        "made": today,
        "build": args.label,
        "relay_boot": boot.strftime("%Y-%m-%d %H:%M:%S %z"),
        "relay_boot_epoch": int(got["boot"]),
        "relay_boot_source": "--boot" if args.boot else "the relay's stored boot time",
        "substitutions": dict(sorted(pairs.items(), key=lambda kv: (-len(kv[0]), kv[0]))),
    }
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"{out}: {len(pairs)} pairs, relay boot {doc['relay_boot']} ({doc['relay_boot_source']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
