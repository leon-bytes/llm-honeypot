#!/usr/bin/env bash
#
# measure_build.sh - everything that can be measured on the deployed honeypot WITHOUT
# the root password, in one go, paced. For the night of the final measurement.
#
#   scripts/measure_build.sh <label>            the whole set (about five hours)
#   scripts/measure_build.sh <label> --quick    identity, API, the 43 once in each mode
#                                               (about 25 minutes): a check after a deploy
#   scripts/measure_build.sh <label> --resume   go on after an interruption: a step whose
#                                               output file exists is not run again
#   scripts/measure_build.sh <label> --no-loo   all of it but the leave-one-out runs (for a
#                                               build serving a fine-tuned model, 2026-10-18)
#
# <label> names the build in every file it writes, e.g. build-1016. One label, one
# deployed commit: it refuses to go on if the Orchestrator's commit changes on the way.
#
# What it does, in order (res_* files in the project folder, git-ignored):
#   0  checks: both the relay and at least one model node answer, nobody is logged in
#   0b restarts the relay (scripts/orch_relay_restart.sh): the machine as recorded
#   1  the identity file (this build's addresses and IDs for the scorer)
#   3  the 43 test commands, normal mode and model-only mode, twice each; and once with
#      the code scope of 14 October off (the ablation; not with --quick)
#   4  the corpus commands the model answers, three ways: recording shown, own
#      recording hidden, strict                              (the long part)
#   2  the emulated API against the three API recordings, and the shell against the
#      API during the recorded attack (three requests reach the model). Run after 3 and 4 since
#      2026-10-14: the attack leaves traces on docker0, as on a real machine
#   5  the relay's log lines of this run, for the response times
#   6  the harness: figures and numbers for the paper
#
# NOT measured here, because it needs the root password or hands on hardware (the
# user): the rehearsal through the front end (scripts/honeypot_rehearsal.sh), the
# front door of the reference machine, and the load test without pauses.
#
# Pacing: 15 s after every generated answer, the pace the model nodes are known to
# survive (docs/jetson-stability.md). Before each step that uses the model it looks at
# the nodes; if none is up it stops instead of hammering a dead one.

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")/.."

LABEL=${1:?usage: scripts/measure_build.sh <label> [--quick] [--resume] [--no-loo]}
QUICK=0; RESUME=0; NOLOO=0
for a in "${@:2}"; do
    case $a in --quick) QUICK=1 ;; --resume) RESUME=1 ;; --no-loo) NOLOO=1 ;; *) echo "unknown option $a"; exit 1 ;; esac
done
PY=.venv/bin/python
PAUSE=15
DATE=$(date +%F)
SOCK=$HOME/.orch-measure.sock
LOG=res_measure_${LABEL}.log
NOTE=res_build_${LABEL}.txt

say() { echo "[$(date +%T)] $*" | tee -a "$LOG"; }
# the serving Jetsons, by number, from the relay's config (Jetson N is nodeN_ipv4 in site.local.json)
nodes() { $PY -c 'import sys; sys.path.insert(0, "."); from honeypot.site import SITE as S; n = {S["node%d_ipv4" % i]: str(i) for i in range(1, 5)}; print(" ".join(n[b["base_url"].split("//")[1].split(":")[0]] for b in S.load_json("honeypot/config.json")["backends"]))'; }
commit() { ssh -o BatchMode=yes lab-orch 'cat ~/honeypot/DEPLOYED'; }
health() { curl -s -m 5 http://127.0.0.1:18000/health; }
nodes_up() { health | $PY -c 'import json,sys; print(sum(b["up"] for b in json.load(sys.stdin)["backends"]))'; }
close_tunnel() { ssh -S "$SOCK" -O exit lab-orch 2>/dev/null || true; }
trap close_tunnel EXIT

if [ -e "$NOTE" ] && [ $RESUME = 0 ]; then
    echo "$NOTE exists: the label $LABEL was used before. Pick a new label, or add --resume."; exit 1
fi
ssh -o ExitOnForwardFailure=yes -M -S "$SOCK" -f -N -L 18000:127.0.0.1:8000 lab-orch
COMMIT=$(commit)
if [ -e "$NOTE" ]; then
    [ "$(sed -n 's/^commit //p' "$NOTE")" = "$COMMIT" ] || { echo "the Orchestrator now runs $COMMIT, not the commit this label was started on. New label."; exit 1; }
else
    { echo "label $LABEL"; echo "commit $COMMIT"; echo "started $(date '+%F %T')"; } > "$NOTE"
fi
START=$(sed -n 's/^started //p' "$NOTE")

say "== 0. checks: build $LABEL = commit $COMMIT"
H=$(health); say "   $H"
[ "$(echo "$H" | $PY -c 'import json,sys; print(json.load(sys.stdin)["sessions"])')" = 0 ] || { say "somebody is logged in to the honeypot; not started"; exit 1; }
[ "$(nodes_up)" -ge 1 ] || { say "no model node is up; not started"; exit 1; }
[ "$(echo "$H" | $PY -c 'import json,sys; print(json.load(sys.stdin).get("withheld_shown", False))')" = False ] || { say "the relay is the class build (class_show_withheld): not measured for the paper"; exit 1; }
# The ablation run of the 43 needs the answer mode scope_off (since 2026-10-15); a relay
# that does not list it is older than the build this script is for.
[ $QUICK = 1 ] || echo "$H" | $PY -c 'import json,sys; sys.exit(0 if "scope_off" in json.load(sys.stdin).get("modes", []) else 1)' \
    || { say "the deployed relay does not know the answer mode scope_off: deploy the build first; not started"; exit 1; }
for j in $(nodes); do say "   jetson$j: $(ssh -o BatchMode=yes -o ConnectTimeout=6 lab-j$j 'tail -1 /var/log/jetson-health.log' 2>/dev/null || echo 'no answer')"; done

step() {            # step <output file pattern> <description> <command...>
    local out=$1 what=$2; shift 2
    if [ $RESUME = 1 ] && compgen -G "$out" >/dev/null; then say "   have $what already ($out)"; return 0; fi
    [ "$(commit)" = "$COMMIT" ] || { say "the deployed commit changed during the run; stopping"; exit 1; }
    say "   $what"
    "$@" >> "$LOG" 2>&1
}
model_step() {
    [ "$(nodes_up)" -ge 1 ] || { say "no model node is up before: $2. Stopping; what was measured so far is kept."; exit 1; }
    step "$@"
    for j in $(nodes); do say "      jetson$j: $(ssh -o BatchMode=yes -o ConnectTimeout=6 lab-j$j 'tail -1 /var/log/jetson-health.log' 2>/dev/null | cut -d' ' -f2,5,6 || true)"; done
}

say "== 0b. a fresh relay start (the machine as recorded: not attacked since boot)"
scripts/orch_relay_restart.sh 2>&1 | tee -a "$LOG"

say "== 1. identity"
step "res_relay_identity_${LABEL}_*.json" "identity file" $PY tools/build_scorer_identity.py --label "$LABEL"
IDENT=$(ls res_relay_identity_${LABEL}_*.json | tail -1)

say "== 3. the 43"
RUNS="r1 r2"; [ $QUICK = 1 ] && RUNS="r1"
for r in $RUNS; do
    model_step "res_relay_43_normal_${LABEL}-${r}_*.json" "the 43, normal mode, run $r" \
        $PY tools/run43_for_scorer.py --mode normal --label "$LABEL-$r" --pause $PAUSE
    model_step "res_relay_43_model-only_${LABEL}-${r}_*.json" "the 43, model-only mode, run $r" \
        $PY tools/run43_for_scorer.py --mode model_only --label "$LABEL-$r" --pause $PAUSE
done
if [ $QUICK = 0 ]; then
    # The ablation (the user, 2026-10-15): once, the 43 with the categories moved to code
    # on 14 October handed back to the model, for these sessions only (honeypot.mode
    # "scope_off"; the deployed config is not touched). With the two modes above the
    # paper shows code scope on / off / model-only.
    model_step "res_relay_43_scope-off_${LABEL}-r1_*.json" "the 43, code scope of 14 October off, run r1" \
        $PY tools/run43_for_scorer.py --mode scope_off --label "$LABEL-r1" --pause $PAUSE
fi

if [ $QUICK = 0 ] && [ $NOLOO = 1 ]; then
    say "== 4. leave-one-out: not run (--no-loo; a fine-tuned model was trained on most of the corpus)"
elif [ $QUICK = 0 ]; then
    say "== 4. the corpus commands the model answers (three variants; the long part)"
    for v in none own strict; do
        model_step "res_loo_${v}_${LABEL}_*.json" "leave-one-out, variant $v" \
            $PY tools/run_leave_one_out.py --variant "$v" --label "$LABEL" --pause $PAUSE
    done
fi

# Last of the measurements: it replays the recorded attack, which starts a container on
# the default bridge, and docker0 keeps the traces of that (as on a real machine). Every
# shell answer above is measured before it, as the reference was recorded.
# Three of its requests reach a model node since 2026-10-15 (the output of commands run
# inside a container: two execs and the new container's log); the tool paces them.
say "== 2. the API and the shell against the API (after the shell, see above)"
model_step "res_apicompare_${LABEL}.json" "API comparison" $PY tools/measure_deployed_api.py --label "$LABEL" --identity "$IDENT"

say "== 5. the relay's log of this run"
ssh -o BatchMode=yes lab-orch 'cat ~/honeypot/relay-logs/relay.jsonl' \
    | $PY -c 'import sys, json
start = sys.argv[1].replace(" ", "T")
for line in sys.stdin:
    try:
        if json.loads(line)["ts"][:19] >= start: sys.stdout.write(line)
    except Exception: pass' "$START" > "res_relaylog_${LABEL}.jsonl"
say "   $(wc -l < "res_relaylog_${LABEL}.jsonl") lines since $START"

if [ $QUICK = 0 ]; then
    say "== 6. the harness"
    if [ $NOLOO = 1 ]; then
        # not the paper's own build: its numbers go beside the paper's build
        # (eval_harness.py --label <paper build> --ft-label <this>), so only a look here
        $PY tools/eval_harness.py --label "$LABEL" --scratch "res_harness_${LABEL}" 2>&1 | tee -a "$LOG" | tail -12
    else
        $PY tools/eval_harness.py --label "$LABEL" 2>&1 | tee -a "$LOG" | tail -12
    fi
fi
{ echo "finished $(date '+%F %T')"; } >> "$NOTE"
say "done: $LABEL (commit $COMMIT). Log: $LOG"
