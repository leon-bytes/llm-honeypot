#!/usr/bin/env bash
#
# honeypot_rehearsal.sh - record the honeypot with the tools that recorded the
# reference machine, and compare. The class in miniature, from the dev machine.
#
#   scripts/honeypot_rehearsal.sh             # Cowrie on port 2222 (the lab test port)
#   scripts/honeypot_rehearsal.sh --port 22   # after the move to the class port
#
# It connects ONLY to the honeypot (the Orchestrator), through the jump host. The address is
# the honeypot's own from site.local.json, on purpose: there is no option to point it at
# the reference machine.
#
# It asks once for the root password (the honeypot accepts the reference machine's).
# The password goes to the tools in an environment variable of this one process: never
# on a command line, never into a file or a log.
#
# What it does, into rehearsal-<date-time>/ (git-ignored):
#   0  restarts the relay (scripts/orch_relay_restart.sh), so that a measurement run
#      before (its replay of the recorded attack) leaves no traces on docker0
#   1  before login: version string, algorithm lists, login methods    -> frontdoor.json
#   2  the login text and the first prompt, byte for byte               (same file)
#   3  the 43 test commands through Cowrie, one fresh login each         -> cap43.json
#      scored with the scorer against the reference recording            -> scores/
#   4  the emulated API against the three API recordings, and the shell
#      against the API during the recorded attack                        -> res_apicompare_*.json
#   5  a summary of all four                                             -> SUMMARY.txt
#
# Steps 1 to 3 were tried on 2026-10-13 against a Cowrie and a relay running on
# the dev machine with a made-up password (no model there, so the generated answers were the
# fallback), again that night with the Cowrie export of the evening; step 4 has run
# against the Orchestrator. The whole script in one go, against the real honeypot, is
# what your first run is.
#
# To put a rehearsal's numbers into the paper (only one recorded on the build the
# paper's other numbers come from): tools/eval_harness.py --label <label> --rehearsal <folder> If a step stops, the others' output is
# still in the folder; keep SUMMARY.txt and the last lines shown.
#
# Step 3 takes about ten minutes: there are 8 seconds between commands, because the
# model nodes must not be sent answers back to back (docs/jetson-stability.md). It
# records with `--end prompt`: the honeypot is sent each test command exactly as a
# student would type it, not with the recording tool's end marker glued on, which would
# put a different line in front of the model than the one being tested.
#
# Needs: Cowrie listening on the Orchestrator (docs/orchestrator-services.md, step 4 or 7),
# the relay running, and no measurement run going on (it makes about 60 logins).

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")/.."

# the Orchestrator (hp_ipv4 in site.local.json). Not an option.
HONEYPOT=$(python3 -c 'import sys; sys.path.insert(0, "."); from honeypot.site import SITE; print(SITE.hp_ipv4)')
PORT=2222
[ "${1:-}" = --port ] && PORT=${2:?--port needs a number}
PY=.venv/bin/python
OUT=rehearsal-$(date +%Y%m%d-%H%M)
mkdir -p "$OUT/scores"
LABEL=rehearsal-$(date +%Y%m%d)

read -rsp "Root password of the honeypot (not shown): " HONEYPOT_PW; echo
export HONEYPOT_PW
[ -n "$HONEYPOT_PW" ] || { echo "empty; nothing done"; exit 1; }

echo "== 0. a fresh relay start (the machine as recorded: not attacked since boot)"
scripts/orch_relay_restart.sh
# The class build (config class_show_withheld, 2026-10-15) is rehearsed at the freeze, but
# never for the paper: the folder is marked, and eval_harness.py --rehearsal refuses it.
if ! ssh -o BatchMode=yes lab-orch 'curl -s -m 5 http://127.0.0.1:8000/health' | $PY -c 'import json,sys; sys.exit(1 if json.load(sys.stdin).get("withheld_shown") else 0)'; then
    echo "   the relay is the CLASS BUILD (withheld examples shown): this rehearsal is a check, not for the paper"
    echo "recorded on the class build (class_show_withheld); not for the paper" > "$OUT/CLASS-BUILD"
fi

echo "== 1 and 2. the front door (port $PORT)"
$PY tools/capture_frontdoor.py --host "$HONEYPOT" --port "$PORT" --user root --jump lab-dev2 \
    --password-env HONEYPOT_PW --part both --banner-only --out "$OUT/frontdoor.json" --force
$PY - "$OUT/frontdoor.json" <<'PYEOF' | tee "$OUT/frontdoor.txt"
import json, re, sys
# the newest recording of the reference machine's front door: gt_frontdoor_2026-10.json
# once its sshd has been restricted and recorded again (docs/ssh-front-door-decision.md)
import glob
REAL = sorted(glob.glob("gt_frontdoor_20*.json"))[-1]
print(f"compared with         {REAL}")
real, ours = json.load(open(REAL)), json.load(open(sys.argv[1]))
rp, op = real["preauth"], ours["preauth"]
print(f"version string        {'same' if rp['ident'] == op['ident'] else 'DIFFERENT: ' + op['ident']}")
for k, want in rp["server_kexinit"].items():
    got = op["server_kexinit"].get(k, [])
    missing, extra = [a for a in want if a not in got], [a for a in got if a not in want]
    order = [a for a in want if a in got] == [a for a in got if a in want]
    state = "same" if got == want else f"offers {len(got)} of {len(want)}"
    print(f"{k:22}{state}" + (f"; missing {missing}" if missing else "") + (f"; EXTRA {extra}" if extra else "")
          + ("" if order else "; ORDER DIFFERS"))
print(f"login methods         {'same' if rp['auth_methods'] == op['auth_methods'] else 'DIFFERENT: ' + str(op['auth_methods'])}")
print(f"negotiated            real {rp['negotiated']['algorithm']} / {rp['negotiated']['server->client']['cipher']}; "
      f"honeypot {op['negotiated']['algorithm']} / {op['negotiated']['server->client']['cipher']}")
norm = lambda t: re.sub(r"Last login: .*? from [0-9.]+", "Last login: <when> from <where>", t)
a, b = norm(real["login"]["banner_text"]), norm(ours["login"]["banner_text"])
print(f"login text and prompt {'same bytes (the Last login values aside)' if a == b else 'DIFFERENT'}")
if a != b:
    i = next((k for k, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    print(f"   {len(a)} bytes on the reference machine, {len(b)} on the honeypot; the first difference is at byte {i}")
    print("   real    :", repr(a[max(i - 40, 0):i + 40]))
    print("   honeypot:", repr(b[max(i - 40, 0):i + 40]))
    if b.startswith(a) and b[len(a):] == "\x1b[4h":
        print("   (only the front end's ESC[4h after the first prompt: known, docs/cowrie-review-2026-10-13-evening.md)")
PYEOF

echo "== 3. the 43 through Cowrie"
$PY capture_session_v3.py --host "$HONEYPOT" --port "$PORT" --user root --jump lab-dev2 \
    --password-env HONEYPOT_PW --commands ground_truth_43.json --out "$OUT/cap43.json" \
    --end prompt --pause 8 --timeout 40
# The 43 leave junk.txt, junk and junkdir in /root, and the honeypot's file state is
# machine-wide and kept: one more login removes them, as the reference machine's captures
# did (found 2026-10-14: the next measurement's `mkdir junkdir` said "File exists").
echo '[{"n": 1, "command": "rm -rf /root/junk.txt /root/junk /root/junkdir"}, {"n": 2, "command": "ls /root"}]' > "$OUT/tidy-commands.json"
$PY capture_session_v3.py --host "$HONEYPOT" --port "$PORT" --user root --jump lab-dev2 \
    --password-env HONEYPOT_PW --commands "$OUT/tidy-commands.json" --out "$OUT/tidy.json" \
    --end prompt --pause 8 --timeout 40 >/dev/null
echo "   tidied; /root now: $($PY -c 'import json,sys; print(json.load(open(sys.argv[1]))[1]["output"].replace(chr(10), " "))' "$OUT/tidy.json")"
unset HONEYPOT_PW
$PY tools/build_scorer_identity.py --label "$LABEL" --out "$OUT/identity.json"
$PY - "$OUT" <<'PYEOF'
import json, sys
out = sys.argv[1]
real = {e["n"]: e for e in json.load(open("gt43_lab_2026-09.json"))}
run = [dict(n=e["n"], command=e["command"], real=real[e["n"]]["output"], model=e["output"],
            real_exit_code=real[e["n"]]["exit_code"], model_exit_code=e.get("exit_code"),
            elapsed_ms=e.get("elapsed_ms"), real_elapsed_ms=real[e["n"]].get("elapsed_ms"),
            tier="through-cowrie", answer_mode="normal", build="rehearsal")
       for e in json.load(open(f"{out}/cap43.json"))]
json.dump(run, open(f"{out}/run43.json", "w"), indent=1)
PYEOF
python3 eval_scorer.py --file "$OUT/run43.json" --identity "$OUT/identity.json" --out "$OUT/scores" \
    | tee "$OUT/score.txt"
if [ "$PORT" != 22 ]; then
    # Through the test port, env and env | sort rightly show that port in SSH_CONNECTION
    # and SSH_CLIENT, where the reference machine shows 22; that is the rehearsal's port,
    # not the honeypot (found 2026-10-14: 15/27 here against 17/27 through the relay).
    # Scored a second time with only that field written as 22, labeled as such.
    scripts/rehearsal_port22.py "$OUT/run43.json" "$PORT" "$OUT/run43_port22.json"
    python3 eval_scorer.py --file "$OUT/run43_port22.json" --identity "$OUT/identity.json" \
        --out "$OUT/scores-port22" > "$OUT/score-port22.txt"
fi

echo "== 4. the API, and the shell against the API"
$PY tools/measure_deployed_api.py --label "$LABEL" --identity "$OUT/identity.json" | tee "$OUT/api.txt"
mv "res_apicompare_$LABEL.json" res_api_phase?_"$LABEL".json "$OUT"/ 2>/dev/null || true

echo "== 5. summary"
{
    echo "Rehearsal of $(date '+%F %T'), honeypot $HONEYPOT port $PORT, relay commit $(ssh -o BatchMode=yes lab-orch 'cat ~/honeypot/DEPLOYED 2>/dev/null' || echo '?')"
    [ -e "$OUT/CLASS-BUILD" ] && echo "CLASS BUILD: the withheld corpus examples are shown to the model; a check, not for the paper"
    echo
    echo "-- front door"; cat "$OUT/frontdoor.txt"
    echo
    echo "-- the 43 through Cowrie"; grep -E "HEADLINE|stateful group|skip group|exit code|latency" "$OUT/score.txt" || true
    if [ -f "$OUT/score-port22.txt" ]; then
        echo "   the same with the server port in SSH_CONNECTION/SSH_CLIENT written as 22 (the class port; env, env | sort):"
        grep -E "HEADLINE" "$OUT/score-port22.txt" | sed 's/^/   /' || true
    fi
    $PY - "$OUT/cap43.json" <<'PYEOF'
import json, sys
cap = json.load(open(sys.argv[1]))
print(f"   no prompt came back (exit -1): {sum(e['exit_code'] == -1 for e in cap)} of {len(cap)}; "
      f"fallback answers (Segmentation fault): {sum(e['output'] == 'Segmentation fault' for e in cap)}")
PYEOF
    echo
    echo "-- API and cross-surface"; tail -6 "$OUT/api.txt"
} > "$OUT/SUMMARY.txt"
cat "$OUT/SUMMARY.txt"
echo
echo "everything is in $OUT/ (team-only: it holds answers with the recordings' content)"
