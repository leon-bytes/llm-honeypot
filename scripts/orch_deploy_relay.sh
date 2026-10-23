#!/usr/bin/env bash
#
# orch_deploy_relay.sh - put the relay code of this checkout on the Orchestrator and
# restart the relay. No sudo.
#
#   scripts/orch_deploy_relay.sh            # deploy and restart
#   scripts/orch_deploy_relay.sh --check    # only show what differs; changes nothing
#
# What it does, in order:
#   1  refuses if the working tree has uncommitted changes under honeypot/ (what runs
#      there should be a commit), and runs the tests that take a second
#   2  copies honeypot/ (code, config, seed), the corpus, the rules file and the site
#      values (site.local.json: the relay refuses to start without them) with rsync;
#      relay-state/ (boot time, install secret, file state, last login) and relay-logs/
#      on the Orchestrator are never touched, so addresses, MACs and IDs stay the same
#   3  restarts the relay: through its service if scripts/orch_relay_service.sh has been
#      run, by hand otherwise (the previous relay.out is kept as relay.out.before-<time>)
#   4  checks /health, both listeners and that the install's identity did not move
#
# The relay is down for about a second. Do not run it during a measurement run or
# while a student is on the honeypot.

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")/.."
H=lab-orch
remote() { ssh -o BatchMode=yes "$H" "export XDG_RUNTIME_DIR=/run/user/\$(id -u); $1"; }

if [ "${1:-}" = --check ]; then
    rsync -an --delete --itemize-changes --exclude __pycache__ honeypot/ "$H":honeypot/honeypot/
    rsync -an --itemize-changes corpus284_lab_2026-09.json eval_not_gradable.json site.local.json "$H":honeypot/
    exit 0
fi

if [ -n "$(git status --porcelain -- honeypot/)" ]; then
    echo "uncommitted changes under honeypot/: commit first, so that what runs is a commit"
    git status --short -- honeypot/
    exit 1
fi
COMMIT=$(git rev-parse --short HEAD)
python3 -m py_compile honeypot/*.py
python3 -c "import json; json.load(open('honeypot/config.json')); json.load(open('honeypot/docker_seed.json'))"

echo "== identity before"
BEFORE=$(remote 'curl -s -m 5 http://127.0.0.1:2375/networks' | python3 -c "import sys,json,hashlib; print(hashlib.sha256(json.dumps(sorted(n['Id'] for n in json.load(sys.stdin))).encode()).hexdigest()[:16])" || echo none)
echo "   network ids: $BEFORE"

echo "== copy ($COMMIT)"
rsync -a --delete --exclude __pycache__ honeypot/ "$H":honeypot/honeypot/
[ -f site.local.json ] || { echo "no site.local.json: the relay would refuse to start"; exit 1; }
rsync -a corpus284_lab_2026-09.json eval_not_gradable.json site.local.json "$H":honeypot/

echo "== restart"
if remote 'systemctl --user is-enabled -q honeypot-relay 2>/dev/null'; then
    remote 'systemctl --user restart honeypot-relay'
else
    remote 'cd ~/honeypot
        for p in $(pgrep -f "^python3 -m honeypot.relay"); do kill $p; done
        for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f "^python3 -m honeypot.relay" >/dev/null || break; sleep 0.5; done
        [ -f relay.out ] && mv relay.out relay.out.before-$(date +%Y%m%d-%H%M%S)
        (setsid nohup python3 -m honeypot.relay --config honeypot/config.json > relay.out 2>&1 < /dev/null &)'
fi
for _ in $(seq 1 20); do remote 'curl -s -m 2 http://127.0.0.1:8000/health' 2>/dev/null | grep -q '"ok": true' && break; sleep 1; done

echo "== check"
remote "echo $COMMIT > ~/honeypot/DEPLOYED; pgrep -af '^python3 -m honeypot.relay'; curl -s -m 3 http://127.0.0.1:8000/health; echo; ss -tln | grep -E ':8000 |:2375 '; tail -2 ~/honeypot/relay.out"
AFTER=$(remote 'curl -s -m 5 http://127.0.0.1:2375/networks' | python3 -c "import sys,json,hashlib; print(hashlib.sha256(json.dumps(sorted(n['Id'] for n in json.load(sys.stdin))).encode()).hexdigest()[:16])")
echo "   network ids: $AFTER"
if [ "$BEFORE" != none ] && [ "$BEFORE" != "$AFTER" ]; then
    echo "THE INSTALL'S IDENTITY MOVED (network ids differ): look at relay-state/ before anything else"
    exit 1
fi
echo "deployed $COMMIT."
