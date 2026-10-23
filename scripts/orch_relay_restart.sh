#!/usr/bin/env bash
#
# orch_relay_restart.sh - restart the relay on the Orchestrator (no code change, no sudo)
# so that a measurement starts from the machine as it was recorded: nobody had attacked
# it since boot. What lives only in the relay's memory is reset: the container state
# (back to the seed) and with it docker0's history. docker0 gets carrier with its first
# container and, like a real bridge, keeps its link-local address and counters after the
# container is gone (honeypot/net.py); the reference machine's recordings were taken on a
# boot where docker0 had never carried one. Found 2026-10-14: the quick check's API step
# (the recorded attack) ran before the 43, and `ifconfig` then failed on docker0.
# The install's identity, boot time and file state are in relay-state/ and stay.
#
# Refuses while somebody is logged in to the honeypot.
set -Eeuo pipefail
H=lab-orch
remote() { ssh -o BatchMode=yes "$H" "export XDG_RUNTIME_DIR=/run/user/\$(id -u); $1"; }
S=$(remote 'curl -s -m 5 http://127.0.0.1:8000/health' | python3 -c 'import json,sys; print(json.load(sys.stdin)["sessions"])')
[ "$S" = 0 ] || { echo "somebody is logged in to the honeypot ($S sessions); not restarted"; exit 1; }
remote 'systemctl --user restart honeypot-relay'
for _ in $(seq 1 20); do
    remote 'curl -s -m 2 http://127.0.0.1:8000/health' 2>/dev/null | grep -q '"ok": true' && { echo "relay restarted: $(remote 'curl -s -m 2 http://127.0.0.1:8000/health')"; exit 0; }
    sleep 1
done
echo "the relay did not come back within 20 s"; exit 1
