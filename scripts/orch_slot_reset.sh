#!/usr/bin/env bash
#
# orch_slot_reset.sh - put the honeypot back to the machine as recorded, between two
# class teams. The Orchestrator is OURS, not the reference machine, so this needs no
# special OK (it is the ordinary relay restart plus clearing the attacker-visible state).
# No sudo.
#
#   scripts/orch_slot_reset.sh            # reset; refuses while anyone is logged in
#   scripts/orch_slot_reset.sh --keep-log # keep relay-logs/relay.jsonl (default: archive it)
#
# What a team leaves in the honeypot, and what this clears:
#   - containers, images, networks, volumes a team made through the shell or the API,
#     and docker0's carrier/link-local history: all in the relay's MEMORY, so a restart
#     alone resets them to the seed (honeypot/docker.py builds DockerState from the seed
#     at start; scripts/orch_relay_restart.sh).
#   - files and directories a team created or removed: relay-state/files.json. Removed,
#     so the next team sees the machine's own files and nothing of the last team's.
#   - the "Last login" line: relay-state/last_login.json. Removed, so the first login
#     shows the recorded initial value again (config initial_last_login).
#   - the previous team's command log: relay-logs/relay.jsonl, archived (team-only data)
#     unless --keep-log.
#   - live SSH sessions and their shell state: the relay restart drops every in-memory
#     session, and the reset refuses to run while anyone is still connected.
# What is KEPT (removing it would move the machine's identity, which an attacker can see):
#   - relay-state/boot.json (the pinned boot time) and relay-state/install.json (the
#     install secret): the addresses, MACs, container IDs and setup dates are seeded from
#     these. Delete them and every per-boot value changes. Never delete them between
#     slots.
#
# Testing and timing wait until the user is back on the lab network.
set -Eeuo pipefail
H=lab-orch
KEEP_LOG=0
[ "${1:-}" = --keep-log ] && KEEP_LOG=1
remote() { ssh -o BatchMode=yes "$H" "export XDG_RUNTIME_DIR=/run/user/\$(id -u); $1"; }

S=$(remote 'curl -s -m 5 http://127.0.0.1:8000/health' | python3 -c 'import json,sys; print(json.load(sys.stdin)["sessions"])')
[ "$S" = 0 ] || { echo "somebody is logged in to the honeypot ($S sessions); not reset"; exit 1; }

# 1. stop the relay so nothing rewrites the state files while we remove them
remote 'systemctl --user stop honeypot-relay'

# 2. clear the attacker-visible state; KEEP boot.json and install.json
remote 'cd ~/honeypot/relay-state && rm -f files.json last_login.json && ls -1'
if [ "$KEEP_LOG" = 0 ]; then
    remote 'cd ~/honeypot/relay-logs 2>/dev/null && [ -f relay.jsonl ] && mv relay.jsonl "relay.jsonl.slot-$(date +%Y%m%d-%H%M%S)" || true'
fi

# 3. start the relay (re-seeds the Docker state and the sessions) and wait for health
remote 'systemctl --user start honeypot-relay'
for _ in $(seq 1 20); do
    remote 'curl -s -m 2 http://127.0.0.1:8000/health' 2>/dev/null | grep -q '"ok": true' && break
    sleep 1
done

echo "health: $(remote 'curl -s -m 3 http://127.0.0.1:8000/health')"
echo "state now: $(remote 'ls -1 ~/honeypot/relay-state')"
echo "reset done. Check: a fresh SSH login shows the recorded 'Last login' line, docker ps"
echo "shows the three iot-stack containers, and /root has no leftover files."
echo
echo "Cowrie itself is not restarted: it is a system service (sudo), and the relay"
echo "restart above already drops every session. If you want a clean Cowrie too, run"
echo "on the Orchestrator:  sudo systemctl restart cowrie"
