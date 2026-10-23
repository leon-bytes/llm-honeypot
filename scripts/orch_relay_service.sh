#!/usr/bin/env bash
#
# orch_relay_service.sh - turn the hand-started relay on the Orchestrator into a
# service that comes back after a reboot. No sudo: it is a service of the user `pi`.
#
# The one thing that does need sudo, ONCE, before this script:
#
#   ssh -t lab-orch 'sudo loginctl enable-linger pi'
#
# ("lingering": pi's services start at boot and keep running when nobody is logged
# in. Without it the relay would stop when the last SSH session of pi closes, so this
# script refuses to switch over until it is on.)
#
# Then, FROM FEDORA-DEV:
#
#   cd ~/projects/honeypot
#   scripts/orch_relay_service.sh            # install, switch over, check
#   scripts/orch_relay_service.sh status     # read-only
#
# What it does: copies deploy/systemd/honeypot-relay.service to
# ~/.config/systemd/user/ on the Orchestrator, stops the relay that was started by
# hand, enables and starts the service, and checks /health and both listeners. The
# relay's state (relay-state/, boot.json included) is not touched, so addresses and
# IDs stay what they are.
#
# Afterwards a deploy is: rsync, then
#   ssh lab-orch 'systemctl --user restart honeypot-relay'
# Back to a hand start: ssh lab-orch 'systemctl --user disable --now honeypot-relay'

set -Eeuo pipefail
cd "$(dirname "$0")/.."
H=lab-orch
remote() { ssh -o BatchMode=yes "$H" "export XDG_RUNTIME_DIR=/run/user/\$(id -u); $1"; }

if [ "${1:-}" = status ]; then
    remote 'loginctl show-user pi -p Linger; systemctl --user is-enabled honeypot-relay 2>&1; systemctl --user is-active honeypot-relay 2>&1; pgrep -af "^python3 -m honeypot.relay" || echo "no relay process"; curl -s -m 3 http://127.0.0.1:8000/health; echo'
    exit 0
fi

LINGER=$(remote 'loginctl show-user pi -p Linger --value')
if [ "$LINGER" != yes ]; then
    echo "Lingering is off for pi, so the service would stop when the last SSH session closes."
    echo "Run this once, then this script again:"
    echo "    ssh -t lab-orch 'sudo loginctl enable-linger pi'"
    exit 1
fi

echo "== install the unit"
remote 'mkdir -p ~/.config/systemd/user'
scp -q deploy/systemd/honeypot-relay.service "$H":.config/systemd/user/honeypot-relay.service
remote 'systemctl --user daemon-reload'

echo "== stop the hand-started relay, start the service"
# One remote command, so the gap without a relay is as short as possible.
remote 'if ! systemctl --user is-active -q honeypot-relay; then
            pids=$(pgrep -f "^python3 -m honeypot.relay" || true)
            [ -z "$pids" ] || kill $pids
            for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f "^python3 -m honeypot.relay" >/dev/null || break; sleep 0.5; done
        fi
        systemctl --user enable -q honeypot-relay
        systemctl --user restart honeypot-relay'

echo "== check"
for _ in $(seq 1 20); do remote 'curl -s -m 2 http://127.0.0.1:8000/health' 2>/dev/null | grep -q '"ok": true' && break; sleep 1; done
remote 'systemctl --user is-active honeypot-relay; pgrep -af "^python3 -m honeypot.relay"; curl -s -m 3 http://127.0.0.1:8000/health; echo; ss -tln | grep -E ":8000 |:2375 "; tail -2 ~/honeypot/relay.out'
echo "done. After the next reboot of the Orchestrator the relay starts by itself."
