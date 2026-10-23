#!/usr/bin/env bash
#
# jetson_fan_cool.sh - let the Jetson's fan run harder, so the board stays cooler under
# sustained load. It changes nothing about how fast the board computes.
#
# Why (docs/jetson-stability.md, "13 October, what the evidence says"): Jetson 1 froze
# under answers without pauses while its hottest sensor sat at 69 to 70 C and the
# kernel's "hot surface" notice (its 70 C mark) flipped on and off 102 times in the
# last three and a half minutes. The crash record of Jetson 4 on 8 October ends inside
# the same notices. The runs that stayed under about 62 C all survived. And at 69 C
# the fan was running at about two thirds: NVIDIA ships two fan tables, "quiet" (the
# default, in use here) and "cool", and "quiet" does not reach full speed before 95 C.
#
#   quiet:  35 C off, rising to 73% at 74 C, full at 95 C
#   cool :  35 C off, rising to full at 70 C
#
# So "cool" gives about half as much again of the fan at any temperature. It is louder
# and nothing else. Whether heat is the CAUSE of the freeze is not proven; this removes
# the one condition every freeze had in common without making an answer slower.
#
# What it does: sets FAN_DEFAULT_PROFILE to cool in /etc/nvfancontrol.conf (a copy of
# the file is kept next to it), removes the fan service's saved state, which would
# otherwise bring "quiet" back, and restarts the fan service. The model keeps running;
# no reboot. It then shows the profile in use and the fan's speed.
#
# Run it FROM FEDORA-DEV, once per Jetson:
#
#   cd ~/projects/honeypot
#   scp scripts/jetson_fan_cool.sh lab-j1:
#   ssh -t lab-j1 'sudo bash ~/jetson_fan_cool.sh' 2>&1 | tee docs/jetson-fan-j1-$(date +%Y%m%d-%H%M).log
#
# Stops at the first error; can be run again. Undo: `sudo bash ~/jetson_fan_cool.sh quiet`.

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ "$(uname -m)" = aarch64 ] || { echo "this is not a Jetson"; exit 1; }
WANT=${1:-cool}
case "$WANT" in cool|quiet) ;; *) echo "usage: $0 [cool|quiet]"; exit 1 ;; esac
CONF=/etc/nvfancontrol.conf
echo "== $(hostname), $(date)"
grep -q "FAN_PROFILE $WANT {" "$CONF" || { echo "$CONF has no profile '$WANT'; nothing changed"; exit 1; }

# Both helpers end with success on purpose: some sensors cannot be read and not every
# hwmon folder has an rpm file, and with `set -E` a failing last command inside $(...)
# printed a harmless "STOPPED at line ..." (seen on all four boards, 2026-10-14).
hot() { local t; t=$( { cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null || true; } | sort -n | tail -1); echo $(( ${t:-0} / 1000 )); }
fan() { for h in /sys/class/hwmon/hwmon*; do
            if [ -e "$h/pwm1" ]; then printf 'pwm %s of 255' "$(cat "$h/pwm1")"; fi
            if [ -e "$h/rpm" ]; then printf ', %s rpm' "$(cat "$h/rpm")"; fi
        done; true; }

echo "== before"
grep FAN_DEFAULT_PROFILE "$CONF"
echo "   hottest sensor $(hot) C, fan $(fan)"

echo "== 1. the default profile"
if grep -q "^\s*FAN_DEFAULT_PROFILE $WANT\s*$" "$CONF"; then
    echo "   already $WANT in $CONF"
else
    cp -n "$CONF" "$CONF.before-fan-change"
    sed -i -E "s/^(\s*FAN_DEFAULT_PROFILE)\s+\S+/\1 $WANT/" "$CONF"
    echo "   set (the file as it was: $CONF.before-fan-change)"
fi

echo "== 2. restart the fan service without its saved state"
systemctl stop nvfancontrol
rm -f /var/lib/nvfancontrol/status
systemctl start nvfancontrol
sleep 6

echo "== after"
systemctl is-active nvfancontrol
cat /var/lib/nvfancontrol/status 2>/dev/null | sed 's/^/   /' || true
nvfancontrol -q 2>/dev/null | sed 's/^/   /' || true
echo "   hottest sensor $(hot) C, fan $(fan)"
if nvfancontrol -q 2>/dev/null | grep -q "FAN_PROFILE:$WANT\|FAN_PROFILE: *$WANT" \
        || grep -q "$WANT" /var/lib/nvfancontrol/status 2>/dev/null; then
    echo "done: the fan follows the '$WANT' table."
else
    echo "NOT CONFIRMED: the fan service does not report '$WANT'. Keep the lines above for diagnosis."
    exit 1
fi
