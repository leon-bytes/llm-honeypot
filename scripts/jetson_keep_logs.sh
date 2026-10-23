#!/usr/bin/env bash
#
# jetson_keep_logs.sh - make a Jetson leave evidence when it hangs or reboots.
#
# Changes nothing about ollama or the model. Three things, all about logs:
#   1  the system journal is kept on disk (today it lives in memory and is lost at
#      every reboot), with a size cap, and written out every 10 s instead of every 5 min
#   2  a small service writes one line every 5 s: free memory, swap, the hottest
#      temperature, llama-server's memory, the load - and forces that line onto the
#      disk at once, so the last line before a hang survives
#   3  that file is rotated weekly
# It also shows whether the kernel left a crash record from an earlier crash (pstore).
#
# Run it FROM FEDORA-DEV, once per Jetson (example for Jetson 1):
#
#   cd ~/projects/honeypot
#   scp scripts/jetson_keep_logs.sh lab-j1:
#   ssh -t lab-j1 'sudo bash ~/jetson_keep_logs.sh' 2>&1 | tee docs/jetson-logs-j1-$(date +%Y%m%d-%H%M).log
#
# It stops at the first error (set -e) and can be run again: every step checks whether
# it is already done. Undo: at the end of docs/jetson-stability.md.

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ "$(uname -m)" = aarch64 ] || { echo "this is not a Jetson (uname -m: $(uname -m))"; exit 1; }
echo "== $(hostname), $(date)"

echo "== 0. did the kernel leave a crash record? (read-only)"
if ls /sys/fs/pstore/* >/dev/null 2>&1; then
    ls -la /sys/fs/pstore
    echo "   -> there are records. Copy them before the next reboot: sudo cp -a /sys/fs/pstore ~/pstore-$(date +%Y%m%d)"
else
    echo "   none in /sys/fs/pstore"
fi
find /var/lib/systemd/pstore -mindepth 1 2>/dev/null | head -20 || true

echo "== 1. the journal on disk"
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/keep.conf <<'CONF'
# Written by jetson_keep_logs.sh: keep the journal across reboots, at most 500 MB,
# and write it to disk every 10 s (the default is 5 minutes), so that a hang loses
# seconds of log, not minutes.
[Journal]
Storage=persistent
SystemMaxUse=500M
SyncIntervalSec=10s
CONF
systemctl restart systemd-journald
journalctl --flush
echo "   journal on disk: $(journalctl --disk-usage | sed 's/.*take up //')"

echo "== 2. one line of health every 5 s, forced onto the disk"
cat > /usr/local/sbin/jetson-health.sh <<'SH'
#!/bin/sh
# Written by jetson_keep_logs.sh. One line every 5 s into /var/log/jetson-health.log:
# memory still available, free swap, the hottest temperature, llama-server's own
# memory, the load. `sync FILE` forces the line onto the disk, so the last line before
# a hang is still there afterwards.
LOG=/var/log/jetson-health.log
while :; do
    mem=$(awk '/^MemAvailable|^MemFree|^SwapFree/ {printf "%s%dMB ", $1, $2/1024}' /proc/meminfo)
    hot=$(cat /sys/devices/virtual/thermal/thermal_zone*/temp 2>/dev/null | sort -n | tail -1)
    rss=$(ps -C llama-server -o rss= 2>/dev/null | awk '{s+=$1} END {printf "%d", s/1024}')
    echo "$(date '+%F %T') ${mem}hottest=$(( ${hot:-0} / 1000 ))C llama_server=${rss:-0}MB load=$(cut -d' ' -f1 /proc/loadavg)" >> "$LOG"
    sync "$LOG"
    sleep 5
done
SH
chmod 755 /usr/local/sbin/jetson-health.sh
cat > /etc/systemd/system/jetson-health.service <<'UNIT'
[Unit]
Description=One line of memory and temperature every 5 s, kept on disk (jetson_keep_logs.sh)

[Service]
ExecStart=/usr/local/sbin/jetson-health.sh
Restart=always
RestartSec=5
Nice=10

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now jetson-health.service
sleep 7
echo "   last line: $(tail -1 /var/log/jetson-health.log)"

echo "== 3. rotate that file weekly, keep 8 weeks"
cat > /etc/logrotate.d/jetson-health <<'ROT'
/var/log/jetson-health.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
ROT

echo "== summary (read-only)"
echo "   journal kept on disk : $([ -d /var/log/journal ] && echo yes || echo NO)"
echo "   boots in the journal : $(journalctl --list-boots --no-pager | wc -l) (grows by one at every reboot from now on)"
echo "   health service       : $(systemctl is-active jetson-health.service), starts at boot: $(systemctl is-enabled jetson-health.service)"
echo "   syslog and kern.log  : already kept by rsyslog ($(systemctl is-active rsyslog)); they are where the cause of 2026-10-08 was found"
echo "done. Nothing about ollama was changed."
