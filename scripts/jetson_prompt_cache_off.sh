#!/usr/bin/env bash
#
# jetson_prompt_cache_off.sh - stop the model server from filling the Jetson's memory.
#
# The cause of the hangs of 2026-10-06 and 2026-10-08 (docs/jetson-stability.md):
# llama-server, which ollama runs, keeps a copy of every prompt's state in memory, up
# to a limit of 8192 MB - more than the board has. Each of the relay's prompts costs
# about 80 MB, and at about 4 GB (some 50 prompts) the Jetson is out of memory.
#
# Two changes to the ollama service, in a new file next to the existing override:
#   1  LLAMA_ARG_CACHE_RAM=0   llama-server's own switch for "no prompt cache"
#                              (its log says: use `--cache-ram 0` to disable it)
#   2  MemoryMax=3G            a safety net: if the service ever grows past 3 GB of
#                              ordinary memory, the kernel stops llama-server alone
#                              (ollama starts it again at the next request) instead of
#                              the whole board freezing
# Then ollama is restarted (the model reloads, about 30 s) and the script CHECKS in the
# log whether llama-server really started without the cache. If the setting did not
# reach it, the script says so and exits 1; the safety net is in place either way.
#
# Run it FROM FEDORA-DEV, once per Jetson, AFTER jetson_keep_logs.sh:
#
#   cd ~/projects/honeypot
#   scp scripts/jetson_prompt_cache_off.sh lab-j1:
#   ssh -t lab-j1 'sudo bash ~/jetson_prompt_cache_off.sh' 2>&1 | tee docs/jetson-cache-j1-$(date +%Y%m%d-%H%M).log
#
# Stops at the first error; can be run again. Undo: at the end of
# docs/jetson-stability.md.

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR

[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ "$(uname -m)" = aarch64 ] || { echo "this is not a Jetson"; exit 1; }
MODEL=qwen2.5:3b-instruct-q4_K_M
DROPIN=/etc/systemd/system/ollama.service.d/prompt-cache.conf
echo "== $(hostname), $(date)"

echo "== before"
grep -a "prompt cache is\|cache state" /var/log/syslog | tail -2 | cut -c1-170 || true
free -m | sed -n 1,2p

echo "== 1. the two settings"
mkdir -p /etc/systemd/system/ollama.service.d
cat > "$DROPIN" <<'CONF'
# Written by jetson_prompt_cache_off.sh (docs/jetson-stability.md).
[Service]
# llama-server's switch for its in-memory prompt cache: 0 MB = off. Its default limit
# is 8192 MB, more memory than this board has.
Environment="LLAMA_ARG_CACHE_RAM=0"
# Safety net: ordinary memory of the whole service, model weights on the GPU not
# counted. It normally uses about 0.6 GB.
MemoryMax=3G
MemorySwapMax=0
CONF
systemctl daemon-reload
echo "   MemoryMax now: $(systemctl show ollama -p MemoryMax --value)"

echo "== 2. restart ollama and load the model (about 30 s)"
MARK=$(date '+%F %T')
systemctl restart ollama
for _ in $(seq 1 30); do curl -s -m 2 http://127.0.0.1:11434/api/version >/dev/null && break; sleep 1; done
curl -s -m 120 http://127.0.0.1:11434/v1/chat/completions -H 'Content-Type: application/json' \
     -d "{\"model\": \"$MODEL\", \"max_tokens\": 1, \"messages\": [{\"role\": \"user\", \"content\": \"ok\"}]}" >/dev/null
sleep 2
ollama ps

echo "== 3. did llama-server start without the cache?"
LINE=$(journalctl -u ollama --since "$MARK" --no-pager | grep -a "prompt cache is" | tail -1 || true)
echo "   since $MARK: ${LINE:-no line about the prompt cache}"
if echo "$LINE" | grep -q "prompt cache is enabled"; then
    echo "   NOT applied: llama-server still has its prompt cache."
    echo "   ollama did not pass LLAMA_ARG_CACHE_RAM on. The safety net (MemoryMax=3G) IS in"
    echo "   place. The fallback is a small wrapper around llama-server."
    exit 1
fi
echo "   applied: no prompt cache."
free -m | sed -n 1,2p
echo "done."
