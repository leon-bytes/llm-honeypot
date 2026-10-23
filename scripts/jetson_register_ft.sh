#!/usr/bin/env bash
#
# jetson_register_ft.sh - register the fine-tuned Qwen3 1.7B (honeypot-ft-1p7b) on one
# Jetson, the way it was done on Jetsons 1 and 4 (docs/finetune-next-steps-2026-10-15.md).
# No sudo. Loads nothing: the served model and the relay are untouched, and nothing is
# generated. `ollama rm honeypot-ft-1p7b` on the board undoes it.
#
#   scripts/jetson_register_ft.sh lab-j2
#
#   1  copies offline/finetune-models/honeypot-ft-1p7b-q4_K_M.gguf to ~/ft/ on the board
#      (skipped if it is there with the right checksum) and checks the checksum there
#   2  writes ~/ft/Modelfile-1p7b (Qwen3's chat format ending in an empty reasoning
#      block, as in training; the guide's step 14) and `ollama create`s the model
#   3  checks that ollama's ID is the one on Jetsons 1 and 4 (f2e462db45e7)
# Then, from the dev machine: tools/measure_node_model.py --node lab-jN --model
# honeypot-ft-1p7b --check-only (169 of 169 prompts as in training; loads the model for a
# moment, so not while a measurement runs).

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR
NODE=${1:?usage: jetson_register_ft.sh lab-jN}
cd "$(dirname "$0")/.."
GGUF=offline/finetune-models/honeypot-ft-1p7b-q4_K_M.gguf
NAME=honeypot-ft-1p7b
WANT_ID=f2e462db45e7
SUM=$(sha256sum "$GGUF" | cut -d' ' -f1)
echo "== $NODE: $(date '+%F %T'), file $SUM"

echo "== 1. the file"
ssh "$NODE" 'mkdir -p ~/ft && df -h ~ | tail -1'
if [ "$(ssh "$NODE" "sha256sum ~/ft/$(basename "$GGUF") 2>/dev/null | cut -d' ' -f1")" != "$SUM" ]; then
    scp -q "$GGUF" "$NODE:ft/"
fi
[ "$(ssh "$NODE" "sha256sum ~/ft/$(basename "$GGUF") | cut -d' ' -f1")" = "$SUM" ] \
    || { echo "checksum differs on $NODE"; exit 1; }
echo "   checksum fine on the board"

echo "== 2. Modelfile and ollama create"
ssh "$NODE" "cat > ~/ft/Modelfile-1p7b" <<EOF
FROM /home/user/ft/$(basename "$GGUF")
TEMPLATE """{{- range .Messages }}<|im_start|>{{ .Role }}
{{ .Content }}<|im_end|>
{{ end }}<|im_start|>assistant
<think>

</think>

"""
PARAMETER stop <|im_end|>
PARAMETER stop <|im_start|>
EOF
ssh "$NODE" "ollama create $NAME -f ~/ft/Modelfile-1p7b 2>&1 | tail -2"

echo "== 3. the ID"
ID=$(ssh "$NODE" "ollama list | awk '\$1 ~ /^$NAME/ {print \$2}'")
echo "   $NAME: $ID"
[ "$ID" = "$WANT_ID" ] || { echo "ID differs from Jetsons 1 and 4 ($WANT_ID)"; exit 1; }
ssh "$NODE" 'ollama ps'
echo "done: $NAME registered on $NODE (not loaded, not served)."
