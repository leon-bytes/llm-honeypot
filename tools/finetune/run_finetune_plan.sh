#!/usr/bin/env bash
#
# run_finetune_plan.sh - the four fine-tuning runs of the plan of 14 October, in order,
# with one command:
#
#   1. Qwen2.5-3B, LoRA      (the baseline; the comparison of methods)
#   2. Qwen2.5-3B, QLoRA
#   3. Qwen2.5-3B, DoRA
#   4. Qwen3-1.7B, with the method that won 1 to 3 (the faster challenger)
#
# Each run is scored on the held-back records, and so is each base model. The winner of
# 1 to 3 is picked by the rule fixed in compare_evals.py (--winner) before any run:
# most exact answers on the corpus and debian records. WINNER=lora (or qlora, dora)
# overrides it, for example to start the challenger before DoRA has finished.
#
# Order matters: if time runs short, the first runs are the ones that count (LoRA and
# QLoRA on the 3B first, as decided). Stopped with Ctrl-C or by a power cut, the same
# line starts again where it was: finished runs are skipped, a half-finished one is
# moved aside and started again. A method that fails does not stop the others.
#
# Run it on the PC, in the fine-tuning folder, the virtual environment active
# (docs/finetuning-on-the-5090.md, steps 1 to 7 done):
#
#   (venv) $ bash scripts/run_finetune_plan.sh data/20261014 2>&1 | tee -a plan.log
#
# The whole chain on 40 records first (about 15 minutes; the first time QLoRA and
# Qwen3 run anywhere), then delete the trial:
#
#   (venv) $ TRY=1 bash scripts/run_finetune_plan.sh data/20261014
#   (venv) $ rm -r runs/*-try* evals/*-try.json
#
# Settings: BASE (default models/qwen2.5-3b-instruct), CHALLENGER (default
# models/qwen3-1.7b), WINNER (see above), BASE_METHODS (default "lora qlora dora";
# "lora qlora" leaves DoRA out when time is short: the challenger then gets the better
# of the two, and DoRA can follow later with the default). Nothing is uploaded anywhere.

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR

DATA=${1:?the data folder, e.g. data/20261014}
BASE=${BASE:-models/qwen2.5-3b-instruct}
CHALLENGER=${CHALLENGER:-models/qwen3-1.7b}
HERE=$(cd "$(dirname "$0")" && pwd)
S="${TRY:+-try}"
[ -d "$CHALLENGER" ] || { echo "no challenger model in $CHALLENGER (step 5 of the guide)"; exit 1; }

echo "=== plan started $(date '+%F %T')"
STATUS=0
BASE_METHODS=${BASE_METHODS:-lora qlora dora}
echo "=== 1-3: $BASE with $BASE_METHODS"
MODEL="$BASE" TAG= METHODS="$BASE_METHODS" bash "$HERE/run_three_methods.sh" "$DATA" || STATUS=1

if [ -z "${WINNER:-}" ]; then
    SCORED=()
    for M in lora qlora dora; do
        if [ -f "evals/$M$S.json" ]; then SCORED+=("evals/$M$S.json"); fi
    done
    [ ${#SCORED[@]} -gt 0 ] || { echo "no method of 1-3 was scored; nothing to pick from"; exit 1; }
    echo "=== the winner of 1-3 (the rule in compare_evals.py)"
    WINNER=$(python "$HERE/compare_evals.py" --winner "${SCORED[@]}")
    WINNER=${WINNER%"$S"}
fi
case "$WINNER" in lora|qlora|dora) ;; *) echo "WINNER must be lora, qlora or dora, not '$WINNER'"; exit 1;; esac

echo "=== 4: $CHALLENGER with $WINNER"
MODEL="$CHALLENGER" TAG=-q3 METHODS="$WINNER" bash "$HERE/run_three_methods.sh" "$DATA" || STATUS=1

echo
echo "=== all runs, one table ($(date '+%F %T'))"
REPORTS=()
for R in base lora qlora dora base-q3 "$WINNER-q3"; do
    if [ -f "evals/$R$S.json" ]; then REPORTS+=("evals/$R$S.json"); fi
done
if [ ${#REPORTS[@]} -ge 2 ]; then python "$HERE/compare_evals.py" "${REPORTS[@]}"; fi
if [ "$STATUS" -ne 0 ]; then
    echo "=== plan ended with a failure (see FAILED above); the finished runs are complete"
    exit 1
fi
echo "=== plan done $(date '+%F %T'). Bring back: plan.log, evals/*.json and runs/*/log.jsonl."
