#!/usr/bin/env bash
#
# run_three_methods.sh - the three fine-tuning runs for the comparison, one after
# another, then their scores on the held-back records and one table.
#
#   lora    the baseline
#   qlora   the same adapter, trained on the base model loaded in 4-bit
#   dora    LoRA with direction and size trained apart
#
# The same data, seed and settings for all three; only --method differs. Each run
# gets its own folder; a method whose run has finished is skipped, so the script can be
# started again after an interruption: a half-finished run folder is moved aside to
# runs/<method>-unfinished-<time> (nothing is deleted) and that method starts again.
# A method that fails is reported and the next one runs (2026-10-14: overnight, one
# failure must not stop the others); the script then ends with an error.
#
# Run it on the PC, in the fine-tuning folder, with the virtual environment active and
# offline (docs/finetuning-on-the-5090.md, steps 1 to 7 done):
#
#   (venv) $ cd ~/ai/finetuning/honeypot
#   (venv) $ bash scripts/run_three_methods.sh data/20261014 2>&1 | tee three-methods.log
#
# The one argument is the data folder. It writes runs/<method>/, evals/<method>.json,
# evals/base.json if it is not there yet, and prints the table at the end. Nothing is
# uploaded anywhere.
#
# To try it first on 40 records (a few minutes, then delete runs/ and evals/ again):
#
#   (venv) $ TRY=1 bash scripts/run_three_methods.sh data/20261014
#
# Another base model and fewer methods (2026-10-14): MODEL is the base model's folder,
# TAG is added to every folder and report name so runs of two models never mix, and
# METHODS chooses the methods (default all three):
#
#   (venv) $ MODEL=models/qwen3-1.7b TAG=-q3 METHODS=lora bash scripts/run_three_methods.sh data/20261014

set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR

DATA=${1:?the data folder, e.g. data/20261014}
MODEL=${MODEL:-models/qwen2.5-3b-instruct}
HERE=$(cd "$(dirname "$0")" && pwd)
[ -f "$DATA/train.jsonl" ] && [ -f "$DATA/val.jsonl" ] || { echo "no train.jsonl / val.jsonl in $DATA"; exit 1; }
[ -d "$MODEL" ] || { echo "no base model in $MODEL (step 5 of the guide)"; exit 1; }
[ -n "${VIRTUAL_ENV:-}" ] || { echo "activate the virtual environment first: source venv/bin/activate"; exit 1; }
export HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1

EXTRA=()
SUFFIX="${TAG:-}"
METHODS=${METHODS:-lora qlora dora}
if [ -n "${TRY:-}" ]; then
    EXTRA=(--limit 40 --limit-val 10 --epochs 1 --eval-every 20)
    SUFFIX="${TAG:-}-try"
    echo "TRY: 40 records, one pass; folders end in -try"
fi
mkdir -p runs evals

if [ ! -f "evals/base$SUFFIX.json" ]; then
    echo "== the base model on the held-back records"
    python "$HERE/eval_heldback.py" --model "$MODEL" --data "$DATA" --out "evals/base$SUFFIX.json" \
        ${TRY:+--limit 10}
fi

finished() { [ -f "$1/log.jsonl" ] && grep -q '"done": true' "$1/log.jsonl"; }

FAILED=()
for METHOD in $METHODS; do
    RUN="runs/$METHOD$SUFFIX"
    if finished "$RUN"; then
        echo "== $METHOD: $RUN finished before, skipped"
    else
        if [ -e "$RUN" ]; then
            ASIDE="$RUN-unfinished-$(date '+%Y%m%d-%H%M%S')"
            echo "== $METHOD: $RUN did not finish; moved aside to $ASIDE"
            mv "$RUN" "$ASIDE"
            rm -f "evals/$METHOD$SUFFIX.json"
        fi
        echo "== $METHOD: training ($(date '+%F %T'))"
        if ! python "$HERE/train_lora.py" --method "$METHOD" --model "$MODEL" --data "$DATA" \
                --out "$RUN" "${EXTRA[@]}"; then
            echo "== $METHOD: FAILED ($(date '+%F %T')); going on with the next method"
            FAILED+=("$METHOD")
            continue
        fi
    fi
    if [ ! -f "evals/$METHOD$SUFFIX.json" ]; then
        echo "== $METHOD: the best checkpoint on the held-back records"
        if ! python "$HERE/eval_heldback.py" --model "$MODEL" --adapter "$RUN/best" --data "$DATA" \
                --out "evals/$METHOD$SUFFIX.json" ${TRY:+--limit 10}; then
            echo "== $METHOD: scoring FAILED"
            FAILED+=("$METHOD")
        fi
    fi
done

echo
echo "== the table ($(date '+%F %T'))"
REPORTS=("evals/base$SUFFIX.json")
for METHOD in $METHODS; do
    if [ -f "evals/$METHOD$SUFFIX.json" ]; then REPORTS+=("evals/$METHOD$SUFFIX.json"); fi
done
if [ ${#REPORTS[@]} -ge 2 ]; then python "$HERE/compare_evals.py" "${REPORTS[@]}"; fi
echo
echo "time, speed and graphics memory per method:"
for METHOD in $METHODS; do
    if finished "runs/$METHOD$SUFFIX"; then tail -1 "runs/$METHOD$SUFFIX/log.jsonl"; fi
done
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "FAILED: ${FAILED[*]}. Check the log; the others are complete."
    exit 1
fi
echo "done. Bring back: the log, evals/*.json and runs/*/log.jsonl."
