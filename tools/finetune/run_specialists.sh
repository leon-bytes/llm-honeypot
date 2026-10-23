#!/usr/bin/env bash
#
# run_specialists.sh - the specialist experiment (the user, 2026-10-15): one fine-tune
# per kind of record (corpus, debian, code), each trained only on its own kind, against
# the generalists of the plan of 14 October, which were trained on all three. A paper
# result: does a model node that specializes do better than one that does everything?
#
# Same method (DoRA, the winner of 14 October) and the same settings as the generalists:
# train_lora.py's defaults, which the plan used (rank 16, alpha 32, dropout 0, lr 1e-4,
# three passes, 16 records per step, the same seed). Each specialist's best checkpoint is
# chosen on the held-back records of its own kind; then it is scored on ALL 169 held-back
# records (its own kind, and the others: what a failover to it would give).
#
# Order: the 1.7B first (about 2 h for its three), then the 3B (about 4.7 h). Stopped,
# the same line goes on where it was: finished runs are skipped, a half-finished one is
# moved aside and started again. A run that fails does not stop the others.
#
# On the PC, in the fine-tuning folder, the virtual environment active:
#
#   (venv) $ bash scripts/run_specialists.sh data/20261014 2>&1 | tee -a specialists.log
#
# Settings: MODELS (default "q3 3b"), SOURCES (default "corpus debian code"). TRY=1 runs
# the whole chain on 40 records first (folders and reports end in -try; delete them
# afterwards). Nothing is uploaded anywhere.
set -Eeuo pipefail
trap 'echo "STOPPED at line $LINENO: $BASH_COMMAND" >&2' ERR
DATA=${1:?the full data folder, e.g. data/20261014}
HERE=$(cd "$(dirname "$0")" && pwd)
MODELS=${MODELS:-q3 3b}
SOURCES=${SOURCES:-corpus debian code}
[ -f "$DATA/train.jsonl" ] && [ -f "$DATA/val.jsonl" ] || { echo "no train.jsonl / val.jsonl in $DATA"; exit 1; }
[ -n "${VIRTUAL_ENV:-}" ] || { echo "activate the virtual environment first: source venv/bin/activate"; exit 1; }
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1
EXTRA=(); EVAL_EXTRA=(); T=""
if [ -n "${TRY:-}" ]; then
    EXTRA=(--limit 40 --limit-val 10 --epochs 1 --eval-every 20); EVAL_EXTRA=(--limit 10); T="-try"
    echo "TRY: 40 records, one pass; folders end in -try"
fi
mkdir -p runs evals
finished() { [ -f "$1/log.jsonl" ] && grep -q '"done": true' "$1/log.jsonl"; }
echo "=== specialists started $(date '+%F %T')"
FAILED=()
for M in $MODELS; do
    case $M in
        q3) MODEL=models/qwen3-1.7b; TAG=-q3; GEN=evals/dora-q3.json ;;
        3b) MODEL=models/qwen2.5-3b-instruct; TAG=; GEN=evals/dora.json ;;
        *) echo "MODELS takes q3 and 3b, not '$M'"; exit 1 ;;
    esac
    [ -d "$MODEL" ] || { echo "no base model in $MODEL"; exit 1; }
    for SRC in $SOURCES; do
        SUB="$DATA-$SRC"
        python "$HERE/split_by_source.py" --data "$DATA" --source "$SRC" --out "$SUB"
        RUN="runs/spec-$SRC$TAG$T"
        REPORT="evals/spec-$SRC$TAG$T.json"
        if finished "$RUN"; then
            echo "== $SRC$TAG: $RUN finished before, skipped"
        else
            if [ -e "$RUN" ]; then
                ASIDE="$RUN-unfinished-$(date '+%Y%m%d-%H%M%S')"
                echo "== $SRC$TAG: $RUN did not finish; moved aside to $ASIDE"
                mv "$RUN" "$ASIDE"; rm -f "$REPORT"
            fi
            echo "== $SRC$TAG: training on $SUB ($(date '+%F %T'))"
            if ! python "$HERE/train_lora.py" --method dora --model "$MODEL" --data "$SUB" \
                    --out "$RUN" "${EXTRA[@]}"; then
                echo "== $SRC$TAG: FAILED ($(date '+%F %T')); going on"; FAILED+=("$SRC$TAG"); continue
            fi
        fi
        if [ ! -f "$REPORT" ]; then
            echo "== $SRC$TAG: its best checkpoint on all held-back records"
            if ! python "$HERE/eval_heldback.py" --model "$MODEL" --adapter "$RUN/best" --data "$DATA" \
                    --out "$REPORT" "${EVAL_EXTRA[@]}"; then
                echo "== $SRC$TAG: scoring FAILED"; FAILED+=("$SRC$TAG")
            fi
        fi
    done
    SPECS=()
    for SRC in corpus debian code; do [ -f "evals/spec-$SRC$TAG$T.json" ] && SPECS+=("evals/spec-$SRC$TAG$T.json"); done
    if [ -z "$T" ] && [ -f "$GEN" ] && [ ${#SPECS[@]} -eq 3 ]; then
        echo "=== $M: the specialists against the generalist (the rule in compare_evals.py)"
        python "$HERE/compare_evals.py" --specialists "$GEN" "${SPECS[@]}" || true
    fi
done
echo
echo "time, speed and graphics memory per run:"
for M in $MODELS; do
    TAG=; [ "$M" = q3 ] && TAG=-q3
    for SRC in $SOURCES; do finished "runs/spec-$SRC$TAG$T" && tail -1 "runs/spec-$SRC$TAG$T/log.jsonl"; done
done
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "FAILED: ${FAILED[*]}. Check the log; the others are complete."; exit 1
fi
echo "=== specialists done $(date '+%F %T'). Bring back: specialists.log, evals/spec-*.json and runs/spec-*/log.jsonl."
