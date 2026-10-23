# Laya's eval harness (Llama 3.2 1B fine-tunes)

Self-contained; nothing here imports from or changes the rest of the repo.

| File | What it does |
|---|---|
| `big_test.py` | Scores one GGUF served by `llama-server` on the test sets (`/completion`, HF chat template, greedy, `n_predict` 2048). Writes one JSONL row per record: `set, n, command, gold, pred, exact, similarity, prompt_n, predicted_n, ms`. A server error counts as a miss and is flagged `server_error`. |
| `gt_score.py` | Normalisation for the 43 ground-truth commands: masks the honeypot's own IPv4/IPv6/MAC and the per-test volatile fields (sizes, PIDs, timestamps). Used for exact match on gt43. |
| `gate.py` | Promotion gate for comparing two training arms. Per-record exact match averaged over seeds, paired cluster bootstrap (clusters = `meta.n`, 4,000 resamples) within each test set. |
| `leak_audit.py` | Checks added training files against the 169 held-back records and gt43: exact command, exact (command, reply), and 3+ shared consecutive answer lines. All inputs are chat-format JSONL (`{"messages": [system, user, assistant]}`), gt43 included. |

## Gate rule (epoch 2)
- Primary metric: mean exact rate over val (only commands unseen in training), test2 (held-out programs) and gt43.
- test3 (held-out sessions from our own session generator) is a guard only: an arm may not lose more than 3 points there.
- PROMOTED: primary CI lower bound > 0, no primary set's CI upper bound < 0, guard holds. REJECTED: CI upper bound < 0 or point delta <= 0. Otherwise INCONCLUSIVE.
- gt43 ungraded: the `skip` items in `eval_not_gradable.json`, plus n=16 (leaked into an early data build) and n=8/9 (they need file content the prompt never contains).

```
python gate.py <bench dir> eval_not_gradable.json train.jsonl val.jsonl "arm=runA,runA_s2:control=runC,runC_s2"
```

Differences from `eval_scorer.py`: this is strict exact match after normalisation (no set, semantic or tolerant tiers), and it compares arms statistically rather than scoring one model. We'll also report results with `eval_scorer.py` and `tools/finetune/eval_heldback.py` so the numbers line up with yours.
