#!/usr/bin/env python3
"""Fine-tune the honeypot's language model on the relay's own prompts (LoRA, QLoRA, DoRA).

Input: train.jsonl and val.jsonl from tools/build_training_data.py. Each line is one
chat: the relay's system prompt, the command the attacker typed, and the answer the
machine gives. The model learns only the answer: the prompt is masked out of the loss.

What it writes into --out:
  log.jsonl              one line per evaluation: step, training loss, held-back loss
  checkpoint-<step>/     the LoRA adapter at that step (a few tens of MB each)
  best/                  a copy of the checkpoint with the lowest held-back loss
  run.json               every setting of this run, and the data's manifest

Three methods, one switch (--method), everything else the same for all three (data,
seed, rank, learning rate, schedule), so that their results can be compared:

  lora    the baseline: small added matrices on every linear layer, base model frozen in
          16-bit precision
  qlora   the same adapter, trained on the base model loaded in 4-bit (NF4, double
          quantisation, bitsandbytes). The weights take about a third of the memory,
          but peft's 4-bit preparation makes the activations 32-bit, so on long records
          a run takes more memory than LoRA (measured on the 5090, 2026-10-14). The
          adapter that comes out is an ordinary LoRA adapter: it is evaluated and merged
          on the FULL-precision base (eval_heldback.py and merge_adapter.py do that),
          never on the 4-bit one. Needs a CUDA card.
  dora    LoRA with the weight split into a direction and a size, both trained
          (`use_dora` in peft). Somewhat slower per step; merges like LoRA.

Memory (on the RTX 5090, 2026-10-14): without help the 3B fits records of about 1,650
to 1,870 tokens with QLoRA and DoRA, the 1.7B about 3,146; the longest records have
5,500 tokens, more than the 32 GB card holds.
So a record longer than the current limit is run with gradient checkpointing (its
activations recomputed in the backward pass: slower, a fraction of the memory), and
every other record runs at full speed. The limit starts at --checkpoint-above; when a
record runs out of memory anyway, its share of the gradient is undone, it is run again
checkpointed, and the limit drops below its length for the rest of the run. Records
are never skipped or cut for memory. --grad-checkpoint checkpoints every record.

Nothing is sent anywhere: no experiment tracker, no telemetry. With HF_HUB_OFFLINE=1
set, it also refuses to touch the network for the model.

Step by step, with every flag explained: docs/finetuning-on-the-5090.md.

Run (the real thing; see the doc for the dry run first):
  python train_lora.py --method lora --model ~/ai/finetuning/honeypot/models/qwen2.5-3b-instruct \
      --data ~/ai/finetuning/honeypot/data/20261013 --out ~/ai/finetuning/honeypot/runs/lora
"""
from __future__ import annotations
import argparse
import json
import math
import os
import pathlib
import random
import shutil
import sys
import time

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("WANDB_DISABLED", "true")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import torch                                                    # noqa: E402
from peft import LoraConfig, get_peft_model                     # noqa: E402
from transformers import AutoModelForCausalLM, AutoTokenizer    # noqa: E402

# The linear layers of every transformer block in Qwen2.5 (attention and MLP).
LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


def load_jsonl(path: pathlib.Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def encode(tok, record: dict, max_tokens: int):
    """(input ids, labels) for one chat, or None if it does not fit. The prompt is the
    chat template up to and including the assistant header, exactly what the model is
    given at inference; the labels are -100 there, so only the answer and the
    end-of-turn token are learned. An empty answer is just the end-of-turn token: the
    command prints nothing."""
    msgs = record["messages"]
    # enable_thinking=False: a Qwen3 base answers without a reasoning block, as it must
    # on the Jetsons (its template then ends the prompt with an empty one); a template
    # that has no such switch (Qwen2.5) ignores it.
    prompt = tok.apply_chat_template(
        msgs[:-1], tokenize=False, add_generation_prompt=True, enable_thinking=False)
    answer = msgs[-1]["content"] + tok.eos_token
    p = tok(prompt, add_special_tokens=False)["input_ids"]
    a = tok(answer, add_special_tokens=False)["input_ids"]
    if len(p) + len(a) > max_tokens:
        return None
    return p + a, [-100] * len(p) + a


@torch.no_grad()
def heldback_loss(model, items, device) -> float:
    """Mean loss per answer token over the held-back records."""
    model.eval()
    total, tokens = 0.0, 0
    for ids, labels in items:
        x = torch.tensor([ids], device=device)
        y = torch.tensor([labels], device=device)
        n = sum(1 for t in labels if t != -100)
        total += model(input_ids=x, labels=y).loss.item() * n
        tokens += n
    model.train()
    return total / max(tokens, 1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--method", choices=["lora", "qlora", "dora"], default="lora",
                    help="lora (baseline), qlora (base model in 4-bit), dora (direction and size)")
    ap.add_argument("--model", required=True, help="folder of the base model (or its name on the hub)")
    ap.add_argument("--data", required=True, help="folder with train.jsonl and val.jsonl")
    ap.add_argument("--out", required=True, help="folder for checkpoints and the log (must not exist)")
    ap.add_argument("--epochs", type=float, default=3.0, help="passes over the training data")
    ap.add_argument("--lr", type=float, default=1e-4, help="peak learning rate")
    ap.add_argument("--rank", type=int, default=16, help="LoRA rank: the size of what is trained")
    ap.add_argument("--alpha", type=int, default=32, help="LoRA scaling, usually twice the rank")
    ap.add_argument("--dropout", type=float, default=0.0,
                    help="LoRA dropout; 0 (2026-10-14): a third less memory, and DoRA's fast path")
    ap.add_argument("--accumulate", type=int, default=16,
                    help="records per optimiser step (one record is in memory at a time)")
    ap.add_argument("--max-tokens", type=int, default=8192,
                    help="longest chat kept; the relay's context window is 8192")
    ap.add_argument("--eval-every", type=int, default=1000,
                    help="evaluate and save a checkpoint every N records")
    ap.add_argument("--limit", type=int, help="use only the first N training records (dry run)")
    ap.add_argument("--limit-val", type=int, help="use only the first N held-back records")
    ap.add_argument("--seed", type=int, default=20261008)
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    ap.add_argument("--grad-checkpoint", action="store_true",
                    help="checkpoint every record: slowest, least memory")
    ap.add_argument("--checkpoint-above", type=int, default=0,
                    help="checkpoint records longer than this many tokens from the start "
                         "(0: none until one runs out of memory; the limit then learns)")
    args = ap.parse_args()

    out = pathlib.Path(args.out).expanduser()
    if out.exists():
        sys.exit(f"{out} exists already: every run gets a folder of its own")
    data = pathlib.Path(args.data).expanduser()
    model_path = str(pathlib.Path(args.model).expanduser()) if os.path.exists(
        os.path.expanduser(args.model)) else args.model
    random.seed(args.seed)
    torch.manual_seed(args.seed)

    tok = AutoTokenizer.from_pretrained(model_path)
    train_records = load_jsonl(data / "train.jsonl")[:args.limit]
    val_records = load_jsonl(data / "val.jsonl")[:args.limit_val]
    train = [e for e in (encode(tok, r, args.max_tokens) for r in train_records) if e]
    val = [e for e in (encode(tok, r, args.max_tokens) for r in val_records) if e]
    skipped = len(train_records) - len(train), len(val_records) - len(val)
    n_tok = sum(len(ids) for ids, _ in train)
    print(f"training records: {len(train)} ({skipped[0]} too long, left out), "
          f"{n_tok / 1e6:.2f} M tokens per epoch, longest {max(len(i) for i, _ in train)}; "
          f"held back: {len(val)} ({skipped[1]} too long)")
    # For the time projection of a dry run (--limit): the tokens of the whole data set.
    full_tok = n_tok
    if args.limit:
        full_tok = 0
        for r in load_jsonl(data / "train.jsonl"):
            e = encode(tok, r, args.max_tokens)
            full_tok += len(e[0]) if e else 0

    dtype = torch.bfloat16 if args.device.startswith("cuda") else torch.float32
    if args.method == "qlora":
        # The base model in 4-bit: NF4 with double quantisation, computing in 16-bit,
        # the settings of the QLoRA paper. bitsandbytes does this on a CUDA card only.
        if not args.device.startswith("cuda"):
            sys.exit("--method qlora needs a CUDA graphics card (bitsandbytes 4-bit loading)")
        from peft import prepare_model_for_kbit_training
        from transformers import BitsAndBytesConfig
        model = AutoModelForCausalLM.from_pretrained(
            model_path, device_map={"": args.device},
            quantization_config=BitsAndBytesConfig(
                load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
                bnb_4bit_compute_dtype=torch.bfloat16))
        # Casts the layer norms to 32-bit and lets gradients pass the frozen 4-bit layers.
        # Checkpointing is switched per record below, not here.
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=False)
    else:
        model = AutoModelForCausalLM.from_pretrained(model_path, dtype=dtype)
        model.to(args.device)
    # Gradient checkpointing is set up once and then switched per record (layers_ckpt).
    # Non-reentrant: needs no input that requires a gradient, and works with frozen layers.
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    layers_ckpt = [m for m in model.modules() if getattr(m, "gradient_checkpointing", False)]
    if not layers_ckpt:
        sys.exit("this model has no layers that can be checkpointed; the memory guard needs them")
    model.config.use_cache = False
    model = get_peft_model(model, LoraConfig(
        r=args.rank, lora_alpha=args.alpha, lora_dropout=args.dropout, bias="none",
        task_type="CAUSAL_LM", target_modules=LORA_TARGETS,
        use_dora=args.method == "dora"))
    model.print_trainable_parameters()
    model.train()

    steps_total = math.ceil(len(train) * args.epochs / args.accumulate)
    warmup = max(1, round(steps_total * 0.03))
    opt = torch.optim.AdamW((p for p in model.parameters() if p.requires_grad),
                            lr=args.lr, weight_decay=0.0)

    def lr_at(step: int) -> float:              # linear warm-up, then a cosine down to 0
        if step < warmup:
            return args.lr * (step + 1) / warmup
        done = (step - warmup) / max(steps_total - warmup, 1)
        return args.lr * 0.5 * (1 + math.cos(math.pi * min(done, 1.0)))

    out.mkdir(parents=True)
    manifest = data / "manifest.json"
    (out / "run.json").write_text(json.dumps({
        "method": args.method, "args": vars(args), "torch": torch.__version__,
        "gpu": torch.cuda.get_device_name(0) if args.device.startswith("cuda") else None,
        "records": {"train": len(train), "val": len(val), "too_long": skipped},
        "data_manifest": json.loads(manifest.read_text()) if manifest.exists() else None,
    }, indent=1, default=str) + "\n")

    def evaluate(seen: int, step: int, train_loss: float, started: float, best: list) -> None:
        loss = heldback_loss(model, val, args.device)
        ckpt = out / f"checkpoint-{seen}"
        model.save_pretrained(ckpt)
        entry = {"records_seen": seen, "optimizer_step": step,
                 "epoch": round(seen / len(train), 3), "train_loss": round(train_loss, 4),
                 "heldback_loss": round(loss, 4), "minutes": round((time.time() - started) / 60, 1),
                 "checkpointed": mem["checkpointed"], "out_of_memory": mem["out_of_memory"]}
        with open(out / "log.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")
        mark = ""
        if loss < best[0]:
            best[0] = loss
            shutil.rmtree(out / "best", ignore_errors=True)
            shutil.copytree(ckpt, out / "best")
            mark = "  <- best so far, copied to best/"
        print(json.dumps(entry) + mark, flush=True)

    cuda = args.device.startswith("cuda")
    trained = [p for p in model.parameters() if p.requires_grad]
    limit = [args.checkpoint_above or 10**9]    # longest record run without checkpointing
    mem = {"checkpointed": 0, "out_of_memory": 0}

    def set_ckpt(on: bool) -> None:
        for m in layers_ckpt:
            m.gradient_checkpointing = on

    def one_record(ids, labels) -> float:
        """Forward and backward of one record, its gradient added to the accumulated one.
        Runs it checkpointed if it is longer than the limit; if it runs out of memory
        uncheckpointed, puts the gradients back as they were before it, lowers the limit
        and runs it again checkpointed."""
        ckpt = args.grad_checkpoint or len(ids) > limit[0]
        saved = None if ckpt else [None if p.grad is None else p.grad.clone() for p in trained]
        try:
            return run_record(ids, labels, ckpt)
        except torch.OutOfMemoryError:
            if ckpt:
                raise
        # Outside the except block, so the failed attempt's tensors are already freed.
        for p, g in zip(trained, saved):
            p.grad = g
        del saved
        if cuda:
            torch.cuda.empty_cache()
        limit[0] = min(limit[0], len(ids) - 1)
        mem["out_of_memory"] += 1
        print(f"  a record of {len(ids)} tokens ran out of graphics memory: undone and run again "
              f"checkpointed; from now on every record over {limit[0]} tokens is", flush=True)
        return run_record(ids, labels, True)

    def run_record(ids, labels, ckpt: bool) -> float:
        set_ckpt(ckpt)
        mem["checkpointed"] += ckpt
        x = torch.tensor([ids], device=args.device)
        y = torch.tensor([labels], device=args.device)
        loss = model(input_ids=x, labels=y).loss
        (loss / args.accumulate).backward()
        return loss.item()

    order = list(range(len(train)))
    seen = step = 0
    running, running_n = 0.0, 0
    best = [float("inf")]
    started = time.time()
    total_records = int(len(train) * args.epochs)
    tokens_done, train_s = 0, 0.0      # training alone, without the held-back evaluations
    opt.zero_grad(set_to_none=True)
    while seen < total_records:
        random.shuffle(order)
        for i in order:
            if seen >= total_records:
                break
            ids, labels = train[i]
            t0 = time.time()
            running += one_record(ids, labels)      # .item() waits for the card, so t is right
            running_n += 1
            seen += 1
            tokens_done += len(ids)
            if seen % args.accumulate == 0 or seen == total_records:
                for g in opt.param_groups:
                    g["lr"] = lr_at(step)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
                opt.zero_grad(set_to_none=True)
                step += 1
            train_s += time.time() - t0
            if seen % args.eval_every == 0 or seen == total_records:
                evaluate(seen, step, running / max(running_n, 1), started, best)
                running, running_n = 0.0, 0
    minutes = (time.time() - started) / 60
    peak = (f"; peak graphics memory {torch.cuda.max_memory_allocated() / 2**30:.1f} GiB"
            if cuda else "")
    with open(out / "log.jsonl", "a") as f:
        f.write(json.dumps({"done": True, "method": args.method, "records_seen": seen,
                            "minutes": round((time.time() - started) / 60, 1),
                            "best_heldback_loss": round(best[0], 4),
                            "tokens_per_s": round(tokens_done / max(train_s, 1e-9)),
                            "checkpointed": mem["checkpointed"],
                            "out_of_memory": mem["out_of_memory"],
                            "checkpoint_above": None if limit[0] >= 10**9 else limit[0],
                            "peak_gpu_gib": round(torch.cuda.max_memory_allocated() / 2**30, 2)
                            if args.device.startswith("cuda") else None}) + "\n")
    print(f"done ({args.method}): {seen} records in {minutes:.1f} minutes; "
          f"best held-back loss {best[0]:.4f} -> {out / 'best'}{peak}")
    print(f"memory guard: {mem['checkpointed']} records checkpointed, "
          f"{mem['out_of_memory']} ran out of memory and were run again")
    if args.limit:
        # A dry run's projection for the whole data set at the default three passes. The
        # held-back evaluations every --eval-every records come on top (about a tenth).
        rate = tokens_done / max(train_s, 1e-9)
        print(f"speed: {rate:,.0f} tokens/s; a full run over all {full_tok / 1e6:.1f} M tokens, "
              f"3 passes, would take about {3 * full_tok / rate / 3600:.1f} hours of training "
              f"(its first records warm the card up, so this is a little high)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
