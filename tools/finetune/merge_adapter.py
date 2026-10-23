#!/usr/bin/env python3
"""Fold a LoRA, QLoRA or DoRA checkpoint into the base model and save a complete model.

All three kinds of checkpoint go the same way: into the base model at FULL precision
(16-bit here). A QLoRA adapter was trained on a 4-bit copy of the base, but it must not
be merged into that copy: the 4-bit weights would be what gets converted for the
Jetsons, quantised a second time.

Only needed after a "go": the Jetsons run a single model file, not a base model plus an
adapter. The folder this writes is what llama.cpp converts to GGUF
(docs/finetuning-on-the-5090.md, last part). It changes neither the base model nor the
checkpoint.

Run:
  python merge_adapter.py --model ~/ai/finetuning/honeypot/models/qwen2.5-3b-instruct \
      --adapter ~/ai/finetuning/honeypot/runs/run1/best --out ~/ai/finetuning/honeypot/merged/run1
"""
import argparse
import os
import sys

os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")

import torch                                                    # noqa: E402
from peft import PeftModel                                      # noqa: E402
from transformers import AutoModelForCausalLM, AutoTokenizer    # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", required=True, help="folder of the base model")
    ap.add_argument("--adapter", required=True, help="folder of the LoRA checkpoint")
    ap.add_argument("--out", required=True, help="folder for the merged model (must not exist)")
    args = ap.parse_args()
    out = os.path.expanduser(args.out)
    if os.path.exists(out):
        sys.exit(f"{out} exists already")
    base = os.path.expanduser(args.model)
    model = AutoModelForCausalLM.from_pretrained(base, dtype=torch.float16)
    model = PeftModel.from_pretrained(model, os.path.expanduser(args.adapter)).merge_and_unload()
    model.save_pretrained(out, safe_serialization=True)
    AutoTokenizer.from_pretrained(base).save_pretrained(out)
    print(f"merged model written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
