#!/usr/bin/env python3
"""CPU check of tools/finetune/train_lora.py's memory guard, with a tiny random model.

The guard (2026-10-14) runs a record checkpointed when it is longer than a limit, and
when a record runs out of graphics memory it puts the accumulated gradients back as
they were, lowers the limit and runs the record again checkpointed. There is no GPU
here, so this script fakes the out-of-memory error: the decoder layers raise it for
records longer than FAKE_LIMIT tokens unless checkpointed, once in the forward pass of
the first layer and once in the middle of the backward pass (after some gradients have
been added, which is the case that needs the undo).

It trains the same tiny model four times on the same records and requires the four
adapters to be the same (to 1e-6): no guard needed (all records short enough), every
record checkpointed (--grad-checkpoint), faked errors in the forward pass, faked errors
in the backward pass. If the undo were wrong, the last one would differ.

Needs a virtual environment with CPU torch, transformers and peft, and the Qwen2.5
tokenizer files (tokenizer.json, tokenizer_config.json) in a folder:

  python tools/check_finetune_cpu.py --tokenizer <folder> --work <scratch folder>
"""
from __future__ import annotations
import argparse
import json
import pathlib
import runpy
import shutil
import sys

import torch
from safetensors.torch import load_file
from transformers import AutoTokenizer, Qwen2Config, Qwen2ForCausalLM
from transformers.models.qwen2 import modeling_qwen2

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAKE_LIMIT = 300
MODE = {"where": None, "raised": 0}


def fake_oom_layer():
    original = modeling_qwen2.Qwen2DecoderLayer.forward

    def forward(self, hidden_states, *a, **k):
        long = self.training and hidden_states.shape[1] > FAKE_LIMIT and torch.is_grad_enabled()
        if long and not self.gradient_checkpointing:
            if MODE["where"] == "forward" and self.self_attn.layer_idx == 0:
                MODE["raised"] += 1
                raise torch.OutOfMemoryError("fake: forward")
            if MODE["where"] == "backward" and self.self_attn.layer_idx == 0:
                def hook(grad):
                    MODE["raised"] += 1
                    raise torch.OutOfMemoryError("fake: backward")
                hidden_states = hidden_states.clone()
                hidden_states.register_hook(hook)    # fires after the upper layers' grads
        return original(self, hidden_states, *a, **k)

    modeling_qwen2.Qwen2DecoderLayer.forward = forward


def make_data(work: pathlib.Path) -> pathlib.Path:
    data = work / "data"
    data.mkdir(parents=True)
    rows = []
    for i in range(12):
        filler = "\n".join(f"line {i} {j} of a recorded answer" for j in range(4 + 12 * (i % 3)))
        rows.append({"messages": [{"role": "system", "content": "You are a Linux machine."},
                                  {"role": "user", "content": f"cat file{i}.txt"},
                                  {"role": "assistant", "content": filler}],
                     "meta": {"source": "corpus"}})
    for name, part in (("train", rows), ("val", rows[:3])):
        (data / f"{name}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in part))
    return data


def train(model_dir, data, out, extra, where):
    MODE["where"], MODE["raised"] = where, 0
    sys.argv = ["train_lora.py", "--model", str(model_dir), "--data", str(data), "--out", str(out),
                "--epochs", "2", "--accumulate", "4", "--eval-every", "12", "--device", "cpu",
                "--rank", "4", *extra]
    try:
        runpy.run_path(str(ROOT / "tools/finetune/train_lora.py"), run_name="__main__")
    except SystemExit as e:
        if e.code not in (0, None):
            raise
    return load_file(out / f"checkpoint-24/adapter_model.safetensors"), MODE["raised"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tokenizer", required=True)
    ap.add_argument("--work", required=True)
    args = ap.parse_args()
    work = pathlib.Path(args.work)
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    tok = AutoTokenizer.from_pretrained(args.tokenizer)
    torch.manual_seed(1)
    cfg = Qwen2Config(vocab_size=len(tok), hidden_size=32, intermediate_size=64,
                      num_hidden_layers=3, num_attention_heads=4, num_key_value_heads=2,
                      max_position_embeddings=2048, tie_word_embeddings=True)
    model_dir = work / "tiny"
    Qwen2ForCausalLM(cfg).save_pretrained(model_dir)
    tok.save_pretrained(model_dir)
    data = make_data(work)
    lens = [len(tok(tok.apply_chat_template(json.loads(l)["messages"], tokenize=False))["input_ids"])
            for l in (data / "train.jsonl").read_text().splitlines()]
    print("record lengths:", sorted(lens), "fake limit:", FAKE_LIMIT)
    assert any(n > FAKE_LIMIT for n in lens) and any(n <= FAKE_LIMIT for n in lens)

    fake_oom_layer()
    plain, _ = train(model_dir, data, work / "plain", [], None)
    allck, _ = train(model_dir, data, work / "allck", ["--grad-checkpoint"], None)
    fwd, n_fwd = train(model_dir, data, work / "fwd", [], "forward")
    bwd, n_bwd = train(model_dir, data, work / "bwd", [], "backward")
    assert n_fwd >= 1 and n_bwd >= 1, (n_fwd, n_bwd)
    for name, other in (("every record checkpointed", allck), ("errors in the forward", fwd),
                        ("errors in the backward", bwd)):
        worst = max((plain[k] - other[k]).abs().max().item() for k in plain)
        print(f"{name}: largest difference from the plain run {worst:.2e}")
        assert worst < 1e-6, name
    last = [json.loads(l) for l in (work / "bwd/log.jsonl").read_text().splitlines()][-1]
    print("closing log line of the backward run:", last)
    assert last["out_of_memory"] == n_bwd and last["checkpoint_above"] < max(lens)
    print("OK: the memory guard changes nothing in what is learned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
