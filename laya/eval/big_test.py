"""Score one served GGUF model on several test sets through llama-server's chat endpoint.

Same metrics as train_eval.py, plus per-reply server timings, so every candidate is judged the
way it will run on the Jetson (quantized, llama.cpp, the GGUF's own chat template).
"""

import difflib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from transformers import AutoTokenizer

url, train_path, out_path, model_name, model_dir = sys.argv[1:6]
test_paths = sys.argv[6:]
# Raw /completion with the HF chat template: the same prompt bytes as training, and no
# server-side output parsing (llama-server's tool-call parser rejects JSON-looking replies).
tok = AutoTokenizer.from_pretrained(model_dir)
SERVER_ERROR = "\x00server error: "
train_commands = {
    json.loads(line)["messages"][1]["content"]
    for line in Path(train_path).read_text().splitlines()
}


def ask(messages):
    prompt = tok.apply_chat_template(
        messages, add_generation_prompt=True, tokenize=False
    )
    if tok.bos_token and prompt.startswith(tok.bos_token):
        prompt = prompt[len(tok.bos_token) :]  # llama-server adds BOS itself
    body = {
        "prompt": prompt,
        "temperature": 0,
        "n_predict": 2048,
        "cache_prompt": False,
    }
    req = urllib.request.Request(
        url + "/completion",
        json.dumps(body).encode(),
        {"Content-Type": "application/json"},
    )
    try:
        resp = json.load(urllib.request.urlopen(req, timeout=600))
    except urllib.error.HTTPError as e:
        # llama-server's output parser rejects some byte sequences with HTTP 500; the relay would get
        # no reply either, so score it as a miss (the sentinel never equals a gold answer).
        return SERVER_ERROR + e.read().decode(errors="replace"), {}
    return resp.get("content", ""), resp.get("timings", {})


summary = {"model": model_name}
with open(out_path, "w") as out:
    for path in test_paths:
        name = path.rsplit("/", 1)[-1].removesuffix(".jsonl").removesuffix("_norules")
        rows = []
        for line in Path(path).read_text().splitlines():
            rec = json.loads(line)
            messages = rec["messages"]
            pred, t = ask(messages[:-1])
            gold = messages[-1]["content"]
            row = {
                "set": name,
                "n": str(rec["meta"]["n"]),
                "command": messages[1]["content"],
                "gold": gold,
                "pred": pred,
                "exact": pred.strip() == gold.strip(),
                "similarity": difflib.SequenceMatcher(None, pred, gold).ratio(),
                "unseen": messages[1]["content"] not in train_commands,
                "server_error": pred.startswith(SERVER_ERROR),
                "gold_empty": not gold.strip(),
                "pred_empty": not pred.strip(),
                "prompt_n": t.get("prompt_n", 0),
                "predicted_n": t.get("predicted_n", 0),
                "ms": t.get("prompt_ms", 0) + t.get("predicted_ms", 0),
            }
            rows.append(row)
            out.write(json.dumps(row) + "\n")
        unseen = [r for r in rows if r["unseen"]]
        mean = lambda rs, k: sum(float(r[k]) for r in rs) / max(1, len(rs))
        summary[name] = {
            "n": len(rows),
            "exact": mean(rows, "exact"),
            "similarity": mean(rows, "similarity"),
            "n_unseen": len(unseen),
            "unseen_exact": mean(unseen, "exact"),
            "empty_recall": mean([r for r in rows if r["gold_empty"]], "pred_empty"),
            "mean_prompt_tokens": mean(rows, "prompt_n"),
            "mean_output_tokens": mean(rows, "predicted_n"),
            "mean_ms_b200": mean(rows, "ms"),
        }
print(json.dumps(summary))
