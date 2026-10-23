"""Score honeypot replies on the 43 ground-truth commands using eval_not_gradable.json's rules.

skip entries are left out. mask entries have their volatile fields replaced on both sides
before comparing. Network identity is masked everywhere: the honeypot must answer with the
Orchestrator's own addresses, so the reference machine's IPs and MACs can't be expected.
"""

import difflib
import json
import re
import sys
from pathlib import Path

IDENTITY = [
    (re.compile(r"\b10\.77\.10\.2[01]\b"), "<SELF_IP4>"),
    (re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.IGNORECASE), "<MAC>"),
    # An IPv6 address needs "::" or a hex letter; otherwise clock times like 20:43:42 would match.
    (
        re.compile(
            r"\b(?=[0-9a-f:]*(?:::|[a-f]))(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?:/\d+)?",
            re.IGNORECASE,
        ),
        "<IP6>",
    ),
]
NUM = re.compile(r"\d+(?:[.,]\d+)?[KMGTP]?i?B?%?")
STAMP = re.compile(r"\b[A-Z][a-z]{2} +\d{1,2} +(?:\d{2}:\d{2}|\d{4})\b")
HASHPATH = re.compile(r"/var/lib/(?:docker|containerd)/\S+")
MASKS = {
    4: lambda t: NUM.sub("<N>", HASHPATH.sub("<HASHPATH>", t)),
    18: lambda t: "\n".join(
        line for line in t.split("\n") if "scaling MHz" not in line
    ),
    22: lambda t: re.sub(
        r"(SSH_(?:CLIENT|CONNECTION)=\S+ )\d+",
        r"\1<PORT>",
        re.sub(r"XDG_SESSION_ID=\d+", "XDG_SESSION_ID=<N>", t),
    ),
    30: lambda t: STAMP.sub("<TIME>", t),
    32: lambda t: re.sub(
        r"^total \d+",
        "total <N>",
        re.sub(
            r"^(\S{10}\.?) +\d+",
            r"\1 <LINKS>",
            STAMP.sub("<TIME>", t),
            flags=re.MULTILINE,
        ),
        flags=re.MULTILINE,
    ),
    33: lambda t: re.sub(
        r"((?:RX|TX) (?:packets|errors) )\d+( +(?:bytes|dropped) )\d+(?: \([^)]*\))?",
        r"\1<N>\2<N>",
        t,
    ),
    34: lambda t: re.sub(r"Boot ID: \S+", "Boot ID: <ID>", t),
    38: lambda t: re.sub(r"\d+/(\S+)", r"<PID>/\1", t),
    39: lambda t: re.sub(r"pid=\d+", "pid=<PID>", t),
    40: lambda t: HASHPATH.sub("<HASHPATH>", t),
}
MASKS[37] = MASKS[22]


def normalise(n, text):
    text = text.strip()
    for pattern, repl in IDENTITY:
        text = pattern.sub(repl, text)
    return MASKS.get(n, lambda t: t)(text)


def score(gt_path, rules_path, replies_path):
    rules = json.loads(Path(rules_path).read_text())["ground_truth_43"]
    gold = {e["n"]: e for e in json.loads(Path(gt_path).read_text())}
    replies = [json.loads(line) for line in Path(replies_path).read_text().splitlines()]
    replies = [r for r in replies if r.get("set") == "gt43"]
    graded = []
    for entry, r in zip(gold.values(), replies):
        assert entry["command"] == r["command"], (entry["n"], r["command"])
        if rules.get(str(entry["n"]), {}).get("grade") == "skip":
            continue
        g, p = normalise(entry["n"], entry["output"]), normalise(entry["n"], r["pred"])
        graded.append(
            {
                "n": entry["n"],
                "command": entry["command"],
                "exact": g == p,
                "similarity": difflib.SequenceMatcher(None, p, g).ratio(),
                "ms": r.get("ms", 0),
            }
        )
    return graded


def demo():
    assert normalise(1, "top - 20:43:42 up") != normalise(1, "top - 21:00:00 up"), (
        "clock times must not be masked as IPv6"
    )
    assert normalise(4, "/dev/mmcblk0p2  117G  8.2G  104G   8% /") == normalise(
        4, "/dev/mmcblk0p2  117G  6.1G  106G   6% /"
    )
    assert normalise(39, 'users:(("sshd",pid=812,fd=6))') == normalise(
        39, 'users:(("sshd",pid=99,fd=6))'
    )
    assert normalise(1, "inet 10.77.10.20") == normalise(1, "inet 10.77.10.21")
    assert normalise(1, "raspberrypi") != normalise(1, "raspberry")


if __name__ == "__main__":
    demo()
    gt_path, rules_path = sys.argv[1:3]
    for path in sys.argv[3:]:
        rows = score(gt_path, rules_path, path)
        ex = sum(r["exact"] for r in rows)
        print(
            f"{path.rsplit('/', 1)[-1]:24s} graded {len(rows)}  exact {ex}/{len(rows)} = {ex / len(rows):.0%}  "
            f"similarity {sum(r['similarity'] for r in rows) / len(rows):.2f}"
        )
