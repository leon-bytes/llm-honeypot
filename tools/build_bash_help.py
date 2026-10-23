#!/usr/bin/env python3
"""build_bash_help.py - the texts of bash's `help` builtin, recorded from bash 5.2.37 in
the Debian 13 arm64 userland (offline/debian13-arm64, the reference machine's version),
into honeypot/bash_help.json.

`help` reached the model and came back `command not found` (the unmasking probes of
2026-10-17, docs/unmask-probes.md), although it is a builtin whose every text is fixed by
the bash version. What is kept:
  list80   `help` with no argument at 80 columns (its table follows the width)
  names    the topics in bash's own order (`help -d '*'`), each with its `-d` line, its
           `-s` line and its full text (`help NAME`)
The relay's `help` (Shell._help) answers from this; the rules for which topics a word
matches are bash's (exact name first, else every name it begins), checked against the
real bash in tests/fixtures/bash_oracle.json.

Run (the dev machine, no network, under a minute):
  .venv/bin/python tools/build_bash_help.py
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from bash_oracle import userland            # noqa: E402

OUT = ROOT / "honeypot" / "bash_help.json"
HEADER = "Shell commands matching keyword `*'\n\n"


def main() -> int:
    lst, d, s, long_ = (r["output"] for r in userland(
        ["COLUMNS=80 help", "help -d '*'", "help -s '*'", "help '*'"]))
    for text in (d, s, long_):
        assert text.startswith(HEADER), text[:80]
    d, s, long_ = (t[len(HEADER):] for t in (d, s, long_))
    names = [line.split(" - ", 1)[0] for line in d.splitlines()]
    shorts = s.splitlines()
    assert len(names) == len(shorts) == len(d.splitlines())
    lines = long_.split("\n")
    starts, k = [], 0
    for name, short in zip(names, shorts):
        assert short.startswith(f"{name}: "), (name, short)
        while lines[k] != short:
            k += 1
        starts.append(k)
    starts.append(len(lines) - 1)        # the text ends with a newline
    topics = []
    for i, name in enumerate(names):
        topics.append({"name": name, "d": d.splitlines()[i], "s": shorts[i],
                       "long": "\n".join(lines[starts[i]:starts[i + 1]]) + "\n"})
    # each full text must be what `help NAME` prints for a name that is no pattern
    plain = [t for t in topics if not any(c in t["name"] for c in "*?[")]
    for t, r in zip(plain, userland([f"help -- '{t['name']}'" for t in plain])):
        assert r["output"] == t["long"], t["name"]
    OUT.write_text(json.dumps({"bash": "5.2.37(1)-release (aarch64-unknown-linux-gnu)",
                               "list80": lst, "topics": topics}, indent=1) + "\n")
    print(f"{OUT}: {len(topics)} topics, list {len(lst)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
