"""What the relay knows about Ground Truth: the recorded corpus.

1. Retrieval examples for the model, picked by shared 3-letter chunks
   (the same scoring as try_model_v3.py). This is the corpus's use in the live
   answer path; it is also the fine-tuning data (tools/build_training_data.py).
2. OFF BY DEFAULT (config `replay_tier`, decided 2026-10-08): an exact-answer cache.
   A command typed exactly as recorded, whose answer does not depend on time, boot
   or session, was answered from the recording without asking the model. That is a
   lookup of the command text in a table of stored answers - the hash-table caching
   ruled out for the study - so it is not part of the evaluated system. The code is
   kept behind the flag; with the flag off the table is not even built.

Only corpus284_lab_2026-09.json is used. gt43_lab_2026-09.json is the test set and
must never reach the honeypot, or the score measures memorisation.

Everything leaving this module has passed through `Substitutions`, so Ground
Truth's addresses never reach an attacker (R1, R2).
"""
from __future__ import annotations
import json
import os
import re

from .site import SITE

# Answers that depend on the clock, the boot, the process table or the session.
# They are never served from the recording, whatever the not-gradable file says.
_DYNAMIC = re.compile(
    r"""^\s*(date|uptime|w|who|users|last|lastlog|ps|top|htop|pgrep|pidof|free|vmstat
             |iostat|mpstat|journalctl|dmesg|systemctl|service|docker|ss|netstat|lsof
             |history|env|printenv|tty|sensors|vcgencmd|stat|time)\b
        |/proc/|/sys/class/thermal|\$\$|\$RANDOM|\bmktemp\b""", re.X)

# Recorded outputs that carry a live countdown or counter, whatever the command.
_DYNAMIC_OUTPUT = re.compile(r"valid_lft \d+sec|RX packets \d+|TX packets \d+")

# Commands whose answers change once the attacker has changed files in the session.
_READS_FILES = re.compile(r"^\s*(ls|ll|dir|find|du|df|tree|cat|more|less|head|tail|wc|file)\b")


class Substitutions:
    """Replace Ground Truth's identity with the Orchestrator's, longest match first."""

    def __init__(self, pairs: dict[str, str], rewriters=()):
        """`rewriters`: (compiled pattern, replacement) passes run after the literal
        pairs, for values with too many forms to list (identity.date_rewriters)."""
        self.rewriters = list(rewriters)
        self.pairs = sorted(pairs.items(), key=lambda kv: -len(kv[0]))
        self._re = (re.compile("|".join(re.escape(k) for k, _ in self.pairs), re.I)
                    if self.pairs else None)
        self._map = {k.lower(): v for k, v in self.pairs}

    def __call__(self, text: str) -> str:
        if not text:
            return text
        if self._re:
            text = self._re.sub(lambda m: self._map[m.group(0).lower()], text)
        for pattern, repl in self.rewriters:
            text = pattern.sub(repl, text)
        return text


def _grams(s: str) -> set:
    s = s.lower()
    return {s[i:i + 3] for i in range(len(s) - 2)}


def _paths(s: str) -> set:
    return set(re.findall(r'[~.]?/[\w./-]+|\.\w[\w.-]*', s))


def _team_only(path: str, empty):
    """A team-only recording (the corpus, the rules on what is not gradable). It is not in
    the shared repository: on the example site file (site.py) the relay runs without it,
    and the model is then shown no examples; with the real site file it is required."""
    if SITE.is_example and not os.path.exists(path):
        return empty
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class Knowledge:
    def __init__(self, corpus_path: str, not_gradable_path: str, subs: Substitutions,
                 replay: bool = False, hidden=()):
        """`replay`: build and serve the exact-answer cache (config `replay_tier`).
        Off, `cache` stays empty and `cached` never answers.
        `hidden`: corpus numbers never loaded at all (config `hidden_examples`): the
        recordings whose answers overlap a test answer, so the model is never shown a
        piece of what it is tested on."""
        corpus = _team_only(corpus_path, [])
        ng = _team_only(not_gradable_path, {}).get("corpus_284", {})
        skip = {int(n) for n, v in ng.items() if v.get("grade") == "skip"}
        hidden = {int(n) for n in hidden}
        volatile = {int(n) for n in ng}

        self.subs = subs
        self.replay = bool(replay)
        self.examples = []          # retrieval pool
        self.cache = {}             # exact command -> entry; empty unless `replay`
        for e in corpus:
            if e["n"] in skip or e["n"] in hidden or "[capture error]" in e["output"]:
                continue
            entry = {"n": e["n"], "command": e["command"], "output": subs(e["output"]),
                     "exit_code": e["exit_code"]}
            self.examples.append(entry)
            if (self.replay and e["n"] not in volatile and not _DYNAMIC.search(e["command"])
                    and not _DYNAMIC_OUTPUT.search(e["output"])):
                self.cache[e["command"].strip()] = entry
        self._grams = [_grams(e["command"]) for e in self.examples]

    def cached(self, cmd: str, fs, paths: list[str]) -> dict | None:
        """The recorded answer, unless the command reads files that attackers have
        since changed (`paths` are the ones it reads, `fs` the machine's changes).
        Always None while the replay tier is off."""
        if not self.replay:
            return None
        e = self.cache.get(cmd.strip())
        if e and _READS_FILES.search(cmd) and fs.touches(paths):
            return None
        return e

    def retrieve(self, cmd: str, k: int, hide=frozenset()) -> list[dict]:
        """The k recorded examples closest to `cmd`. `hide`: corpus numbers left out
        for this one question (measurement only, `honeypot.hide_examples`: the
        leave-one-out test asks a corpus command with its own recording hidden)."""
        q, qp = _grams(cmd), _paths(cmd)
        scored = []
        for e, c in zip(self.examples, self._grams):
            if not c or e["n"] in hide:
                continue
            score = len(q & c) / len(q | c)
            if qp & _paths(e["command"]):
                score += 0.5
            if score > 0.05:
                scored.append((score, e))
        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:k]]
