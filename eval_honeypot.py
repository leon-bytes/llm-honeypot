#!/usr/bin/env python3
"""
Honeypot shell eval: grade run output files against the lab ground truth.

Usage:
  python eval_honeypot.py --gt gt43_lab_2026-09.json \
      --rules eval_not_gradable.json \
      --run res_cloud_v3.json --run res_jetson_v3.json \
      [--identity identity.json] [--out results/]

Key design points
  * The ground truth comes from --gt, NOT from the run file's `real` field
    (older runs carry a stale, pre-lab reference; the script warns about it).
  * Tiers, in order: exact -> masked -> semantic. Skip-listed tests are graded
    on structure only ("structural") and reported as their own group.
  * Groups: CORE (headline) / STATEFUL / SKIP. Empty-expected tests are tagged.
  * Every failure gets one reason code (heuristic, fixed precedence).
  * Identity: optional --identity JSON {"substitutions": {"<gt value>": "<honeypot value>"}}.
    Expected output is rewritten with the honeypot's identity before comparing,
    and any gt value that shows up in a model answer is flagged identity_leak.
    Entries whose value is "REPLACE_ME" are ignored.
"""
import argparse, csv, difflib, ipaddress, json, os, re, statistics, sys
from collections import Counter

STATEFUL = {6, 7, 8, 9, 29, 30, 31, 32}
# Both of these come ONLY from eval_not_gradable.json (see load_rules); nothing is hard-coded:
#   SET_COMPARE : tests whose line order is not stable between runs on the same machine (netstat/ss
#                 list sockets in no guaranteed order); compared as a multiset of lines, after the mask.
#                 Read from compare_as_set_not_sequence -> ground_truth_43.
#   MASK_TESTS  : tests the rules file marks grade="mask"; the masking code for each lives in MASKS.
SET_COMPARE = set()
MASK_TESTS = set()
EMPTY_EXPECTED = {6, 10, 29}
ANSI = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[A-Za-z]")
MONTH = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
LLM_LEAK = re.compile(
    r"\b(language model|LLM|as an AI|I am an AI|I'm an AI|Qwen|OpenAI|ChatGPT|Claude|Anthropic|Ollama|GPT)\b",
    re.I)


# ---------------------------------------------------------------- normalise
def norm(t):
    t = ANSI.sub("", t or "").replace("\r\n", "\n").replace("\r", "")
    lines = [l.rstrip() for l in t.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def substitute(t, subs):
    for k in sorted(subs, key=len, reverse=True):
        t = t.replace(k, subs[k])
    return t


# -------------------------------------------------------------------- masks
def _df(t):
    out = []
    for l in t.split("\n"):
        p = l.split()
        if len(p) >= 6 and p[0] != "Filesystem":
            p[2], p[3], p[4] = "<U>", "<A>", "<P>"
            p[5] = re.sub(r"[0-9a-f]{64}", "<HASH>", p[5])
            l = " ".join(p)
        out.append(l)
    return "\n".join(out)


def _env(t):
    t = re.sub(r"(SSH_CONNECTION=\S+ )\d+( \S+ \d+)", r"\1<PORT>\2", t)
    t = re.sub(r"(SSH_CLIENT=\S+ )\d+( \d+)", r"\1<PORT>\2", t)
    return re.sub(r"XDG_SESSION_ID=\d+", "XDG_SESSION_ID=<N>", t)


def _ls(t):
    t = re.sub(MONTH + r"\s+\d+\s+(?:\d\d:\d\d|\d{4})", "<TS>", t)
    t = re.sub(r"^(total )\d+", r"\1<N>", t, flags=re.M)
    t = re.sub(r"^(\S{10})\s+\d+", r"\1 <L>", t, flags=re.M)
    return re.sub(r"(\S+\s+\S+\s+)\d+( <TS> \.bash_history)", r"\1<SZ>\2", t)


def _ifconfig(t):
    t = re.sub(r"(packets|bytes) \d+", r"\1 <N>", t)
    t = re.sub(r"\(\d+(?:\.\d+)? [KMG]?i?B\)", "(<SZ>)", t)
    t = re.sub(r"ether [0-9a-f:]{17}", "ether <MAC>", t)
    t = re.sub(r"\bveth[0-9a-f]{7}\b", "vethX", t)
    # link-local IPv6 (fe80::...) is generated per boot (derived from the MAC / privacy-random)
    t = re.sub(r"fe80::[0-9a-f:]+", "fe80::<LL>", t)
    # the order of an interface's inet6 lines can change between boots: compare them as a set
    blocks = []
    for block in t.split("\n\n"):
        lines = block.split("\n")
        idx = [i for i, l in enumerate(lines) if l.strip().startswith("inet6 ")]
        for i, l in zip(idx, sorted(lines[i] for i in idx)):
            lines[i] = l
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


MASKS = {
    4: _df,
    18: lambda t: re.sub(r"(scaling MHz:\s+)\S+", r"\1<V>", t),
    22: _env, 37: _env,
    30: _ls, 32: _ls,
    33: _ifconfig,
    34: lambda t: re.sub(r"(Boot ID:\s+)\S+", r"\1<ID>", t),
    38: lambda t: re.sub(r"(LISTEN\s+)\d+/", r"\1<PID>/", t),
    39: lambda t: re.sub(r"pid=\d+", "pid=<PID>", t),
    40: lambda t: re.sub(r"snapshots/\d+", "snapshots/<N>", re.sub(r"[0-9a-f]{64}", "<HASH>", t)),
}

# --------------------------------------------------- structural checks (skip)
TOP_CHECKS = [r"^top - \d\d:\d\d:\d\d up .*load average: [\d.]+, [\d.]+, [\d.]+$",
              r"^Tasks: \d+ total", r"^%Cpu\(s\):", r"^MiB Mem :", r"^MiB Swap:",
              r"PID USER\s+PR\s+NI\s+VIRT\s+RES\s+SHR S\s+%CPU\s+%MEM\s+TIME\+ COMMAND"]
PS_ROW = r"^\S+\s+\d+\s+[\d.]+\s+[\d.]+\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+.+$"
STRUCT = {
    14: dict(checks=[r"^USER\s+PID\s+%CPU\s+%MEM\s+VSZ\s+RSS\s+TTY\s+STAT\s+START\s+TIME\s+COMMAND$"], min_line_frac=0.5),
    23: dict(checks=[r"\A\d+\Z"]),
    24: dict(checks=[PS_ROW, r"grep bash$"], all_lines=PS_ROW),
    25: dict(checks=[PS_ROW, r"grep bash$"], all_lines=PS_ROW),
    26: dict(checks=[r"\A\d+\.\d\d \d+\.\d\d\Z"]),
    27: dict(checks=[r"\A\d+\.\d\d \d+\.\d\d\Z"]),
    36: dict(checks=TOP_CHECKS),
    43: dict(checks=[r"^PING 8\.8\.8\.8 \(8\.8\.8\.8\) 56\(84\) bytes of data\.",
                     r"Destination Net Unreachable", r"100% packet loss"]),
}


def structural(n, exp, model):
    spec = STRUCT.get(n)
    if not spec:  # fallback: shape similarity
        r = difflib.SequenceMatcher(None, shape(exp), shape(model)).ratio()
        return r >= 0.85
    for c in spec["checks"]:
        if not re.search(c, model, re.M):
            return False
    if "all_lines" in spec and not all(re.match(spec["all_lines"], l) for l in model.split("\n") if l):
        return False
    if "min_line_frac" in spec and len(model.split("\n")) < spec["min_line_frac"] * len(exp.split("\n")):
        return False
    if n == 36 and not _top_mem_ok(exp, model):
        return False
    return True


MEM_LINE = re.compile(r"^MiB Mem\s*:\s*([\d.]+) total,\s*([\d.]+) free,\s*([\d.]+) used,\s*([\d.]+) buff/cache", re.M)


def _top_mem_ok(exp, model, ratio=5.0):
    """top's memory line must be the same order of magnitude as the real one."""
    a, b = MEM_LINE.search(exp), MEM_LINE.search(model)
    if not a or not b:
        return True  # nothing to compare; the regex checks above already require the line to exist
    for x, y in zip(a.groups(), b.groups()):
        u, v = float(x), float(y)
        if abs(u - v) <= 1:
            continue
        if min(u, v) <= 0 or max(u, v) / min(u, v) > ratio:
            return False
    return True


# ---------------------------------------------------------------- semantic
NUM = re.compile(r"^([-+]?\d+(?:\.\d+)?)([A-Za-z%]*)$")
TIME = re.compile(r"^\d\d:\d\d(:\d\d)?$")


def shape(t):
    return re.sub(r"\d", "#", t)


def semantic_equal(a, b, ratio=1.5):
    """Same layout; non-numeric tokens identical; numbers same unit and within `ratio`."""
    la, lb = a.split("\n"), b.split("\n")
    if len(la) != len(lb):
        return False
    for x, y in zip(la, lb):
        tx, ty = x.split(), y.split()
        if len(tx) != len(ty):
            return False
        for p, q in zip(tx, ty):
            if p == q or (TIME.match(p) and TIME.match(q)):
                continue
            mp, mq = NUM.match(p), NUM.match(q)
            if not (mp and mq) or mp.group(2) != mq.group(2):
                return False
            u, v = float(mp.group(1)), float(mq.group(1))
            if abs(u - v) <= 1:
                continue
            if min(u, v) <= 0 or max(u, v) / min(u, v) > ratio:
                return False
    return True


# ------------------------------------------------------- tolerant (calibrated)
# Commands whose layout/sizes legitimately vary by hardware or util-linux version.
# Calibrated to the April human verdicts (df -h and lscpu were judged PASSED despite
# different sizes / a different section layout). Reported as their own tier ("tolerant").
def _df_tolerant(exp, model):
    ea, mb = exp.split("\n"), model.split("\n")
    if ea[0].split() != mb[0].split():
        return False
    def rows(L):
        return [l.split() for l in L[1:] if l.strip()]
    ra, rb = rows(ea), rows(mb)
    if any(len(r) != 6 or not NUM.match(r[1]) or not NUM.match(r[2]) or not NUM.match(r[3]) or not r[4].endswith("%") for r in rb):
        return False
    root = lambda R: next((r for r in R if r[-1] == "/"), None)
    xa, xb = root(ra), root(rb)
    if not xa or not xb or xa[0] != xb[0]:
        return False
    return semantic_equal(xa[1], xb[1])  # root filesystem size within 1.5x, same unit


LSCPU_ID = ["Architecture", "CPU op-mode(s)", "Byte Order", "CPU(s)", "On-line CPU(s) list", "Vendor ID",
            "Model name", "Model", "Thread(s) per core", "Core(s) per cluster", "Socket(s)", "Cluster(s)",
            "Stepping", "BogoMIPS", "Flags"]


def _lscpu_tolerant(exp, model):
    def kv(t):
        d = {}
        for l in t.split("\n"):
            if ":" in l:
                k, v = l.split(":", 1)
                d.setdefault(k.strip(), " ".join(v.split()))
        return d
    a, b = kv(exp), kv(model)
    for k in LSCPU_ID:
        if k in a and a[k] != b.get(k):
            return False
    for k in ("CPU max MHz", "CPU min MHz"):
        if k in a and (k not in b or abs(float(a[k]) - float(b[k])) > 1):
            return False
    return True


TOLERANT = {4: _df_tolerant, 18: _lscpu_tolerant}


# ------------------------------------------------------------ rules file
def load_rules(path=None):
    """Read eval_not_gradable.json (the single source for skip / mask / set-compare lists).
    Prints where each list came from. Missing file or malformed JSON stops the run (no silent fallback)."""
    here = os.path.dirname(os.path.abspath(__file__))
    cands = [path] if path else ["eval_not_gradable.json", os.path.join(here, "eval_not_gradable.json")]
    found = next((c for c in cands if c and os.path.exists(c)), None)
    if not found:
        sys.exit("ERROR: rules file not found (looked for: %s). Put eval_not_gradable.json next to the "
                 "scripts or pass --rules <path>." % ", ".join(c for c in cands if c))
    try:
        r = json.load(open(found))
        gt43 = r["ground_truth_43"]
    except (ValueError, KeyError) as ex:
        sys.exit(f"ERROR: rules file {found} is not usable ({type(ex).__name__}: {ex}). Fix the file; "
                 "refusing to guess.")
    skip = {int(k) for k, v in gt43.items() if v["grade"] == "skip"}
    mask = {int(k) for k, v in gt43.items() if v["grade"] == "mask"}
    sec = r.get("compare_as_set_not_sequence", {}).get("ground_truth_43")
    setl = set() if sec is None else {int(k) for k in (sec.keys() if isinstance(sec, dict) else sec)}
    MASK_TESTS.clear(); MASK_TESTS.update(mask)
    SET_COMPARE.clear(); SET_COMPARE.update(setl)
    print(f"rules file          : {found}")
    print(f"  skip list         : {sorted(skip)}")
    print(f"  masked tests      : {sorted(mask)}")
    print(f"  set-compare tests : {sorted(setl) if sec is not None else 'NONE - key compare_as_set_not_sequence -> ground_truth_43 not found in the rules file'}")
    if sec is None:
        print("  WARNING: no set-compare list, so tests like netstat/ss are compared in line ORDER.")
    no_impl = sorted(mask - set(MASKS))
    if no_impl:
        print(f"  WARNING: marked 'mask' in the rules file but no masking code exists for tests {no_impl}; compared unmasked.")
    unused = sorted(set(MASKS) - mask)
    if unused:
        print(f"  WARNING: masking code exists for tests {unused} but the rules file does not mark them 'mask'; NOT applied.")
    return skip, found


# --------------------------------------------------------------- reasoning
def toks(t):
    return {re.sub(r"\W", "", w) for w in t.split() if re.sub(r"\W", "", w)}


def example_matches(cmd, ex):
    """A retrieved example is useful if it is the same command and, when the test command
    has non-flag arguments, shares at least one of them (so `cat /etc/hostname` does not
    count as a match for `cat .bashrc`)."""
    a, b = cmd.split(), ex.split()
    if not a or not b or a[0].strip("\"'") != b[0]:
        return False
    args = [t for t in a[1:] if not t.startswith("-") and t not in ("|", "2>/dev/null")]
    return not args or any(t in b[1:] for t in args)


def classify(n, cmd, exp, model, run, leak_keys, examples_cmds):
    er = (run.get("empty_reason") or "").lower()
    if model == "" and exp != "":
        if "chose to say nothing" in er or "dodg" in er:
            return "empty_dodged"
        if "cut off" in er or "truncat" in er or "length" in er:
            return "empty_cutoff"
        if "block" in er:
            return "empty_blocked"
        return "empty_other"
    if n in STATEFUL:
        return "stateful_no_memory"
    if any(k in model for k in leak_keys):
        return "identity_leak"
    if LLM_LEAK.search(model) and not LLM_LEAK.search(exp):
        return "llm_identity_leak"
    if exp == "":
        return "hallucinated_content"
    if shape(exp) == shape(model):
        return "wrong_live_value"
    a, b = toks(exp), toks(model)
    if a and b and len(a & b) / len(a | b) >= 0.9:
        return "formatting_drift"
    if examples_cmds is not None and not any(example_matches(cmd, c) for c in examples_cmds):
        return "no_matching_example"
    return "hallucinated_content"


def _set_equal(a, b):
    la = sorted(l for l in a.split("\n") if l.strip())
    lb = sorted(l for l in b.split("\n") if l.strip())
    return bool(la) and la == lb


def _safe(fn, *a):
    """Run a tolerant check; if it raises, say so on stderr instead of silently counting a failed test."""
    try:
        return fn(*a)
    except Exception as ex:
        print(f"  WARNING: grading rule {getattr(fn, '__name__', fn)} raised {type(ex).__name__}: {ex}", file=sys.stderr)
        return False


# ---------------------------------------------- ifconfig: link-local must match the interface's MAC
def _eui64_ll(mac):
    b = [int(x, 16) for x in mac.split(":")]
    b[0] ^= 2
    return ipaddress.ip_address("fe80::%x:%x:%x:%x" % (b[0] << 8 | b[1], b[2] << 8 | 0xFF, 0xFE00 | b[3], b[4] << 8 | b[5]))


def _ifc_kind(name):
    return "br" if name.startswith("br-") else "veth" if name.startswith("veth") else name


def _ll_ok(exp, model):
    """On the real machine the Docker bridges and veths derive their fe80 address from the interface MAC
    (EUI-64); eth0's is random (NetworkManager), so it is not checked. For every interface kind where the REAL
    answer shows the MAC-derived address, the honeypot's address must be the one ITS OWN ether line implies."""
    def blocks(t):
        for b in t.split("\n\n"):
            nm = re.match(r"^(\S+?):", b)
            mac = re.search(r"ether ([0-9a-f:]{17})", b)
            ll = re.search(r"inet6 (fe80::[0-9a-f:]+)", b)
            if nm and mac and ll:
                yield nm.group(1), mac.group(1), ll.group(1)
    def eui(mac, ll):
        try:
            return ipaddress.ip_address(ll) == _eui64_ll(mac)
        except ValueError:
            return False
    kinds = {_ifc_kind(n) for n, mac, ll in blocks(exp) if eui(mac, ll)}
    return all(eui(mac, ll) for n, mac, ll in blocks(model) if _ifc_kind(n) in kinds)


def grade(g, run, subs, leak_keys, rules_skip):
    n, cmd = g["n"], g["command"]
    exp = norm(substitute(g["output"], subs))
    model = norm(run.get("model", ""))
    tags = []
    if n in rules_skip: tags.append("skip")
    if n in STATEFUL: tags.append("stateful")
    if n in EMPTY_EXPECTED: tags.append("empty_expected")
    group = "SKIP" if n in rules_skip else ("STATEFUL" if n in STATEFUL else "CORE")

    tier = None
    if n in rules_skip:
        if structural(n, exp, model): tier = "structural"
    elif exp == model:
        tier = "exact"
    else:
        m = MASKS.get(n) if n in MASK_TESTS else None
        if m and m(exp) == m(model):
            tier = "masked"
        elif n in SET_COMPARE and _set_equal(m(exp) if m else exp, m(model) if m else model):
            tier = "set"
        else:
            me, mm = (m(exp), m(model)) if m else (exp, model)
            if me and mm and semantic_equal(me, mm):
                tier = "semantic"
            elif n in TOLERANT and exp and model and _safe(TOLERANT[n], exp, model):
                tier = "tolerant"
    reason = ""
    if tier and n == 33 and tier != "exact" and not _ll_ok(exp, model):
        tier, reason = None, "link_local_mismatch"
    if tier is None and not reason:
        reason = classify(n, cmd, exp, model, run, leak_keys, run.get("examples"))
    return dict(n=n, command=cmd, group=group, tags="|".join(tags),
                outcome="PASS" if tier else "FAIL", tier=tier or "", reason=reason,
                ms=run.get("ms", run.get("elapsed_ms", "")), empty_reason=run.get("empty_reason", ""))


# ------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--run", action="append", required=True)
    ap.add_argument("--identity")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()

    gt = {e["n"]: e for e in json.load(open(a.gt))}
    rules_skip, _ = load_rules(a.rules)
    subs = {}
    if a.identity:
        subs = {k: v for k, v in json.load(open(a.identity))["substitutions"].items() if v != "REPLACE_ME"}
    leak_keys = [k for k, v in subs.items() if k != v]
    if not a.identity:
        print("note: no --identity given; identity substitution and leak check are OFF\n")
    os.makedirs(a.out, exist_ok=True)

    summaries = []
    for path in a.run:
        name = os.path.splitext(os.path.basename(path))[0]
        runs = {e["n"]: e for e in json.load(open(path))}
        stale = [n for n, e in runs.items() if n in gt and norm(e.get("real", "")) != norm(gt[n]["output"])]
        rows = [grade(gt[n], runs[n], subs, leak_keys, rules_skip) for n in sorted(gt) if n in runs]
        with open(os.path.join(a.out, name + "_per_test.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

        def tally(sel):
            r = [x for x in rows if sel(x)]
            return sum(x["outcome"] == "PASS" for x in r), len(r)
        core = tally(lambda x: x["group"] == "CORE")
        core_ne = tally(lambda x: x["group"] == "CORE" and "empty_expected" not in x["tags"])
        st = tally(lambda x: x["group"] == "STATEFUL")
        sk = tally(lambda x: x["group"] == "SKIP")
        tiers = Counter(x["tier"] for x in rows if x["outcome"] == "PASS" and x["group"] == "CORE")
        reasons = Counter(x["reason"] for x in rows if x["outcome"] == "FAIL")
        reasons_core = Counter(x["reason"] for x in rows if x["outcome"] == "FAIL" and x["group"] == "CORE")
        ms = [float(x["ms"]) for x in rows if x["ms"] != ""]

        print("=" * 64); print(name)
        if stale:
            print(f"  WARNING: this run's `real` field differs from the lab ground truth on {len(stale)} tests "
                  f"{stale}.\n  Graded against --gt, but the run was produced against a stale reference; re-run it.")
        print(f"  HEADLINE  core stateless : {core[0]}/{core[1]}   (excluding empty-expected: {core_ne[0]}/{core_ne[1]})")
        print(f"  pass tiers (core)        : {dict(tiers)}")
        print(f"  stateful group           : {st[0]}/{st[1]}   (reported separately)")
        print(f"  skip group (structural)  : {sk[0]}/{sk[1]}   (reported separately)")
        print(f"  failures by reason, core : {dict(reasons_core)}")
        print(f"  failures by reason, all  : {dict(reasons)}")
        print(f"  latency ms               : median {statistics.median(ms):.0f}, max {max(ms):.0f}")
        free = [x["n"] for x in rows if "empty_expected" in x["tags"] and x["outcome"] == "PASS"]
        print(f"  empty-expected 'free' passes (n): {free}")
        summaries.append(dict(run=name, core_pass=core[0], core_total=core[1], core_nonempty_pass=core_ne[0],
                              core_nonempty_total=core_ne[1], stateful_pass=st[0], stateful_total=st[1],
                              skip_pass=sk[0], skip_total=sk[1], median_ms=statistics.median(ms), max_ms=max(ms),
                              reasons=json.dumps(reasons)))
    with open(os.path.join(a.out, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summaries[0].keys())); w.writeheader(); w.writerows(summaries)
    print("\nwrote per-test CSVs and summary.csv to", a.out)


if __name__ == "__main__":
    main()