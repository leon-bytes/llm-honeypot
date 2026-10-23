#!/usr/bin/env bash
#
# publish_check.sh - what the shared repository would commit from this folder, and whether
# any of it holds something that must not leave the dev machine.
#
#   bash tools/publish_check.sh                        # the exclude in to-school/hsync/
#   bash tools/publish_check.sh --exclude FILE         # another copy of the exclude
#   bash tools/publish_check.sh --exclude - < FILE     # the exclude on stdin (over ssh)
#   bash tools/publish_check.sh --list                 # also print every published file
#   bash tools/publish_check.sh --digests              # also print each hit's digest (for
#                                                      # an entry in publish_check.allow)
#
# The whole project is copied to the school VM, and git there decides what is committed,
# using the allowlist in the school repo's .git/info/exclude (git ignore syntax). This
# check uses the SAME file, so the check and git always agree. The school VM runs it over
# ssh before every sync; a nonzero exit stops the sync.
#
# 1. Lists exactly what git would commit: a throwaway git repo whose .git/info/exclude is
#    the allowlist, against this work tree. git applies the project's own .gitignore files
#    (per directory) on top, exactly as the school repo will, so an ignored file inside an
#    allowed folder (a __pycache__, a built wheel) stays out here too.
# 2. Reads every published file (a .gz unpacked) and reports, by file name and kind only,
#    never the value:
#      site value <key>   a value from site.local.json (addresses, MACs, the served
#                         credentials, the dev machine's user, home and host name)
#      lab address        any other address on the lab's or the class's network, or
#                         under the lab's IPv6 prefix
#      password hash      a crypt(3) hash ($y$, $6$, $2b$, ...)
#      private key        a PEM/OpenSSH/PuTTY private key block
#      home path          /home/<name>, /Users/<name> or C:\Users\<name> of a user who is
#                         not one of the simulated or lab machines' own (pi, cowrie,
#                         influxdb, user) or the example's (devuser)
#
# tools/publish_check.allow may let one file's hits of one kind through, by a digest of
# exactly the strings found (never the strings themselves): upstream Cowrie's sample
# users and fake shadow file, for instance. A changed or added string changes the digest
# and is reported again. Site values and lab addresses can never be allowed.
#
# Exit status: 0 nothing found; 1 something found (the list says what and where);
# 2 the check could not run (no site.local.json, no exclude, git failed).
# Needs bash, git and python3 (standard library). Writes nothing outside a temp dir.

set -Eeuo pipefail
cd "$(dirname "$0")/.."
EXCLUDE=to-school/hsync/honeypot.exclude
LIST=0
DIGESTS=0
while [ $# -gt 0 ]; do
    case $1 in
        --exclude) EXCLUDE=${2:?--exclude needs a file, or - for stdin}; shift 2 ;;
        --list) LIST=1; shift ;;
        --digests) DIGESTS=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ "$EXCLUDE" = - ]; then
    cat > "$TMP/exclude"
else
    [ -f "$EXCLUDE" ] || { echo "no exclude file: $EXCLUDE" >&2; exit 2; }
    cp "$EXCLUDE" "$TMP/exclude"
fi
[ -s "$TMP/exclude" ] || { echo "the exclude file is empty" >&2; exit 2; }
[ -f site.local.json ] || { echo "no site.local.json: nothing to check the values against" >&2; exit 2; }
echo "exclude: sha256 $(sha256sum < "$TMP/exclude" | cut -c1-16)…, $(grep -cv '^[[:space:]]*\(#.*\)\?$' "$TMP/exclude") rules"

# What git would commit from this tree with that allowlist: a throwaway repo whose
# info/exclude is the allowlist, `git add -n` (dry run) against this work tree. git honours
# the project's per-directory .gitignore too, exactly as the school repo will. GIT_DIR wins
# over the real .git in this folder, which git add skips anyway.
git init -q "$TMP/sim"
cp "$TMP/exclude" "$TMP/sim/.git/info/exclude"
if ! GIT_DIR="$TMP/sim/.git" git --work-tree="$PWD" -C "$PWD" add -A -n > "$TMP/all" 2> "$TMP/err"; then
    echo "the git simulation failed:" >&2; cat "$TMP/err" >&2; exit 2
fi
sed -E "s/^add '(.*)'$/\1/" "$TMP/all" | sort > "$TMP/files"
[ "$LIST" = 1 ] && cat "$TMP/files"

python3 - "$TMP/files" "$DIGESTS" <<'PY'
import collections, gzip, hashlib, ipaddress, json, os, pathlib, re, sys


def _crash(kind, err, tb):          # a crash must never read as "found" or as "clean"
    import traceback
    traceback.print_exception(kind, err, tb)
    print("the check could not run", file=sys.stderr)
    os._exit(2)


sys.excepthook = _crash

files = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8", errors="surrogateescape") if l.strip()]
site = {k: v for k, v in json.load(open("site.local.json")).items() if not k.startswith("_")}

# what is in the files
checks = [(f"site value {k}", re.compile(rf"(?<![\w.]){re.escape(v)}(?![\w]|\.\d)"))
          for k, v in sorted(site.items(), key=lambda kv: -len(kv[1]))]
D = "\\$"
checks += [
    ("password hash", re.compile(D + r"(?:1|2[abxy]?|5|6|7|y|gy|sha1|md5|argon2(?:id|i|d)|pbkdf2-[\w-]+)"
                                 + D + r"[./A-Za-z0-9$=,+-]{8,}")),
    ("private key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----|PuTTY-User-Key-File-\d")),
]
ALLOWED_HOMES = {"pi", "cowrie", "influxdb", "user", "devuser"}
home = re.compile(r"(?:/home/|/Users/|[A-Za-z]:\\\\?Users\\\\?)([A-Za-z0-9._-]+)")
nets = [ipaddress.ip_network(site["lab_net"]), ipaddress.ip_network(site["student_net"])]
v4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w]|\.\d)")
prefix6 = site["lab_resolver6"].split("::")[0].lower()
values = set(site.values())


def lab_addresses(text):
    out = []
    for m in v4.finditer(text):
        try:
            a = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if m.group(0) not in values and any(a in n for n in nets):
            out.append(m.group(0))
    low = text.lower()
    i = low.find(prefix6)
    while i >= 0:
        j = i + len(prefix6)
        while j < len(low) and low[j] in "0123456789abcdef:":
            j += 1
        if low[i:j] not in {v.lower() for v in values}:
            out.append(low[i:j])
        i = low.find(prefix6, j)
    return out


allow = {}
allow_file = pathlib.Path("tools/publish_check.allow")
if allow_file.is_file():
    for line in allow_file.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            path, kind, digest = line.split("\t")[:3]
            if kind.startswith("site value") or kind == "lab address":
                print(f"REFUSED  {allow_file}: a {kind} cannot be allowed")
                sys.exit(2)
            allow[(path, kind)] = digest

found = collections.defaultdict(lambda: collections.defaultdict(list))
for f in files:
    p = pathlib.Path(f)
    try:
        raw = p.read_bytes()
        if f.endswith(".gz"):
            raw = gzip.decompress(raw)
    except OSError as e:
        found[f][f"unreadable ({e.__class__.__name__})"].append(f)
        continue
    text = raw.decode("utf-8", errors="replace")
    # and as text again, for a value inside a JSON or Python string right after an
    # escape (after a written-out newline, its letter n would hide where the value starts)
    plain = (text.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
             .replace('\\"', '"'))
    for kind, rx in checks:
        found[f][kind] += max(([m.group(0) for m in rx.finditer(s)] for s in (text, plain)), key=len)
    found[f]["lab address"] += max((lab_addresses(s) for s in (text, plain)), key=len)
    found[f]["home path"] += max(([m.group(0) for m in home.finditer(s) if m.group(1) not in ALLOWED_HOMES]
                                  for s in (text, plain)), key=len)

hits = collections.defaultdict(collections.Counter)
allowed, digests = [], {}
for f, kinds in found.items():
    for kind, strings in kinds.items():
        if not strings:
            continue
        d = hashlib.sha256("\n".join(sorted(strings)).encode()).hexdigest()[:16]
        digests[(f, kind)] = d
        if allow.get((f, kind)) == d:
            allowed.append((f, kind, len(strings)))
        else:
            hits[f][kind] += len(strings)

tops = collections.Counter(f.split("/")[0] + ("/" if "/" in f else "") for f in files)
print(f"published: {len(files)} files")
for t, n in sorted(tops.items()):
    print(f"  {t:28s} {n}")
if allowed:
    print(f"allowed by tools/publish_check.allow: {len(allowed)} hits in "
          f"{len({a[0] for a in allowed})} files (upstream sample data, unchanged)")
stale = [k for k in allow if k not in digests or digests[k] != allow[k]]
for path, kind in stale:
    if (path, kind) not in digests:
        print(f"  note: allow entry no longer needed: {path}\t{kind}")
if sys.argv[2] == "1":
    for (f, kind), d in sorted(digests.items()):
        print(f"digest  {f}\t{kind}\t{d}")
if not hits:
    print("OK: no site value, lab address, password hash, private key or dev-side home path "
          "in any of them")
    sys.exit(0)
print(f"FOUND in {len(hits)} files (file: kind x count; values are never printed):")
for f in sorted(hits):
    print(f"  {f}: " + ", ".join(f"{k} x{n}" for k, n in sorted(hits[f].items())))
sys.exit(1)
PY
