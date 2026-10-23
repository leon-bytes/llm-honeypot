#!/usr/bin/env python3
"""
ssh_offer.py - make the two machines look the same before login, and prove it.

Decided 2026-10-13 (the team's decision): the reference machine's sshd is restricted to exactly
the key-exchange, cipher and MAC lists the honeypot's front end offers, in the same
order. This tool does the three things that decision needs, none of which needs a
password (everything here happens before login):

  measure   what a server offers before login, read with the system's `ssh -vv`
            (through tools/capture_frontdoor.py): version string, the offer lists in
            the order sent, the extension message, what a current client negotiates
            and whether it prints the post-quantum warning.
  dropin    the three lines for the reference machine's sshd, written from a measured
            offer of the honeypot (never from a message or from memory).
  verify    start a real sshd of the reference machine's version (the Debian package
            10.0p1-7+deb13u2, in the arm64 userland of offline/debian13-arm64, on
            127.0.0.1 only) with that drop-in, measure it, and compare with the
            honeypot's offer. This is the check BEFORE anything is changed on the
            reference machine.
  compare   two measured offers, field by field; exit 1 if anything differs.

Usage (from the project root, in the venv):

  .venv/bin/python tools/ssh_offer.py measure --host HONEYPOT_IP --port 2222 --jump lab-dev2 \\
      --out ssh_offer_honeypot.json
  .venv/bin/python tools/ssh_offer.py dropin --from ssh_offer_honeypot.json
  .venv/bin/python tools/ssh_offer.py verify --honeypot ssh_offer_honeypot.json
  .venv/bin/python tools/ssh_offer.py measure --host REF_IP --jump lab-dev2 --out ssh_offer_gt.json
  .venv/bin/python tools/ssh_offer.py compare ssh_offer_gt.json ssh_offer_honeypot.json
(REF_IP, HONEYPOT_IP: the reference machine's and the honeypot's addresses, ref_ipv4 and
hp_ipv4 in site.local.json)

`measure` against the reference machine is one connection that is refused before
login. It leaves sshd lines in that machine's journal (volatile) and nothing else; it
is the same connection as the front-door capture's first part (docs/gt-changes.md).

What sshd adds by itself, whatever the configuration says (found 2026-10-13, and the
reason `verify` exists): it ends its key-exchange list with `ext-info-s` and
`kex-strict-s-v00@openssh.com`, and after the key exchange it sends an extension
message with its signature algorithms, `publickey-hostbound@openssh.com` and
`ping@openssh.com`. No setting removes these. The front end has to send the same; a
drop-in alone cannot make the two offers identical. docs/ssh-front-door-decision.md.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

BOX = ROOT / "offline" / "debian13-arm64"
PKGS = ROOT / "offline" / "openssh-gt"
WORK = PKGS / "work"                      # unpacked packages, test keys, test config
# The file's name and content say nothing about a study: a participant with root reads
# it, on both machines. Where the lists come from is recorded in the .source file
# beside it, which stays here.
DROPIN = ROOT / "scripts" / "gt_sshd_dropin" / "10-algorithms.conf"
RECORDED = ROOT / "gt_frontdoor_2026-09.json"
TEST_PORT = 22022
LISTS = ("KEX algorithms", "ciphers ctos", "ciphers stoc", "MACs ctos", "MACs stoc")
# sshd appends these to its key-exchange list itself; they are not algorithms and
# cannot be configured (openssh kex.c, kex_proposal_populate_entries).
MARKERS = ("ext-info-s", "kex-strict-s-v00@openssh.com")


def offer_from(rec: dict) -> dict:
    """The comparable part of a pre-login record (tools/capture_frontdoor.py's)."""
    vv = rec.get("ssh_vv_stderr", "")
    ext = [re.sub(r"^debug\d: ", "", ln) for ln in vv.splitlines()
           if "kex_ext_info" in ln or "SSH2_MSG_EXT_INFO received" in ln]
    return {
        "ident": rec.get("ident"),
        "ends_with_crlf": rec.get("ends_with_crlf"),
        "server_kexinit": rec.get("server_kexinit", {}),
        "negotiated": rec.get("negotiated", {}),
        "auth_methods": rec.get("auth_methods"),
        "extension_messages": ext,
        "strict_kex_in_use": "resetting send seqnr" in vv,
        "post_quantum_warning": "not using a post-quantum key exchange" in vv,
        "refusal": [ln for ln in rec.get("other_stderr_lines", []) if "Permission denied" in ln],
    }


def measure(host: str, port: int, jump: str | None, user: str = "root") -> dict:
    import capture_frontdoor
    rec = capture_frontdoor.preauth(host, port, user, jump)
    out = offer_from(rec)
    out.update({"host": host, "port": port, "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "client": rec.get("client"), "ssh_vv_stderr": rec.get("ssh_vv_stderr")})
    return out


def differences(a: dict, b: dict, na: str, nb: str) -> list[str]:
    """What a client can see differ between two offers. The host key and the address
    in the refusal line belong to each machine and are not compared."""
    out = []
    for k in ("ident", "ends_with_crlf", "auth_methods", "extension_messages",
              "strict_kex_in_use", "post_quantum_warning"):
        if a.get(k) != b.get(k):
            out.append(f"{k}:\n    {na}: {a.get(k)}\n    {nb}: {b.get(k)}")
    for k in sorted(set(a["server_kexinit"]) | set(b["server_kexinit"])):
        la, lb = a["server_kexinit"].get(k, []), b["server_kexinit"].get(k, [])
        if la != lb:
            only_a = [x for x in la if x not in lb]
            only_b = [x for x in lb if x not in la]
            what = (f"only {na}: {only_a}; only {nb}: {only_b}" if only_a or only_b
                    else "same entries, another order")
            out.append(f"{k}: {what}\n    {na}: {','.join(la)}\n    {nb}: {','.join(lb)}")
    na_, nb_ = dict(a["negotiated"]), dict(b["negotiated"])
    if na_ != nb_:
        out.append(f"negotiated by this client:\n    {na}: {na_}\n    {nb}: {nb_}")
    return out


def dropin_text(honeypot: dict, source: str) -> str:
    """The drop-in: the honeypot's three lists without sshd's own markers. Refuses a
    list with an entry the reference machine's sshd did not offer by default, since
    its sshd may not have it."""
    recorded = json.loads(RECORDED.read_text())["preauth"]["server_kexinit"]
    k = honeypot["server_kexinit"]
    for both in (("ciphers ctos", "ciphers stoc"), ("MACs ctos", "MACs stoc")):
        if k[both[0]] != k[both[1]]:
            sys.exit(f"the honeypot offers different {both[0]} and {both[1]}; sshd has one "
                     "setting for both directions. Not written.")
    kex = [x for x in k["KEX algorithms"] if x not in MARKERS]
    for name, have, base in (("KexAlgorithms", kex, recorded["KEX algorithms"]),
                             ("Ciphers", k["ciphers ctos"], recorded["ciphers ctos"]),
                             ("MACs", k["MACs ctos"], recorded["MACs ctos"])):
        unknown = [x for x in have if x not in base]
        if unknown or not have:
            sys.exit(f"{name}: {unknown or 'empty list'} is not in what the reference machine's "
                     "sshd offered when it was recorded. Not written.")
    return (f"KexAlgorithms {','.join(kex)}\n"
            f"Ciphers {','.join(k['ciphers ctos'])}\n"
            f"MACs {','.join(k['MACs ctos'])}\n")


# ------------------------------------------------------------------ the test sshd

def _unpack() -> pathlib.Path:
    """The server package and its two libraries, unpacked next to the .deb files. The
    userland itself is not changed: the programs are lent to it when it is started."""
    debs = sorted(PKGS.glob("*.deb"))
    if len(debs) < 3:
        sys.exit(f"the packages are not in {PKGS} (see docs/ssh-front-door-decision.md, "
                 "'The test sshd')")
    root = WORK / "root"
    if not (root / "usr/sbin/sshd").exists():
        for deb in debs:
            tmp = WORK / "x" / deb.stem
            tmp.mkdir(parents=True, exist_ok=True)
            subprocess.run(["ar", "x", str(deb)], cwd=tmp, check=True)
            data = next(tmp.glob("data.tar.*"))
            root.mkdir(parents=True, exist_ok=True)
            subprocess.run(["tar", "-xf", str(data), "-C", str(root)], check=True)
    etc = WORK / "etc"
    (etc / "sshd_config.d").mkdir(parents=True, exist_ok=True)
    (WORK / "run").mkdir(exist_ok=True)
    for kind, bits in (("ed25519", None), ("rsa", "3072"), ("ecdsa", "256")):
        key = etc / f"ssh_host_{kind}_key"
        if not key.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", kind, *(["-b", bits] if bits else []),
                            "-N", "", "-f", str(key)], check=True)
    # The reference machine's own settings (gt_frontdoor_2026-09.json), with PAM off
    # (there is none to talk to here; it plays no part before login) and test keys.
    (etc / "sshd_config").write_text(
        "Include /etc/sshtest/sshd_config.d/*.conf\nPermitRootLogin yes\n"
        "KbdInteractiveAuthentication no\nUsePAM no\nX11Forwarding yes\nPrintMotd no\n"
        "AcceptEnv LANG LC_* COLORTERM NO_COLOR\nHostKey /etc/sshtest/ssh_host_rsa_key\n"
        "HostKey /etc/sshtest/ssh_host_ecdsa_key\nHostKey /etc/sshtest/ssh_host_ed25519_key\n")
    passwd = (BOX / "rootfs/etc/passwd").read_text()
    import os
    passwd += f"sshd:x:100:65534::/run/sshd:/usr/sbin/nologin\ntester:x:{os.getuid()}:{os.getgid()}::/root:/bin/bash\n"
    (WORK / "passwd").write_text(passwd)
    return root


def _box(root: pathlib.Path, *argv: str) -> list[str]:
    lib = root / "usr/lib/aarch64-linux-gnu"
    wrap = next(lib.glob("libwrap.so.0.*"))
    wtmp = next(lib.glob("libwtmpdb.so.0.*"))
    return [str(BOX / "proot"), "-q", str(BOX / "qemu-aarch64-static"), "-r", str(BOX / "rootfs"),
            "-b", "/dev", "-b", "/proc", "-b", "/sys",
            "-b", f"{root}/usr/sbin/sshd:/usr/sbin/sshd",
            "-b", f"{root}/usr/lib/openssh/sshd-session:/usr/lib/openssh/sshd-session",
            "-b", f"{root}/usr/lib/openssh/sshd-auth:/usr/lib/openssh/sshd-auth",
            "-b", f"{WORK}/etc:/etc/sshtest", "-b", f"{WORK}/run:/run/sshd",
            "-b", f"{wrap}:/usr/lib/aarch64-linux-gnu/libwrap.so.0",
            "-b", f"{wtmp}:/usr/lib/aarch64-linux-gnu/libwtmpdb.so.0",
            "-b", f"{WORK}/passwd:/etc/passwd", "-w", "/root", "/usr/bin/env", "-i",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", *argv]


def test_sshd_offer(dropin: str | None) -> dict:
    """Start the reference machine's sshd version on 127.0.0.1 with `dropin` (None: its
    defaults), measure its offer, stop it. Run as the ordinary user, so the server
    skips the steps that need root; they come after the offer."""
    root = _unpack()
    conf = WORK / "etc/sshd_config.d/50-test.conf"
    conf.unlink(missing_ok=True)
    if dropin is not None:
        conf.write_text(dropin)
    check = subprocess.run(_box(root, "/usr/sbin/sshd", "-t", "-f", "/etc/sshtest/sshd_config"),
                           capture_output=True, text=True)
    if check.returncode:
        sys.exit("sshd refuses this configuration:\n" + check.stdout + check.stderr)
    version = subprocess.run(_box(root, "/usr/sbin/sshd", "-V"), capture_output=True, text=True)
    proc = subprocess.Popen(_box(root, "/usr/sbin/sshd", "-D", "-e", "-f", "/etc/sshtest/sshd_config",
                                 "-p", str(TEST_PORT), "-o", "ListenAddress=127.0.0.1",
                                 "-o", "PidFile=none"),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        import socket
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", TEST_PORT), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.5)
        else:
            sys.exit("the test sshd did not start")
        out = measure("127.0.0.1", TEST_PORT, None)
    finally:
        # the emulator runs sshd as a child of the wrapper: stop both, by process number
        kids = subprocess.run(["pgrep", "-f", f"[s]shd -D -e -f /etc/sshtest/sshd_config -p {TEST_PORT}"],
                              capture_output=True, text=True).stdout.split()
        proc.kill()
        proc.wait()
        for pid in kids:
            subprocess.run(["kill", "-9", pid], capture_output=True)
    out["sshd_version"] = (version.stdout + version.stderr).strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1].strip())
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure", help="read a server's offer before login")
    m.add_argument("--host", required=True)
    m.add_argument("--port", type=int, default=22)
    m.add_argument("--jump", help="SSH alias to go through, e.g. lab-dev2")
    m.add_argument("--out", required=True)
    d = sub.add_parser("dropin", help="write the reference machine's drop-in from a measured offer")
    d.add_argument("--from", dest="src", required=True)
    d.add_argument("--out", default=str(DROPIN))
    v = sub.add_parser("verify", help="try the drop-in on a real sshd of the reference machine's version")
    v.add_argument("--honeypot", required=True, help="the honeypot's measured offer")
    v.add_argument("--dropin", default=str(DROPIN))
    c = sub.add_parser("compare", help="two measured offers")
    c.add_argument("a")
    c.add_argument("b")
    args = ap.parse_args()

    if args.cmd == "measure":
        out = measure(args.host, args.port, args.jump)
        pathlib.Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
        print(f"{out['ident']}")
        for k in LISTS[:1] + ("host key algorithms",) + LISTS[1::2] + ("compression ctos",):
            print(f"  {k:20} {','.join(out['server_kexinit'].get(k, []))}")
        print(f"  negotiated           {out['negotiated'].get('algorithm')} / "
              f"{out['negotiated'].get('server->client', {}).get('cipher')}")
        print(f"  strict key exchange  {'in use' if out['strict_kex_in_use'] else 'NOT in use'}")
        print(f"  post-quantum warning {'printed' if out['post_quantum_warning'] else 'not printed'}")
        print(f"-> {args.out}")
        return 0
    if args.cmd == "dropin":
        text = dropin_text(json.loads(pathlib.Path(args.src).read_text()), args.src)
        path = pathlib.Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        src = json.loads(pathlib.Path(args.src).read_text())
        path.with_suffix(".source").write_text(
            f"{path.name}: the three lists the honeypot's front end offered before login,\n"
            f"measured {src.get('measured_at')} at {src.get('host')}:{src.get('port')} "
            f"({args.src}), without sshd's own two markers.\n")
        print(text, end="")
        print(f"-> {path}")
        return 0
    if args.cmd == "verify":
        honeypot = json.loads(pathlib.Path(args.honeypot).read_text())
        recorded = offer_from(json.loads(RECORDED.read_text())["preauth"])
        print("1. the test sshd with its defaults against the recording of the reference machine")
        default = test_sshd_offer(None)
        print(f"   {default['sshd_version']}")
        diff = differences(default, recorded, "test sshd", "recording")
        print("   " + ("identical: the test sshd stands for the reference machine's" if not diff
                       else "DIFFERENT, so the test proves nothing:\n   " + "\n   ".join(diff)))
        if diff:
            return 2
        print("2. the test sshd with the drop-in against the honeypot")
        restricted = test_sshd_offer(pathlib.Path(args.dropin).read_text())
        diff = differences(restricted, honeypot, "sshd + drop-in", "honeypot")
        if not diff:
            print("   IDENTICAL in everything a client sees before login "
                  "(host key and address apart).")
            return 0
        print(f"   {len(diff)} difference(s) the drop-in does not remove:")
        for d_ in diff:
            print("   - " + d_.replace("\n", "\n   "))
        return 1
    a, b = (json.loads(pathlib.Path(p).read_text()) for p in (args.a, args.b))
    diff = differences(a, b, pathlib.Path(args.a).stem, pathlib.Path(args.b).stem)
    print("identical before login (host key and address apart)" if not diff
          else "\n".join("- " + d_ for d_ in diff))
    return 1 if diff else 0


if __name__ == "__main__":
    sys.exit(main())
