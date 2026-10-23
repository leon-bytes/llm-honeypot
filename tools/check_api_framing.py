#!/usr/bin/env python3
"""
check_api_framing.py - verify that a recorded Docker API capture kept its
multiplexed stream bodies intact.

WHY THIS EXISTS: the honeypot must reproduce Docker's 8-byte frame headers on
/containers/*/logs and on the exec stream, byte for byte - a client that
de-multiplexes clean text instead sees corruption and knows the box is fake
(one of the things that would give the honeypot away). The first Phase 1
capture stored bodies only as UTF-8-with-replacement, which silently destroyed
any frame length byte >= 0x80, i.e. every frame carrying 128 bytes or more. The
influxdb log record lost its very first frame length that way.

So: for every record whose body is a multiplexed stream, walk the frames and
check they tile the body exactly. Run it on both phase files after any capture.

    .venv/bin/python tools/check_api_framing.py gt_api_phase1_2026-09.json ...

Exit status 0 means every stream body parses; 1 means at least one is damaged.
"""
from __future__ import annotations
import base64, json, sys

# Paths whose bodies are multiplexed streams. /logs without a tty and
# /exec/*/start without a tty both use the framing; /stats and the rest are
# plain JSON.
STREAM_MARKERS = ("/logs", "/start")


def is_stream(rec):
    """A record carries framed output if it is a log read, or an exec start that
    actually returned a multiplexed stream (Docker says so in Content-Type)."""
    path = rec.get("path", "")
    ctype = " ".join(v for k, v in rec.get("headers", []) if k.lower() == "content-type")
    if "multiplexed-stream" in ctype:
        return True
    return "/logs" in path and rec.get("status") == 200 and rec.get("body")


def raw_body(rec):
    """The authoritative bytes: body_b64 when present, else the text."""
    if "body_b64" in rec:
        return base64.b64decode(rec["body_b64"]), "b64"
    return rec.get("body", "").encode("utf-8", "surrogateescape"), "text"


def walk(raw):
    """Walk the frames. Returns (frames, error_or_None)."""
    frames, i = [], 0
    while i < len(raw):
        if i + 8 > len(raw):
            return frames, f"truncated header at byte {i} ({len(raw) - i} bytes left)"
        stream = raw[i]
        if stream not in (0, 1, 2):
            return frames, (f"frame {len(frames)} at byte {i}: stream byte is "
                            f"0x{stream:02x}, not 0x00/0x01/0x02 - the header is damaged")
        if raw[i + 1:i + 4] != b"\x00\x00\x00":
            return frames, (f"frame {len(frames)} at byte {i}: bytes 1-3 are "
                            f"{raw[i + 1:i + 4]!r}, expected three zero bytes")
        ln = int.from_bytes(raw[i + 4:i + 8], "big")
        if i + 8 + ln > len(raw):
            return frames, (f"frame {len(frames)} at byte {i}: header claims {ln} "
                            f"payload bytes but only {len(raw) - i - 8} remain")
        frames.append((stream, ln))
        i += 8 + ln
    return frames, None


def main(paths):
    bad = 0
    for path in paths:
        try:
            recs = json.load(open(path, encoding="utf-8"))
        except Exception as e:
            print(f"[framing] {path}: cannot read ({e})")
            bad += 1
            continue
        if isinstance(recs, dict):
            recs = recs.get("requests", [])
        streams = [r for r in recs if is_stream(r)]
        print(f"\n[framing] {path}: {len(recs)} records, {len(streams)} framed stream(s)")
        for r in streams:
            raw, src = raw_body(r)
            frames, err = walk(raw)
            tag = f"n={r['n']:>3} {r['path'][:46]:46.46s}"
            if err:
                bad += 1
                print(f"  DAMAGED  {tag}  [{src}] {err}")
                if src == "text":
                    print(f"           body has {r['body'].count(chr(0xFFFD))} U+FFFD "
                          f"replacement char(s) - recorded lossily, re-record with the "
                          f"current tool to fix")
            else:
                big = sum(1 for _, ln in frames if ln >= 128)
                print(f"  ok       {tag}  [{src}] {len(frames)} frame(s), "
                       f"{big} with a length byte >= 0x80")
    print(f"\n[framing] {'FAILED: ' + str(bad) + ' damaged body/bodies' if bad else 'all stream bodies parse cleanly'}")
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
