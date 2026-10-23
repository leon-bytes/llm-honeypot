#!/usr/bin/env python3
"""Stage arm64 container images for Ground Truth Pi as docker-archive tarballs.

The dev machine is x86_64 and has no Docker daemon, but it has skopeo, which can pull
another architecture's image without running it and write a tarball that
`docker load` accepts. The lab has no internet (hard rule 2), so this is how the
images get in.

THE STACK: one coherent home-sensor setup, not three unrelated installs -
mosquitto receives readings from sensors around the house, Node-RED reacts to
them, InfluxDB stores them over time. Each part feeds the next, it is what
people build from tutorials, and it is exactly the kind of box someone would
expose the Docker API on to manage remotely. That gives the paper a one-sentence
description of the simulated machine.

Images are pinned by arm64 manifest digest, not by tag, so re-staging produces
byte-identical tarballs even after a tag moves. To adopt newer images, run with
--refresh-digests, check what it prints, and paste the new digests into IMAGES.

Usage:
    python3 tools/fetch_docker_images.py                    # copy pinned digests
    python3 tools/fetch_docker_images.py --dry-run          # verify pins only
    python3 tools/fetch_docker_images.py --refresh-digests  # what the tags point at now
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile

ARCH, OS = "arm64", "linux"

# repo, tag (for reference and the name docker shows), tarball, pinned arm64 digest.
# Digests resolved 2026-09-27.
IMAGES = [
    ("docker.io/library/eclipse-mosquitto", "2", "eclipse-mosquitto-2.tar",
     "sha256:38c0da4f2ef84284d47b3b3eeea1cb3bdeabe81ee10caf0cd5c5ff61ee3ea408"),
    ("docker.io/nodered/node-red", "4.1", "node-red-4.1.tar",
     "sha256:c81912d66cb3639170484395ada550c94dfe0a56289cfaec3c8e6dec31f0d164"),
    ("docker.io/library/influxdb", "2.7-alpine", "influxdb-2.7-alpine.tar",
     "sha256:991673dc2d237bd79b15d6627410d72de111387e7dac673dbb92cf3333ffcc8c"),
]

# Images staged for the previous stack, removed when this runs.
SUPERSEDED = ["nginx-alpine.tar", "redis-7-alpine.tar"]


def load_name(repo: str, tag: str) -> str:
    """What `docker load` should call the image: drop the registry prefix and
    the library/ namespace, exactly as docker would display it."""
    short = repo.removeprefix("docker.io/").removeprefix("library/")
    return f"{short}:{tag}"


def run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{p.stderr.strip()}")
    return p.stdout


def inspect(ref: str) -> dict:
    return json.loads(run(["skopeo", "inspect", "--override-os", OS,
                           "--override-arch", ARCH, f"docker://{ref}"]))


def verify_archive(path: pathlib.Path) -> str:
    """Read the architecture out of a docker-archive tarball's image config."""
    with tarfile.open(path) as tf:
        manifest = json.loads(tf.extractfile("manifest.json").read())
        cfg = json.loads(tf.extractfile(manifest[0]["Config"]).read())
        return f"{cfg.get('architecture')}/{cfg.get('os')}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="offline/images")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="re-copy even if a verified archive is already staged")
    ap.add_argument("--refresh-digests", action="store_true",
                    help="print what the tags resolve to now and exit")
    args = ap.parse_args()

    if not shutil.which("skopeo"):
        sys.exit("skopeo not found - needed to pull arm64 images on this x86_64 host")

    root = pathlib.Path(__file__).resolve().parent.parent
    outdir = root / args.outdir if not pathlib.Path(args.outdir).is_absolute() \
        else pathlib.Path(args.outdir)

    if args.refresh_digests:
        print("Current arm64 digests for the pinned tags:")
        for repo, tag, _, pinned in IMAGES:
            d = inspect(f"{repo}:{tag}")["Digest"]
            mark = "unchanged" if d == pinned else "CHANGED - update IMAGES"
            print(f"  {repo}:{tag}\n    {d}  ({mark})")
        return

    print(f"[verify] {len(IMAGES)} pinned arm64 digests")
    for repo, tag, fname, digest in IMAGES:
        d = inspect(f"{repo}@{digest}")
        arch = f"{d.get('Architecture')}/{d.get('Os')}"
        if arch != f"{ARCH}/{OS}":
            sys.exit(f"ERROR: {repo}@{digest} is {arch}, not {ARCH}/{OS}")
        print(f"  {load_name(repo, tag):<28} {arch:<12} {digest[:26]}...")

    if args.dry_run:
        print("[dry-run] nothing copied")
        return

    outdir.mkdir(parents=True, exist_ok=True)
    lock = []
    print(f"\n[copy] -> {outdir}")
    for repo, tag, fname, digest in IMAGES:
        dest = outdir / fname
        name = load_name(repo, tag)
        if dest.exists() and not args.force:
            # Resume: a complete, correct archive is kept so a retry after a
            # registry timeout does not re-transfer hundreds of MB. A truncated
            # one fails verification and is re-copied.
            try:
                if verify_archive(dest) == f"{ARCH}/{OS}":
                    print(f"  {fname:<28} {dest.stat().st_size/1e6:6.1f} MB  already staged, verified")
                    lock.append(f"{repo}:{tag}\t{name}\t{fname}\t{dest.stat().st_size}\t{digest}")
                    continue
            except Exception:
                print(f"  {fname:<28} incomplete, re-copying")
        if dest.exists():
            dest.unlink()          # skopeo will not overwrite an existing archive
        run(["skopeo", "copy", "--override-os", OS, "--override-arch", ARCH,
             f"docker://{repo}@{digest}", f"docker-archive:{dest}:{name}"])
        arch = verify_archive(dest)
        if arch != f"{ARCH}/{OS}":
            sys.exit(f"ERROR: {fname} contains {arch}")
        print(f"  {fname:<28} {dest.stat().st_size/1e6:6.1f} MB  {arch}  OK")
        lock.append(f"{repo}:{tag}\t{name}\t{fname}\t{dest.stat().st_size}\t{digest}")

    for old in SUPERSEDED:
        p = outdir / old
        if p.exists():
            p.unlink()
            print(f"  removed superseded {old}")

    lockfile = outdir / "IMAGES.lock"
    lockfile.write_text(
        "# arm64 images staged for Ground Truth Pi - home-sensor stack\n"
        "#   mosquitto: receives sensor readings   Node-RED: automation logic\n"
        "#   InfluxDB:  stores readings over time\n"
        "# Run with docker compose from /root/iot-stack/docker-compose.yml.\n"
        "# Ports are published on 127.0.0.1 only: a scan from outside still finds\n"
        "# just 22 and 2375 (what the honeypot fakes), while ss and the Docker API\n"
        "# show the ports as a real setup would.\n"
        "# repo:tag\tload name\tfile\tbytes\tpinned arm64 digest\n"
        + "\n".join(lock) + "\n", encoding="utf-8")
    print(f"[copy] wrote {lockfile}")


if __name__ == "__main__":
    main()
