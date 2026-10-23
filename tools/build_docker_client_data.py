#!/usr/bin/env python3
"""What the real docker CLIENT knows by itself, recorded from Ground Truth's own client.

The shell's docker commands (honeypot/dockercli.py) ask the fake API for everything
about the machine. Two kinds of text come from the client alone, and are recorded here
from the real one (tools/docker_cli_oracle.py: Ground Truth's docker-ce-cli 29.8.1 and
its compose and buildx plugins, in the arm64 userland):

  honeypot/docker_help.json     `docker <command> --help`, for every command path the
                                shell answers in code (aliases included)
  honeypot/docker_client.json   the client's half of `docker version` and `docker info`,
                                the order of the keys in their JSON forms, compose's
                                version, and the request body of a plain `docker create`

Run after adding a command path to PATHS in honeypot/dockercli.py:
  .venv/bin/python tools/build_docker_client_data.py
"""
from __future__ import annotations
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
from docker_cli_oracle import Oracle                         # noqa: E402
from honeypot import dockercli                               # noqa: E402

OUT = ROOT / "honeypot"


def main() -> int:
    o = Oracle("base")
    try:
        def run(*argv):
            r = o.run(list(argv))
            if r["exit"] != 0:
                sys.exit(f"docker {' '.join(argv)}: exit {r['exit']}\n{r['output']}")
            return r["output"]

        paths = sorted({" ".join(p) for p in dockercli.PATHS} | set(dockercli.GROUPS)
                       | {"compose", "compose ls", "compose ps", "compose version"})
        help_texts = {p: run(*p.split(), "--help") for p in paths}
        version = json.loads(run("version", "--format", "json"))
        info = json.loads(run("info", "--format", "json"))
        # The body the client POSTs for a plain `docker create IMAGE`: a hundred fields
        # it always sends, whatever the flags. The shell starts from it and changes
        # what the flags change (honeypot/dockercli.py, _run_or_create).
        image = run("images", "--format", "{{.Repository}}:{{.Tag}}").split()[0]
        o.requests.clear()
        run("create", image)
        create_body = next(json.loads(r["request_body"]) for r in o.requests
                           if r["method"] == "POST" and "/containers/create" in r["path"])
        create_body["Image"] = ""
        client = {
            "_comment": "Recorded from the real client by tools/build_docker_client_data.py; "
                        "do not edit by hand.",
            "version_client": version["Client"],
            "version_server_keys": list(version["Server"]),
            "info_keys": [k for k in info if k != "ClientInfo"],
            "info_client": info["ClientInfo"],
            "compose_version": json.loads(run("compose", "version", "--format", "json"))["version"],
            "create_body": create_body,
        }
    finally:
        o.close()
    (OUT / "docker_help.json").write_text(json.dumps(help_texts, indent=1, ensure_ascii=False) + "\n")
    (OUT / "docker_client.json").write_text(json.dumps(client, indent=1, ensure_ascii=False) + "\n")
    print(f"{len(help_texts)} help texts -> honeypot/docker_help.json; client data -> "
          f"honeypot/docker_client.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
