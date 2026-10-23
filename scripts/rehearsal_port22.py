#!/usr/bin/env python3
"""rehearsal_port22.py RUN43 PORT OUT - the rehearsal's run file with the server port in
SSH_CONNECTION and SSH_CLIENT written as 22.

A rehearsal through Cowrie's test port (2222) gets that port back from `env` and
`env | sort`, as a real sshd would; the reference machine was recorded on port 22, and
the scorer masks the client's port but not the server's. This changes nothing else,
so the second score differs from the first only by what the class port will give.
"""
import json
import re
import sys

run, port, out = sys.argv[1], sys.argv[2], sys.argv[3]
rows = json.load(open(run))
for r in rows:
    text = r["model"] or ""
    text = re.sub(rf"^(SSH_CONNECTION=\S+ \d+ \S+) {port}$", r"\1 22", text, flags=re.M)
    text = re.sub(rf"^(SSH_CLIENT=\S+ \d+) {port}$", r"\1 22", text, flags=re.M)
    r["model"] = text
json.dump(rows, open(out, "w"), indent=1)
