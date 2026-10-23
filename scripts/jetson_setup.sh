#!/usr/bin/env bash
#
# jetson_setup.sh - make Jetson 2, 3 or 4 a model server like Jetson 1:
# ollama 0.34.0 with the JetPack 6 GPU libraries, as a service, and MAXN_SUPER.
#
# The same script runs on each of the three Jetsons; it works out which one it is
# on and refuses to run on Jetson 1, which is already set up and in use.
#
# Run it FROM FEDORA-DEV, once per Jetson (example for Jetson 2):
#
#   cd ~/projects/honeypot
#   ssh -t lab-j2 'sudo bash ~/ollama-0.34.0/jetson_setup.sh' 2>&1 \
#     | tee docs/jetson-setup-j2-$(date +%Y%m%d-%H%M).log
#
# The log is written on the dev machine, not on the Jetson.
#
# It stops at the first error (set -e). Every step checks whether it is already done
# and skips itself, so after any stop - or a reboot - the fix is to deal with the
# cause and run the same command again.
#
# Steps, in order:
#   1  preflight: root, arm64, JetPack 6, which Jetson, staged files and checksums
#   2  install the ollama program and the JetPack 6 GPU libraries into /usr/local
#   3  the `ollama` system account (GPU access), and `user` in its group
#   4  the service file and Jetson 1's three settings
#   5  start the service now and at every boot; wait until it answers
#   6  check ollama found the GPU (CUDA), not just the CPU
#   7  Jetson 4 only: register the base model copied from Jetson 1
#   8  power mode MAXN_SUPER (may ask to reboot; see docs/jetson-ollama-setup.md)
#   9  read-only summary
#
# Everything it writes mirrors Jetson 1 as read on 2026-10-02
# (docs/jetson-ollama-setup.md).

set -Eeuo pipefail

VERSION=0.34.0
LOGIN_USER=user
STAGE="$(getent passwd "$LOGIN_USER" | cut -d: -f6)/ollama-$VERSION"
MODEL_DIR="$(getent passwd "$LOGIN_USER" | cut -d: -f6)/models/qwen2.5-3b-instruct-q4_K_M"
MODEL_NAME=qwen2.5:3b-instruct-q4_K_M
MODEL_BLOB=sha256-5ee4f07cdb9beadbbb293e85803c569b01bd37ed059d2715faa7bb405f31caa6
UNIT=/etc/systemd/system/ollama.service
OVERRIDE=/etc/systemd/system/ollama.service.d/override.conf

STEP=0
CURRENT=startup

step() { STEP=$((STEP + 1)); CURRENT="$1"; printf '\n=== step %d: %s ===\n' "$STEP" "$1"; }
note() { printf '    %s\n' "$*"; }
stop_banner() {
  printf '\n================================================================\n'
  printf 'STOPPED at step %d (%s)\n' "$STEP" "$CURRENT"
  printf '  %s\n' "$@"
  printf 'No later step was attempted.\n\n'
  printf 'Every step is safe to repeat. Fix the cause and run the same\n'
  printf 'command again - completed steps detect themselves and are skipped.\n'
  printf '================================================================\n'
}
die() { stop_banner "$*" >&2; exit 1; }
on_err() { local rc=$? line=${BASH_LINENO[0]}; stop_banner "line $line, exit status $rc" >&2; }
trap on_err ERR

printf '=== Jetson model-server setup ===\n'
printf 'host   : %s\n' "$(hostname)"
printf 'date   : %s\n' "$(date)"
printf 'staging: %s\n' "$STAGE"

# ---------------------------------------------------------------- 1. preflight
step "preflight"
[ "$(id -u)" -eq 0 ] || die "must run as root - use: sudo bash $0"
arch=$(dpkg --print-architecture)
[ "$arch" = arm64 ] || die "architecture is $arch, expected arm64"
grep -q '^# R36 ' /etc/nv_tegra_release || die "not JetPack 6 (L4T R36): $(head -1 /etc/nv_tegra_release)"
host=$(hostname)
case "$host" in
  jetson2|jetson3|jetson4) note "this is $host" ;;
  jetson1) die "this is Jetson 1, which is already set up and serving the relay - not touching it" ;;
  *) die "unexpected hostname '$host' (expected jetson2, jetson3 or jetson4)" ;;
esac
id "$LOGIN_USER" >/dev/null 2>&1 || die "login user '$LOGIN_USER' not found"
for f in ollama-linux-arm64.tar.zst ollama-linux-arm64-jetpack6.tar.zst sha256sum.txt; do
  [ -f "$STAGE/$f" ] || die "missing $STAGE/$f - copy offline/ollama-$VERSION/ from the dev machine"
done
(cd "$STAGE" && grep -E 'ollama-linux-arm64(-jetpack6)?\.tar\.zst$' sha256sum.txt | sha256sum -c --quiet -) \
  || die "staged archives do not match the release checksums - copy them again"
note "staged archives present, checksums match"
grep -q '< POWER_MODEL ID=2 NAME=MAXN_SUPER >' /etc/nvpmodel.conf \
  || die "power mode 2 is not MAXN_SUPER on this board; not guessing"
command -v zstd >/dev/null || die "zstd not installed (needed to unpack the archives)"

# ---------------------------------------------------------------- 2. install
step "install ollama $VERSION"
if /usr/local/bin/ollama --version 2>&1 | grep -q "version is $VERSION" \
   && [ -f /usr/local/lib/ollama/cuda_jetpack6/libcudart.so.12 ]; then
  note "ollama $VERSION and the JetPack 6 libraries already installed - skipped"
else
  if systemctl is-active --quiet ollama 2>/dev/null; then
    systemctl stop ollama
    note "stopped the running ollama service before replacing its files"
  fi
  tar -C /usr/local --zstd -xf "$STAGE/ollama-linux-arm64.tar.zst"
  tar -C /usr/local --zstd -xf "$STAGE/ollama-linux-arm64-jetpack6.tar.zst"
  /usr/local/bin/ollama --version 2>&1 | grep -q "version is $VERSION" \
    || die "installed, but /usr/local/bin/ollama does not report $VERSION"
  note "unpacked into /usr/local (bin/ollama, lib/ollama, lib/ollama/cuda_jetpack6)"
fi

# ---------------------------------------------------------------- 3. account
step "ollama account"
if id ollama >/dev/null 2>&1; then
  note "account ollama exists - not recreated"
else
  useradd -r -s /bin/false -U -m -d /usr/share/ollama ollama
  note "created system account ollama, home /usr/share/ollama"
fi
usermod -a -G video,render ollama
usermod -a -G ollama "$LOGIN_USER"
note "ollama in groups: $(id -nG ollama)"
note "$LOGIN_USER in group ollama: $(id -nG "$LOGIN_USER" | tr ' ' '\n' | grep -qx ollama && echo yes)"

# ---------------------------------------------------------------- 4. service files
step "service and settings files"
changed=0
write_if_different() {   # path, then content on stdin
  local path=$1 tmp
  tmp=$(mktemp)
  cat > "$tmp"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"; note "$path already correct - unchanged"
  else
    mkdir -p "$(dirname "$path")"
    install -m 0644 "$tmp" "$path"; rm -f "$tmp"; changed=1; note "wrote $path"
  fi
}
write_if_different "$UNIT" <<'EOF'
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/snap/bin"

[Install]
WantedBy=default.target
EOF
write_if_different "$OVERRIDE" <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0"
Environment="OLLAMA_KEEP_ALIVE=-1"
Environment="OLLAMA_CONTEXT_LENGTH=8192"
EOF

# ---------------------------------------------------------------- 5. start
step "start the service"
systemctl daemon-reload
systemctl enable ollama >/dev/null 2>&1
started_at=$(date +%s)
if [ "$changed" -eq 1 ] || ! systemctl is-active --quiet ollama; then
  systemctl restart ollama
  note "started (enabled at boot)"
else
  started_at=$(systemctl show -p ActiveEnterTimestamp --value ollama | xargs -I{} date -d {} +%s)
  note "already running with these settings - left alone"
fi
ver=""
for _ in $(seq 1 60); do
  ver=$(curl -s --max-time 2 http://127.0.0.1:11434/api/version || true)
  [ -n "$ver" ] && break
  sleep 1
done
[ -n "$ver" ] || die "ollama did not answer on 127.0.0.1:11434 within 60 s - see: journalctl -u ollama -n 50"
echo "$ver" | grep -q "\"$VERSION\"" || die "ollama answered, but not as $VERSION: $ver"
note "answering: $ver"

# ---------------------------------------------------------------- 6. GPU
step "check the GPU is used"
gpu=""
for _ in $(seq 1 30); do
  gpu=$(journalctl -u ollama --since "@$started_at" --no-pager 2>/dev/null | grep 'msg="inference compute"' | tail -1 || true)
  [ -n "$gpu" ] && break
  sleep 1
done
[ -n "$gpu" ] || die "no 'inference compute' line in the ollama log - see: journalctl -u ollama -n 50"
note "${gpu#*msg=}"
echo "$gpu" | grep -q 'library=CUDA' \
  || die "ollama is not using the GPU (no library=CUDA). The JetPack 6 libraries did not load."

# ---------------------------------------------------------------- 7. base model (Jetson 4)
step "base model"
if [ "$host" != jetson4 ]; then
  note "only Jetson 4 gets the base model now - skipped on $host"
elif [ -f "/usr/share/ollama/.ollama/models/blobs/$MODEL_BLOB" ] \
     && ollama list 2>/dev/null | awk '{print $1}' | grep -qx "$MODEL_NAME"; then
  note "$MODEL_NAME already registered with Jetson 1's weights - skipped"
else
  [ -f "$MODEL_DIR/Modelfile" ] && [ -f "$MODEL_DIR/model.gguf" ] \
    || die "staged model missing in $MODEL_DIR - copy offline/models/qwen2.5-3b-instruct-q4_K_M/ from the dev machine"
  (cd "$MODEL_DIR" && sha256sum -c --quiet SHA256SUMS) || die "staged model.gguf does not match its checksum"
  note "registering $MODEL_NAME (copies 1.9 GB into ollama's store; takes a minute)"
  (cd "$MODEL_DIR" && ollama create "$MODEL_NAME" -f Modelfile)
  [ -f "/usr/share/ollama/.ollama/models/blobs/$MODEL_BLOB" ] \
    || die "registered, but Jetson 1's weights file ($MODEL_BLOB) is not in the store"
  # ollama 0.34 re-lays the file out on create (same tensors, different order), so
  # the registered model's digest differs from Jetson 1's; see docs/jetson-ollama-setup.md.
  note "registered from Jetson 1's weights file"
fi

# ---------------------------------------------------------------- 8. power mode
step "power mode MAXN_SUPER"
mode=$(nvpmodel -q 2>/dev/null | sed -n 's/^NV Power Mode: //p')
if [ "$mode" = MAXN_SUPER ]; then
  note "already MAXN_SUPER - skipped"
else
  note "currently $mode; switching to MAXN_SUPER (mode 2)"
  note "IF IT ASKS TO REBOOT: answer yes. Afterwards run the same command again."
  nvpmodel -m 2 || true
  mode=$(nvpmodel -q 2>/dev/null | sed -n 's/^NV Power Mode: //p')
  if [ "$mode" = MAXN_SUPER ]; then
    note "now MAXN_SUPER"
  else
    note "still $mode: the change takes effect at the next reboot."
    note "Reboot this Jetson when convenient, then run the same command again to confirm."
  fi
fi

# ---------------------------------------------------------------- 9. summary
step "summary (read-only)"
note "ollama      : $(curl -s --max-time 2 http://127.0.0.1:11434/api/version)"
note "service     : $(systemctl is-active ollama), $(systemctl is-enabled ollama) at boot"
note "listening   : $(ss -ltnH 'sport = :11434' | awk '{print $4}' | tr '\n' ' ')"
note "models      : $(ollama list 2>/dev/null | awk 'NR>1{print $1}' | tr '\n' ' ')"
note "power mode  : $(nvpmodel -q 2>/dev/null | sed -n 's/^NV Power Mode: //p')"
printf '\n=== %s done ===\n' "$host"
