#!/usr/bin/env bash
# Idempotent installer for BTC Hunt on Ubuntu 22.04 / 24.04 EC2 instances.
# Run as root:  sudo bash deploy/ec2/install.sh
#
# Safe to re-run: it never overwrites /etc/btc-hunt.env (which may contain
# your Basic-auth password) and only appends the data-volume fstab entry once.
#
# Environment overrides:
#   APP_DIR       app checkout                     (default /opt/btc-hunt)
#   DATA_DIR      persistent dataset directory    (default /var/lib/btc-hunt)
#   DATA_DEVICE   optional secondary EBS device  (default "" = root volume)
#   BIND          gunicorn listen address        (default 127.0.0.1:8000)
#   SERVICE_USER  unprivileged OS user           (default btc-hunt)
#   ENABLE_UFW    set to 1 to enable host fw     (default 0; SG is the firewall)
#   RENDER_ONLY   set to 1 to just render configs into RENDER_DIR and exit
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/btc-hunt}"
DATA_DIR="${DATA_DIR:-/var/lib/btc-hunt}"
DATA_DEVICE="${DATA_DEVICE:-}"
ENV_FILE="${ENV_FILE:-/etc/btc-hunt.env}"
SERVICE_USER="${SERVICE_USER:-btc-hunt}"
BIND="${BIND:-127.0.0.1:8000}"
ENABLE_UFW="${ENABLE_UFW:-0}"
RENDER_ONLY="${RENDER_ONLY:-0}"
RENDER_DIR="${RENDER_DIR:-/tmp/btc-hunt-config}"

log() { echo "[btc-hunt-install] $*"; }

TPL_DIR="$APP_DIR/deploy/ec2"

if [ ! -f "$APP_DIR/btc_hunt.py" ] || [ ! -f "$APP_DIR/requirements.txt" ]; then
  echo "ERROR: clone the repo into $APP_DIR before running this script" >&2
  exit 1
fi
if [ ! -f "$TPL_DIR/btc-hunt.service.tpl" ]; then
  echo "ERROR: this checkout has no deploy/ec2/ directory (wrong branch?)" >&2
  exit 1
fi

render_unit() {
  sed -e "s|__APP_DIR__|$APP_DIR|g" \
      -e "s|__SERVICE_USER__|$SERVICE_USER|g" \
      -e "s|__ENV_FILE__|$ENV_FILE|g" \
      -e "s|__BIND__|$BIND|g" \
      "$TPL_DIR/btc-hunt.service.tpl" > "$1"
  chmod 0644 "$1"
}

render_nginx() {
  sed -e "s|__BIND__|$BIND|g" \
      "$TPL_DIR/nginx-btc-hunt.conf.tpl" > "$1"
  chmod 0644 "$1"
}

# Preview mode needs no root and changes nothing on the host.
if [ "$RENDER_ONLY" = "1" ]; then
  mkdir -p "$RENDER_DIR"
  render_unit  "$RENDER_DIR/btc-hunt.service"
  render_nginx "$RENDER_DIR/nginx-btc-hunt.conf"
  log "rendered configs into $RENDER_DIR"
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (sudo bash deploy/ec2/install.sh)" >&2
  exit 1
fi

for cmd in python3 git nginx systemctl curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: '$cmd' is missing. Install prerequisites first:" >&2
    echo "  sudo apt-get install -y python3 python3-venv python3-pip git nginx curl" >&2
    exit 1
  fi
done

trap 'echo "[btc-hunt-install] FAILED at line $LINENO" >&2; systemctl status btc-hunt --no-pager -l || true; journalctl -u btc-hunt -n 40 --no-pager || true' ERR

# 1. Unprivileged service account -------------------------------------------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  log "creating system user $SERVICE_USER"
  useradd --system --user-group --no-create-home --home-dir /nonexistent \
          --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# 2. Persistent data directory (optional dedicated EBS volume) --------------
mkdir -p "$DATA_DIR"
if [ -n "$DATA_DEVICE" ]; then
  # Nitro instances expose a second EBS volume as /dev/nvme1n1 even when the
  # block device mapping says /dev/sdf. Wait briefly for it to appear.
  for _ in $(seq 1 10); do [ -b "$DATA_DEVICE" ] && break; sleep 2; done
  if [ -b "$DATA_DEVICE" ]; then
    FSTYPE="$(blkid -o value -s TYPE "$DATA_DEVICE" || true)"
    if [ -z "$FSTYPE" ]; then
      log "formatting $DATA_DEVICE as ext4"
      mkfs.ext4 -F -L btchunt-data "$DATA_DEVICE"
      FSTYPE=ext4
    fi
    UUID="$(blkid -o value -s UUID "$DATA_DEVICE")"
    if ! grep -q "UUID=$UUID" /etc/fstab; then
      printf 'UUID=%s %s %s defaults,nofail,noatime 0 2\n' \
        "$UUID" "$DATA_DIR" "$FSTYPE" >> /etc/fstab
    fi
    mount -a
    log "mounted $DATA_DEVICE ($FSTYPE) at $DATA_DIR"
  else
    log "WARNING: $DATA_DEVICE not found; using the root volume for $DATA_DIR"
  fi
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"

# 3. Environment file (never overwrite an existing one) ---------------------
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
# Read by the btc-hunt systemd unit. Keep this file private (mode 0600).
DISK_PATH=$DATA_DIR
ESPLORA_URL=https://blockstream.info/api
PYTHONUNBUFFERED=1

# Optional HTTP Basic auth for the dashboard. Uncomment BOTH lines, then
# sudo systemctl restart btc-hunt
#APP_USER=admin
#APP_PASSWORD=change-me

# Optional: comma-separated .gz mirror URLs, tried BEFORE the built-in
# public mirrors. Leave commented to use the built-in defaults. Restart with
# sudo systemctl restart btc-hunt after editing this file.
#DATASET_URLS=https://my-mirror.example/bitcoin.hex.gz

# Optional: dataset download / build time budgets in seconds. Defaults are
# 1800 (30 min) for the download and 7200 (2 h) for the two parse passes.
#DOWNLOAD_DEADLINE_SECS=1800
#BUILD_DEADLINE_SECS=7200

# Set to 1 to verify Base58Check checksums on untrusted custom dumps (slower).
#DATASET_VERIFY_CHECKSUM=0

# Skip TSV rows with balance <= this value. Default 0 drops zero/negative
# balances; -1 keeps every row. No effect on text/hex dumps without balances.
#DATASET_MIN_BALANCE=0

# Prefer LoyceV dated balance TSVs (default 1). Set to 0 to prefer the
# smaller text-only dumps. Restart after changing this file.
#DATASET_PREFER_BALANCE_TSV=1

# Esplora access for nonce-reuse scans, the automatic balance gate and the
# /results balance checks: pace requests, cache responses, cap one uploaded
# address file. Defaults: 0.3 s spacing, 2 retries, 4096 entries, 5000
# addresses, 2 MB of text.
# TWO mainnet endpoints are used by default (ESPLORA_URL plus
# https://mempool.space/api). On HTTP 429 the endpoint that answered is parked
# for a cooldown and the request fails over to the other one. Setting
# ESPLORA_URLS replaces that list entirely - never put a testnet endpoint here.
#ESPLORA_URLS=https://blockstream.info/api,https://mempool.space/api
#ESPLORA_MIN_INTERVAL=0.3
#ESPLORA_MAX_RETRIES=2
#ESPLORA_CACHE_SIZE=4096
# Per-endpoint 429 cooldown cap and adaptive spacing cap (seconds).
#ESPLORA_MAX_BACKOFF_SECS=60
#ESPLORA_PACE_MAX_SECS=2
# User-Agent sent to Esplora. Public instances throttle the stock
# python-requests agent harder than an identified one.
#ESPLORA_USER_AGENT=btc-hunt (github.com/Phaviwylera/edurep)
#NONCE_MAX_ADDRESSES=5000
#NONCE_MAX_UPLOAD_BYTES=2000000

# Bloom false-positive rate. Default 0.000001 (~183 MB bitset for 51M rows,
# k~19). Rebuild the bloom on /data after changing it (Download & build bloom
# reuses the cached .gz). Lower = fewer false HITs, larger/slower build.
#BLOOM_FP_RATE=0.000001

# Max unique hit addresses checked by one /results "Check balances" run, and
# how many extra passes to make over addresses that were still throttled
# (HTTP 429) when a pass ended.
#VERIFY_MAX_ADDRESSES=5000
#VERIFY_RETRY_PASSES=3

# Live-check every Bloom candidate at hit time and skip 0-BTC addresses.
# Set AUTO_VERIFY_HITS=0 for the old save-candidate-first behaviour;
# AUTO_VERIFY_MIN_SATS=0 keeps zero-balance hits with balance badges.
#AUTO_VERIFY_HITS=1
#AUTO_VERIFY_MIN_SATS=1

# Randstorm range chunking: split large ranges automatically and cap one
# accepted run. Defaults: 5,000,000 ms per chunk, 4,000,000,000 ms total
# (~46.3 days of timestamps, ~800 chunks, many hours of work). Stop keeps
# everything found so far, so a long run can be abandoned at any point.
#RANDSTORM_MAX_MS=5000000
#RANDSTORM_MAX_TOTAL_MS=4000000000

# Allow the dashboard's Kill all jobs button to replace this Gunicorn worker.
# Set to 0 to only stop jobs without restarting the worker.
#BTC_HUNT_WORKER_RESTART=1
EOF
  chmod 0600 "$ENV_FILE"
  log "created $ENV_FILE (add APP_USER / APP_PASSWORD there to require login)"
fi

# 4. Virtualenv + pinned dependencies ---------------------------------------
if [ ! -x "$APP_DIR/.venv/bin/python" ]; then
  log "creating virtualenv"
  python3 -m venv "$APP_DIR/.venv"
fi
log "installing requirements"
"$APP_DIR/.venv/bin/pip" install --disable-pip-version-check -q -r "$APP_DIR/requirements.txt"
# Code stays root-owned/read-only for the service user; the process only ever
# writes to DATA_DIR. This also keeps `sudo git pull` working on the checkout.
chmod -R a+rX "$APP_DIR"

# The deploy command lives OUTSIDE the git checkout so that `git reset --hard`
# during an update cannot corrupt the script that is currently executing.
install -m 0755 "$APP_DIR/deploy/ec2/update.sh" /usr/local/bin/btc-hunt-update
log "installed /usr/local/bin/btc-hunt-update"
install -m 0755 "$APP_DIR/deploy/ec2/reset.sh" /usr/local/bin/btc-hunt-reset
log "installed /usr/local/bin/btc-hunt-reset"

# 5. systemd unit ------------------------------------------------------------
log "installing systemd unit"
render_unit /etc/systemd/system/btc-hunt.service
systemctl daemon-reload
systemctl enable btc-hunt.service

# 6. nginx reverse proxy ------------------------------------------------------
log "installing nginx site"
render_nginx /etc/nginx/sites-available/btc-hunt
rm -f /etc/nginx/sites-enabled/default
ln -sfn /etc/nginx/sites-available/btc-hunt /etc/nginx/sites-enabled/btc-hunt
nginx -t
systemctl enable --now nginx
systemctl reload nginx

# 7. Start / restart the app ---------------------------------------------------
log "starting btc-hunt"
systemctl restart btc-hunt.service

if [ "$ENABLE_UFW" = "1" ] && command -v ufw >/dev/null 2>&1; then
  ufw allow OpenSSH
  ufw allow 'Nginx Full'
  ufw --force enable
  log "ufw enabled"
fi

# 8. Smoke test ----------------------------------------------------------------
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1/health >/dev/null 2>&1 && break
  sleep 1
done
printf 'health: '
curl -fsS http://127.0.0.1/health
echo
log "done — dashboard at http://<this-instance-public-ip>/ (port 80)"
