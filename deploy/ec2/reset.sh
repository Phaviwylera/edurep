#!/usr/bin/env bash
# Kill every in-process BTC Hunt job and start from a clean worker.
#
#   sudo btc-hunt-reset              # force-deploy latest main, then restart
#   sudo btc-hunt-reset --no-deploy  # restart the current checkout only
#
# Installed to /usr/local/bin/btc-hunt-reset by install.sh. It lives outside
# the checkout so a `git reset --hard` during the forced update cannot change
# the script that is currently running.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (sudo btc-hunt-reset)" >&2
  exit 1
fi

APP_DIR="${APP_DIR:-/opt/btc-hunt}"
ENV_FILE="${ENV_FILE:-/etc/btc-hunt.env}"
DISK_PATH="$(sed -n 's/^DISK_PATH=//p' "$ENV_FILE" 2>/dev/null | tail -n 1)"
DISK_PATH="${DISK_PATH:-/var/lib/btc-hunt}"
BUSY_MARKER="$DISK_PATH/.btc-hunt-busy"
BUSY_PID_FILE="$DISK_PATH/.btc-hunt-busy.pid"
export APP_DIR ENV_FILE

NO_DEPLOY=0
case "${1:-}" in
  --no-deploy) NO_DEPLOY=1 ;;
  "") ;;
  *) echo "usage: $0 [--no-deploy]" >&2; exit 2 ;;
esac

echo "[reset] stopping btc-hunt.service — this kills every in-process job"
systemctl stop btc-hunt.service || true
rm -f "$BUSY_MARKER" "$BUSY_PID_FILE"
echo "[reset] cleared .btc-hunt-busy and .btc-hunt-busy.pid"

if [ "$NO_DEPLOY" -eq 1 ]; then
  echo "[reset] starting service from the current checkout"
  systemctl start btc-hunt.service
else
  UPDATE="/usr/local/bin/btc-hunt-update"
  if [ ! -x "$UPDATE" ]; then
    UPDATE="$APP_DIR/deploy/ec2/update.sh"
  fi
  if [ ! -f "$UPDATE" ]; then
    echo "ERROR: cannot find btc-hunt-update or $APP_DIR/deploy/ec2/update.sh" >&2
    exit 1
  fi
  echo "[reset] forcing a fresh deploy of origin/main"
  if ! env BTC_HUNT_FORCE_UPDATE=1 bash "$UPDATE"; then
    echo "[reset] deploy failed — starting the current service anyway" >&2
    systemctl start btc-hunt.service || true
    exit 1
  fi
fi

for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
printf '[reset] health: '
curl -fsS http://127.0.0.1/health || true
echo
echo "[reset] fresh worker is up; saved hits and dataset were not deleted"
