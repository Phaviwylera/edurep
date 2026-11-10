#!/usr/bin/env bash
# THE deploy command. install.sh copies this to /usr/local/bin/btc-hunt-update
# (a stable path outside the git checkout) so it can safely `git reset --hard`
# its own source tree while running.
#
# Usage:  sudo btc-hunt-update
#
# Idempotent: if the instance already runs the latest commit and /health is OK,
# it exits without restarting anything. Used by the auto-pull timer, the
# GitHub Actions workflow (via SSM) and manual deploys.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/btc-hunt}"
REPO_BRANCH="${REPO_BRANCH:-main}"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (sudo btc-hunt-update)" >&2
  exit 1
fi
if ! git -C "$APP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: $APP_DIR is not a git checkout" >&2
  exit 1
fi

# Jobs live in the app process; restarting mid-job would kill a long dataset
# build or scan. The app writes .btc-hunt-busy plus .btc-hunt-busy.pid while a
# job is alive. Defer the whole deploy (do NOT fetch) so the next timer tick
# can pick it up later.
ENV_FILE="${ENV_FILE:-/etc/btc-hunt.env}"
DISK_PATH="$(sed -n 's/^DISK_PATH=//p' "$ENV_FILE" 2>/dev/null | tail -n 1)"
DISK_PATH="${DISK_PATH:-/var/lib/btc-hunt}"
BUSY_MARKER="$DISK_PATH/.btc-hunt-busy"
# A hard-killed process can leave the marker behind forever. Wait a little
# longer than the app's own build budget before declaring the marker stale.
BUILD_DEADLINE_SECS="$(sed -n 's/^BUILD_DEADLINE_SECS=//p' "$ENV_FILE" 2>/dev/null | tail -n 1)"
case "$BUILD_DEADLINE_SECS" in ''|*[!0-9]*) BUILD_DEADLINE_SECS=7200 ;; esac
BUSY_MAX_AGE_SECS="${BUSY_MAX_AGE_SECS:-$((BUILD_DEADLINE_SECS + 600))}"
BUSY_PID_FILE="$DISK_PATH/.btc-hunt-busy.pid"
clear_busy_marker(){ rm -f "$BUSY_MARKER" "$BUSY_PID_FILE"; }
if [ -f "$BUSY_MARKER" ] && [ "${BTC_HUNT_FORCE_UPDATE:-0}" != "1" ]; then
  # Newer builds write the worker PID next to the marker. If that process is
  # gone (or the PID was reused by something else), the marker is stale —
  # clear it now instead of waiting for the 130-minute age fallback.
  if [ -f "$BUSY_PID_FILE" ]; then
    BUSY_PID="$(cat "$BUSY_PID_FILE" 2>/dev/null || true)"
    case "$BUSY_PID" in
      ''|*[!0-9]*)
        echo "[update] invalid busy PID file — clearing stale marker"
        clear_busy_marker ;;
      *)
        if ! kill -0 "$BUSY_PID" 2>/dev/null; then
          echo "[update] job process $BUSY_PID is gone — clearing stale marker"
          clear_busy_marker
        elif ! tr '\0' ' ' < "/proc/$BUSY_PID/cmdline" 2>/dev/null | grep -q "btc_hunt:app"; then
          echo "[update] busy PID $BUSY_PID is no longer BTC Hunt — clearing stale marker"
          clear_busy_marker
        fi
        ;;
    esac
  fi
  if [ -f "$BUSY_MARKER" ]; then
    MARKER_MTIME="$(stat -c %Y "$BUSY_MARKER" 2>/dev/null || echo 0)"
    MARKER_AGE="$(( $(date +%s) - MARKER_MTIME ))"
    if [ "$MARKER_AGE" -gt "$BUSY_MAX_AGE_SECS" ]; then
      echo "[update] stale busy marker (${MARKER_AGE}s old) — clearing and deploying"
      clear_busy_marker
    else
      echo "[update] job running ($(cat "$BUSY_MARKER")) — deferring deploy until it finishes"
      echo "[update] to override: sudo env BTC_HUNT_FORCE_UPDATE=1 btc-hunt-update"
      exit 0
    fi
  fi
fi

# Stamp written ONLY after install.sh (and therefore the service restart)
# succeeds. Comparing HEAD alone is not enough: if a previous run reset the
# checkout but install.sh failed (e.g. a transient pip/network error), the
# next tick would see "HEAD unchanged + /health OK" and never restart the old
# process — leaving the previous UI live forever.
DEPLOY_STAMP="$DISK_PATH/.btc-hunt-deployed"
DEPLOYED=""
if [ -f "$DEPLOY_STAMP" ]; then
  DEPLOYED="$(cat "$DEPLOY_STAMP" 2>/dev/null || true)"
fi

BEFORE="$(git -C "$APP_DIR" rev-parse HEAD)"
echo "[update] fetching origin/$REPO_BRANCH"
git -C "$APP_DIR" fetch --depth 1 origin "$REPO_BRANCH"
git -C "$APP_DIR" reset --hard FETCH_HEAD
AFTER="$(git -C "$APP_DIR" rev-parse HEAD)"

if [ "${BTC_HUNT_FORCE_UPDATE:-0}" != "1" ] &&
   [ "$BEFORE" = "$AFTER" ] && [ "$DEPLOYED" = "$AFTER" ] &&
   curl -fsS http://127.0.0.1/health >/dev/null 2>&1; then
  echo "[update] already up to date at ${AFTER:0:7} — no restart"
  exit 0
fi

echo "[update] deploying ${BEFORE:0:7} -> ${AFTER:0:7}"
bash "$APP_DIR/deploy/ec2/install.sh"
printf '%s\n' "$AFTER" > "$DEPLOY_STAMP"
chmod 0644 "$DEPLOY_STAMP" 2>/dev/null || true
echo "[update] deployed ${AFTER:0:7}"
