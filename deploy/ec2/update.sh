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

BEFORE="$(git -C "$APP_DIR" rev-parse HEAD)"
echo "[update] fetching origin/$REPO_BRANCH"
git -C "$APP_DIR" fetch --depth 1 origin "$REPO_BRANCH"
git -C "$APP_DIR" reset --hard FETCH_HEAD
AFTER="$(git -C "$APP_DIR" rev-parse HEAD)"

if [ "$BEFORE" = "$AFTER" ] && curl -fsS http://127.0.0.1/health >/dev/null 2>&1; then
  echo "[update] already up to date at ${AFTER:0:7} — no restart"
  exit 0
fi

echo "[update] deploying ${BEFORE:0:7} -> ${AFTER:0:7}"
bash "$APP_DIR/deploy/ec2/install.sh"
echo "[update] deployed ${AFTER:0:7}"
