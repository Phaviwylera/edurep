#!/usr/bin/env bash
# Turn on zero-config auto-deploy: the instance polls GitHub every 2 minutes
# and deploys any new commit on main. No GitHub secrets, no IAM, no inbound
# ports. Run once, as root, on the EC2 instance:
#
#   sudo bash /opt/btc-hunt/deploy/ec2/enable-autopull.sh
#
# To turn it off: sudo systemctl disable --now btc-hunt-autopull.timer
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/btc-hunt}"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (sudo bash deploy/ec2/enable-autopull.sh)" >&2
  exit 1
fi
if [ ! -x /usr/local/bin/btc-hunt-update ]; then
  echo "ERROR: /usr/local/bin/btc-hunt-update is missing; run install.sh first" >&2
  exit 1
fi

install -m 0644 "$APP_DIR/deploy/ec2/btc-hunt-autopull.service" \
  /etc/systemd/system/btc-hunt-autopull.service
install -m 0644 "$APP_DIR/deploy/ec2/btc-hunt-autopull.timer" \
  /etc/systemd/system/btc-hunt-autopull.timer
systemctl daemon-reload
systemctl enable --now btc-hunt-autopull.timer

echo "[autopull] enabled — pushes to main deploy within ~2 minutes"
systemctl list-timers btc-hunt-autopull.timer --no-pager
echo "Logs: sudo journalctl -u btc-hunt-autopull.service -f"
