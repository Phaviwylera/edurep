#!/bin/bash
# cloud-init user-data for a fresh Ubuntu 22.04 / 24.04 EC2 instance.
#
# Paste this whole file into "Advanced details > User data" at launch, or pass
# it to the CLI with:  --user-data file://deploy/ec2/user-data.sh
#
# SECURITY: user-data is stored in your AWS account and readable from the
# instance metadata service. NEVER put passwords, tokens or keys in it.
# Set APP_USER / APP_PASSWORD in /etc/btc-hunt.env over SSH after boot instead.
#
# For a private repo, add a read-only deploy key to the instance before
# cloning, or switch REPO_URL to an HTTPS URL you can authenticate.
set -euo pipefail
exec > >(tee /var/log/btc-hunt-bootstrap.log) 2>&1

REPO_URL="${REPO_URL:-https://github.com/Phaviwylera/edurep.git}"
# Deploys the default branch (main), which contains deploy/ec2/. Override
# REPO_BRANCH to launch from another branch.
REPO_BRANCH="${REPO_BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/btc-hunt}"
# Nitro (t3/m6i/...) exposes a second EBS volume as /dev/nvme1n1 even when
# the block device mapping says /dev/sdf. Set to "" to keep data on the root
# volume. install.sh falls back to the root volume if the device is absent.
DATA_DEVICE="${DATA_DEVICE:-/dev/nvme1n1}"

echo "[bootstrap] installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip git nginx curl ca-certificates

echo "[bootstrap] fetching $REPO_URL @ $REPO_BRANCH"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch --depth 1 origin "$REPO_BRANCH"
  git -C "$APP_DIR" reset --hard FETCH_HEAD
else
  rm -rf "$APP_DIR"
  git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$APP_DIR"
fi

echo "[bootstrap] installing service"
APP_DIR="$APP_DIR" DATA_DEVICE="$DATA_DEVICE" bash "$APP_DIR/deploy/ec2/install.sh"

echo "[bootstrap] complete"
