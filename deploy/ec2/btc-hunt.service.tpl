# systemd unit template for BTC Hunt.
# deploy/ec2/install.sh substitutes the placeholders below and installs
# this as /etc/systemd/system/btc-hunt.service. Do not install this file as-is.
[Unit]
Description=BTC Hunt Flask dashboard (gunicorn)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=__SERVICE_USER__
Group=__SERVICE_USER__
WorkingDirectory=__APP_DIR__
Environment=PYTHONUNBUFFERED=1
# Optional file (mode 0600) holding DISK_PATH, ESPLORA_URL and the
# APP_USER / APP_PASSWORD Basic-auth credentials. Leading "-" = optional.
EnvironmentFile=-__ENV_FILE__
ExecStart=__APP_DIR__/.venv/bin/gunicorn btc_hunt:app --bind __BIND__ --timeout 180 --workers 1 --threads 8 --access-logfile - --error-logfile -
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=60

# Gunicorn listens on loopback only; nginx is the public-facing server.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=true

[Install]
WantedBy=multi-user.target
