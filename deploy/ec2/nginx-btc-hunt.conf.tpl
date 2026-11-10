# nginx site template for BTC Hunt.
# deploy/ec2/install.sh substitutes the upstream address and installs this as
# /etc/nginx/sites-available/btc-hunt. Do not install this file as-is.
server {
    # IPv4 only: EC2 instances in IPv4-only subnets may have IPv6 disabled at
    # the kernel level, and an [::]:80 listener would then fail to bind.
    listen 80 default_server;
    server_name _;

    client_max_body_size 16m;

    # Liveness probe: no logging noise, no buffering.
    location = /health {
        proxy_pass http://__BIND__/health;
        proxy_set_header Host $host;
        access_log off;
    }

    location / {
        proxy_pass http://__BIND__;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # Job progress uses short JSON polls. These settings also keep any
        # long-running request (e.g. a CLI-driven scan) from being buffered.
        proxy_buffering off;
        proxy_cache off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        gzip off;
    }
}
