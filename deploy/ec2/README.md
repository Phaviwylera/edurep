# Deploying BTC Hunt on Amazon EC2

Yes — the app is a plain Flask/Gunicorn process and runs on EC2 without any
code changes. This directory contains an idempotent installer, a cloud-init
user-data script, and config templates.

> **This workspace has no AWS/EC2 integration, CLI or credentials**, so it
> cannot launch the instance for you. Everything below runs from your own AWS
> account (CLI or console); the repo side is already prepared and pushed.

**Want automatic deploys?** See [AUTODEPLOY.md](AUTODEPLOY.md) — push to
`main` on GitHub and EC2 updates itself, with no manual steps.

## Architecture

```
Internet ──(SG: 80/443)──> nginx :80 ──> gunicorn 127.0.0.1:8000 ──> btc_hunt:app
                                                     │
                                                     └──> /var/lib/btc-hunt  (EBS volume)
                                                          blockchair.tsv.gz, funded.bloom,
                                                          btc_hunt.sqlite, results.json
```

- Gunicorn listens on **loopback only** — port 8000 is never exposed.
- nginx is the public entry point; progress is served as short, cache-free
  JSON polls rather than long-lived SSE streams, so no connection is held open.
- `systemd` supervises the app (`btc-hunt.service`), reading `/etc/btc-hunt.env`.
- `DISK_PATH` points at the EBS-backed data directory, so the dataset and
  results survive reboots. Keep `DeleteOnTermination=false` on that volume.

## Sizing

| Item | Suggested | Why |
| --- | --- | --- |
| AMI | Ubuntu 24.04 LTS (amd64) | Python 3.12 is present; `python3-venv` is the only extra build dep |
| Instance | `t3.small` (2 vCPU / 2 GB) | The two-pass bloom build needs ~100 MB of RAM, not several GB |
| Root volume | 20 GB gp3 | OS + venv |
| Data volume | 20 GB gp3, encrypted | ~1.5 GB dataset + bloom + SQLite; increase if you keep several dumps |
| Region | any | Pick one close to you; the dataset mirrors are public HTTPS |

A `t3.micro` (1 GB) will boot and serve the dashboard, but the dataset build
and the CPU-heavy jobs will be slow. There is no auto-scaling: jobs and their
progress live in one process, so run **one** instance only.

## Option A — launch with the AWS CLI

From the repo root, with an AWS CLI configured locally:

```bash
REGION=us-east-1
VPC_ID=vpc-xxxxxxxxxxxxxxxxx
SUBNET_ID=subnet-xxxxxxxxxxxxxxxxx      # public subnet
KEY_NAME=my-keypair
MY_IP="$(curl -s https://checkip.amazonaws.com)/32"

# 1. Security group: SSH from your IP only, HTTP/HTTPS public.
SG_ID=$(aws ec2 create-security-group --region "$REGION" \
  --group-name btc-hunt-sg --description "BTC Hunt dashboard" \
  --vpc-id "$VPC_ID" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "$MY_IP"
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# 2. Current Ubuntu 24.04 AMI (no hard-coded AMI IDs).
AMI_ID=$(aws ssm get-parameter --region "$REGION" \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query Parameter.Value --output text)

# 3. Launch. /dev/sdf shows up as /dev/nvme1n1 on Nitro instances, which is
#    what user-data.sh expects in DATA_DEVICE.
INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI_ID" --instance-type t3.small --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" --subnet-id "$SUBNET_ID" \
  --associate-public-ip-address \
  --block-device-mappings '[{"DeviceName":"/dev/sdf","Ebs":{"VolumeSize":20,"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":false}}]' \
  --metadata-options 'HttpTokens=required,HttpEndpoint=enabled' \
  --user-data file://deploy/ec2/user-data.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=btc-hunt}]' \
  --query 'Instances[0].InstanceId' --output text)

aws ec2 wait instance-status-ok --region "$REGION" --instance-ids "$INSTANCE_ID"
PUBLIC_IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

# cloud-init needs a few minutes after status-ok to finish apt + pip
curl -fsS "http://$PUBLIC_IP/health"    # -> {"status":"ok"}
```

`user-data.sh` clones the default branch `main` (which contains `deploy/ec2/`).
Set `REPO_BRANCH` at the top of the file to launch from a different branch.
For a **private repo**, install a read-only deploy key on the instance first —
never bake credentials into user-data (it is readable via IMDS and stored in
your AWS account).

## Option B — launch from the console

1. **Launch instance** → Ubuntu Server 24.04 LTS (64-bit x86), `t3.small`.
2. Key pair: pick one you can use for SSH. Network: public subnet.
3. Storage: keep the root volume, **Add new volume** 20 GB gp3 at `/dev/sdf`,
   untick *Delete on termination*, enable encryption.
4. Security group: SSH (22) from *My IP*, HTTP (80) and HTTPS (443) as needed.
   Do **not** open port 8000.
5. Expand **Advanced details** → paste the entire `deploy/ec2/user-data.sh`
   into **User data**. Under *Metadata options* set **IMDSv2: required**.
6. Launch, wait ~3–5 minutes, then browse to `http://<public-ip>/health`.

Bootstrap log: `/var/log/btc-hunt-bootstrap.log`.

## Option C — install on an existing Ubuntu instance

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends python3 python3-venv python3-pip git nginx curl
sudo git clone --depth 1 https://github.com/Phaviwylera/edurep.git /opt/btc-hunt
# DATA_DEVICE is optional; omit it to keep data on the root volume.
sudo env DATA_DEVICE=/dev/nvme1n1 bash /opt/btc-hunt/deploy/ec2/install.sh
```

`install.sh` is idempotent. `RENDER_ONLY=1 bash deploy/ec2/install.sh` just
renders the systemd/nginx configs into `/tmp/btc-hunt-config` if you want to
review them without touching the host.

## After boot

1. **Check:** `curl http://<public-ip>/health` → `{"status":"ok"}`.
   `sudo systemctl status btc-hunt` and `sudo journalctl -u btc-hunt -f`.
2. **Require a login.** The dashboard has unauthenticated `POST` endpoints and
   a public IP. Edit `/etc/btc-hunt.env` (mode `0600`), uncomment both lines:
   ```
   APP_USER=admin
   APP_PASSWORD=use-a-long-random-password
   ```
   Then `sudo systemctl restart btc-hunt`. Values with spaces/`#` need quoting
   per systemd `EnvironmentFile` rules. `/health` deliberately stays public.
3. **Enable HTTPS before using Basic auth** (otherwise credentials travel in
   cleartext). Point a DNS A record at an Elastic IP, then:
   ```bash
   sudo apt-get install -y certbot python3-certbot-nginx
   sudo certbot --nginx -d dashboard.example.com
   ```
   certbot rewrites the nginx site; the proxy settings in the template are kept.
4. **Build the dataset:** open `/` → `/data` → *Download & build bloom*. The
   ~1.5 GB dump, `funded.bloom` and the SQLite DB land in `DISK_PATH`
   (`/var/lib/btc-hunt`). The installer's two-pass builder keeps memory low.

## Operations

| Task | Command |
| --- | --- |
| Logs | `sudo journalctl -u btc-hunt -f` |
| Restart | `sudo systemctl restart btc-hunt` |
| nginx config check | `sudo nginx -t` |
| **Deploy (pull latest `main`, reconfigure, restart, health check)** | `sudo btc-hunt-update` |
| Auto-deploy logs | `sudo journalctl -u btc-hunt-autopull.service -f` |
| Data usage | `df -h /var/lib/btc-hunt` |
| Backup | EBS snapshot of the data volume (stop `btc-hunt` first for a consistent SQLite file) |

Differences from the Render Blueprint: no automatic deploys on push, no managed
TLS/logs, and you own OS patching — but you get full control, cheaper sustained
CPU, and a real persistent volume. Note `.python-version` is only used by
Render; on EC2 the system Python (3.12 on Ubuntu 24.04) is used inside the
venv, and `requirements.txt` pins the dependencies.

## Verifying a deploy

Every page footer shows `build <commit>` and the process start time, and
`GET /health` (public, no auth) returns the same id:

```bash
curl http://127.0.0.1/health
# {"status":"ok","build":"f5871ab","started":"2026-11-10T05:20:00+00:00"}
```

If `build` is missing or stale after a merge to `main`, check
`sudo journalctl -u btc-hunt-autopull.service -n 30 --no-pager` and
`sudo systemctl status btc-hunt-autopull.timer`. A **running job** creates
`.btc-hunt-busy` and legitimately defers the restart; the footer shows that
too. `btc-hunt-update` now records `.btc-hunt-deployed` only after a
successful `install.sh` + restart, so a failed install is retried on the next
tick instead of being mistaken for "already up to date".
`sudo env BTC_HUNT_FORCE_UPDATE=1 btc-hunt-update` redeploys immediately, but
it **kills any running job** — only use it when no job is active.

## Bulk nonce-reuse scans

Open `/nonce` and use **Scan file** to upload a `.txt` (or CSV whose first
column is an address) with up to `NONCE_MAX_ADDRESSES` (default 5000) mainnet
addresses. Blank lines, `#` comments, duplicates and extra columns are
ignored. The job shares the single `nonce` slot with single-address scans, so
the progress bar, log and **Stop** button work; the busy marker also protects
it from the 2-minute auto-pull restarting a live scan.

Public Blockstream Esplora is rate limited: ~750 requests (29 addresses ×
~26 calls) is enough to get a 429. The app paces requests with
`ESPLORA_MIN_INTERVAL` (default 0.3 s), caches responses in a bounded LRU,
and on 429/5xx applies a **process-wide cooldown** (honouring `Retry-After`,
exponential, capped by `ESPLORA_MAX_BACKOFF_SECS=60`) so one rate limit does
not cascade into thousands of skipped addresses. It doubles the spacing up to
`ESPLORA_PACE_MAX_SECS=2` and decays it back on success. A rate-limited
address is retried once and, if still blocked, written to
`/var/lib/btc-hunt/nonce_retry.txt` for re-upload; the job is flagged
`partial` rather than claiming 100%. Tune these in `/etc/btc-hunt.env` and
`sudo systemctl restart btc-hunt`:

```bash
ESPLORA_MIN_INTERVAL=0.5
ESPLORA_URLS=https://blockstream.info/api,https://mempool.space/api
ESPLORA_MAX_RETRIES=3
ESPLORA_MAX_BACKOFF_SECS=120
ESPLORA_CACHE_SIZE=8192
NONCE_MAX_ADDRESSES=10000
```

`ESPLORA_URLS` must contain **mainnet** endpoints only. A 3,000-address run
against the free public APIs takes hours; a local Bitcoin Core node or paid
RPC is the only fast option.

Only legacy P2PKH spending signatures are parsed today; `bc1...` addresses
are accepted but segwit witness signatures will not yield `r` values. Hits
land in `/var/lib/btc-hunt/btc_hunt.sqlite` and are visible at `/results`;
export all of them (the page shows only 500) with the JSONL download links on
that page. Nonce reuse does **not** need `funded.bloom`.

## False positives and balance checks

Randstorm/brainwallet `★★★ HIT` lines are Bloom-filter candidates, not
confirmed wallets. `BLOOM_FP_RATE` defaults to `0.000001` (~183 MB bitset for
51M rows, k≈19); the previous `0.001` produced ~12,000 false hits per 4M
timestamps × 3 derived addresses. Change it in `/etc/btc-hunt.env`, restart,
then rebuild the bloom on `/data` — **Download & build bloom** reuses the
cached `.gz`, so no 1.7 GB re-download is needed.

Open `/results` and click **Check balances** (or **Force re-check** to clear
the in-process Esplora cache). The job is paced by `ESPLORA_MIN_INTERVAL`,
stoppable, checks up to `VERIFY_MAX_ADDRESSES` (default 5000) unique
addresses, and stores results in `btc_hunt.sqlite`. Each hit gets a badge:
`likely Bloom false positive` when the chain shows `tx_count=0` and 0 sats,
`spent / empty`, or a BTC amount to verify manually with a block explorer.
The JSONL downloads on `/results` include the same fields. Verification never
calls the explorer from inside the attack loop.

## Dataset mirrors

`/data` tries, in order: any `DATASET_URLS` you configured, up to four recent
dated **balance TSVs** discovered from the `addresses.loyce.club` HTML index,
up to two dated text dumps as fallback, the `privatekeyfinder.io` dumps, then
the official (throttled) `gz.blockchair.com` dump. LoyceV is first because it
is the source proven to work from EC2; Cloudflare may 403
`privatekeyfinder.io` from AWS IPs. LoyceV's `LATEST` aliases were disabled in
2026 in favour of torrents; the app does not run a BitTorrent client, it uses
the dated HTTP links from the index. Override with a comma-separated
`DATASET_URLS=` in `/etc/btc-hunt.env` (then
`sudo systemctl restart btc-hunt`), or paste one URL into the **Dataset URL**
box on `/data`. Any gzip containing addresses, `address<TAB>balance` TSV rows,
`balance<TAB>address` rows, or 40-character hash160 hex lines works. Rows with
a detected balance ≤ `DATASET_MIN_BALANCE` (default `0`) are skipped; both
column orders are accepted, and text-only/hex dumps with no balance column are
kept as-is. Set `DATASET_PREFER_BALANCE_TSV=0` in `/etc/btc-hunt.env` and
restart to prefer the smaller text dump instead.

A ~1.7 GB / ~51M-row LoyceV balance TSV downloads in one piece and then needs
two CPU-heavy parse passes. Defaults are `DOWNLOAD_DEADLINE_SECS=1800` (30 min)
and `BUILD_DEADLINE_SECS=7200` (2 h); raise them in `/etc/btc-hunt.env` and
restart if your instance is slower. `DATASET_VERIFY_CHECKSUM=1` re-enables
per-row Base58Check verification for untrusted files. Set
`DATASET_MIN_BALANCE=-1` in `/etc/btc-hunt.env` and restart to keep
zero-balance rows as well.

To place a file manually (useful when the instance cannot reach a mirror but
your laptop can):

```bash
scp bitcoin.hex.gz ubuntu@<public-ip>:/tmp/bitcoin.hex.gz
sudo cp /tmp/bitcoin.hex.gz /var/lib/btc-hunt/blockchair.tsv.gz
sudo chown btc-hunt:btc-hunt /var/lib/btc-hunt/blockchair.tsv.gz
```

Then click **Download & build bloom** — the cached file is used as-is. Click
**Re-download & rebuild** to discard it and fetch fresh data.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Start button does nothing | The page shows the server message in a banner — usually `bloom not built`: build it at `/data` first |
| Dataset build shows no progress | Hard-refresh `/data` (Ctrl+Shift+R) after a deploy; the live log and progress bar poll `/api/job/dataset` every second |
| `/health` times out | Security group inbound rules; `sudo systemctl status btc-hunt`; `sudo nginx -t`; bootstrap log |
| 502 Bad Gateway | gunicorn not running — `sudo journalctl -u btc-hunt -n 100`; confirm `127.0.0.1:8000` matches in both rendered configs |
| Progress panel never updates | Hard-refresh (Ctrl+Shift+R) to load the new polling UI; check `sudo journalctl -u btc-hunt -f` |
| Auto-pull stuck on `job running` | A stale busy marker older than `BUILD_DEADLINE_SECS + 600` (default 130 min) is cleared automatically; `sudo env BTC_HUNT_FORCE_UPDATE=1 btc-hunt-update` forces it immediately |
| Bulk nonce scan reports 0 hits but every line after N says `HTTP 429` | The old build counted rate-limited addresses as scanned. Update to the latest `main`: 429 now triggers a global cooldown, blocked addresses are retried and saved to `/var/lib/btc-hunt/nonce_retry.txt`, and the job shows `partial`. Raise `ESPLORA_MIN_INTERVAL` or add `ESPLORA_URLS` |
| Lots of `★★★ HIT` lines but every address has 0 BTC | These are Bloom false positives. `sudo journalctl -u btc-hunt -f` shows the FP rate; set `BLOOM_FP_RATE=0.000001` (default now), rebuild the bloom on `/data`, and use **Check balances** on `/results` to flag never-funded hits |
| New UI (e.g. bulk upload on `/nonce`) not showing after a merge | Check the page footer / `curl /health` for the `build` hash; `sudo journalctl -u btc-hunt-autopull.service -n 30 --no-pager`; `sudo btc-hunt-update`. A previously failed `install.sh` used to leave the old process running forever — the `.btc-hunt-deployed` stamp now forces a retry. Hard-refresh the tab (Ctrl+Shift+R) |
| `dataset build exceeded its time budget` | Raise `BUILD_DEADLINE_SECS` in `/etc/btc-hunt.env` and `sudo systemctl restart btc-hunt`; the cached `.gz` is reused, so no re-download is needed. Defaults are now 2 h total / 30 min download |
| All dataset mirrors failed | LoyceV disabled its `LATEST` direct download (torrent-only); the app now discovers dated snapshots from its index. Paste a working `.gz` URL into the Dataset URL field, set `DATASET_URLS` in `/etc/btc-hunt.env`, or `sudo cp` a dump to `/var/lib/btc-hunt/blockchair.tsv.gz` |
| 401 after enabling auth | Restart the service; `/etc/btc-hunt.env` is read once at process start |
| Data gone after reboot | Verify `UUID=... /var/lib/btc-hunt` is in `/etc/fstab` and the volume is still attached |
