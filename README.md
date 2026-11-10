# BTC Hunt — Render deployment

A single-file Flask dashboard (`btc_hunt.py`) served by Gunicorn, with a
persistent disk for the dataset, bloom filter and SQLite results.
`render.yaml` is a [Render Blueprint](https://render.com/docs/blueprint-spec)
that provisions the whole service.

> **The service has to be created from your own Render account.** This
> workspace has no Render integration or API token, so it can prepare and
> verify the repo but cannot press "Deploy" for you. Everything below is a
> few clicks in the Render Dashboard.

Prefer your own VM? See [Deploying on EC2](deploy/ec2/README.md) for a
cloud-init user-data script, systemd unit, nginx config and AWS CLI launch
commands — and [Push-to-deploy on AWS](deploy/ec2/AUTODEPLOY.md) for automatic
deploys on every push to `main`.

## Deploy (Blueprint)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Phaviwylera/edurep)

The button deploys the repo's default branch (`main`), which contains
`render.yaml` and `deploy/ec2/`. To deploy a different branch, append
`/tree/<branch-name>` to the `repo` URL in the link above.

Or do it manually:

1. Make sure `main` is pushed to GitHub (`git push origin main` if you are
   working from a local clone).
2. In the [Render Dashboard](https://dashboard.render.com/): **New → Blueprint**
   → connect `Phaviwylera/edurep` (install Render's GitHub App if the repo is private).
3. **Branch:** `main` (the repo's default branch; select another branch in the
   form if needed). **Blueprint Path:** `render.yaml` (root of repo).
4. Review the resources Render lists: one web service `btc-hunt`, plan `1c-2g`,
   and a 10 GB disk `btc-hunt-data` mounted at `/data`.
5. Render will prompt for `APP_USER` and `APP_PASSWORD`. Set both to require a
   login, or leave them blank (see [Security](#security)).
6. Click **Deploy Blueprint**. The first build (`pip install`) takes a couple of
   minutes; the service is live at `https://btc-hunt-xxxx.onrender.com`.

Render supplies `PORT=10000`; the start command binds `0.0.0.0:$PORT`, which is
required for the health check and the public URL to work.

## What the Blueprint configures

| Setting | Value | Reason |
| --- | --- | --- |
| `runtime` | `python` | Native Python runtime; version pinned by [`.python-version`](.python-version) to `3.12.6` |
| `plan` | `1c-2g` | A **paid** plan is mandatory for a persistent disk. `0.5c-512mb` is the cheapest paid option if you want to trim cost |
| `buildCommand` | `pip install -r requirements.txt` | Flask, requests, Gunicorn |
| `startCommand` | `gunicorn btc_hunt:app --bind 0.0.0.0:$PORT ...` | One worker / 8 threads: jobs and their progress state live in-process |
| `healthCheckPath` | `/health` | Liveness route with no disk or dataset dependency |
| `disk` | 10 GB at `/data` | Keeps the ~1.5 GB dataset, `funded.bloom` and `btc_hunt.sqlite` across deploys/restarts |

### Environment variables

| Variable | Default | Notes |
| --- | --- | --- |
| `DISK_PATH` | `/data` (set by Blueprint) | All persistent files go here |
| `ESPLORA_URL` | `https://blockstream.info/api` | Used by the nonce-reuse attack |
| `PYTHONUNBUFFERED` | `1` | Unbuffered logs |
| `APP_USER` / `APP_PASSWORD` | empty | Optional HTTP Basic auth; **both** must be set to enable it |
| `DATASET_URLS` | unset | Comma-separated `.gz` mirror URLs tried before the built-in defaults |
| `DOWNLOAD_DEADLINE_SECS` | `1800` | Network budget for one mirror download |
| `BUILD_DEADLINE_SECS` | `7200` | Total budget for download + two-pass bloom build |
| `DATASET_VERIFY_CHECKSUM` | `0` | Set to `1` to verify Base58Check checksums on untrusted dumps (slower) |
| `DATASET_MIN_BALANCE` | `0` | Skip TSV rows with balance ≤ this value; `-1` disables filtering |
| `DATASET_PREFER_BALANCE_TSV` | `1` | Prefer LoyceV dated balance TSVs; set to `0` to prefer smaller text dumps |
| `ESPLORA_URLS` | `ESPLORA_URL` | Comma-separated **mainnet** Esplora base URLs; rotated after a 429 |
| `ESPLORA_MIN_INTERVAL` | `0.3` | Minimum seconds between Esplora requests; `0` disables pacing. Doubled on 429 up to `ESPLORA_PACE_MAX_SECS` |
| `ESPLORA_MAX_RETRIES` | `2` | Extra attempts on HTTP 429/5xx, after the shared cooldown |
| `ESPLORA_CACHE_SIZE` | `4096` | Bounded in-memory cache of Esplora responses per process |
| `ESPLORA_MAX_BACKOFF_SECS` | `60` | Cap on the global cooldown after a 429 (or `Retry-After`, if larger) |
| `ESPLORA_PACE_MAX_SECS` | `2` | Cap on the adaptive inter-request spacing after repeated 429s |
| `NONCE_MAX_ADDRESSES` | `5000` | Cap on addresses in one bulk upload |
| `NONCE_MAX_UPLOAD_BYTES` | `2000000` | Cap on the uploaded text size |
| `BLOOM_FP_RATE` | `0.000001` | Bloom false-positive target; lower = fewer false hits, larger/slower build. Rebuild the bloom after changing it |
| `VERIFY_MAX_ADDRESSES` | `5000` | Max unique hit addresses checked by one `/results` balance run |
| `AUTO_VERIFY_HITS` | `1` | Live-check every Bloom candidate before saving; `0` restores save-candidate-only mode |
| `AUTO_VERIFY_MIN_SATS` | `1` | Minimum chain+mempool sats to save a hit; `0` keeps zero-balance hits with balance fields |
| `RANDSTORM_MAX_MS` | `5000000` | Automatic Randstorm chunk size in ms; large `/randstorm` ranges are split into sequential chunks |
| `RANDSTORM_MAX_TOTAL_MS` | `50000000` | Total ms accepted by `/api/randstorm`; raise it to run longer ranges |
| `BTC_HUNT_BUILD_ID` | auto-detected git short hash | Override the build id shown in the page footer and `/health` when deploying from a tarball without `.git` |
| `BTC_HUNT_WORKER_RESTART` | `1` | Let the **Kill all jobs** button replace the Gunicorn worker; `0` only stops jobs |
| `PORT` | set by Render | Do not override |

`Procfile` contains the same start command for Heroku-style platforms; Render
uses `startCommand` from the Blueprint.

## After the first deploy

1. `GET /health` → `{"status":"ok"}` — Render uses this to mark the deploy live.
2. Open `/` → `/data` → **Download & build bloom**. It tries LoyceV's dated
   **balance TSVs** first (its `LATEST` direct download was disabled in 2026),
   then text dumps and other public mirrors. The balance TSV is ~1.7 GB and
   lets `DATASET_MIN_BALANCE` (default `0`) remove zero-balance rows; text/hex
   dumps are fallbacks. Set `DATASET_PREFER_BALANCE_TSV=0` to prefer the smaller
   text dump. The parser autodetects address TSVs, plain address lists and
   hash160-hex dumps, then makes two streaming passes to build `funded.bloom`
   on the persistent disk. It does **not** materialise a Python `set` of ~51M
   hashes — that would need several GB of RAM. A ~1.7 GB / ~51M-row dump has a
   30-minute download budget and a 2-hour total budget by default; both are
   configurable.
   Watch progress through the live log on that page. Interrupted downloads go
   to a `.part` file and responses are verified to be real gzip data, so a
   truncated dump or an HTML error page is never treated as complete. Use
   **Re-download & rebuild** to discard a cached dump and start over.
3. Once `funded.bloom` exists, the Randstorm / brainwallet / nonce-reuse pages
   are usable and hits are stored in SQLite, visible at `/results`.

Data lives on the disk, so it survives redeploys. It does **not** survive
deleting the service or detaching the disk.

## Bulk nonce-reuse scans

The **Nonce Reuse** tab accepts a `.txt` file with one mainnet address per
line (a CSV/TSV's first column also works). Blank lines, `#` comments,
duplicates and anything after the first column (balance, label, ...) are
ignored; the status message reports how many invalid/duplicate lines were
skipped. Both legacy `1...`/`3...` and bech32 `bc1...` addresses are accepted —
the old `[1-9A-HJ-NP-Za-km-z]{2,90}` regex wrongly rejected bech32 addresses
containing `0`.

The scan uses the same `nonce` job as a single-address scan, so the progress
bar, live log and **Stop** button all work, and only one nonce job can run at a
time. Only **legacy P2PKH spends** are parsed — segwit witness and taproot
signatures are not supported yet. Esplora's `/address/{addr}/txs` also returns
just the most recent 25 transactions by default, so heavily used addresses are
only partly covered. A recovered private key that does not reproduce the target
address is logged but not saved, so `/results` is not flooded with bogus
recoveries.

### Rate limiting (HTTP 429)

Each address costs 1 `/address/{addr}/txs` call plus 1 `/tx/{txid}/hex` call
for every transaction that has a legacy `scriptSig`; 29 addresses × ~26 calls
is already ~750 requests. Public Esplora instances rate-limit that quickly.
The client now:

- paces every request with `ESPLORA_MIN_INTERVAL` (default `0.3` s) and caches
  responses in a bounded LRU;
- on 429/5xx sets a **process-wide cooldown** (honouring `Retry-After`,
  otherwise exponential, capped by `ESPLORA_MAX_BACKOFF_SECS`), so one rate
  limit pauses the whole scan instead of producing thousands of instant
  failures; doubles the spacing up to `ESPLORA_PACE_MAX_SECS`, then decays it
  back on success;
- optionally rotates through `ESPLORA_URLS` (e.g.
  `https://blockstream.info/api,https://mempool.space/api`) — **mainnet only**;
  never add a testnet endpoint here;
- keeps **Stop** responsive during those waits;
- **never reports a rate-limited address as "0 hits"**. Blocked addresses are
  retried once after the cooldown; any that still fail are written to
  `DISK_PATH/nonce_retry.txt` for re-upload, the job is flagged `partial`, and
  the progress bar stops short of 100%.

A few thousand addresses against the public API takes **hours**, not minutes.
Raise `ESPLORA_MIN_INTERVAL` or add a second endpoint if you still see 429s.
For a large list, a local Bitcoin Core node or a paid RPC endpoint is the only
way to scan it quickly; the public APIs are shared and rate-limited. Modern
wallets use RFC 6979 deterministic nonces, so reused `r` values are extremely
rare regardless of throughput.

`/results` shows the newest 500 hits. Use **Download all (JSONL)** or
**Download nonce results (JSONL)** there to export every hit.

## Verifying hits and false positives

`h in bf` is a probabilistic membership test against a **dated snapshot** of
funded addresses, not a live-balance lookup. At the old `BLOOM_FP_RATE=0.001`,
a 4,000,001-timestamp Randstorm run performs ~12M membership tests (three
derived addresses per key) and expects **~12,000 false ★★★ HITs**. The default
is now `0.000001`, cutting that to ~12 while growing the bitset from ~90 MB to
~183 MB for 51M rows (k rises from ~10 to ~19). Raise it if the extra build
time/memory is a problem; lower it for even fewer false alarms. Changing the
rate requires a rebuild — **Download & build bloom** on `/data` rebuilds from
the cached `.gz` (no re-download), or use **Re-download & rebuild** to replace
the dump too. An existing `funded.bloom` still loads fine: its own `m`/`k` are
stored in the file header.

### Automatic live balance gate

By default (`AUTO_VERIFY_HITS=1`), every Bloom candidate — Randstorm,
brainwallet or nonce reuse — is checked live against `ESPLORA_URL` **before**
it is saved or logged as a hit. The lookup uses the same paced/cache/429-cooldown
`_esplora_get()` as the rest of the app, honours **Stop**, and stores the result
in SQLite. `_save_result()` itself still performs only local SQLite / JSONL
writes; the network call is in the attack loop's candidate gate.

`AUTO_VERIFY_MIN_SATS=1` (default) skips zero-balance candidates: the log shows
`[-] skipped <addr>: 0 BTC · never funded (Bloom false positive)` instead of
`★★★ HIT`, and nothing is written to `/results`. Set
`AUTO_VERIFY_MIN_SATS=0` to keep every candidate with balance fields, or
`AUTO_VERIFY_HITS=0` to restore the old "save candidate, verify later" mode.
If the explorer fails, the hit is still saved with `balance_error` and
`balance_verdict=check_failed`; it is never silently discarded.

Saved hits carry `balance_sats`, `balance_tx_count`, `balance_checked_at`,
`balance_error` and `balance_verdict` directly in the result payload, and
`/results` badges populate immediately. This adds one paced API request per
candidate, so very large scans are slower; use `ESPLORA_URLS` or a private
Esplora endpoint if needed.

`/results` also keeps **Check balances** / **Force re-check** for refreshing
stored balances later. It starts a paced, stoppable job that queries
`ESPLORA_URL` for every saved hit address and stores the result in SQLite.
Badges:

- `0 BTC · never funded — likely Bloom false positive` (chain `tx_count == 0`)
- `0 BTC · spent / empty`
- `X BTC — verify manually with a block explorer`
- `check failed: ...` if the explorer was unreachable

Balances are cached per process; **Force re-check** clears that cache. The
JSONL downloads include `balance_sats`, `balance_tx_count`,
`balance_checked_at`, `balance_error` and `balance_verdict`. Only
`VERIFY_MAX_ADDRESSES` (default 5000) unique addresses are checked per run.

A funded hit is still only a candidate: it comes from a snapshot, and a Bloom
false positive can coincidentally have a balance. Always confirm with a block
explorer before trusting any private key. Only test addresses you own or are
authorised to test.

## Checking which build is live

Every page has a footer showing `build <commit>`, the process start time, and a
note when a running job is deferring auto-deploy. `GET /health` is public and
returns the same build id, so from any device:

```bash
curl http://<your-host>/health
# {"status":"ok","build":"f5871ab","started":"2026-11-10T05:20:00+00:00"}
```

Compare `build` with the newest commit on `main`. If the field is missing (a
process started before this change) or the hash is old, the auto-pull has not
restarted the service yet. On EC2:

```bash
sudo systemctl status btc-hunt-autopull.timer
sudo journalctl -u btc-hunt-autopull.service -n 30 --no-pager
sudo btc-hunt-update
```

`btc-hunt-update` writes `.btc-hunt-deployed` only after `install.sh` and the
service restart succeed, so a failed install is retried on the next 2-minute
tick instead of leaving the old process running forever. Dashboard HTML is
served with `Cache-Control: no-store`, but an already-open tab can still show
the previous layout until you hard-refresh (Ctrl+Shift+R).

## Kill all jobs / fresh start

The **Kill all jobs** button in the header of every page (and
`POST /api/jobs/kill-all`) stops `dataset`, `randstorm`, `brainwallet`,
`nonce` and `verify` jobs at once, clears both `.btc-hunt-busy` and
`.btc-hunt-busy.pid`, and — when Basic auth is configured and the app runs
under Gunicorn — sends SIGTERM/SIGKILL to the current worker so the master
starts a replacement with an empty `_JOBS` dict. `GET /api/jobs` reports all
five slots. Saved hits, the Bloom filter and the cached `.gz` are **not**
deleted; this is a process/job reset, not a data wipe. Set
`BTC_HUNT_WORKER_RESTART=0` to disable the worker restart.

On EC2 the equivalent one-command fresh start is:

```bash
sudo btc-hunt-reset
```

It stops `btc-hunt.service`, removes both deploy markers, forces
`btc-hunt-update` to fetch `main`, reinstalls, restarts and checks `/health`.
`sudo btc-hunt-reset --no-deploy` just restarts the service from the current
checkout. Until the build containing `btc-hunt-reset` has propagated, the
existing one-liner does the same job:

```bash
sudo env BTC_HUNT_FORCE_UPDATE=1 btc-hunt-update
```

Either command intentionally kills any running job. Stop a long scan from the
UI first if you want it to finish cleanly.

## Run locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
PORT=10000 DISK_PATH=./local-data .venv/bin/gunicorn btc_hunt:app \
  --bind 0.0.0.0:$PORT --timeout 180 --workers 1 --threads 16
# or: .venv/bin/python btc_hunt.py --port 10000
```

Worker/CLI modes are unchanged, e.g. `python btc_hunt.py --build-bloom` or
`python btc_hunt.py --worker randstorm --shard 3/10`.

## Security

The dashboard has unauthenticated `POST` endpoints that start long-running
jobs, and a Render web service is reachable by anyone on the internet. Set
`APP_USER` and `APP_PASSWORD` (Blueprint prompts for both) to put HTTP Basic
auth in front of every route except `/health`; browsers will prompt for the
credentials and the progress polls will reuse them. Leaving them blank keeps the
original open behaviour — do not do that on a public URL. Render's IP allow
list is only available on Scale/Enterprise plans, so the in-app auth is the
practical option on smaller plans.

## Known constraints

- **Paid plan required.** Render's free tier has an ephemeral filesystem and
  cannot attach a persistent disk, so `DISK_PATH` would be wiped on every deploy.
- **Third-party dataset mirrors.** The old fixed `addresses.loyce.club`
  `LATEST` aliases now 404 and `3xpl.com` returns 400; the LoyceV owner asks
  heavy users to use torrents instead. Rather than ship a BitTorrent client,
  the app scrapes LoyceV's small HTML index for dated balance TSVs, tries up
  to four of them first, then text dumps and several other live mirrors.
  Cloudflare may return 403 from
  EC2 for `privatekeyfinder.io`; those URLs remain as fallbacks only.
  `gz.blockchair.com` is a last resort but free downloads are throttled to
  ~10 kB/s. If your network blocks all of them,
  paste a working `.gz` URL into the **Dataset URL** field on `/data`, set
  `DATASET_URLS`, or copy a `.gz` to `DISK_PATH/blockchair.tsv.gz` yourself
  (Render SSH + `scp`, or `sudo cp` on EC2) — a cached file is used without
  re-downloading.
- **Single instance only.** Job state (`_JOBS`) and the SQLite DB are in-process
  and on a local disk. Do not set `numInstances` > 1 or add autoscaling.
- **Python 3.12.** Pinned because dependency versions are pinned. The app also
  ships a pure-Python RIPEMD160 fallback for OpenSSL 3 builds that lack the
  legacy provider, so address derivation works on any Render Python image.
