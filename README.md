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
| `PORT` | set by Render | Do not override |

`Procfile` contains the same start command for Heroku-style platforms; Render
uses `startCommand` from the Blueprint.

## After the first deploy

1. `GET /health` → `{"status":"ok"}` — Render uses this to mark the deploy live.
2. Open `/` → `/data` → **Download & build bloom**. This downloads the address
   dump (HTTPS first, then the two fallback mirrors), then parses it twice to
   build `funded.bloom` on the persistent disk. It is a large download and a
   CPU-heavy job; watch progress through the live log on that page. If a
   download is interrupted it is written to a `.part` file and retried, so a
   truncated dump is never treated as complete.
3. Once `funded.bloom` exists, the Randstorm / brainwallet / nonce-reuse pages
   are usable and hits are stored in SQLite, visible at `/results`.

Data lives on the disk, so it survives redeploys. It does **not** survive
deleting the service or detaching the disk.

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
- **Third-party dataset mirrors.** `build_bloom` needs outbound access to
  `addresses.loyce.club` or `3xpl.com`. If all mirrors are unreachable, upload
  the `.tsv.gz` to `/data` yourself (Render SSH + `scp`) and it will be used
  without re-downloading.
- **Single instance only.** Job state (`_JOBS`) and the SQLite DB are in-process
  and on a local disk. Do not set `numInstances` > 1 or add autoscaling.
- **Python 3.12.** Pinned because dependency versions are pinned. The app also
  ships a pure-Python RIPEMD160 fallback for OpenSSL 3 builds that lack the
  legacy provider, so address derivation works on any Render Python image.
