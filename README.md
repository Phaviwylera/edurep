# BTC Hunt — Render deployment

A single-file Flask dashboard (`btc_hunt.py`) served by Gunicorn, with a
persistent disk for the dataset, bloom filter and SQLite results.
`render.yaml` is a [Render Blueprint](https://render.com/docs/blueprint-spec)
that provisions the whole service.

Four scans ship today: the timestamp dataset sweep, Randstorm-style
millisecond timestamps, passphrase brainwallets, ECDSA nonce reuse — plus an
[Ethereum page](#ethereum-timestamp-sweeps-weak-keys-live-rpc-balances) that
sweeps weak Ethereum generators and verifies every candidate live over
JSON-RPC.

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
| `ESPLORA_URL` | `https://blockstream.info/api` | Primary Esplora base URL: nonce reuse, the automatic balance gate and `/results` balance checks |
| `PYTHONUNBUFFERED` | `1` | Unbuffered logs |
| `APP_USER` / `APP_PASSWORD` | empty | Optional HTTP Basic auth; **both** must be set to enable it |
| `DATASET_URLS` | unset | Comma-separated `.gz` mirror URLs tried before the built-in defaults |
| `DOWNLOAD_DEADLINE_SECS` | `1800` | Network budget for one mirror download |
| `BUILD_DEADLINE_SECS` | `7200` | Total budget for download + two-pass bloom build |
| `DATASET_VERIFY_CHECKSUM` | `0` | Set to `1` to verify Base58Check checksums on untrusted dumps (slower) |
| `DATASET_MIN_BALANCE` | `0` | Skip TSV rows with balance ≤ this value; `-1` disables filtering |
| `DATASET_PREFER_BALANCE_TSV` | `1` | Prefer LoyceV dated balance TSVs; set to `0` to prefer smaller text dumps |
| `ESPLORA_URLS` | `ESPLORA_URL,https://mempool.space/api` | Comma-separated **mainnet** Esplora base URLs. Each keeps its own 429 cooldown and requests fail over to the next base that is still answering. Setting this replaces the default list entirely |
| `ESPLORA_MIN_INTERVAL` | `0.3` | Minimum seconds between Esplora requests; `0` disables pacing. Doubled on 429 up to `ESPLORA_PACE_MAX_SECS` |
| `ESPLORA_MAX_RETRIES` | `2` | Extra attempts on HTTP 429/5xx, each on an endpoint that is not cooling down |
| `ESPLORA_CACHE_SIZE` | `4096` | Bounded in-memory cache of Esplora responses per process |
| `ESPLORA_MAX_BACKOFF_SECS` | `60` | Cap on the **per-endpoint** cooldown after a 429 (or `Retry-After`, if larger) |
| `ESPLORA_PACE_MAX_SECS` | `2` | Cap on the adaptive inter-request spacing after repeated 429s |
| `ESPLORA_USER_AGENT` | `btc-hunt/<build> (github.com/Phaviwylera/edurep)` | `User-Agent` sent to Esplora; public instances throttle the stock `python-requests` agent harder |
| `NONCE_MAX_ADDRESSES` | `5000` | Cap on addresses in one bulk upload |
| `NONCE_MAX_UPLOAD_BYTES` | `2000000` | Cap on the uploaded text size |
| `BLOOM_FP_RATE` | `0.000001` | Bloom false-positive target; lower = fewer false hits, larger/slower build. Rebuild the bloom after changing it |
| `VERIFY_MAX_ADDRESSES` | `5000` | Max unique hit addresses checked by one `/results` balance run (Bitcoin **and** Ethereum) |
| `VERIFY_RETRY_PASSES` | `3` | Extra passes over addresses that were still throttled (HTTP 429) when a `/results` balance run ended |
| `AUTO_VERIFY_HITS` | `1` | Live-check every Bloom candidate before saving; `0` restores save-candidate-only mode |
| `AUTO_VERIFY_MIN_SATS` | `1` | Minimum chain+mempool sats to save a hit; `0` keeps zero-balance hits with balance fields |
| `RANDSTORM_MAX_MS` | `5000000` | Automatic Randstorm chunk size in ms; large `/randstorm` ranges are split into sequential chunks |
| `RANDSTORM_MAX_TOTAL_MS` | `4000000000` | Total ms accepted by one `/api/randstorm` run — 4,000,000,000 ms ≈ 46.3 days ≈ 800 default chunks. Raise it to run longer ranges. See [Scan speed](#scan-speed-and-the-ec-backend) for what that costs in wall-clock time |
| `EC_BACKEND` | `auto` | `auto` uses libsecp256k1 (`coincurve`) when importable, otherwise the pure-Python windowed path. Force one with `libsecp256k1` or `python`; shown by `/health` and the page footer |
| `ETH_RPC_URLS` | `ethereum-rpc.publicnode.com,eth.drpc.org,rpc.flashbots.net,ethereum.blockpi.network/v1/rpc/public` | Comma-separated Ethereum JSON-RPC endpoints for `/eth` balance checks. Each keeps its own cooldown; requests fail over. Point this at your own node for any serious sweep |
| `ETH_RPC_BATCH` | `50` | Addresses per JSON-RPC batch request (two calls each). This is the **starting** size: it halves when an endpoint refuses arrays or a large batch, and grows back after 20 clean requests |
| `ETH_RPC_TIMEOUT` | `25` | Seconds per RPC request |
| `ETH_PREFLIGHT` | `1` | Probe every endpoint (`eth_blockNumber` + a small batch) before deriving anything and use only the ones that answer. `0` skips the probe |
| `ETH_DEAD_COOL_SECS` | `3600` | How long an endpoint that answered **401/403** is parked. A refusal is not a rate limit — it means "we will not answer this host" |
| `ETH_ERROR_COOL_SECS` | `30` | Park time after a timeout, connection error or other 4xx |
| `ETH_RPC_ROUNDS` | `3` | Full rounds over the usable endpoints that one batch gets before it is queued for a later re-check |
| `ETH_PENDING_MAX` | `200000` | Cap on `eth_pending.jsonl` (unchecked candidates). Beyond it, candidates are counted as `dropped` and the log warns once |
| `ETH_RPC_USER_AGENT` | the Esplora-style agent | Override the `User-Agent` sent to RPC endpoints; some gateways 403 an unidentified client |
| `ETH_MIN_WEI` | `1` | Minimum balance (wei) to save an Ethereum hit; `0` also saves never-used and emptied addresses |
| `ETH_VERIFY_BALANCES` | `1` | Live-check derived addresses before saving. `0` skips verification entirely and only counts candidates as `unchecked` |
| `ETH_MAX_STEPS` | `5000000` | Timestamps per chunk on `/eth`; larger ranges split automatically |
| `ETH_MAX_TOTAL_STEPS` | `20000000` | Total timestamps accepted by one run — `/api/eth/timestamp` **and** the era batch, where it applies to the sum of the per-era steps (the Trust Wallet window is 2,505,600) |
| `ETH_ERA_STEPS` | `1000000` | Default slice of **each** era taken by one era-batch run (floored at 1000). The eras are billions of timestamps wide, so this is a sample, not a sweep — raise it only if you have a private RPC endpoint |
| `ETH_MAX_WEAK_KEYS` | `2000000` | Cap on sequential + pasted keys per weak-key run |
| `BIP39_WORDLIST_PATH` | `data/bip39_english.txt` | The vendored 2048-word BIP-39 English list (SHA-256 `2f5eed53…`) |
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
- on 429/5xx parks **that endpoint** for a cooldown (honouring `Retry-After`,
  otherwise exponential, capped by `ESPLORA_MAX_BACKOFF_SECS`) and fails over
  to the next base that is still answering, so one throttled public instance
  no longer freezes the whole scan; the shared spacing also doubles up to
  `ESPLORA_PACE_MAX_SECS`, then decays back on success;
- uses two **mainnet** bases by default (`ESPLORA_URL` plus
  `https://mempool.space/api`); override the list with `ESPLORA_URLS` —
  **mainnet only**, never add a testnet endpoint here. `GET /api/esplora`
  reports which base is cooling down and for how long;
- keeps **Stop** responsive during those waits;
- **never reports a rate-limited address as "0 hits"**. Blocked addresses are
  retried once after the cooldown; any that still fail are written to
  `DISK_PATH/nonce_retry.txt` for re-upload, the job is flagged `partial`, and
  the progress bar stops short of 100%.

A few thousand addresses against the public API takes **hours**, not minutes.
A second endpoint is now the default; raise `ESPLORA_MIN_INTERVAL`, or point
`ESPLORA_URLS` at your own Esplora instance, if you still see 429s.
For a large list, a local Bitcoin Core node or a paid RPC endpoint is the only
way to scan it quickly; the public APIs are shared and rate-limited. Modern
wallets use RFC 6979 deterministic nonces, so reused `r` values are extremely
rare regardless of throughput.

`/results` shows the newest 500 hits. Use **Download all (JSONL)** or
**Download nonce results (JSONL)** there to export every hit.

## Scan speed and the EC backend

Every Randstorm timestamp and every brainwallet passphrase needs one secp256k1
scalar multiplication, so that multiplication *is* the scan speed. Measured on
one vCPU over 200 random keys:

| Backend | µs per key | vs. old | 4,000,000,000 ms run |
| --- | ---: | ---: | --- |
| affine double-and-add, inversion per step (**old**, and run twice per key) | 6,012 | 1× | ~735 days |
| Jacobian double-and-add | 1,665 | 3.6× | — |
| Jacobian + precomputed fixed-base window (`w=4`) | 437 | 13.9× | ~28 days |
| libsecp256k1 via `coincurve` | 24 | 251× | ~7 days |

Three changes sit on top of that table:

1. **One multiplication per key.** `derive_addresses()` used to call `ec_mul()`
   twice — once for the compressed pubkey, once for the uncompressed one.
   `derive_pubkeys()` now computes the point once and encodes both forms.
2. **Hash-first probing.** The loops encoded three addresses and then decoded
   them again with `_address_to_hash160()` purely to probe the filter.
   `derive_candidates()` yields `hash160(pubkey)` directly, and
   `encode_address()` only runs for a candidate that actually matched — about
   0.15 ms saved per timestamp on the ~100% of keys that miss.
3. **A real backend switch.** `coincurve` is used when importable; otherwise the
   windowed pure-Python path runs (its 1,024-entry table is built once, lazily,
   in ~7 ms). `EC_BACKEND=libsecp256k1|python` forces one, and `/health` plus
   every page footer report which is active.

End to end — RC4, one multiplication and three bloom probes per timestamp, with
no address encoding on a miss — the same vCPU went from **~63 timestamps/s to
~6,700 with coincurve** (a ~106× speed-up) and **~1,635 without it** (~26×):

| Range | Chunks | With coincurve (6,700 ts/s) | Pure Python (1,635 ts/s) |
| --- | ---: | --- | --- |
| 5,000,000 ms (one chunk) | 1 | ~12 min | ~51 min |
| 86,400,000 ms (1 day) | 18 | ~3.6 h | ~15 h |
| 4,000,000,000 ms (46.3 days, the cap) | 800 | ~7 days | ~28 days |

Measured in a 1-vCPU sandbox; a c6i.large will differ somewhat, and the live
rate is printed in the job detail (`… ts/s`) and in the footer via `/health`.

`coincurve` is optional and lives in `requirements-fast.txt`, **not**
`requirements.txt`, so a platform with no matching wheel and no C toolchain
still deploys:

```bash
pip install -r requirements.txt          # required
pip install -r requirements-fast.txt     # optional, ~244x faster EC
```

`deploy/ec2/install.sh` installs it opportunistically and only warns on
failure — and since `sudo btc-hunt-update` (and the auto-pull timer) re-runs
`install.sh`, an existing EC2 box picks it up on the next deploy. The Render
Blueprint's `buildCommand` does the same. All backends return identical points;
the test suite compares each one against the slow affine reference.

A 4,000,000,000 ms run is still ~7 days on one worker even with the native
backend. Shard it across machines with `--worker randstorm --shard i/n`, or
scan a narrower window first — **Stop** keeps every hit found so far, so a long
run can be abandoned and resumed in pieces.

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
brainwallet or nonce reuse — is checked live against the configured Esplora
endpoints **before** it is saved or logged as a hit. The lookup uses the same
paced/cached `_esplora_get()` as the rest of the app (per-endpoint 429
cooldowns plus failover), honours **Stop**, and stores the result in SQLite. `_save_result()` itself still performs only local SQLite / JSONL
writes; the network call is in the attack loop's candidate gate.

`AUTO_VERIFY_MIN_SATS=1` (default) skips zero-balance candidates: the log shows
`[-] skipped <addr>: 0 BTC · never funded (Bloom false positive)` instead of
`★★★ HIT`, and nothing is written to `/results`. Set
`AUTO_VERIFY_MIN_SATS=0` to keep every candidate with balance fields, or
`AUTO_VERIFY_HITS=0` to restore the old "save candidate, verify later" mode.
If the explorer fails, the hit is still saved with `balance_error` and
`balance_verdict=check_failed`; it is never silently discarded. An HTTP 429 is
handled differently because it says nothing about the address: the hit is saved
with `balance_verdict=check_failed_throttled` and `balance_retry=true`, no
`balance_checks` row is written, and `/results` keeps showing *not checked yet*
so the next **Check balances** run picks the address up again.

Saved hits carry `balance_sats`, `balance_tx_count`, `balance_checked_at`,
`balance_error` and `balance_verdict` directly in the result payload, and
`/results` badges populate immediately. This adds one paced API request per
candidate, so very large scans are slower; use `ESPLORA_URLS` or a private
Esplora endpoint if needed.

`/results` also keeps **Check balances** / **Force re-check** for refreshing
stored balances later. It starts a paced, stoppable job that queries every
saved hit address across the configured endpoints and stores the result in
SQLite. Addresses that were still throttled when a pass ended are re-queued for
up to `VERIFY_RETRY_PASSES` extra passes (with a growing wait) and are reported
as `throttled` in the job detail instead of as errors; the progress bar stops
short of 100% until they are resolved. Badges:

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

## Ethereum: timestamp sweeps, weak keys, live RPC balances

`/eth` adds Ethereum to the same dashboard. The curve is identical
(secp256k1), so the EC backend from the Randstorm work is reused unchanged;
only the address hash differs — an Ethereum address is the last 20 bytes of
**Keccak-256** (the pre-NIST padding, not `hashlib.sha3_256`) over the 64-byte
uncompressed public key *without* its `0x04` prefix, rendered in EIP-55
mixed case.

The important structural difference: **there is no bloom filter.** No public
dump of funded Ethereum addresses exists, so the scan runs in the opposite
direction. Candidates are derived locally, then checked against the chain in
batches — `ETH_RPC_BATCH` addresses per HTTP request, two JSON-RPC calls each
(`eth_getBalance` + `eth_getTransactionCount` at `latest`). The batch *is* the
filter.

### The fixed era windows (batch and manual)

The widely circulated "era & vulnerability" table is built into the app as
fixed scan values, in `ETH_ERAS`. Tick any of them on `/eth` (or launch the
defaults from the home page) and one job sweeps them **in sequence**; every era
can also be loaded into the manual Start/End/Unit fields and edited.

| Era | id | Window (UTC) | Unit | Timestamps wide | Can a timestamp sweep find it? |
| --- | --- | --- | --- | --- | --- |
| Era 1 — 2014 presale / ICO genesis | `presale` | 2014-07-22 → 2014-09-02 | ms | 3,715,199,001 | **No.** Unticked by default |
| Era 2 — 2015 Frontier | `frontier` | 2015-07-30 → 2015-12-31 | ms | 13,391,999,001 | Only clock-seeded wallets |
| Era 3 — CryptoJS `Math.random` | `cryptojs` | 2018-01-01 → 2020-01-01 | ms | 63,072,000,001 | Only wallets *also* seeded from the clock |
| Era 4 — Trust Wallet ext v2.68 | `tw` | 2022-11-24 → 2022-12-22 | s | 2,505,600 | **Yes** — the only complete window here |

Two corrections to the table as it circulates, both encoded in the app and in
the tests:

* **Era 3's end is `1577836800000`**, not `15778368000000`. The 14-digit value
  has one digit too many and lands in the year 2471.
* **The CryptoJS bug is CVE-2023-46233** (`WordArray.random` falling back to
  `Math.random`, fixed in CryptoJS 4.2.0). "CVE-2026-71851" does not exist and
  appears nowhere in this codebase except in the note that says so.

**Era 1 is kept, and kept honest.** Presale private keys were generated by a
real CSPRNG; the documented weakness is in the *encrypted keystore* (weak
password, IV reuse). A browser PRNG that collapsed to a millisecond timestamp
therefore yields the keystore **password/IV**, not a private key — so a
private-key timestamp sweep of this window cannot recover a presale wallet, and
the page, the log and `--list-eras` all say so every time it is selected. It is
listed so the window is never mistaken for a scannable one.

**A batch run samples each era; it does not sweep it.** With the default
`ETH_ERA_STEPS=1000000`, one run covers 0.0016% of Era 3, and
`ETH_MAX_TOTAL_STEPS` (20,000,000) refuses anything larger outright. The whole
of Era 3 is ~30 days of pure CPU at the ~24,000 `sha256_dec` candidates/s
measured on the EC2 box — and 1.26 billion batch requests, which is ~8 years at a
sustainable 5 requests/s from a public endpoint. The RPC, not the CPU, is the
wall. Use `steps` to size the sample and `offset` to walk through the era run by
run — the same offset plus steps resumes exactly where the last run stopped, and
every run logs the exact slice and the percentage of the window it covered.

The eras run **sequentially inside one job** on purpose: the RPC endpoint, not
the CPU, is the bottleneck, so parallel era jobs multiply 429s without finding
anything faster, while one job keeps one progress bar, one Stop button and one
retry queue.

### What each recipe can and cannot find

A timestamp is a **seed for a broken generator, never a private key**. Each
recipe reproduces one specific generator and declares the unit it was fed; the
page disables recipes that do not accept the selected unit.

| Recipe id | What it computes | Unit | Honest expectation |
| --- | --- | --- | --- |
| `tw_bip39_s` | MT19937 seeded with the Unix timestamp in seconds → first four 32-bit outputs as 16 bytes of BIP-39 entropy → mnemonic → PBKDF2-HMAC-SHA512 (2048) → BIP-32 `m/44'/60'/0'/0/0` | s | The Trust Wallet browser-extension shape. Each layer matches its published test vector, but **the exact order in which the vulnerable library consumed MT output is not publicly documented**, so a miss means "this recipe shape did not match", not "the window is safe" |
| `sha256_dec` | `privkey = sha256(str(timestamp))` | ms, s | The classic timestamp brainwallet, common in 2015-era scripts and tutorials |
| `keccak_dec` | `privkey = keccak256(str(timestamp))` | ms, s | The Ethereum-native variant of the same idea |
| `sha256_be8` | `privkey = sha256(timestamp as 8-byte big-endian)` | ms, s | What a program hashing the raw integer would produce |
| `mt19937_s` | MT19937 seeded with seconds → first eight outputs used directly as the key | s | Timestamp-seeded keys with no BIP-39 layer |
| `raw` | `privkey = timestamp` | ms, s | Included because early users really did this; no wallet library generates keys this way |

Documented windows, as preset buttons on the page (exact UTC epochs):

| Window | Range | Verdict |
| --- | --- | --- |
| Trust Wallet extension v2.68 | `1669248000`–`1671753599` s (2022-11-24 → 2022-12-22), 2,505,600 seeds | **The genuine timestamp-seeded Ethereum window.** Worth sweeping with `tw_bip39_s` / `mt19937_s`, with the caveat above |
| Frontier era | `1438214400000`–`1451606399000` ms (2015-07-30 → 2015-12-31) | 13.4 billion ms timestamps. Weak/brainwallet generation was real here, but sweep a slice — the whole range is weeks of RPC-bound work |
| CryptoJS < 4.2 era | `1514764800`–`1577836799` s (2018 → 2020) | CVE-2023-46233 made `WordArray.random` fall back to `Math.random`. Recovering those wallets needs the **browser PRNG state**, not a timestamp sweep: a timestamp recipe only finds keys that were *also* seeded from the clock |
| 2014 presale | `1405987200000`–`1409702399000` ms (2014-07-22 → 2014-09-02) | **Will not recover a presale wallet.** Presale keys came from a real CSPRNG; the documented weakness is in the *encrypted keystore* (weak password, IV reuse). Kept only so the window is not mistaken for a scannable one |

The 2015–2016 "ethercombing" / Blockchain Bandit drain was **sequential and
dictionary private keys**, not timestamps — that is the second card on `/eth`
(`1..N` plus any pasted hex keys), and it is the only Ethereum vector on this
page that is known to have actually paid out.

### Verification, saving and exporting

Every batch is checked before anything is saved:

- `wei > 0` → saved as a hit, logged `★★★ ETH HIT`, verdict
  `funded_verify_manually`. Nothing here proves the funds are spendable — it
  proves the address is *live*, and you must confirm by hand before acting.
- `wei == 0, nonce == 0` → **skipped** (never used), counted in the job detail.
  Set `ETH_MIN_WEI=0` to save them anyway.
- `wei == 0, nonce > 0` → used and emptied; logged, not saved as a hit.
- Transport failure or HTTP 429 → the batch stores **nothing** (a rate limit is
  not a verdict), is counted as `throttled`, and is **appended to
  `eth_pending.jsonl`** so the derivation work is not lost. Drain it later with
  **Re-check queued candidates** on `/eth`.
- A per-call RPC error (one item in the batch) stores an error row and saves
  the candidate fail-open, rather than dropping a possible hit.

ETH rows reuse the `balance_checks` table with an exact split: `sats` holds
whole **gwei**, `mempool_sats` holds the remaining **wei**
(`sats * 1e9 + mempool_sats` reconstructs the balance with no float error), and
`tx_count` holds the **nonce**. `/results` shows ETH badges
(`1.234568 ETH · nonce 7`), **Check ETH balances** re-checks every saved `0x`
address in batches with retry passes, and **Download Ethereum results
(JSONL)** exports every `eth_*` bucket.

### Endpoints: three failure modes, three different responses

Four public, keyless endpoints are configured by default
(`ethereum-rpc.publicnode.com`, `eth.drpc.org`, `rpc.flashbots.net`,
`ethereum.blockpi.network/v1/rpc/public`); set `ETH_RPC_URLS` (comma-separated)
to replace them. **Public endpoints reject datacenter traffic.** `1rpc.io/eth`
answered an EC2 host in `ap-south-1` with `HTTP 403 Forbidden`, and
`eth.llamarpc.com` was returning 525/403 in October 2026 measurements, so
neither ships as a default any more. Treat any built-in list as unverified: use
**Test RPC** (`POST /api/eth/ping`) or, better, your own node.

| What comes back | What the client does |
| --- | --- |
| `429` / `5xx` | Parks **that** endpoint for an escalating cooldown (honouring `Retry-After`), fails over to the next one, and slows the global spacing. When nothing is left standing it **waits** for a cooldown to expire and retries the same batch — it does not drop it |
| `401` / `403` | Parks that endpoint for `ETH_DEAD_COOL_SECS` (1 h) and marks it *refusing*. If **every** endpoint refuses, the run **stops** with an explicit message instead of deriving candidates nobody can check — continuing would only grow the queue |
| `400` / `413`, or a single object instead of an array | "We do not take arrays" or "that batch is too big": the endpoint is remembered as batch-less, the batch size **halves** for later batches (growing back after 20 clean requests), and the current batch is answered with single calls |
| timeout / connection error / non-JSON | Parks the endpoint for `ETH_ERROR_COOL_SECS` and fails over |

Every job starts with a **pre-flight probe** (`ETH_PREFLIGHT=1`): one parallel
round of `eth_blockNumber` plus a small batch probe per endpoint, logged with
block height, latency and batch support. Only the endpoints that answer are used
for the run; if none answer, the job stops before deriving anything. That probe
costs about a second and is what turns "two hours of `403` lines" into one
readable message.

### The retry queue: nothing derived is thrown away

Deriving a candidate costs up to ~2.7 ms (PBKDF2 dominates), so a batch that
cannot be checked is **appended to `eth_pending.jsonl`** on the data disk —
address, private key, recipe, timestamp and the reason it was queued. That
covers throttling, refusals, and a **Stop** pressed mid-run (whatever is still
in the buffer is queued, not dropped). `ETH_PENDING_MAX` caps the file; past the
cap, candidates are counted as `dropped` and the log warns once.

**Re-check queued candidates** on `/eth` (`POST /api/eth/retry`) drains the file
in batches — no re-derivation — saves funded addresses with exactly the payload
a live sweep would have produced, and rewrites the file with whatever is still
unchecked. `GET /api/eth/pending` reports the count, the path, the current batch
size and the endpoint states.

### Measured speed (this matters less than your RPC)

Derivation rates measured on one vCPU (`c6i.large`), per candidate including
address encoding, with the Trust Wallet 2,505,600-seed window as the yardstick:

| Recipe | coincurve + pycryptodome | coincurve + pure-Python Keccak | pure-Python EC + pycryptodome | pure-Python EC + Keccak |
| --- | --- | --- | --- | --- |
| `raw` | 31,240/s → 1.3 min | 1,197/s → 35 min | 12,693/s → 3.3 min | 1,161/s → 36 min |
| `sha256_dec` | 28,838/s → 1.4 min | 1,387/s → 30 min | 2,544/s → 16 min | 844/s → 50 min |
| `mt19937_s` | 3,617/s → 12 min | 1,114/s → 38 min | 1,510/s → 28 min | 760/s → 55 min |
| `tw_bip39_s` | 641/s → 65 min | 411/s → 102 min | 340/s → 123 min | 304/s → 137 min |

Job-level rates are a little lower (loop, chunking and progress bookkeeping):
23,780 ts/s for `sha256_dec` and 540 ts/s for `tw_bip39_s` with both optional
accelerators installed. `pycryptodome` does Keccak-256 in ~3.4 µs versus
~400 µs for the pure-Python permutation (~117×); `tw_bip39_s` is dominated by
PBKDF2-HMAC-SHA512, which no backend here accelerates.

**Those numbers are the ceiling, not the expectation.** At 23,780 ts/s with
batches of 50 addresses, the sweep would need ~475 HTTP requests per second —
no public endpoint allows that, and you will be rate-limited within seconds.
Real throughput is set by your RPC: sweeping the Trust Wallet window needs
~50,000 batch requests, so at a sustainable 5 req/s that is ~2.8 hours of
network time regardless of how fast the derivation is. `ETH_RPC_URLS` pointing
at your own node (or a paid provider) is the only way to make a large sweep
practical; `ESPLORA_MIN_INTERVAL` spaces the requests.

### Headless sweep

```bash
# no bloom filter is needed, so no --build-bloom first
.venv/bin/python btc_hunt.py --cli-eth 1669248000 1671753599 \
  --unit s --recipes tw_bip39_s,sha256_dec

# the fixed eras: list them, then batch several in one run.
# ERA[:STEPS[@OFFSET]] — 50k from the start of Era 2, then 50k from 2M into Era 3
.venv/bin/python btc_hunt.py --list-eras
.venv/bin/python btc_hunt.py --cli-eth-era frontier:50000,cryptojs:50000@2000000 \
  --recipes sha256_dec
```

`--steps N` sets the default per-era slice when an era token omits it. The
batch refuses an unknown era, a unit no selected recipe accepts, and a total
over `ETH_MAX_TOTAL_STEPS` **before** deriving anything.

### Scope

Only sweep windows and addresses you own or are authorised to test. Sweeping
someone else's address space is key-guessing, and a funded hit is not
authorisation to move funds.

## Checking which build is live

Every page has a footer showing `build <commit>`, the process start time, the
active EC backend, and a note when a running job is deferring auto-deploy.
`GET /health` is public and returns the same build id, so from any device:

```bash
curl http://<your-host>/health
# {"status":"ok","build":"a942280","started":"2026-11-10T05:20:00+00:00",
#  "ec":"libsecp256k1 (coincurve 21.0.0)","keccak":"pycryptodome 4.4.0"}
```

`ec` reads `libsecp256k1 (coincurve <version>)` when the optional native
backend is installed, or `python windowed w=4` when the pure-Python fallback is
running (~4x slower — see [Scan speed](#scan-speed-and-the-ec-backend)).
`keccak` reads `pycryptodome <version>` or `python keccak-f1600 (~400 us/hash)`
and only affects the Ethereum page (~117x slower without it — see
[Ethereum](#ethereum-timestamp-sweeps-weak-keys-live-rpc-balances)).

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
.venv/bin/pip install -r requirements-fast.txt   # optional: native EC, ~244x faster
PORT=10000 DISK_PATH=./local-data .venv/bin/gunicorn btc_hunt:app \
  --bind 0.0.0.0:$PORT --timeout 180 --workers 1 --threads 16
# or: .venv/bin/python btc_hunt.py --port 10000
```

Worker/CLI modes are unchanged, e.g. `python btc_hunt.py --build-bloom` or
`python btc_hunt.py --worker randstorm --shard 3/10`.

## Tests

```bash
python tests/test_eth.py       # no pytest, no network: requests is monkeypatched
```

29 groups: published vectors for every Ethereum primitive, the recipes, the
JSON-RPC client (batching, per-item errors, batch refusal, 429 failover, 403
parking, pre-flight probe, adaptive batch size), the sweeps, the retry queue and
its drainer, the fixed era table (including the corrected CVE id and the
14-digit end), the era batch route/job/CLI, the dashboard widgets, and a Bitcoin
regression group. It writes only to a temporary `DISK_PATH` and runs the CLI
groups as subprocesses with `ETH_VERIFY_BALANCES=0`, so it needs no network.

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
- **Ethereum has no local dataset.** Every `/eth` candidate is checked over
  JSON-RPC, so public endpoints — not the CPU — set the sweep rate, and a
  large window needs your own node or a paid provider. Public endpoints also
  reject datacenter IPs outright (HTTP 403), which the pre-flight probe reports
  before a run wastes hours. See
  [Ethereum](#ethereum-timestamp-sweeps-weak-keys-live-rpc-balances).
- **The era windows cannot be swept.** Era 2 is 13.4 billion timestamps and
  Era 3 is 63.1 billion; at the ~24,000 candidates/s measured on EC2 that is ~6
  and ~30 days of pure CPU, but 268 million and 1.26 billion batch requests —
  ~2 and ~8 years at a sustainable 5 requests/s from a public endpoint. The era batch therefore samples
  `ETH_ERA_STEPS` timestamps per era and reports the exact slice and the
  percentage of the window it covered. Era 1 (2014 presale) is additionally
  **not** recoverable by a private-key timestamp sweep at all —
  see [The fixed era windows](#the-fixed-era-windows-batch-and-manual).
- **Single instance only.** Job state (`_JOBS`) and the SQLite DB are in-process
  and on a local disk. Do not set `numInstances` > 1 or add autoscaling.
- **Python 3.12.** Pinned because dependency versions are pinned. The app also
  ships a pure-Python RIPEMD160 fallback for OpenSSL 3 builds that lack the
  legacy provider, so address derivation works on any Render Python image.
