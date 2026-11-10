#!/usr/bin/env python3
"""Live block monitor test suite — run it with `python tests/test_live.py`.

No pytest, no internet: `requests.get` is monkeypatched against a synthetic
Esplora (and one group serves that same synthetic chain over a real localhost
HTTP server to exercise the CLI end to end). It covers

  1-2   the published BIP-143 vectors: segwit sighash digests, and rebuilding
        raw transactions from Esplora JSON byte-for-byte
  3-4   DER parsing, scriptSig pushes, and address decoding for all five
        standard output types (bech32 and bech32m)
  5-6   signature extraction per input type — including what is deliberately
        NOT supported (Taproot, OP_CODESEPARATOR truncation) — and the
        nonce-reuse key recovery, verified against a published private key
  7-9   the rolling SQLite index: collisions, pruning, the row cap
  10-14 the monitor itself: block paging, cross-block reuse found and saved,
        Stop, following the tip, and rate limiting
  15-16 single-address mode: paginated history, segwit signatures included
  17-18 routes, page copy, API validation, the estimate arithmetic and the CLI

Every assertion that encodes a published test vector says so in a comment.
The vectors are from bitcoin/bips `bip-0143.mediawiki`.
"""
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

DISK = tempfile.mkdtemp(prefix="btc-hunt-live-test-")
DISK_CLI = tempfile.mkdtemp(prefix="btc-hunt-live-cli-")
os.environ.update({
    "DISK_PATH": DISK,
    # Politeness off: this suite must not sleep.
    "ESPLORA_MIN_INTERVAL": "0", "ESPLORA_PACE_MAX_SECS": "0",
    "ESPLORA_CACHE_SIZE": "0", "ESPLORA_MAX_BACKOFF_SECS": "1",
    "ESPLORA_MAX_RETRIES": "0",
    "ESPLORA_URLS": "http://esplora.invalid",
    # No network for balance checks: a hit is saved as a candidate.
    "AUTO_VERIFY_HITS": "0",
    "LIVE_WINDOW_BLOCKS": "10", "LIVE_MAX_BLOCKS": "4",
    "LIVE_POLL_SECS": "5", "LIVE_SIG_ROWS_MAX": "1000",
    "LIVE_HEIGHT_RETRIES": "3", "NONCE_MAX_TXS": "120",
    "APP_USER": "", "APP_PASSWORD": "", "BTC_HUNT_BUILD_ID": "test-live",
    "ETH_PREFLIGHT": "0",
})
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import btc_hunt as b  # noqa: E402

REAL_GET = b.requests.get
N = b.N

# ══════════════════════════════════════════════════════════════════════
# Published BIP-143 vectors (bitcoin/bips, bip-0143.mediawiki)
# ══════════════════════════════════════════════════════════════════════
# --- Native P2WPKH: two inputs, input 0 is a LEGACY P2PK spend, input 1 is
# --- the native segwit one. Both signatures and both sighashes are published,
# --- which anchors _bip143_sighash AND _legacy_sighash (inside a segwit tx).
V_P2WPKH_UNSIGNED = (
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
    "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57"
    "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85"
    "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2"
    "f0167faa815988ac11000000")
V_P2WPKH_SIGNED = (
    "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad"
    "969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a5"
    "5d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4"
    "cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d"
    "57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f"
    "85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50c"
    "e2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5"
    "447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a"
    "8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc7"
    "0f07aeee635711000000")
V_P2WPKH_SPK0 = ("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc19"
                 "8bd25432ac")          # P2PK, 6.25 BTC, legacy sighash
V_P2WPKH_VAL0 = 625000000
V_P2WPKH_SPK1 = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"   # P2WPKH, 6 BTC
V_P2WPKH_VAL1 = 600000000
V_P2WPKH_PRIV1 = ("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286"
                  "feb9")
V_P2WPKH_PUB1 = ("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aee"
                 "e6357")
V_P2WPKH_PRIV0 = ("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027f"
                  "f866")
V_P2WPKH_SIG1 = ("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366"
                 "d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a"
                 "8caed02de67eebee01")
V_P2WPKH_HASH1 = ("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478c"
                  "b670")
V_P2WPKH_CODE1 = "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
# Derived from the published signed serialisation rather than hand-copied, so a
# transcription error cannot masquerade as a failing vector.
V_P2WPKH_SIG0 = b._script_pushes(b._parse_tx(bytes.fromhex(V_P2WPKH_SIGNED))[1][0]
                                 ["scriptsig"])[0].hex()
V_P2WPKH_PREVOUTS = ((V_P2WPKH_SPK0, V_P2WPKH_VAL0), (V_P2WPKH_SPK1, V_P2WPKH_VAL1))

# --- P2SH-P2WPKH
V_P2SH_UNSIGNED = (
    "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477"
    "0100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f3"
    "5b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6"
    "d77c88ac92040000")
V_P2SH_SIGNED = (
    "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a"
    "5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4"
    "eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f00"
    "0000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac"
    "8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485"
    "cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b"
    "92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000")
V_P2SH_SPK = "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387"   # 10 BTC
V_P2SH_VAL = 1000000000
V_P2SH_CODE = "1976a91479091972186c449eb1ded22b78e40d009bdf008988ac"
V_P2SH_HASH = ("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59f"
               "b6")
V_P2SH_PUB = ("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a268"
              "73")

# --- Native P2WSH with OP_CODESEPARATOR and an out-of-range SIGHASH_SINGLE
V_P2WSH_UNSIGNED = (
    "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e"
    "0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee"
    "0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f7"
    "51864167f32e0963f788ac00000000")
V_P2WSH_SIGNED = (
    "01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216"
    "b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e93945"
    "88a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e4"
    "35b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee"
    "0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f7"
    "51864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f"
    "936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30"
    "860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb12"
    "00b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c28696"
    "3bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a5"
    "8ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5"
    "e0d0215ea465ac00000000")
V_P2WSH_SPK0 = ("21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e146"
                "85f8ac")                                    # P2PK, 1.5625 BTC
V_P2WSH_VAL0 = 156250000
V_P2WSH_SPK1 = ("00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6"
                "f6a0")                                    # P2WSH, 49 BTC
V_P2WSH_VAL1 = 4900000000
# the witnessScript is the last witness item of the P2WSH input; the BIP prints
# it length-prefixed (0x47 = 71 bytes) as the scriptCode
V_P2WSH_WS = b._parse_tx(bytes.fromhex(V_P2WSH_SIGNED))[1][1]["witness"][-1].hex()
assert len(bytes.fromhex(V_P2WSH_WS)) == 0x47
# the BIP publishes the whole-script digest for input 1 with nHashType 3
V_P2WSH_HASH_FULL = ("82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e419"
                     "4391")
# ... and the post-OP_CODESEPARATOR digest, which this app does NOT compute
V_P2WSH_HASH_TRUNC = ("fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134"
                      "fc47")
V_P2WSH_PREVOUTS = ((V_P2WSH_SPK0, V_P2WSH_VAL0), (V_P2WSH_SPK1, V_P2WSH_VAL1))

# --- "No FindAndDelete": the witnessScript is itself a DER signature
V_NFD_SIGNED = (
    "0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac83"
    "87f14c1d000000ffffffff01010000000000000000034830450220487fb382c4974de3f7d8"
    "34c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882e"
    "b6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012102a9781d66b61fb5a7ef00ac5ad5bc"
    "6ffc78be7b44a566e3c87870e1079368df4c4aad4830450220487fb382c4974de3f7d834c1"
    "b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6ae"
    "efa1bc3790e39f59eaa46ff7f15ae626c53e0100000000")
V_NFD_SPK = ("00209e1be07558ea5cc8e02ed1d80c0911048afad949affa36d5c3951e3159dbea"
             "19")
V_NFD_VAL = 200000
V_NFD_WS = b._parse_tx(bytes.fromhex(V_NFD_SIGNED))[1][0]["witness"][-1].hex()
assert len(bytes.fromhex(V_NFD_WS)) == 0x4a
V_NFD_HASH = ("71c9cd9b2869b9c70b01b1f0360c148f42dee72297db312638df136f43311f23")

assert b.sha256(bytes.fromhex(V_P2WSH_WS)).hex() == V_P2WSH_SPK1[4:]
assert b.sha256(bytes.fromhex(V_NFD_WS)).hex() == V_NFD_SPK[4:]
assert b._parse_der_sig(bytes.fromhex(V_P2WPKH_SIG0))[2] == 1     # SIGHASH_ALL
assert b._parse_der_sig(bytes.fromhex(V_P2WPKH_SIG1))[2] == 1

try:                                   # optional: only used to double-check
    from coincurve import PublicKey as _CCPub
except Exception:                      # pragma: no cover
    _CCPub = None


# ══════════════════════════════════════════════════════════════════════
# helpers: ECDSA signing, DER encoding, Esplora-shaped fixtures
# ══════════════════════════════════════════════════════════════════════
def der_sig(r, s, htype=1):
    def enc(v):
        bb = int(v).to_bytes(max(1, (int(v).bit_length() + 8) // 8), "big")
        return b"\x02" + bytes([len(bb)]) + bb
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body + bytes([htype])


def ecdsa_sign(d, k, z):
    x, _y = b.pubkey_point(k)
    r = x % N
    s = (pow(k, -1, N) * (z + r * d)) % N
    return r, s


def txid_of(raw):
    """The txid of a serialised tx: double-SHA256 of its NON-witness form."""
    parsed = b._parse_tx(raw)
    assert parsed, raw[:20]
    version, inputs, outputs, locktime, _segwit = parsed
    return b.sha256d(b._serialize_tx(
        version, [dict(i, witness=[]) for i in inputs], outputs, locktime,
        False))[::-1].hex()


def esplora_tx(raw, prevouts, txid=""):
    """Esplora-shaped JSON for a serialised transaction."""
    version, inputs, outputs, locktime, segwit = b._parse_tx(raw)
    vin = []
    for i, inp in enumerate(inputs):
        spk_hex, value = prevouts[i]
        spk = bytes.fromhex(spk_hex)
        entry = {"txid": inp["outpoint"][:32][::-1].hex(),
                 "vout": int.from_bytes(inp["outpoint"][32:], "little"),
                 "scriptsig": inp["scriptsig"].hex(),
                 "sequence": int.from_bytes(inp["sequence"], "little"),
                 "is_coinbase": False,
                 "prevout": {"scriptpubkey": spk_hex, "value": value,
                             "scriptpubkey_type": b.scriptpubkey_to_address(spk)[0],
                             "scriptpubkey_address":
                                 b.scriptpubkey_to_address(spk)[1]}}
        if segwit and inp["witness"]:
            entry["witness"] = [w.hex() for w in inp["witness"]]
        vin.append(entry)
    vout = [{"value": int.from_bytes(o["value"], "little"),
             "scriptpubkey": o["script"].hex()} for o in outputs]
    return {"txid": txid or txid_of(raw),
            "version": int.from_bytes(version, "little"),
            "locktime": int.from_bytes(locktime, "little"),
            "size": len(raw), "weight": len(raw) * 4,
            "vin": vin, "vout": vout}


def make_p2wpkh_tx(prev_txid, prev_vout, d, k, value, htype=1, z2=None):
    """A signed native-P2WPKH spend of `value` sats by privkey d with nonce k.

    Returns (esplora_json, z, r, s). With `z2` given, the signature is made over
    z2 instead of the real digest — used to build the second half of a
    reused-nonce pair.
    """
    pub = b.derive_pubkeys(d)[0]
    spk = "0014" + b.hash160(pub).hex()
    tx = {"txid": "", "version": 2, "locktime": 0,
          "vin": [{"txid": prev_txid, "vout": prev_vout, "scriptsig": "",
                   "sequence": 0xffffffff, "is_coinbase": False,
                   "prevout": {"scriptpubkey": spk, "value": value,
                               "scriptpubkey_type": "v0_p2wpkh",
                               "scriptpubkey_address":
                                   b.segwit_address(0, b.hash160(pub))}}],
          "vout": [{"value": value - 200,
                    "scriptpubkey": "76a914" + "11" * 20 + "88ac"}]}
    tx["vin"][0]["witness"] = []
    raw = b._tx_from_esplora(tx)
    z = b._bip143_sighash(raw, 0, b._p2wpkh_script_code(pub), value, htype)
    assert z is not None
    r, s = ecdsa_sign(d, k, z2 if z2 is not None else z)
    tx["vin"][0]["witness"] = [der_sig(r, s, htype).hex(), pub.hex()]
    tx["txid"] = txid_of(b._tx_from_esplora(tx))
    return tx, z, r, s


class FakeResp:
    def __init__(self, payload=None, status=200, text=None):
        self.status_code = status
        self.headers = {"Retry-After": "1"} if status == 429 else {}
        if text is not None:
            self.text = text
        else:
            self.text = json.dumps(payload) if payload is not None else ""
        self._p = payload

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)


CHAIN = {"tip": 100, "blocks": {}, "addr": {}, "fail": None, "gets": []}


def add_block(height, txs, block_hash=None, timestamp=1700000000):
    h = block_hash or ("%064x" % (0xB10C + height))
    CHAIN["blocks"][height] = {"hash": h, "txs": txs, "timestamp": timestamp}
    return h


def fake_get(url, timeout=None, headers=None, **kw):
    path = url.split("//", 1)[-1]
    path = "/" + path.split("/", 1)[1] if "/" in path else path
    CHAIN["gets"].append(path)
    if CHAIN["fail"] in ("all", path):
        return FakeResp(None, 429)
    parts = [p for p in path.split("/") if p]
    if path == "/blocks/tip/height":
        return FakeResp(text=str(CHAIN["tip"]))
    if len(parts) == 2 and parts[0] == "block-height":
        blk = CHAIN["blocks"].get(int(parts[1]))
        return FakeResp(text=blk["hash"]) if blk else FakeResp(None, 404)
    if len(parts) == 2 and parts[0] == "block":
        for height, blk in CHAIN["blocks"].items():
            if blk["hash"] == parts[1]:
                return FakeResp({"id": blk["hash"], "height": height,
                                 "timestamp": blk["timestamp"],
                                 "tx_count": len(blk["txs"])})
        return FakeResp(None, 404)
    if len(parts) in (3, 4) and parts[0] == "block" and parts[2] == "txs":
        for blk in CHAIN["blocks"].values():
            if blk["hash"] == parts[1]:
                start = int(parts[3]) if len(parts) == 4 else 0
                return FakeResp(blk["txs"][start:start + b.LIVE_PAGE])
        return FakeResp(None, 404)
    if len(parts) >= 3 and parts[0] == "address":
        addr, txs = parts[1], CHAIN["addr"].get(parts[1], [])
        if parts[2] == "txs" and len(parts) == 3:
            return FakeResp(txs[:b.NONCE_TXS_PAGE])
        if parts[2] == "txs" and parts[3] == "mempool":
            return FakeResp([])
        if parts[2] == "txs" and parts[3] == "chain":
            ids = [t["txid"] for t in txs]
            i = ids.index(parts[4]) + 1 if parts[4] in ids else len(ids)
            return FakeResp(txs[i:i + b.NONCE_TXS_PAGE])
    return FakeResp(None, 404)


def reset_chain():
    CHAIN["tip"] = 100
    CHAIN["blocks"].clear()
    CHAIN["addr"].clear()
    CHAIN["fail"] = None
    CHAIN["gets"] = []
    b._esplora_cache_clear()
    with b._RATE_LOCK:
        b._RATE_INTERVAL[0] = b.ESPLORA_MIN_INTERVAL
        b._BASE_COOL.clear()
        b._BASE_FAILS.clear()
        b._RATE_FAILURES[0] = 0
    b.live_reset()
    with b._db() as c:
        c.execute("DELETE FROM results")          # each group starts clean
        c.execute("DELETE FROM balance_checks")
    b.requests.get = fake_get


def newjob():
    return {"progress": 0.0, "detail": "", "stop": False, "throttled": 0,
            "auto_verify_skipped": 0, "alive": True}


def wait_job(name, timeout=60.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        with b._JOBS_LOCK:
            job = b._JOBS.get(name)
            if job is None or not job["alive"]:
                return job
        time.sleep(0.05)
    raise AssertionError("job %s did not finish in %.0fs" % (name, timeout))


b.requests.get = fake_get
print("EC: %s | esplora bases: %s | live window: %s blocks | page: %d tx"
      % (b.EC_BACKEND, ",".join(b._ESPLORA_BASES),
         format(b.LIVE_WINDOW_BLOCKS, ","), b.LIVE_PAGE))

# ══════════════════════════════════════════════════════════════════════
# 1 — published BIP-143 digests, and legacy sighash inside a segwit tx
# ══════════════════════════════════════════════════════════════════════
raw = bytes.fromhex(V_P2WPKH_UNSIGNED)
parsed = b._parse_tx(raw)
assert parsed, "the published unsigned tx must parse"
version, inputs, outputs, locktime, segwit = parsed
assert segwit is False and len(inputs) == 2 and len(outputs) == 2
# re-serialising what was parsed must give the bytes back, exactly
assert b._serialize_tx(version, inputs, outputs, locktime, segwit) == raw
# The P2WPKH scriptCode is the equivalent P2PKH script (BIP-141). BIP-143 prints
# it already length-prefixed for the preimage, so the published constant carries
# a leading 0x19 = 25 bytes; _bip143_sighash adds that prefix itself.
code1 = bytes.fromhex(V_P2WPKH_CODE1)
assert code1[0] == len(code1) - 1 == 0x19, code1.hex()
assert b._p2wpkh_script_code(bytes.fromhex(V_P2WPKH_PUB1)) == code1[1:]
z = b._bip143_sighash(raw, 1, code1[1:], V_P2WPKH_VAL1, 1)
assert "%064x" % z == V_P2WPKH_HASH1, "%064x" % z         # BIP-143 sigHash
# ... and the keypair the BIP publishes for that input really is that key
assert b.derive_pubkeys(int(V_P2WPKH_PRIV1, 16))[0].hex() == V_P2WPKH_PUB1
assert b.hash160(bytes.fromhex(V_P2WPKH_PUB1)).hex() == \
    bytes.fromhex(V_P2WPKH_SPK1)[2:].hex()
# the legacy input of the same transaction: _legacy_sighash must digest the
# NON-witness form. Signing it with the published key and verifying the result
# with libsecp256k1 is the anchor — the digest is right or the signature is not.
raw_signed = bytes.fromhex(V_P2WPKH_SIGNED)
p_signed = b._parse_tx(raw_signed)
assert b._serialize_tx(*p_signed) == raw_signed
z0 = b._legacy_sighash(raw_signed, 0, bytes.fromhex(V_P2WPKH_SPK0), 1)
r0, s0, ht0 = b._parse_der_sig(bytes.fromhex(V_P2WPKH_SIG0))
assert ht0 == 1 and r0 and s0
if _CCPub:
    pub0 = b.derive_pubkeys(int(V_P2WPKH_PRIV0, 16))[0]
    der0 = der_sig(r0, s0, 0)[:-1]          # strip the sighash byte

    def _verifies(pub, sig, digest):
        try:
            return bool(_CCPub(pub).verify(sig, digest, hasher=None))
        except Exception:
            return False

    assert _verifies(pub0, der0, z0.to_bytes(32, "big")), \
        "the published legacy P2PK signature must verify over our digest"
    assert p_signed[4] is True              # it IS a witness-serialised tx ...
    wrong = b.sha256d(raw_signed)           # ... so digesting those bytes fails
    assert not _verifies(pub0, der0, wrong), \
        "a witness-inclusive digest must not verify"
# P2SH-P2WPKH
code_sh = bytes.fromhex(V_P2SH_CODE)
assert code_sh[0] == len(code_sh) - 1 == 0x19, code_sh.hex()
z = b._bip143_sighash(bytes.fromhex(V_P2SH_UNSIGNED), 0, code_sh[1:],
                      V_P2SH_VAL, 1)
assert "%064x" % z == V_P2SH_HASH, "%064x" % z
# Native P2WSH, SIGHASH_SINGLE with no matching output: hashOutputs is 32 zeros
z = b._bip143_sighash(bytes.fromhex(V_P2WSH_UNSIGNED), 1,
                      bytes.fromhex(V_P2WSH_WS), V_P2WSH_VAL1, 3)
assert "%064x" % z == V_P2WSH_HASH_FULL, "%064x" % z
assert "%064x" % z != V_P2WSH_HASH_TRUNC       # truncation is NOT implemented
# "No FindAndDelete": the witnessScript contains a DER blob and is used as-is
z = b._bip143_sighash(bytes.fromhex(V_NFD_SIGNED), 0, bytes.fromhex(V_NFD_WS),
                      V_NFD_VAL, 1)
assert "%064x" % z == V_NFD_HASH, "%064x" % z
# out-of-range input index and garbage bytes are refused, not guessed
assert b._bip143_sighash(raw, 9, b"", 0) is None
assert b._bip143_sighash(b"\x01\x02", 0, b"", 0) is None
assert b._parse_tx(b"") is None and b._parse_tx(b"\x01" * 4) is None
print("1 ok  BIP-143 digests (P2WPKH/P2SH-P2WPKH/P2WSH/no-FindAndDelete) + "
      "legacy sighash inside a segwit tx")

# ══════════════════════════════════════════════════════════════════════
# 2 — Esplora JSON is re-serialised byte-for-byte (the no-per-tx-fetch claim)
# ══════════════════════════════════════════════════════════════════════
for raw_hex, prevouts, name in (
        (V_P2WPKH_SIGNED, V_P2WPKH_PREVOUTS, "native P2WPKH"),
        (V_P2SH_SIGNED, ((V_P2SH_SPK, V_P2SH_VAL),), "P2SH-P2WPKH"),
        (V_P2WSH_SIGNED, V_P2WSH_PREVOUTS, "native P2WSH"),
        (V_NFD_SIGNED, ((V_NFD_SPK, V_NFD_VAL),), "no-FindAndDelete P2WSH")):
    raw = bytes.fromhex(raw_hex)
    rebuilt = b._tx_from_esplora(esplora_tx(raw, prevouts))
    assert rebuilt == raw, "%s: rebuilt %d bytes != published %d bytes" % (
        name, len(rebuilt or b""), len(raw))
# a coinbase input is represented, not dropped: its 36-byte "outpoint" is zeros
cb = {"txid": "0" * 64, "version": 1, "locktime": 0,
      "vin": [{"is_coinbase": True, "scriptsig": "04ffff001d0104",
               "sequence": 0xffffffff, "witness": ["00" * 32],
               "prevout": None}],
      "vout": [{"value": 5000000000, "scriptpubkey": "41" + "04" + "aa" * 64 +
                "ac"}]}
raw = b._tx_from_esplora(cb)
parsed = b._parse_tx(raw)
assert parsed and parsed[4] is True and len(parsed[1]) == 1
assert parsed[1][0]["outpoint"] == b"\x00" * 32 + b"\xff" * 4
# the same tx re-serialised without its witness is what a txid hashes
assert txid_of(raw) == b.sha256d(
    b._serialize_tx(parsed[0], [dict(parsed[1][0], witness=[])], parsed[2],
                    parsed[3], False))[::-1].hex()
print("2 ok  raw transactions rebuilt byte-exactly from Esplora JSON")

# ══════════════════════════════════════════════════════════════════════
# 3 — DER parsing and scriptSig pushes
# ══════════════════════════════════════════════════════════════════════
r, s, ht = b._parse_der_sig(bytes.fromhex(V_P2WPKH_SIG1))
assert r == int(V_P2WPKH_SIG1[8:72], 16), hex(r)
assert "%064x" % r == "3609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a"
assert "%064x" % s == "573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
assert ht == 1
for junk in (b"", b"\x30", b"\x31\x06\x02\x01\x01\x02\x01\x01\x01",
             b"\x30\x06\x02\x01\x01", b"not a signature at all",
             bytes.fromhex(V_P2WPKH_SIG1)[:4]):
    assert b._parse_der_sig(junk) is None, junk
# The P2SH-P2WPKH scriptSig content (published, from the signed vector) is the
# 23-byte redeemScript `16 0014<hash>`; its single push is the witness program.
scriptsig = b._parse_tx(bytes.fromhex(V_P2SH_SIGNED))[1][0]["scriptsig"]
assert scriptsig.hex() == "16001479091972186c449eb1ded22b78e40d009bdf0089"
pushes = b._script_pushes(scriptsig)
assert len(pushes) == 1 and len(pushes[0]) == 22, pushes
assert pushes[0].hex() == "001479091972186c449eb1ded22b78e40d009bdf0089"
# For a NON-witness P2SH spend the last push is the redeemScript that gets
# signed, never the OP_HASH160 <hash> OP_EQUAL wrapper.
wrapper = bytes.fromhex(V_P2SH_SPK)
legacy_p2sh = b"\x01\xaa" + bytes([len(scriptsig)]) + scriptsig
assert b._legacy_script_code(legacy_p2sh, wrapper) == scriptsig
assert b._legacy_script_code(b"", wrapper) == wrapper      # no pushes: wrapper
# and the wrapped-segwit shape is recognised from the same scriptSig
sc, kind = b._segwit_script_code(
    wrapper, scriptsig,
    b._parse_tx(bytes.fromhex(V_P2SH_SIGNED))[1][0]["witness"])
assert kind == "p2sh-p2wpkh" and sc == b._p2wpkh_script_code(
    bytes.fromhex(V_P2SH_PUB)), (kind, sc.hex())
print("3 ok  DER signatures parsed, junk rejected, P2SH signs the redeemScript")

# ══════════════════════════════════════════════════════════════════════
# 4 — address decoding for all five standard output types
# ══════════════════════════════════════════════════════════════════════
kind, addr = b.scriptpubkey_to_address(bytes.fromhex(V_P2WPKH_SPK1))
assert kind == "p2wpkh" and addr.startswith("bc1q")
assert addr == b.p2wpkh_address(bytes.fromhex(V_P2WPKH_PUB1))    # same program
assert b._address_to_hash160(addr).hex() == \
    bytes.fromhex(V_P2WPKH_SPK1)[2:].hex()
kind, addr = b.scriptpubkey_to_address(bytes.fromhex(V_P2SH_SPK))
assert kind == "p2sh" and addr.startswith("3")
assert b._address_to_hash160(addr) == bytes.fromhex(V_P2SH_SPK)[2:22]
p2pkh = bytes.fromhex("76a914" + "ab" * 20 + "88ac")
kind, addr = b.scriptpubkey_to_address(p2pkh)
assert kind == "p2pkh" and addr.startswith("1")
assert b._address_to_hash160(addr) == b"\xab" * 20
kind, addr = b.scriptpubkey_to_address(bytes.fromhex(V_P2WSH_SPK1))
assert kind == "p2wsh" and addr.startswith("bc1q") and len(addr) == 62
tr = bytes.fromhex("5120" + "cd" * 32)
kind, addr = b.scriptpubkey_to_address(tr)
assert kind == "p2tr" and addr.startswith("bc1p"), (kind, addr)
# bech32m checksum: recompute it independently and compare
data = [1] + b._convertbits(b"\xcd" * 32, 8, 5)
assert addr == "bc1" + "".join(b.BECH32[d] for d in
                               data + b._bech32_checksum("bc", data,
                                                         b.BECH32M_CONST))
assert b._bech32_checksum("bc", data, 1) != \
    b._bech32_checksum("bc", data, b.BECH32M_CONST)      # v0 vs v1 differ
assert b.scriptpubkey_to_address(b"\x6a\x04deadbeef")[0] == "other"   # OP_RETURN
assert b.scriptpubkey_to_address(b"")[0] == "other"
print("4 ok  p2pkh/p2sh/p2wpkh/p2wsh/p2tr decoded, bech32 + bech32m correct")

# ══════════════════════════════════════════════════════════════════════
# 5 — signature extraction per input type, incl. what is NOT supported
# ══════════════════════════════════════════════════════════════════════
tx = esplora_tx(bytes.fromhex(V_P2WPKH_SIGNED), V_P2WPKH_PREVOUTS)
sigs, st = b._tx_signatures(tx)
assert st["inputs"] == 2 and st["sigs"] == 2, st
assert st["legacy"] == 1 and st["segwit"] == 1 and st["taproot"] == 0, st
legacy = [s for s in sigs if s["type"] == "legacy"][0]
segwit = [s for s in sigs if s["type"] == "segwit"][0]
assert legacy["vin"] == 0 and segwit["vin"] == 1
assert "%064x" % segwit["z"] == V_P2WPKH_HASH1, "%064x" % segwit["z"]
assert segwit["kind"] == "p2wpkh" and segwit["pubkey"] == V_P2WPKH_PUB1
assert segwit["r"] == int(V_P2WPKH_SIG1[8:72], 16) and segwit["htype"] == 1
assert segwit["amount"] == V_P2WPKH_VAL1 and segwit["spk"] == V_P2WPKH_SPK1
assert legacy["kind"] == "other", legacy["kind"]     # bare P2PK pays no address
assert legacy["z"] == z0, (hex(legacy["z"]), hex(z0))     # same digest as grp 1
# P2SH-P2WPKH: the redeemScript decides the scriptCode, the witness the pubkey
tx = esplora_tx(bytes.fromhex(V_P2SH_SIGNED), ((V_P2SH_SPK, V_P2SH_VAL),))
sigs, st = b._tx_signatures(tx)
assert len(sigs) == 1 and sigs[0]["kind"] == "p2sh-p2wpkh", (sigs, st)
assert "%064x" % sigs[0]["z"] == V_P2SH_HASH, "%064x" % sigs[0]["z"]
assert sigs[0]["pubkey"] == V_P2SH_PUB
# P2WSH with two signatures in one witness: both are indexed, and both get the
# whole-witnessScript digest — the post-OP_CODESEPARATOR one is documented as
# unsupported, so this asserts the limitation instead of hiding it.
tx = esplora_tx(bytes.fromhex(V_P2WSH_SIGNED), V_P2WSH_PREVOUTS)
sigs, st = b._tx_signatures(tx)
assert st["inputs"] == 2 and st["segwit"] == 2 and st["legacy"] == 1, st
p2wsh = [s for s in sigs if s["kind"] == "p2wsh"]
assert len(p2wsh) == 2, [s["kind"] for s in sigs]
assert all(s["htype"] == 3 for s in p2wsh)
assert all("%064x" % s["z"] == V_P2WSH_HASH_FULL for s in p2wsh), \
    ["%064x" % s["z"] for s in p2wsh]
assert all("%064x" % s["z"] != V_P2WSH_HASH_TRUNC for s in p2wsh)
# both witness pubkeys are carried, so a recovered key from an exotic script can
# still be verified against one of them
assert len(p2wsh[0]["pubs"].split(",")) == 2, p2wsh[0]["pubs"]
# no-FindAndDelete: the witnessScript looks like a DER signature but is data —
# only the real signature is extracted
tx = esplora_tx(bytes.fromhex(V_NFD_SIGNED), ((V_NFD_SPK, V_NFD_VAL),))
sigs, st = b._tx_signatures(tx)
assert len(sigs) == 1 and sigs[0]["kind"] == "p2wsh", (sigs, st)
assert "%064x" % sigs[0]["z"] == V_NFD_HASH
# Taproot is counted and skipped, never silently absorbed
tr_spk = "5120" + "cd" * 32
tap = {"txid": "11" * 32, "version": 2, "locktime": 0,
       "vin": [{"txid": "22" * 32, "vout": 0, "scriptsig": "", "sequence": 0,
                "witness": ["aa" * 64],
                "prevout": {"scriptpubkey": tr_spk, "value": 1000,
                            "scriptpubkey_type": "v1_p2tr",
                            "scriptpubkey_address":
                                b.segwit_address(1, bytes.fromhex("cd" * 32))}}],
       "vout": [{"value": 800, "scriptpubkey": "76a914" + "11" * 20 + "88ac"}]}
sigs, st = b._tx_signatures(tap)
assert sigs == [] and st["taproot"] == 1 and st["sigs"] == 0, (sigs, st)
# a witness that does not match its program is skipped, not digested: here a
# P2WPKH witness is claimed to spend somebody else's program
bad = json.loads(json.dumps(tx))
bad["vin"][0]["prevout"]["scriptpubkey"] = \
    "001479091972186c449eb1ded22b78e40d009bdf0089"
bad["vin"][0]["prevout"]["scriptpubkey_address"] = b.segwit_address(
    0, bytes.fromhex("79091972186c449eb1ded22b78e40d009bdf0089"))
bad["vin"][0]["witness"] = [V_P2WPKH_SIG1, V_P2WPKH_PUB1]
sigs, st = b._tx_signatures(bad)
assert sigs == [] and st["bad_digest"] == 1, (sigs, st)
# the address reported for a signature comes from the scriptPubKey, not from a
# stale API field
ok = json.loads(json.dumps(tx))
ok["vin"][0]["prevout"]["scriptpubkey_address"] = "1StaleApiFieldXXXXXXXXXXXXXX"
sigs, st = b._tx_signatures(ok)
assert len(sigs) == 1 and sigs[0]["addr"].startswith("bc1q"), sigs
assert sigs[0]["addr"] == b.segwit_address(
    0, b.sha256(bytes.fromhex(V_NFD_WS)))
# an input with no prevout cannot be digested and is counted, not dropped
noamt = json.loads(json.dumps(tx))
del noamt["vin"][0]["prevout"]["value"]
sigs, st = b._tx_signatures(noamt)
assert sigs == [] and st["no_prevout"] == 1, (sigs, st)
assert b._tx_signatures({"txid": "x", "vin": [], "vout": []})[0] == []
print("5 ok  legacy + P2WPKH + P2SH-P2WPKH + P2WSH extracted; taproot, "
      "mismatched witness and missing prevout counted")

# ══════════════════════════════════════════════════════════════════════
# 6 — key recovery from a repeated nonce, checked against a published key
# ══════════════════════════════════════════════════════════════════════
# The BIP-143 P2WPKH vector publishes r, s, z AND the private key, so k can be
# recovered from it and a second signature made over a different z with the
# SAME k. Recovery must then return that published private key.
d_pub = int(V_P2WPKH_PRIV1, 16)
r1, s1, _ = b._parse_der_sig(bytes.fromhex(V_P2WPKH_SIG1))
z1 = int(V_P2WPKH_HASH1, 16)
k_pub = ((z1 + r1 * d_pub) * pow(s1, -1, N)) % N
assert 0 < k_pub < N
assert ecdsa_sign(d_pub, k_pub, z1) == (r1, s1), "k must reproduce the vector"
z2 = int.from_bytes(b.sha256(b"a different message"), "big") % N
r2, s2 = ecdsa_sign(d_pub, k_pub, z2)
assert r2 == r1 and s2 != s1                       # same nonce -> same r
cands = b.recover_keys_from_pair(r1, s1, z1, s2, z2)
assert d_pub in cands, [hex(c) for c in cands]
ev = b.verify_recovered_key(d_pub, pubkeys=(V_P2WPKH_PUB1,))
assert ev == "pubkey:" + V_P2WPKH_PUB1, ev
assert b.verify_recovered_key((d_pub + 1) % N, pubkeys=(V_P2WPKH_PUB1,)) == ""
# the low-S-normalised (mixed sign) case: one signature has s, the other n-s
s2n = (-s2) % N
cands = b.recover_keys_from_pair(r1, s1, z1, s2n, z2)
assert d_pub in cands, "the mixed-sign case must recover the key too"
# and the reverse order of the pair gives the same answer
assert d_pub in b.recover_keys_from_pair(r1, s2, z2, s1, z1)
# scriptPubKey and address evidence work when the pubkey is unknown (multisig)
spk1 = bytes.fromhex(V_P2WPKH_SPK1)
assert b.verify_recovered_key(d_pub, scriptpubkeys=(V_P2WPKH_SPK1,)).startswith(
    "scriptpubkey:")
assert b.verify_recovered_key(
    d_pub, addresses=(b.segwit_address(0, b.hash160(
        bytes.fromhex(V_P2WPKH_PUB1))),)).startswith("address:")
# a truly degenerate pair implies no key at all
assert b.recover_keys_from_pair(r1, s1, z1, s1, z1) == [] or \
    not any(b.verify_recovered_key(c, pubkeys=(V_P2WPKH_PUB1,))
            for c in b.recover_keys_from_pair(r1, s1, z1, s1, z1))
assert b.recover_keys_from_pair(0, s1, z1, s2, z2) == []       # r out of range
assert b.recover_keys_from_pair(N, s1, z1, s2, z2) == []
# two signatures that merely share an r by construction but not a nonce must
# not produce a verifying key
other = 0xC0FFEE
r3, s3 = ecdsa_sign(other, 0x1234, z1)
assert b.verify_recovered_key(other, pubkeys=(V_P2WPKH_PUB1,)) == ""
print("6 ok  repeated-nonce recovery returns the published private key, "
      "±k and low-S cases included")

# ══════════════════════════════════════════════════════════════════════
# 7 — the rolling index: collisions, pruning, stats, reset, row cap
# ══════════════════════════════════════════════════════════════════════
reset_chain()
assert b.live_stats()["sigs"] == 0
d = 0x1111
pub = b.derive_pubkeys(d)[0].hex()
sg = {"r": 0xAAAA, "s": 11, "z": 22, "htype": 1, "txid": "aa" * 32, "vin": 0,
      "pubkey": pub, "addr": "bc1qtest", "kind": "p2wpkh", "spk": V_P2WPKH_SPK1,
      "amount": 5000}
assert b.live_index_sigs([sg], 100) == []                # first sighting
coll = b.live_index_sigs([dict(sg, txid="bb" * 32, z=33)], 101)
assert len(coll) == 1 and len(coll[0][1]) == 1, coll
assert coll[0][1][0]["txid"] == "aa" * 32 and coll[0][1][0]["height"] == 100
st = b.live_stats()
assert st["sigs"] == 2 and st["distinct_r"] == 1 and st["colliding_r"] == 1, st
assert st["min_height"] == 100 and st["max_height"] == 101
assert st["sat_value"] == 10000, st            # both rows carry their amount
# pruning drops blocks outside the window and keeps the newest ones
for h in range(102, 106):
    b.live_index_sigs([dict(sg, r=0xAAAA + h, txid="%064x" % h)], h)
assert b.live_stats()["sigs"] == 6
assert b.live_prune(105) == 0            # window 10: cut is 95, all are newer
old_w = b.LIVE_WINDOW_BLOCKS
try:
    b.LIVE_WINDOW_BLOCKS = 3
    assert b.live_prune(105) == 2, b.live_stats()      # heights 100 and 101
    st = b.live_stats()
    assert st["sigs"] == 4 and st["min_height"] == 102, st
finally:
    b.LIVE_WINDOW_BLOCKS = old_w
b.live_state_set("last_height", 105)
assert b.live_state_get("last_height") == "105"
assert b.live_state_get("missing", "dflt") == "dflt"
b.live_reset()
assert b.live_stats()["sigs"] == 0 and b.live_state_get("last_height") == ""
# the hard row cap evicts the oldest heights first
old_cap = b.LIVE_SIG_ROWS_MAX
try:
    b.LIVE_SIG_ROWS_MAX = 1000
    for h in (200, 201, 202):
        b.live_index_sigs([dict(sg, r=0xBBBB0000 + h * 1000 + i,
                                txid="%064x" % (h * 1000 + i))
                           for i in range(400)], h)
    st = b.live_stats()
    assert st["sigs"] == 1000, st               # 1200 written, cap is 1000
    assert st["colliding_r"] == 0, st
    with b._db() as c:
        counts = dict(c.execute("SELECT height, COUNT(*) FROM live_sigs "
                                "GROUP BY height"))
    assert counts[202] == 400 and counts[201] == 400, counts
    assert counts[200] == 200, counts           # the oldest rows were evicted
    assert st["sat_value"] == 1000 * 5000, st
finally:
    b.LIVE_SIG_ROWS_MAX = old_cap
    b.live_reset()
print("7 ok  index collisions, window pruning, stats, reset and the row cap")

# ══════════════════════════════════════════════════════════════════════
# 8 — a block is read a page at a time, all of it
# ══════════════════════════════════════════════════════════════════════
reset_chain()
D = 0x2222
txs = []
for i in range(60):
    tx, _z, _r, _s = make_p2wpkh_tx("%064x" % (0xE000 + i), 0, D, 0x5000 + i,
                                      100000 + i)
    txs.append(tx)
add_block(100, txs)
logs, job = [], newjob()
st = b.live_scan_block(100, logs.append, job)
assert st["txs"] == 60, st                      # not the 25 of an unpaged read
assert st["pages"] == 3, st                     # ceil(60/25)
assert st["tx_count"] == 60 and st["sigs"] == 60, st
assert st["segwit"] == 60 and st["legacy"] == 0 and st["hits"] == 0, st
assert b.live_stats()["sigs"] == 60
assert b.live_state_get("last_height") == "100"
assert [p for p in CHAIN["gets"] if "/txs/" in p] == \
    ["/block/%s/txs/0" % st["hash"], "/block/%s/txs/25" % st["hash"],
     "/block/%s/txs/50" % st["hash"]], CHAIN["gets"]
# no per-transaction request was made — that is the whole point of rebuilding
assert not any(p.startswith("/tx/") for p in CHAIN["gets"]), CHAIN["gets"]
# an unreadable block is reported as an error and is not marked as scanned
reset_chain()
st = b.live_scan_block(999, logs.append, newjob())
assert st.get("error") == "no block hash", st
assert b.live_state_get("last_height") == ""
print("8 ok  60-tx block read in 3 pages with no per-transaction request")

# ══════════════════════════════════════════════════════════════════════
# 9 — end to end: a nonce reused across two blocks is found and saved
# ══════════════════════════════════════════════════════════════════════
reset_chain()
D = int(V_P2WPKH_PRIV1, 16)          # the published vector key
K = 0xDEADBEEF
txA, zA, rA, sA = make_p2wpkh_tx("%064x" % 0xA001, 0, D, K, 500000)
# the second spend reuses the nonce: same r, different message
txB, zB, rB, sB = make_p2wpkh_tx("%064x" % 0xA002, 0, D, K, 400000)
assert rA == rB and zA != zB and sA != sB
add_block(100, [txA])
add_block(101, [txB])
CHAIN["tip"] = 101
logs, job = [], newjob()
hits = b.attack_live_blocks(100, False, 2, job=job, log=logs.append)
assert len(hits) == 1, hits
h = hits[0]
assert h["privkey"] == hex(D), h["privkey"]            # the published key
assert h["source"] == "live" and h["evidence"].startswith("pubkey:"), h
assert sorted(h["txids"]) == sorted([txA["txid"], txB["txid"]]), h
assert sorted(h["heights"]) == [100, 101], h
assert h["r"] == hex(rA) and "p2wpkh" in h["sig_kind"], h
rows = [(a, json.loads(pl)) for a, pl in b._db().execute(
    "SELECT attack,payload FROM results")]
assert len(rows) == 1 and rows[0][0] == "nonce", rows
assert rows[0][1]["privkey"] == hex(D) and rows[0][1]["source"] == "live"
assert b.live_state_get("last_height") == "101"
assert job["progress"] == 1.0 and not job.get("partial"), job
assert "2 block(s) scanned" in job["detail"] and "last height 101" in \
    job["detail"], job["detail"]
assert any("★★★ NONCE REUSE" in l for l in logs), logs
assert any("seen again at height 101" in l for l in logs), logs
assert any("what this can find" in l for l in logs), logs      # honest scope
det = job["detail"]
assert "2 block(s) scanned" in det, det
assert "2 sig (2 segwit / 0 legacy / 0 taproot skipped / 0 input(s) unusable)" \
    in det, det
assert "1 r-collision(s)" in det and "index 2 sig / 1 r / 1 colliding r" in det, det
assert any("run totals:" in l for l in logs), logs
# resuming from the persisted height scans nothing new and says so
logs2, job2 = [], newjob()
hits2 = b.attack_live_blocks(None, False, 2, job=job2, log=logs2.append)
assert hits2 == [] and any("resuming from persisted height 101" in l
                           for l in logs2), logs2
assert job2["progress"] == 0.0 and job2.get("partial") is True, job2
assert "nothing new to scan" in job2["detail"], job2["detail"]
print("9 ok  cross-block nonce reuse: key recovered, verified, saved, resumed")

# ══════════════════════════════════════════════════════════════════════
# 10 — Stop, and the honest partial that comes with it
# ══════════════════════════════════════════════════════════════════════
reset_chain()
D, K = 0x3333, 0x77
blocks = {}
for i in range(4):
    tx, _z, _r, _s = make_p2wpkh_tx("%064x" % (0xC000 + i), 0, D, K + i, 90000)
    add_block(100 + i, [tx])
CHAIN["tip"] = 103
logs, job = [], newjob()


def _stop_after_two(msg):
    logs.append(msg)
    if "height 101" in msg:
        job["stop"] = True


hits = b.attack_live_blocks(100, False, 4, job=job, log=_stop_after_two)
assert hits == []
assert job["progress"] < 1.0, job
assert int(b.live_state_get("last_height")) in (100, 101), \
    b.live_state_get("last_height")
assert any("stopped by user" in l for l in logs), logs
# Stop before any block is read: nothing scanned, nothing claimed
reset_chain()
add_block(100, [])
CHAIN["tip"] = 100
logs, job = [], newjob()
job["stop"] = True
b.attack_live_blocks(100, False, 3, job=job, log=logs.append)
assert job["progress"] == 0.0 and b.live_stats()["sigs"] == 0, job
# Stop before the first request is reported as Stop, not as a dead endpoint
assert "stopped before any block was read" in job["detail"], job["detail"]
assert "no Esplora endpoint answered" not in job["detail"], job["detail"]
assert any("stopped by user before the first request" in l for l in logs), logs
print("10 ok  Stop keeps the bar honest and persists only finished heights")

# ══════════════════════════════════════════════════════════════════════
# 11 — following the tip vs stopping at it
# ══════════════════════════════════════════════════════════════════════
reset_chain()
add_block(100, [])
CHAIN["tip"] = 100
logs, job = [], newjob()
t0 = time.time()
b.attack_live_blocks(100, False, 3, job=job, log=logs.append)
assert time.time() - t0 < 5, "no-follow must not wait for a new block"
assert any("caught up to the tip" in l for l in logs), logs
# following with a tip that never moves: it polls, then Stop ends the run
reset_chain()
add_block(100, [])
CHAIN["tip"] = 100
logs, job = [], newjob()
polls = {"n": 0}
real_tip, real_poll = b._live_tip_height, b.LIVE_POLL_SECS


def _tip_stall(should_stop=None):
    polls["n"] += 1
    if polls["n"] >= 4:
        job["stop"] = True
    return 100


b.LIVE_POLL_SECS = 0.05
b._live_tip_height = _tip_stall
try:
    b.attack_live_blocks(100, True, 3, job=job, log=logs.append)
finally:
    b._live_tip_height, b.LIVE_POLL_SECS = real_tip, real_poll
assert polls["n"] >= 4, polls
assert any("stopped by user" in l for l in logs), logs
assert job["progress"] < 1.0, job
assert b.live_state_get("last_height") == "100", b.live_state_get("last_height")

# a new block appearing at the tip is picked up by the same run
reset_chain()
add_block(100, [])
logs, job = [], newjob()
calls = {"n": 0}


def _tip_grow(should_stop=None):
    calls["n"] += 1
    if calls["n"] >= 3:
        add_block(101, [])
        return 101
    return 100


b.LIVE_POLL_SECS = 0.05
b._live_tip_height = _tip_grow
try:
    b.attack_live_blocks(100, True, 2, job=job, log=logs.append)
finally:
    b._live_tip_height, b.LIVE_POLL_SECS = real_tip, real_poll
assert b.live_state_get("last_height") == "101", b.live_state_get("last_height")
assert any("height 101" in l for l in logs), logs
assert job["progress"] == 1.0 and "2 block(s) scanned" in job["detail"], job
print("11 ok  waits for new blocks when following, exits at the tip when not")

# ══════════════════════════════════════════════════════════════════════
# 12 — a throttled endpoint: retried, then the run stops as partial
# ══════════════════════════════════════════════════════════════════════
reset_chain()
tx, _z, _r, _s = make_p2wpkh_tx("%064x" % 0xD001, 0, 0x4444, 0x99, 80000)
add_block(100, [tx])
CHAIN["tip"] = 100
logs, job = [], newjob()
CHAIN["fail"] = "/block/%s/txs/0" % CHAIN["blocks"][100]["hash"]
b.attack_live_blocks(100, False, 2, job=job, log=logs.append)
assert job.get("partial") is True, job
assert job["throttled"] >= 1, job
assert b.live_stats()["sigs"] == 0, "a throttled block must not be indexed"
assert b.live_state_get("last_height") == "", "and must not be marked scanned"
assert any("rate limited" in l for l in logs), logs
assert any("failed 3 time(s) in a row" in l for l in logs), logs
assert any("the resume point stays at nothing scanned yet" in l for l in logs), logs
assert "3 consecutive endpoint failures" in job["detail"], job["detail"]
# no endpoint at all: the run says so instead of reporting a scan
reset_chain()
CHAIN["fail"] = "all"
logs, job = [], newjob()
hits = b.attack_live_blocks(100, False, 2, job=job, log=logs.append)
assert hits == [] and job.get("partial") is True, job
assert "could not read the chain tip" in job["detail"], job["detail"]
assert any("nothing scanned" in l for l in logs), logs
# LIVE_ENABLED=0 refuses instead of pretending
reset_chain()
old_enabled = b.LIVE_ENABLED
try:
    b.LIVE_ENABLED = False
    logs, job = [], newjob()
    b.attack_live_blocks(100, False, 1, job=job, log=logs.append)
    assert "disabled" in job["detail"], job["detail"]
    assert any("disabled by LIVE_ENABLED=0" in l for l in logs), logs
    assert b.live_stats()["sigs"] == 0
finally:
    b.LIVE_ENABLED = old_enabled
print("12 ok  throttling retried then partial; no endpoint and disabled "
      "report honestly")

# ══════════════════════════════════════════════════════════════════════
# 13 — the estimate shown up front is the arithmetic it claims to be
# ══════════════════════════════════════════════════════════════════════
per, reqs, secs = b._live_estimate(10)
assert per == math.ceil(b.LIVE_AVG_TXS / b.LIVE_PAGE) + 2, per
assert reqs == 10 * per and abs(secs - reqs * max(b.ESPLORA_MIN_INTERVAL, 0.05)) < 1e-9
assert b._live_estimate(1)[1] == per
assert "block" not in b._human_secs(secs)          # it is a duration, not a count
assert b._human_secs(0) and b._human_secs(None) == "?"
print("13 ok  the up-front request/time estimate matches its own inputs")

# ══════════════════════════════════════════════════════════════════════
# 14 — single-address mode: paginated history, segwit included
# ══════════════════════════════════════════════════════════════════════
reset_chain()
D, K = 0x5555, 0x2468
pub = b.derive_pubkeys(D)[0]
ADDR = b.segwit_address(0, b.hash160(pub))
many = []
for i in range(75):                                  # more than one 50-tx page
    tx, _z, _r, _s = make_p2wpkh_tx("%064x" % (0xF000 + i), 0, D, K + i, 70000)
    many.append(tx)
CHAIN["addr"][ADDR] = many
logs = []
txs = b._fetch_address_txs(ADDR, logs.append)
assert len(txs) == 75, len(txs)
assert any("/txs/chain/" in g for g in CHAIN["gets"]), CHAIN["gets"]
sigs = b._fetch_sigs_for_address(ADDR, logs.append, txs=txs)
assert len(sigs) == 75, len(sigs)
assert all(s["type"] == "segwit" for s in sigs), "segwit sigs must be visible"
assert any("75 signature(s) extracted" in l for l in logs), logs
assert any("(0 legacy, 75 segwit)" in l for l in logs), logs
# only the first page: the old behaviour silently reported "0 signatures"
CHAIN["gets"] = []
first_page = b._fetch_address_txs(ADDR, logs.append, max_txs=50)
assert len(first_page) == 50
# a reused nonce inside one address's own history is recovered
reset_chain()
txA, zA, rA, sA = make_p2wpkh_tx("%064x" % 0xA100, 0, D, K, 60000)
txB, zB, rB, sB = make_p2wpkh_tx("%064x" % 0xA101, 0, D, K, 55000)
assert rA == rB
CHAIN["addr"][ADDR] = [txA, txB]
logs, job = [], newjob()
hits = b.attack_nonce_reuse(ADDR, logs.append, job)
assert len(hits) >= 1, hits
assert any(h["privkey"] == hex(D) for h in hits), [h["privkey"] for h in hits]
hit = [h for h in hits if h["privkey"] == hex(D)][0]
assert hit["evidence"].startswith("pubkey:"), hit
assert sorted(hit["txids"]) == sorted([txA["txid"], txB["txid"]]), hit
assert any("★★★ KEY" in l for l in logs), logs
# an address with no reuse produces no hit and no invented message
reset_chain()
txC, _z, _r, _s = make_p2wpkh_tx("%064x" % 0xA200, 0, D, K + 1, 60000)
txD, _z, _r, _s = make_p2wpkh_tx("%064x" % 0xA201, 0, D, K + 2, 60000)
CHAIN["addr"][ADDR] = [txC, txD]
logs, job = [], newjob()
assert b.attack_nonce_reuse(ADDR, logs.append, job) == []
assert any("0 reused-r groups" in l for l in logs), logs
print("14 ok  address history paginated, segwit signatures scanned, reuse "
      "recovered")

# ══════════════════════════════════════════════════════════════════════
# 15 — routes, page copy and API validation
# ══════════════════════════════════════════════════════════════════════
reset_chain()
cl = b.app.test_client()
txt = cl.get("/live").get_data(as_text=True)
assert cl.get("/live").status_code == 200
for frag in ("Live block monitor", "startLive()", "watch('live','L')",
             'id="barL"', 'id="logL"', 'id="detailL"', "resetLive()",
             "LIVE_MAX_BLOCKS", "LIVE_SIG_ROWS_MAX", "BIP-143",
             "cannot find", "weak entropy", "illbloom.org", "COLDCARD",
             "Taproot / BIP-341", "OP_CODESEPARATOR", "per-transaction request",
             "probeLive()", "/api/live/status", "Clear index", "RFC 6979",
             "tripwire"):
    assert frag in txt, frag
# no un-substituted placeholder survives, and no fabricated detector is claimed
assert "{body}" not in txt and "%(host)s" not in txt and "{nav}" not in txt
for banned in ("simulated", "placeholder corpus", "ENTROPY ANOMALY",
               "known weak address", "fake success"):
    assert banned.lower() not in txt.lower(), banned
assert "cannot find" in txt and "randstorm" in txt
# the nav pill is present and marked on this page only
assert txt.count('class="on"') == 1 and 'href="/live"' in txt
assert 'href="/live"' in cl.get("/").get_data(as_text=True)
assert 'href="/live"' in cl.get("/nonce").get_data(as_text=True)
assert ("/live", "live monitor") in b.NAV_ITEMS and "live" in b.JOB_NAMES
home = cl.get("/").get_data(as_text=True)
assert "5. Live monitor" in home and 'href="/live"' in home
# status is served without touching the network
CHAIN["gets"] = []
d = cl.get("/api/live/status").get_json()
assert d["ok"] is True and CHAIN["gets"] == [], (d, CHAIN["gets"])
assert d["window_blocks"] == b.LIVE_WINDOW_BLOCKS
assert d["page_size"] == b.LIVE_PAGE and d["enabled"] is True
assert set(d["index"]) >= {"sigs", "distinct_r", "colliding_r", "min_height",
                           "max_height"}
# ping is the explicit network probe
d = cl.post("/api/live/ping").get_json()
assert d["ok"] is True and d["tip"] == CHAIN["tip"], d
CHAIN["fail"] = "all"
d = cl.post("/api/live/ping").get_json()
assert d["ok"] is False and "no Esplora endpoint answered" in d["msg"], d
CHAIN["fail"] = None
# validation: bad input is rejected, size never is
for payload, why in (({"start_block": "abc"}, "integer"),
                     ({"start_block": -5}, "negative"),
                     ({"max_blocks": "many"}, "integer"),
                     ({"max_blocks": 0}, "at least 1")):
    d = cl.post("/api/live", json=payload).get_json()
    assert d["ok"] is False and why in d["msg"], (payload, d)
d = cl.post("/api/live", json={"max_blocks": 100000, "start_block": 100}).get_json()
assert d["ok"] is True, d                    # a huge block count is never refused
assert d["max_blocks"] == 100000
assert "≈" in d["msg"] and "requests" in d["msg"] and "Stop keeps" in d["msg"], d["msg"]
wait_job("live", 30)
# reset refuses while the job runs, and clears when it does not
add_block(100, [])
CHAIN["tip"] = 100
d = cl.post("/api/live", json={"max_blocks": 1}).get_json()
assert d["ok"] is True
wait_job("live", 30)
assert b.live_state_get("last_height") == "100"
d = cl.post("/api/live/reset").get_json()
assert d["ok"] is True and "cleared" in d["msg"], d
assert b.live_state_get("last_height") == "" and b.live_stats()["sigs"] == 0
# disabled: the page still renders and the API refuses
old_enabled = b.LIVE_ENABLED
try:
    b.LIVE_ENABLED = False
    assert "disabled" in cl.get("/live").get_data(as_text=True)
    d = cl.post("/api/live", json={}).get_json()
    assert d["ok"] is False and "LIVE_ENABLED=1" in d["msg"], d
finally:
    b.LIVE_ENABLED = old_enabled
print("15 ok  /live page, honest copy, status without network, validation")

# ══════════════════════════════════════════════════════════════════════
# 16 — the same machinery through the real Flask job runner
# ══════════════════════════════════════════════════════════════════════
reset_chain()
D, K = int(V_P2WPKH_PRIV1, 16), 0xBEEF
txA, _z, rA, _s = make_p2wpkh_tx("%064x" % 0xB001, 0, D, K, 300000)
txB, _z, rB, _s = make_p2wpkh_tx("%064x" % 0xB002, 0, D, K, 250000)
assert rA == rB
add_block(100, [txA])
add_block(101, [txB])
CHAIN["tip"] = 101
cl = b.app.test_client()
d = cl.post("/api/live", json={"start_block": 100, "max_blocks": 2,
                               "follow": False}).get_json()
assert d["ok"] is True, d
job = wait_job("live", 60)
assert job is not None and job["progress"] == 1.0, job
assert job.get("error") == "", job
assert "2 block(s) scanned" in job["detail"], job["detail"]
assert any("★★★ NONCE REUSE" in l for l in job["log"]), job["log"]
rows = [json.loads(pl) for _a, pl in b._db().execute(
    "SELECT attack,payload FROM results WHERE attack='nonce'")]
assert any(r["privkey"] == hex(D) and r["source"] == "live" for r in rows), rows
# a second start while a follower is running is refused, not queued twice
d = cl.post("/api/live", json={"max_blocks": 5, "follow": True}).get_json()
assert d["ok"] is True and d["follow"] is True, d
for _ in range(200):                        # wait for it to be really running
    with b._JOBS_LOCK:
        j = b._JOBS.get("live")
    if j and j["alive"] and ("waiting" in j.get("detail", "")
                             or j.get("progress", 0) > 0):
        break
    time.sleep(0.05)
d2 = cl.post("/api/live", json={"max_blocks": 1}).get_json()
assert d2["ok"] is False and "already running" in d2["msg"], d2
# the UI's Stop button ends the follower, and the run stays honest about it
d3 = cl.post("/api/stop/live", json={}).get_json()
assert d3.get("ok") is not False, d3
job = wait_job("live", 60)
assert job is not None and not job["alive"], job
assert job["progress"] < 1.0, job
reset_chain()
print("16 ok  the Flask job runner drives the monitor to a saved, verified hit")

# ══════════════════════════════════════════════════════════════════════
# 17 — the CLI reports an unreachable endpoint honestly
# ══════════════════════════════════════════════════════════════════════
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, DISK_PATH=DISK_CLI, APP_USER="", APP_PASSWORD="",
           ESPLORA_URLS="http://127.0.0.1:9", ESPLORA_MAX_RETRIES="0",
           ESPLORA_MIN_INTERVAL="0")


def cli(*argv, env=None):
    e = dict(ENV, **(env or {}))
    return subprocess.run([sys.executable, os.path.join(ROOT, "btc_hunt.py"),
                           *argv], capture_output=True, text=True, env=e,
                          timeout=240)


r = cli("--live-status")
assert r.returncode == 0, r.stderr
assert "live index :" in r.stdout and "persisted" in r.stdout, r.stdout
assert "unreachable" in r.stdout, r.stdout          # no endpoint answered
r = cli("--cli-live", "--start-block", "100", "--blocks", "2", "--no-follow")
assert r.returncode == 0, r.stderr
assert "could not read /blocks/tip/height" in r.stdout, r.stdout
assert "nothing scanned" in r.stdout, r.stdout
assert "block(s) scanned" in r.stdout and "0 key(s) recovered" in r.stdout, r.stdout
# the estimate is printed before anything runs, with its assumption stated
assert "requests" in r.stdout and "tx/block assumed" in r.stdout, r.stdout
assert "follow: off" in r.stdout, r.stdout
r = cli("--cli-live", "--blocks", "0")
assert r.returncode != 0 and "--blocks must be at least 1" in (r.stderr + r.stdout)
r = cli("--help")
assert "--cli-live" in r.stdout and "--start-block" in r.stdout
assert "--live-status" in r.stdout and "--no-follow" in r.stdout
print("17 ok  CLI: an unreachable endpoint is reported as nothing scanned")

# ══════════════════════════════════════════════════════════════════════
# 18 — the CLI end to end against a real localhost Esplora
# ══════════════════════════════════════════════════════════════════════
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

SHARED = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        resp = fake_get("http://local" + self.path)
        body = resp.text.encode()
        self.send_response(resp.status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = None
try:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
except OSError:                                   # pragma: no cover
    server = None
if server is not None:
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    reset_chain()
    D, K = int(V_P2WPKH_PRIV1, 16), 0xF00D
    txA, _z, rA, _s = make_p2wpkh_tx("%064x" % 0xCC01, 0, D, K, 200000)
    txB, _z, rB, _s = make_p2wpkh_tx("%064x" % 0xCC02, 0, D, K, 190000)
    assert rA == rB
    add_block(100, [txA])
    add_block(101, [txB])
    CHAIN["tip"] = 101
    r = cli("--cli-live", "--start-block", "100", "--blocks", "2", "--no-follow",
            env={"ESPLORA_URLS": "http://127.0.0.1:%d" % port})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "★★★ NONCE REUSE" in r.stdout, r.stdout
    assert hex(D) in r.stdout, r.stdout
    assert "done — 2 block(s) scanned, 1 key(s) recovered" in r.stdout, r.stdout
    assert "last height persisted: 101" in r.stdout, r.stdout
    r2 = cli("--live-status", env={"ESPLORA_URLS": "http://127.0.0.1:%d" % port})
    assert "colliding r" in r2.stdout and "persisted 101" in r2.stdout, r2.stdout
    assert "tip 101" in r2.stdout and "lag 0 block(s)" in r2.stdout, r2.stdout
    server.shutdown()
else:                                               # pragma: no cover
    print("18 skip  could not bind a localhost port")
if server is not None:
    print("18 ok  CLI scanned a real HTTP Esplora, recovered and reported")

# ══════════════════════════════════════════════════════════════════════
# 19 — no fabricated detectors anywhere in the shipped module
# ══════════════════════════════════════════════════════════════════════
src = open(os.path.join(ROOT, "btc_hunt.py"), encoding="utf-8").read().lower()
for banned in ("simulated", "bloom filter updated", "entropy anomaly",
               "known weak addresses", "todo: implement detector"):
    assert banned not in src, banned
# the two things the pasted scanner claimed and that cannot exist are named as
# impossible in the product copy, not silently dropped
page = cl.get("/live").get_data(as_text=True).lower()
assert "weak entropy" in page and "has not been disclosed" in page
assert "sweeping its output space" in page or "sweep its output space" in page
print("19 ok  no simulated successes or invented detectors in code or copy")

b.requests.get = REAL_GET
shutil.rmtree(DISK, ignore_errors=True)
shutil.rmtree(DISK_CLI, ignore_errors=True)
print("ALL LIVE TESTS PASSED")
