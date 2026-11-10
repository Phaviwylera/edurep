#!/usr/bin/env python3
"""Ethereum test suite — run it with `python tests/test_eth.py`.

No pytest, no network: `requests.post` / `requests.get` are monkeypatched, so
this is safe to run on a deploy box or in CI. It covers

  1-2   published vectors for every primitive, and the recipes built on them
  3-6   the JSON-RPC client: batching, hex parsing, per-item errors, batch
        refusal, 429 failover
  7-11  the sweeps: end-to-end hit, unit filtering, weak keys, throttling, Stop
  12-15 verify job, routes, JSONL export, and a Bitcoin regression check
  16-22 the failure modes that matter on a real host: HTTP 403 parking, the
        pre-flight probe, the durable retry queue and its drainer, adaptive
        batch sizing, the queue cap, and a mid-run Stop
  24-29 the fixed era windows and the era batch: table values, route
        validation, sequential sweeping with per-era steps/offset, Stop, the
        unscannable-era warning, the era widget on /eth, the home-page
        launcher, and the headless --cli-eth-era / --list-eras

Every assertion that encodes a published test vector says so in a comment.
"""
import json
import os
import shutil
import sys
import tempfile
import time

DISK = tempfile.mkdtemp(prefix="btc-hunt-eth-test-")
os.environ.update({
    "DISK_PATH": DISK,
    # Bitcoin-side pacing off: this suite must not sleep.
    "ESPLORA_MIN_INTERVAL": "0", "ESPLORA_PACE_MAX_SECS": "0",
    "ESPLORA_CACHE_SIZE": "0", "ESPLORA_MAX_BACKOFF_SECS": "1",
    # Ethereum knobs, small so the tests stay quick.
    "ETH_RPC_BATCH": "4", "ETH_MAX_STEPS": "1000",
    "ETH_MAX_TOTAL_STEPS": "100000", "ETH_DEAD_COOL_SECS": "30",
    "ETH_ERROR_COOL_SECS": "1", "ETH_RPC_ROUNDS": "2",
    "ETH_PENDING_MAX": "1000", "ETH_PREFLIGHT": "1", "ETH_ERA_STEPS": "20",
    "APP_USER": "", "APP_PASSWORD": "", "BTC_HUNT_BUILD_ID": "test-eth",
})
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import btc_hunt as b  # noqa: E402

REAL_POST = b.requests.post
REAL_GET = b.requests.get
FUNDED = {}          # lowercase address -> wei
NONCES = {}          # lowercase address -> nonce
MODE = {"fail": None, "refuse_batch": False, "posts": [], "dead": []}


class FakeResp:
    def __init__(self, payload, status=200):
        self._p = payload
        self.status_code = status
        self.headers = {"Retry-After": "1"} if status == 429 else {}
        self.text = json.dumps(payload) if payload is not None else (
            "Forbidden" if status == 403 else "")

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %d" % self.status_code)


def _one(call):
    m = call.get("method")
    if m == "eth_blockNumber":
        return {"jsonrpc": "2.0", "id": call.get("id"), "result": "0x123456"}
    if m in ("eth_getBalance", "eth_getTransactionCount"):
        addr = (call.get("params") or [""])[0].lower()
        if MODE["fail"] == "item" and m == "eth_getBalance":
            return {"jsonrpc": "2.0", "id": call.get("id"),
                    "error": {"code": -32000, "message": "boom"}}
        val = (FUNDED.get(addr, 0) if m == "eth_getBalance"
               else NONCES.get(addr, 0))
        return {"jsonrpc": "2.0", "id": call.get("id"), "result": hex(val)}
    return {"jsonrpc": "2.0", "id": call.get("id"),
            "error": {"code": -32601, "message": "unknown method"}}


def fake_post(url, json=None, timeout=None, headers=None, **kw):
    MODE["posts"].append((url, json, headers))
    if url in MODE["dead"] or MODE["fail"] == "403":
        return FakeResp(None, 403)
    if MODE["fail"] == url or MODE["fail"] == "all":
        return FakeResp(None, 429)
    if isinstance(json, list):
        if MODE["refuse_batch"]:
            return FakeResp({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32600, "message": "no batches"}})
        return FakeResp([_one(c) for c in json])
    return FakeResp(_one(json))


def reset_rpc():
    """Clean every piece of per-endpoint, queue and database state."""
    b.requests.post = fake_post
    b._ETH_BATCH_OK.clear()
    b._ETH_BASE_ERR.clear()
    b._ETH_DEAD.clear()
    b._ETH_ACTIVE[:] = []
    b._ETH_BATCH_SIZE[0] = b.ETH_RPC_BATCH
    b._ETH_BATCH_STREAK[0] = 0
    b._ETH_PENDING_N[0] = -1
    MODE["fail"] = None
    MODE["refuse_batch"] = False
    MODE["posts"] = []
    MODE["dead"] = []
    FUNDED.clear()
    NONCES.clear()
    try:
        b._eth_pending_path().unlink()
    except OSError:
        pass
    b._esplora_cache_clear()
    with b._RATE_LOCK:
        b._BASE_COOL.clear()
        b._BASE_FAILS.clear()
        b._RATE_INTERVAL[0] = b.ESPLORA_MIN_INTERVAL
        b._RATE_NEXT[0] = 0.0
    with b._db() as c:
        c.execute("DELETE FROM results")
        c.execute("DELETE FROM balance_checks")


def newjob():
    return {"progress": 0.0, "detail": "", "stop": False, "throttled": 0,
            "auto_verify_skipped": 0, "alive": True}


def wait_job(name, timeout=30.0):
    """Block until a _start_job thread finishes (tests must not race it)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        with b._JOBS_LOCK:
            job = b._JOBS.get(name)
            if job is None or not job["alive"]:
                return job
        time.sleep(0.05)
    raise AssertionError("job %s did not finish in %.0fs" % (name, timeout))


b.requests.post = fake_post
print("EC: %s | keccak: %s | rpc bases: %d | queue: %s"
      % (b.EC_BACKEND, b.ETH_HASH_BACKEND, len(b._ETH_RPC_BASES),
         b._eth_pending_path()))

# ══════════════════════════════════════════════════════════════════════
# 1 — published vectors for every primitive
# ══════════════════════════════════════════════════════════════════════
# Keccak-256 (original padding, NOT hashlib.sha3_256)
assert b.keccak256(b"").hex() == ("c5d2460186f7233c927e7db2dcc703c0e500b653"
                                  "ca82273b7bfad8045d85a470")
assert b.keccak256(b"abc").hex() == ("4e03657aea45a94fc7d47ba826c8d667"
                                     "c0d1e6e33a64a036ec44f58fa12d6c45")
assert b.keccak256(b"testing").hex() == ("5f16f4c7f149ac4f9510d9cf8cf38403"
                                         "8ad348b3bcdc01915f95de12df9d1b02")
# the pure-Python permutation must agree with the native one, incl. rate edges
for s in (b"", b"abc", b"x" * 135, b"y" * 136, b"z" * 200, bytes(range(64))):
    assert b._keccak256_py(s) == b.keccak256(s), len(s)
# MT19937 reference vector, seed 5489
mt = b._MT19937(5489)
assert [mt.int32() for _ in range(5)] == [3499211612, 581869302, 3890346734,
                                          3586334585, 545404204]
# BIP-39: 16 zero bytes -> "abandon x11 about"; TREZOR seed vector
mn = b.bip39_mnemonic(bytes(16))
assert mn == ("abandon abandon abandon abandon abandon abandon abandon "
              "abandon abandon abandon abandon about"), mn
assert b.bip39_seed(mn, "TREZOR").hex() == (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a698"
    "7599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
assert len(b._bip39_words()) == 2048
# BIP-32 test vector 1: m and m/0H, private key AND chain code
k, cc = b.bip32_master(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
assert k.to_bytes(32, "big").hex() == ("e8f32e723decf4051aefac8e2c93c9c5"
                                       "b214313817cdb01a1494b917c8436b35")
assert cc.hex() == ("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ff"
                    "ed37d508")
k1, cc1 = b.bip32_ckd_priv(k, cc, 0x80000000)
assert k1.to_bytes(32, "big").hex() == ("edb2e14f9ee77d26dd93b4ecede8d16e"
                                        "d408ce149b6cd80b0715a2d911a0afea")
assert cc1.hex() == ("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c"
                     "7ae6236141")
# Ethereum addresses for privkeys 1/2/3 and EIP-55 mixed case
assert b.eth_address(1) == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
assert b.eth_address(2) == "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"
assert b.eth_address(3) == "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69"
low = "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
assert ("0x" + "".join(c.upper() if int(b.keccak256(low.encode()).hex()[i], 16)
                       >= 8 else c for i, c in enumerate(low))
        == "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
assert b._ETH_ADDR_RE.match(b.eth_address(9)) and not b._ETH_ADDR_RE.match("0x12")
assert b.eth_account_from_seed(b.bip39_seed(mn)) % b.N != 0
print("1 ok  keccak / MT19937 / BIP-39 / BIP-32 / EIP-55 published vectors")

# ══════════════════════════════════════════════════════════════════════
# 2 — recipes
# ══════════════════════════════════════════════════════════════════════
assert set(b.ETH_RECIPES) >= {"tw_bip39_s", "sha256_dec", "keccak_dec",
                              "sha256_be8", "mt19937_s", "raw"}
assert b.ETH_RECIPES["tw_bip39_s"]["units"] == ("s",)       # seconds only
assert b.ETH_RECIPES["sha256_dec"]["units"] == ("ms", "s")
ts = 1669248000                                             # 2022-11-24 UTC
for rid, r in b.ETH_RECIPES.items():
    out = r["fn"](ts, "s")
    assert len(out) == 1, rid
    priv, extra = out[0]
    assert 0 < priv < b.N, rid
    assert b.eth_address(priv) == b.eth_address(r["fn"](ts, "s")[0][0]), rid
assert b.ETH_RECIPES["raw"]["fn"](12345, "ms")[0] == (12345, {"recipe_input": 12345})
assert b.ETH_RECIPES["sha256_dec"]["fn"](ts, "s")[0][0] == (
    int.from_bytes(b.hashlib.sha256(str(ts).encode()).digest(), "big") % b.N)
tw = b.ETH_RECIPES["tw_bip39_s"]["fn"](ts, "s")[0]
assert len(tw[1]["mnemonic"].split()) == 12
assert tw[1]["path"] == "m/44'/60'/0'/0/0" and len(tw[1]["entropy"]) == 32
assert b.ETH_RECIPES["raw"]["fn"](0, "ms") == []            # key 0 is invalid
print("2 ok  recipes deterministic, units declared, mnemonic well-formed")

# ══════════════════════════════════════════════════════════════════════
# 3 — batched RPC, exact wei/gwei split, badges
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
a1, a2 = b.eth_address(1), b.eth_address(2)
FUNDED[a1.lower()] = 1234567890123456789
NONCES[a1.lower()] = 7
res = b._eth_balances([a1, a2])
assert res[a1]["wei"] == 1234567890123456789 and res[a1]["nonce"] == 7, res
assert res[a1]["error"] == "" and res[a2]["wei"] == 0 and res[a2]["nonce"] == 0
assert len(MODE["posts"]) == 1 and isinstance(MODE["posts"][0][1], list)
assert len(MODE["posts"][0][1]) == 4                    # two calls per address
gwei, rem = divmod(1234567890123456789, 10 ** 9)
assert (gwei, rem) == (1234567890, 123456789)
b._store_eth_check(a1, 1234567890123456789, 7)
row = b._balance_checks()[a1]
assert row["sats"] == gwei and row["mempool_sats"] == rem and row["tx_count"] == 7
assert row["sats"] * 10 ** 9 + row["mempool_sats"] == 1234567890123456789
checks = b._balance_checks()
assert "1.234568 ETH" in b._balance_badge(a1, checks)
assert "nonce 7" in b._balance_badge(a1, checks)
zero = {"sats": 0, "mempool_sats": 0, "tx_count": 0, "error": ""}
assert "never used" in b._balance_badge(a2, {a2: dict(zero)})
assert "emptied" in b._balance_badge(a2, {a2: dict(zero, tx_count=4)})
print("3 ok  batch RPC, exact wei<->gwei split, ETH badges")

# ══════════════════════════════════════════════════════════════════════
# 4 — a per-item RPC error is reported, not read as a zero balance
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
MODE["fail"] = "item"
res = b._eth_balances([b.eth_address(5)])
assert list(res.values())[0]["error"], res
print("4 ok  per-call RPC error surfaces")

# ══════════════════════════════════════════════════════════════════════
# 5 — an endpoint that refuses batches gets single calls
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
MODE["refuse_batch"] = True
base0 = b._ETH_RPC_BASES[0]
res = b._eth_balances([b.eth_address(6), b.eth_address(7)])
assert b._ETH_BATCH_OK.get(base0) is False
assert len(res) == 2 and all(v["error"] == "" for v in res.values())
assert len([p for p in MODE["posts"] if not isinstance(p[1], list)]) == 4
MODE["refuse_batch"] = False
reset_rpc()
b._ETH_BATCH_OK[base0] = False                # remembered from before
res = b._eth_balances([b.eth_address(8), b.eth_address(9)])
assert not any(isinstance(p[1], list) for p in MODE["posts"])
print("5 ok  batch refusal remembered, singles used instead")

# ══════════════════════════════════════════════════════════════════════
# 6 — 429 parks one endpoint and fails over; all-429 raises
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
MODE["fail"] = b._ETH_RPC_BASES[0]
FUNDED[b.eth_address(11).lower()] = 10 ** 18
res = b._eth_balances([b.eth_address(11)])
assert list(res.values())[0]["wei"] == 10 ** 18
assert any(p[0] != b._ETH_RPC_BASES[0] for p in MODE["posts"]), MODE["posts"]
assert b._eth_host(b._ETH_RPC_BASES[0]) in b._eth_status()
assert "cooling" in b._eth_status()
with b._RATE_LOCK:
    assert b._BASE_COOL.get(b._ETH_RPC_BASES[0], 0) > 0
    assert b._BASE_FAILS.get(b._ETH_RPC_BASES[0], 0) >= 1
reset_rpc()
MODE["fail"] = "all"
try:
    b._eth_balances([b.eth_address(12)])
    raise AssertionError("expected the rate-limited error")
except b._EsploraRateLimited as e:
    assert "unavailable after" in str(e), e
print("6 ok  429 parks the endpoint and fails over; all-429 raises")

# ══════════════════════════════════════════════════════════════════════
# 7 — end-to-end timestamp sweep: find, verify, save
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
TS0 = 1669248000
target_priv = b.ETH_RECIPES["sha256_dec"]["fn"](TS0 + 3, "s")[0][0]
target_addr = b.eth_address(target_priv)
FUNDED[target_addr.lower()] = 25 * 10 ** 17
NONCES[target_addr.lower()] = 2
job, logs = newjob(), []
hits = b.attack_eth_timestamp(TS0, TS0 + 9, "s", ["sha256_dec", "raw"],
                              logs.append, job)
assert len(hits) == 1, hits
h = hits[0]
assert h["address"] == target_addr and h["chain"] == "ethereum"
assert h["recipe"] == "sha256_dec" and h["attack"] == "eth_sha256_dec"
assert h["ts"] == TS0 + 3 and h["unit"] == "s"
assert h["balance_wei"] == str(25 * 10 ** 17) and h["balance_eth"] == 2.5
assert h["balance_nonce"] == 2 and h["balance_error"] == ""
assert h["balance_verdict"] == "funded_verify_manually"
assert h["privkey"] == hex(target_priv)
assert job["eth_skipped"] == 19, job              # 20 candidates, 1 funded
assert job.get("eth_queued", 0) == 0, job
assert any("ETH HIT" in l for l in logs), logs
assert "EC: " in logs[0] and "hash: " in logs[0], logs[0]
assert any("RPC " in l and "block " in l for l in logs), logs   # pre-flight
rows = list(b._db().execute("SELECT attack,payload FROM results"))
assert len(rows) == 1 and rows[0][0] == "eth_sha256_dec", rows
assert json.loads(rows[0][1])["address"] == target_addr
assert job["progress"] == 1.0, job
assert any("done — 1 hit(s)" in l for l in logs), logs
print("7 ok  sweep finds, verifies and saves the funded candidate")

# ══════════════════════════════════════════════════════════════════════
# 8 — unit filtering and range caps
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
job, logs = newjob(), []
assert b.attack_eth_timestamp(1, 5, "ms", ["tw_bip39_s"], logs.append, job) == []
assert any("no usable recipe" in l for l in logs), logs
cl = b.app.test_client()
d = cl.post("/api/eth/timestamp", json={"start": 1, "end": 5, "unit": "ms",
                                        "recipes": ["tw_bip39_s"]}).get_json()
assert d["ok"] is False and "no selected recipe accepts unit=ms" in d["msg"], d
d = cl.post("/api/eth/timestamp", json={"start": 1, "end": 5, "unit": "days",
                                        "recipes": ["raw"]}).get_json()
assert d["ok"] is False and "unit must be" in d["msg"], d
d = cl.post("/api/eth/timestamp", json={"start": 5, "end": 1, "unit": "s",
                                        "recipes": ["raw"]}).get_json()
assert d["ok"] is False and "end must be >= start" in d["msg"], d
d = cl.post("/api/eth/timestamp", json={"start": 1, "end": 10 ** 9, "unit": "s",
                                        "recipes": ["raw"]}).get_json()
assert d["ok"] is False and "ETH_MAX_TOTAL_STEPS" in d["msg"], d
print("8 ok  unit filtering and range caps enforced")

# ══════════════════════════════════════════════════════════════════════
# 9 — weak / sequential keys, pasted hex, dedupe
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
FUNDED[b.eth_address(1).lower()] = 10 ** 18
FUNDED[b.eth_address(3).lower()] = 5 * 10 ** 16
NONCES[b.eth_address(3).lower()] = 1
job, logs = newjob(), []
hits = b.attack_eth_weakkeys(5, ["0x2", "deadbeef", "not-hex-zz"], logs.append, job)
addrs = {h["address"] for h in hits}
assert b.eth_address(1) in addrs and b.eth_address(3) in addrs, addrs
assert b.eth_address(2) not in addrs               # 0 wei + nonce 0 -> skipped
assert all(h["attack"] == "eth_weakkey" for h in hits)
assert any("unparsable key" in l for l in logs), logs
assert any("pasted key 0x2 is inside 1..5" in l for l in logs), logs
assert any("weak keys: 1..5 plus 1 pasted" in l for l in logs), logs
rows = list(b._db().execute("SELECT attack FROM results"))
assert rows and all(r[0] == "eth_weakkey" for r in rows), rows
print("9 ok  weak/sequential keys + pasted hex, empty ones skipped")

# ══════════════════════════════════════════════════════════════════════
# 10 — a throttled batch stores no verdict but is queued, never dropped
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
b.ETH_PREFLIGHT = False        # the probe would refuse to start; test the queue
MODE["fail"] = "all"
job, logs = newjob(), []
hits = b.attack_eth_timestamp(TS0, TS0 + 3, "s", ["raw"], logs.append, job)
b.ETH_PREFLIGHT = True
assert hits == [], hits
assert b._balance_checks() == {}                   # a 429 is not a verdict
assert job.get("eth_queued", 0) == 4, job          # but nothing was lost
assert b._eth_pending_count() == 4, b._eth_pending_count()
queued = b._eth_pending_read()
assert len(queued) == 4 and all(q["privkey"] and q["recipe"] == "raw"
                                for q in queued), queued
assert any("queued for re-check" in l for l in logs), logs
print("10 ok  throttled batch: no verdict stored, all 4 queued on disk")

# ══════════════════════════════════════════════════════════════════════
# 11 — Stop before any work
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
job, logs = newjob(), []
job["stop"] = True
assert b.attack_eth_timestamp(TS0, TS0 + 1000, "s", ["raw"], logs.append, job) == []
assert any("stopped" in l for l in logs), logs
print("11 ok  Stop honoured before any work")

# ══════════════════════════════════════════════════════════════════════
# 12 — verify_eth_balances over saved hits
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
a1, a2 = b.eth_address(21), b.eth_address(22)
for addr, kind in ((a1, "eth_raw"), (a2, "eth_weakkey")):
    b._save_result(kind, {"chain": "ethereum", "address": addr, "privkey": "0x15"})
b._save_result("randstorm", {"address": "1EA1FBWhRKK47U6bjb1ZHSCQ5myFDGXcjv"})
assert set(b._all_eth_addresses()) == {a1, a2}          # BTC rows ignored
FUNDED[a1.lower()] = 3 * 10 ** 18
NONCES[a2.lower()] = 9
job, logs = newjob(), []
b.verify_eth_balances(False, logs.append, job)
checks = b._balance_checks()
assert checks[a1]["sats"] * 10 ** 9 == 3 * 10 ** 18
assert checks[a2]["tx_count"] == 9 and checks[a2]["sats"] == 0
assert all(v["error"] == "" for v in checks.values()), checks
assert any("VERIFY MANUALLY" in l for l in logs), logs
assert any("used and emptied" in l for l in logs), logs
assert any("done — 1 with a balance" in l for l in logs), logs
assert job["progress"] == 1.0 and job["throttled"] == 0, job
# throttled addresses are re-queued, not recorded as errors
reset_rpc()
b._save_result("eth_raw", {"chain": "ethereum", "address": a1})
b._save_result("eth_weakkey", {"chain": "ethereum", "address": a2})
MODE["fail"] = "all"
b.ETH_PREFLIGHT = False
b.VERIFY_RETRY_PASSES = 0
job, logs = newjob(), []
b.verify_eth_balances(False, logs.append, job)
b.ETH_PREFLIGHT = True
assert job["throttled"] == 2 and job["progress"] < 1.0, job
assert b._balance_checks() == {}
assert any("still throttled" in l for l in logs), logs
b.VERIFY_RETRY_PASSES = 3
print("12 ok  ETH verify stores exact balances, re-queues throttles")

# ══════════════════════════════════════════════════════════════════════
# 13 — pages and routes
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
txt = cl.get("/eth").get_data(as_text=True)
assert cl.get("/eth").status_code == 200
for frag in ("Manual timestamp sweep", "Trust Wallet", "tw_bip39_s",
             "sha256_dec", "Test RPC", 'id="barTs"', 'id="barWk"', 'id="barQ"',
             "watch('eth_ts','Ts')", "watch('eth_retry','Q')",
             "no bloom filter", "Queued candidates", "eth_pending.jsonl",
             "pre-flight probe", b.ETH_HASH_BACKEND.split()[0]):
    assert frag in txt, frag
assert not any(p in txt for p in ("{bases}", "{batch}", "{pendingn}",
                                  "{rpcstate}", "{deadcool}", "{pendingmax}"))
assert txt.count("preset(") == 5                   # 4 buttons + the function
d = cl.get("/api/eth/recipes").get_json()
assert {r["id"] for r in d["recipes"]} == set(b.ETH_RECIPES)
assert d["batch_addresses"] == 4 and d["min_wei"] == 1
assert d["hash_backend"] == b.ETH_HASH_BACKEND and d["ec_backend"] == b.EC_BACKEND
assert len(d["presets"]) == 4 and d["preflight"] is True
assert d["pending_file"].endswith("eth_pending.jsonl")
p = cl.post("/api/eth/ping", json={}).get_json()
assert p["ok"] is True and len(p["bases"]) == len(b._ETH_RPC_BASES)
assert all(x["block"] == 0x123456 and x["batch"] for x in p["bases"]), p
d = cl.post("/api/eth/weakkeys", json={"count": "0", "keys": ""}).get_json()
assert d["ok"] is False and "set a count" in d["msg"], d
d = cl.post("/api/eth/weakkeys", json={"count": 10 ** 9}).get_json()
assert d["ok"] is False and "ETH_MAX_WEAK_KEYS" in d["msg"], d
for path in ("/health", "/", "/results", "/randstorm", "/nonce", "/data",
             "/brain", "/eth", "/api/esplora", "/api/eth/pending",
             "/api/eth/recipes"):
    assert cl.get(path).status_code == 200, path
health = cl.get("/health").get_json()
assert health["ec"] and health["keccak"], health
res_page = cl.get("/results").get_data(as_text=True)
assert "Check ETH balances" in res_page and "watch('eth_verify','Eth')" in res_page
assert "Download Ethereum results (JSONL)" in res_page
home = cl.get("/").get_data(as_text=True)
assert "4. Ethereum" in home and 'href="/eth"' in home
print("13 ok  /eth page, recipe/ping/pending APIs, validation, all routes")

# ══════════════════════════════════════════════════════════════════════
# 14 — JSONL export filter
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
b._save_result("eth_raw", {"chain": "ethereum", "address": b.eth_address(31)})
b._save_result("eth_weakkey", {"chain": "ethereum", "address": b.eth_address(32)})
b._save_result("randstorm", {"address": "1EA1FBWhRKK47U6bjb1ZHSCQ5myFDGXcjv"})
out = cl.get("/api/results/export?attack=eth").get_data(
    as_text=True).strip().splitlines()
assert len(out) == 2, out
assert all(json.loads(l)["chain"] == "ethereum" for l in out)
assert len(cl.get("/api/results/export").get_data(
    as_text=True).strip().splitlines()) == 3
print("14 ok  attack=eth exports every eth_* bucket")

# ══════════════════════════════════════════════════════════════════════
# 15 — Bitcoin side unchanged
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
b.requests.get = lambda *a, **k: type("R", (), {
    "status_code": 200, "headers": {},
    "text": json.dumps({"chain_stats": {"funded_txo_sum": 0, "spent_txo_sum": 0,
                                        "tx_count": 0}, "mempool_stats": {}}),
    "raise_for_status": lambda s: None})()
empty_bloom = b.BloomFilter.create(8, 0.5)
job, logs = newjob(), []
assert b.attack_randstorm(b.GENESIS_TS, b.GENESIS_TS + 40, empty_bloom,
                          logs.append, job) == []
assert any("EC: " in l for l in logs), logs
assert b.RANDSTORM_MAX_TOTAL_MS == 4_000_000_000
comp, uncomp = b.derive_pubkeys(1)
assert b.encode_address("p2pkh", comp) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
assert b.encode_address("p2pkh_u", uncomp) == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
assert b.encode_address("p2wpkh", comp) == (
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
print("15 ok  Bitcoin randstorm + address vectors unchanged")

# ══════════════════════════════════════════════════════════════════════
# 16 — HTTP 403: park the endpoint, and stop the run if all of them refuse
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
MODE["fail"] = b._ETH_RPC_BASES[0]                   # 429 on the first
MODE["dead"] = [b._ETH_RPC_BASES[1]]                 # 403 on the second
res = b._eth_balances([b.eth_address(41)])           # the third still answers
assert list(res.values())[0]["error"] == "", res
assert len({p_[0] for p_ in MODE["posts"]}) >= 3, MODE["posts"]
dead_base = b._ETH_RPC_BASES[1]
assert "REFUSING" in b._eth_status(), b._eth_status()
with b._RATE_LOCK:
    assert b._BASE_COOL[dead_base] > time.monotonic()
with b._ETH_LOCK:
    assert b._ETH_DEAD[dead_base] > time.monotonic()
assert b._eth_all_dead() is False                    # three still usable
# every endpoint refusing is a different failure: stop, do not grind on
reset_rpc()
b.ETH_PREFLIGHT = False                              # skip the probe for this one
MODE["fail"] = "403"
job, logs = newjob(), []
hits = b.attack_eth_timestamp(TS0, TS0 + 5, "s", ["raw"], logs.append, job)
assert hits == [] and job.get("eth_no_rpc") is True, (hits, job)
# it stops at the FIRST failed batch (4 candidates) rather than grinding through
# the remaining timestamps to derive candidates nobody can check
assert job.get("eth_queued", 0) == 4, job
assert b._eth_pending_count() == 4, b._eth_pending_count()
assert job["progress"] < 1.0, job
assert b._balance_checks() == {}                     # no invented verdicts
assert len([x for x in logs if "EVERY configured" in x]) == 1
assert any("EVERY configured endpoint refused us" in l for l in logs), logs
assert any("stopping" in l for l in logs), logs
assert "no RPC endpoint answered" in job["detail"], job["detail"]
try:
    b._eth_balances([b.eth_address(42)])
    raise AssertionError("expected _EthNoEndpoint")
except b._EthNoEndpoint as e:
    assert "REFUSING" in str(e), e
b.ETH_PREFLIGHT = True
print("16 ok  403 parks an endpoint; blanket refusal stops the run and queues")

# ══════════════════════════════════════════════════════════════════════
# 17 — pre-flight probe: use only what answers, refuse to start if nothing does
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
MODE["fail"] = b._ETH_RPC_BASES[0]
MODE["dead"] = [b._ETH_RPC_BASES[1]]
job, logs = newjob(), []
alive = b._eth_preflight(logs.append, job)
assert alive == b._ETH_RPC_BASES[2:], alive
assert b._eth_bases() == alive                       # the run uses survivors
assert any("UNUSABLE" in l for l in logs), logs
assert any("refusing this host" in l for l in logs), logs
assert any("endpoint(s) usable" in l for l in logs), logs
assert job["eth_rpc_alive"] == len(alive)
# nothing answers -> the sweep must not derive 2.5M candidates for nothing
reset_rpc()
MODE["fail"] = "all"
job, logs = newjob(), []
assert b.attack_eth_timestamp(TS0, TS0 + 50, "s", ["raw"], logs.append, job) == []
assert any("NO endpoint answered" in l for l in logs), logs
assert job.get("eth_queued", 0) == 0, job            # nothing derived at all
assert "no RPC endpoint answered" in job["detail"], job["detail"]
print("17 ok  pre-flight narrows the endpoints and blocks a doomed run")

# ══════════════════════════════════════════════════════════════════════
# 18 — the queue drainer re-checks and saves without re-deriving
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
b.ETH_PREFLIGHT = False
MODE["fail"] = "all"
job, logs = newjob(), []
b.attack_eth_timestamp(TS0, TS0 + 3, "s", ["sha256_dec"], logs.append, job)
b.ETH_PREFLIGHT = True
assert b._eth_pending_count() == 4
queued = b._eth_pending_read()
assert len(queued) == 4 and all(q["privkey"].startswith("0x") for q in queued)
target = b.eth_address(b.ETH_RECIPES["sha256_dec"]["fn"](TS0 + 2, "s")[0][0])
reset_rpc()                                          # endpoints healthy again
b._eth_pending_write(queued)                         # ...but keep the queue
FUNDED[target.lower()] = 4 * 10 ** 18
NONCES[target.lower()] = 3
job, logs = newjob(), []
saved = b.retry_eth_pending(logs.append, job)
assert len(saved) == 1, saved
assert saved[0]["address"] == target
assert saved[0]["balance_wei"] == str(4 * 10 ** 18)
assert saved[0]["recipe"] == "sha256_dec" and saved[0]["ts"] == TS0 + 2
assert saved[0]["balance_nonce"] == 3
assert b._eth_pending_count() == 0                   # queue drained + rewritten
assert not b._eth_pending_path().exists() or b._eth_pending_read() == []
rows = list(b._db().execute("SELECT attack,payload FROM results"))
assert len(rows) == 1 and rows[0][0] == "eth_sha256_dec", rows
assert any("done — 1 hit(s) saved" in l for l in logs), logs
assert job["progress"] == 1.0, job
# a drainer run that is throttled keeps the queue intact
reset_rpc()
b._eth_queue_pending([{"address": b.eth_address(51), "privkey": "0x33",
                       "recipe": "raw", "attack": "eth_raw", "ts": 1,
                       "unit": "s"}], newjob(), None, "test")
assert b._eth_pending_count() == 1
MODE["fail"] = "all"
b.ETH_PREFLIGHT = False
job, logs = newjob(), []
assert b.retry_eth_pending(logs.append, job) == []
assert b._eth_pending_count() == 1, "queue must survive a throttled drain"
b.ETH_PREFLIGHT = True
print("18 ok  queue drainer saves hits without re-deriving, survives throttling")

# ══════════════════════════════════════════════════════════════════════
# 19 — adaptive batch size
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
assert b._eth_batch_size() == 4
MODE["refuse_batch"] = True
b._eth_balances([b.eth_address(60 + i) for i in range(4)])
assert b._eth_batch_size() == 2, b._eth_batch_size()     # halved after refusal
MODE["refuse_batch"] = False
for _ in range(20):                                      # 20 clean batches...
    b._eth_batch_success()
assert b._eth_batch_size() == 3, b._eth_batch_size()     # ...grow one step
for _ in range(20):
    b._eth_batch_success()
assert b._eth_batch_size() == 4, b._eth_batch_size()     # back to the cap
for _ in range(60):
    b._eth_batch_success()
assert b._eth_batch_size() == 4, "must never exceed ETH_RPC_BATCH"
old, new = b._eth_shrink_batch()
assert (old, new) == (4, 2)
assert b._eth_shrink_batch() == (2, 1) and b._eth_shrink_batch() == (1, 1)
b._ETH_BATCH_SIZE[0] = b.ETH_RPC_BATCH
print("19 ok  batch halves on refusal, grows back, floors at 1")

# ══════════════════════════════════════════════════════════════════════
# 20 — the queue is capped, and says so once
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
b.ETH_PENDING_MAX = 2
job, logs = newjob(), []
cands = [b._eth_candidate("raw", 700 + i, {}, "eth_raw", TS0 + i, "s")
         for i in range(5)]
n = b._eth_queue_pending(cands, job, logs.append, "cap test")
assert n == 2 and job["eth_queued"] == 2, (n, job)
assert job["eth_dropped"] == 3, job
assert b._eth_pending_count() == 2
assert sum(1 for l in logs if "retry queue full" in l) == 1, logs
b._eth_queue_pending(cands, job, logs.append, "cap test")     # still full
assert sum(1 for l in logs if "retry queue full" in l) == 1, logs
assert job["eth_dropped"] == 8, job
b.ETH_PENDING_MAX = 1000
print("20 ok  ETH_PENDING_MAX caps the queue and warns once")

# ══════════════════════════════════════════════════════════════════════
# 21 — Stop mid-run queues what was not checked
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
cands = [b._eth_candidate("raw", 800 + i, {}, "eth_raw", TS0 + i, "s")
         for i in range(6)]
job, logs = newjob(), []
saved, stopped = b._eth_flush(cands, logs.append, job, lambda: True)
assert stopped and saved == [] and job["eth_queued"] == 6, (stopped, job)
assert any("stopped —" in l and "queued" in l for l in logs), logs
reset_rpc()
job, logs = newjob(), []
calls = {"n": 0}


def stopper():
    calls["n"] += 1
    return calls["n"] > 2


saved, stopped = b._eth_flush(cands, logs.append, job, stopper)
assert stopped is True and job["eth_queued"] >= 1, (stopped, job)
assert b._eth_pending_count() == job["eth_queued"]
print("21 ok  Stop queues the unchecked remainder instead of dropping it")

# ══════════════════════════════════════════════════════════════════════
# 22 — queue routes
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
d = cl.get("/api/eth/pending").get_json()
assert d["queued"] == 0 and d["cap"] == 1000 and d["batch_size"] == 4, d
assert d["preflight"] is True and d["file"].endswith("eth_pending.jsonl")
r = cl.post("/api/eth/retry", json={}).get_json()
assert r["ok"] is False and "nothing queued" in r["msg"], r
target = b.eth_address(91)
b._eth_queue_pending([{"address": target, "privkey": hex(91), "recipe": "raw",
                       "attack": "eth_raw", "ts": TS0, "unit": "s"}],
                     newjob(), None, "route test")
d = cl.get("/api/eth/pending").get_json()
assert d["queued"] == 1 and d["sample"] == [target], d
FUNDED[target.lower()] = 9 * 10 ** 17
r = cl.post("/api/eth/retry", json={}).get_json()
assert r["ok"] is True, r
job = wait_job("eth_retry")
assert job and not job["error"], job
assert b._eth_pending_count() == 0
rows = [json.loads(p) for _a, p in b._db().execute(
    "SELECT attack,payload FROM results")]
assert len(rows) == 1 and rows[0]["address"] == target, rows
assert rows[0]["balance_wei"] == str(9 * 10 ** 17)
print("22 ok  /api/eth/pending + /api/eth/retry drain the queue end to end")

# ══════════════════════════════════════════════════════════════════════
# 24 — the fixed era table: values, spans, and the two corrections
# ══════════════════════════════════════════════════════════════════════
by_id = {e["id"]: e for e in b.ETH_ERAS}
assert [e["id"] for e in b.ETH_ERAS] == ["presale", "frontier", "cryptojs", "tw"]
# Era 1 — 2014 presale window (published presale dates, UTC)
e = by_id["presale"]
assert (e["start"], e["end"], e["unit"]) == (1405987200000, 1409702399000, "ms")
assert e["scannable"] is False and e["warn"], e
assert "CSPRNG" in e["note"] and "password/IV" in e["note"].lower() \
    or "keystore" in e["note"]
assert e["default"] is False                  # never ticked by default
# Era 2 — Frontier
e = by_id["frontier"]
assert (e["start"], e["end"], e["unit"]) == (1438214400000, 1451606399000, "ms")
assert e["scannable"] is True and e["end"] - e["start"] + 1 == 13391999001
# Era 3 — CryptoJS: the real CVE, and the 14-digit end corrected to 13 digits
e = by_id["cryptojs"]
assert e["end"] == 1577836800000, e["end"]    # NOT 15778368000000 (year 2471)
assert e["end"] - e["start"] + 1 == 63072000001
assert "CVE-2023-46233" in e["note"] and "CVE-2026-71851" in e["note"]
assert e["start"] == 1514764800000            # 2018-01-01T00:00:00Z
# Era 4 — the only genuine timestamp-seeded Ethereum window
e = by_id["tw"]
assert (e["start"], e["end"], e["unit"]) == (1669248000, 1671753599, "s")
assert e["end"] - e["start"] + 1 == 2505600
assert "sha256_dec" in by_id["cryptojs"]["recipes"]
assert all(r in b.ETH_RECIPES for e2 in b.ETH_ERAS for r in e2["recipes"])
# every era's declared recipes must accept that era's unit
for e2 in b.ETH_ERAS:
    assert any(e2["unit"] in b.ETH_RECIPES[r]["units"] for r in e2["recipes"]), e2
assert b.ETH_PRESETS is b.ETH_ERAS            # the older name still resolves
d = cl.get("/api/eth/eras").get_json()
assert d["ok"] is True and len(d["eras"]) == 4
assert d["era_steps"] == b.ETH_ERA_STEPS
# ETH_ERA_STEPS is floored at 1000: the env value 20 above is deliberately too
# small, and a slice smaller than that is not a run worth starting.
assert b.ETH_ERA_STEPS == 1000, b.ETH_ERA_STEPS
assert [x["span"] for x in d["eras"]] == [
    e2["end"] - e2["start"] + 1 for e2 in b.ETH_ERAS]
assert {k for k in d["eras"][0]} >= {"id", "era", "label", "window", "unit",
                                     "start", "end", "span", "recipes",
                                     "default", "scannable", "note",
                                     "default_steps"}
d2 = cl.get("/api/eth/recipes").get_json()
assert d2["eras"] == d2["presets"] and len(d2["eras"]) == 4
print("24 ok  era table values, spans, CVE + 14-digit end corrections")

# ══════════════════════════════════════════════════════════════════════
# 25 — /api/eth/era validation: never start a doomed batch
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
for payload, why in (({"eras": [], "recipes": ["sha256_dec"]}, "at least one era"),
                     ({"eras": ["nope"], "recipes": ["sha256_dec"]}, "unknown era"),
                     ({"eras": ["tw"], "recipes": []}, "at least one recipe"),
                     ({"eras": ["tw"], "recipes": ["not_a_recipe"]}, "recipe"),
                     # a string and a dict list are both accepted forms
                     ({"eras": "tw", "recipes": "sha256_dec", "steps": 5},
                      "ok-ish"),
                     ({"eras": [{"id": "tw", "steps": 5}],
                       "recipes": ["sha256_dec"]}, "dict form")):
    r = cl.post("/api/eth/era", json=payload).get_json()
    if why in ("ok-ish", "dict form"):
        assert r["ok"] is True and r["steps"] == 5, (payload, r)
        wait_job("eth_era", 20)
    else:
        assert r["ok"] is False and why in r["msg"], (payload, r)
# tw_bip39_s and mt19937_s are SECONDS-only; a millisecond era cannot use them,
# so the route must refuse before deriving anything
r = cl.post("/api/eth/era", json={"eras": ["cryptojs"],
                                  "recipes": ["tw_bip39_s", "mt19937_s"],
                                  "steps": 4}).get_json()
assert r["ok"] is False and "unit" in r["msg"] and "ms" in r["msg"], r
assert not b._JOBS["eth_era"]["alive"], b._JOBS["eth_era"]
# ... but a mixed selection passes as long as ONE selected era can use one
# recipe; the eras that cannot are skipped per era and the log says so
r = cl.post("/api/eth/era", json={"eras": ["tw", "frontier"],
                                  "recipes": ["tw_bip39_s"],
                                  "steps": 4}).get_json()
assert r["ok"] is True, r
wait_job("eth_era", 20)
assert not b._JOBS["eth_era"]["alive"], b._JOBS["eth_era"]
# the per-era slice is capped by ETH_MAX_TOTAL_STEPS (100,000 in this suite)
r = cl.post("/api/eth/era", json={"eras": ["frontier", "cryptojs"],
                                  "recipes": ["sha256_dec"],
                                  "steps": 80000}).get_json()
assert r["ok"] is False and "ETH_MAX_TOTAL_STEPS" in r["msg"], r
# ... and the cap is per run, not per era
r = cl.post("/api/eth/era", json={"eras": ["frontier", "cryptojs"],
                                  "recipes": ["sha256_dec"],
                                  "steps": 40000}).get_json()
assert r["ok"] is True and r["steps"] == 80000, r
b._JOBS["eth_era"]["stop"] = True            # do not really sweep 80k per era
wait_job("eth_era", 30)
# an unknown era in a list of known ones is rejected outright, nothing starts
r = cl.post("/api/eth/era", json={"eras": [{"id": "tw", "steps": 10},
                                           {"id": "bogus"}],
                                  "recipes": ["sha256_dec"]}).get_json()
assert r["ok"] is False and "bogus" in r["msg"], r
assert not b._JOBS["eth_era"]["alive"], b._JOBS["eth_era"]
print("25 ok  /api/eth/era validation: unknown ids, units, recipes, cap")

# ══════════════════════════════════════════════════════════════════════
# 26 — attack_eth_eras sweeps the selected eras in sequence, with slices
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
specs = [{"id": "tw", "steps": 6, "offset": 0},
         {"id": "frontier", "steps": 4, "offset": 1000}]
job, logs = newjob(), []
hits = b.attack_eth_eras(specs, ["sha256_dec", "tw_bip39_s"], logs.append, job)
assert job["progress"] == 1.0, job
# era 1: tw is s and takes BOTH recipes (6 steps x 2 = 12 candidates); era 2:
# frontier is ms, so tw_bip39_s is filtered out (4 steps x 1 = 4). Nothing is
# funded, so every candidate is counted as skipped-empty rather than saved.
assert job["eth_skipped"] == 6 * 2 + 4 * 1, job
assert not hits
assert any("batch of 2 era" in l for l in logs), logs
assert any(l.startswith("[era 1/2 · Era 4 tw] ") for l in logs), logs
assert any(l.startswith("[era 2/2 · Era 2 frontier] ") for l in logs), logs
assert any("eras run one after another" in l for l in logs), logs
# the frontier slice starts 1000 steps into the window and is 4 wide
assert any("1438214401000..1438214401003 ms: 4 of 13,391,999,001" in l
           for l in logs), [l for l in logs if "frontier" in l]
assert any("offset 1,000" in l for l in logs), logs
assert job["detail"].startswith("Era "), job["detail"]
# a recipe that no selected era can use is reported per era, not silently dropped
job, logs = newjob(), []
b.attack_eth_eras([{"id": "cryptojs", "steps": 3, "offset": 0}],
                  ["tw_bip39_s"], logs.append, job)
assert job.get("eth_skipped", 0) == 0, job
assert any("no selected recipe accepts unit=ms" in l for l in logs), logs
# an offset past the end of the window is skipped instead of sweeping 0..N
job, logs = newjob(), []
b.attack_eth_eras([{"id": "tw", "steps": 5, "offset": 10 ** 12}],
                  ["sha256_dec"], logs.append, job)
assert job.get("eth_skipped", 0) == 0 and any("past the end of the window" in l
                                              for l in logs), logs
# unscannable Era 1 says so, in the log, every single time
job, logs = newjob(), []
b.attack_eth_eras([{"id": "presale", "steps": 2, "offset": 0}],
                  ["sha256_dec"], logs.append, job)
assert job["eth_skipped"] == 2, job
assert any("NOT recoverable by a private-key sweep" in l for l in logs), logs
assert any("Will NOT recover a presale wallet" in l for l in logs), logs
# a funded candidate anywhere in the batch is saved like any other sweep hit
reset_rpc()
fn = b.ETH_RECIPES["sha256_dec"]["fn"]
ts = by_id["tw"]["start"] + 3
target = b.eth_address(fn(ts, "s")[0][0])
FUNDED[target.lower()] = 5 * 10 ** 17      # the fake RPC keys balances lowercase
NONCES[target.lower()] = 2
job, logs = newjob(), []
hits = b.attack_eth_eras([{"id": "tw", "steps": 6, "offset": 0}],
                         ["sha256_dec"], logs.append, job)
assert len(hits) == 1 and hits[0]["address"] == target, hits
assert hits[0]["ts"] == ts and hits[0]["unit"] == "s", hits[0]
assert hits[0]["recipe"] == "sha256_dec", hits[0]
assert job["eth_skipped"] == 5, job          # 6 candidates, 1 funded
rows = [json.loads(p) for _a, p in b._db().execute(
    "SELECT attack,payload FROM results")]
assert any(r["address"] == target and r["attack"] == "eth_sha256_dec"
           for r in rows), rows
assert any("HIT" in l for l in logs), logs
print("26 ok  era batch: sequential eras, per-era slices, offsets, warnings")

# ══════════════════════════════════════════════════════════════════════
# 27 — Stop mid-batch and no-endpoint stop the whole batch
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
job, logs = newjob(), []
job["stop"] = True
b.attack_eth_eras([{"id": "tw", "steps": 5}, {"id": "frontier", "steps": 5}],
                  ["sha256_dec"], logs.append, job)
assert job.get("eth_skipped", 0) == 0, job
assert any("stopped before tw" in l for l in logs), logs
# Stop between eras: era 1 runs, era 2 does not
reset_rpc()
job, logs = newjob(), []
_orig = b.attack_eth_timestamp


def _stop_after(*a, **kw):
    out = _orig(*a, **kw)
    job["stop"] = True
    return out


b.attack_eth_timestamp = _stop_after
b.attack_eth_eras([{"id": "tw", "steps": 3}, {"id": "frontier", "steps": 3}],
                  ["sha256_dec"], logs.append, job)
b.attack_eth_timestamp = _orig
assert job["eth_skipped"] == 3, job        # only era 1 ran
assert any("stopped before frontier" in l for l in logs), logs
assert job["progress"] < 1.0, job
# every endpoint refusing: the batch stops rather than deriving blind
reset_rpc()
MODE["fail"] = "all"
b.ETH_PREFLIGHT = True
job, logs = newjob(), []
b.attack_eth_eras([{"id": "tw", "steps": 4}, {"id": "frontier", "steps": 4}],
                  ["sha256_dec"], logs.append, job)
b.ETH_PREFLIGHT = True
# the pre-flight probe found zero live endpoints: era 1 derived nothing and the
# batch stopped instead of walking on to era 2
assert job.get("eth_no_rpc") or job.get("eth_rpc_alive") == 0, job
assert job.get("eth_skipped", 0) == 0, job
assert any("stopping the batch: no RPC endpoint answered" in l for l in logs), logs
assert job["progress"] < 1.0, job             # honestly unfinished
assert "stopped early: no RPC endpoint" in logs[-1], logs[-1]
print("27 ok  era batch honours Stop and stops when no endpoint answers")

# ══════════════════════════════════════════════════════════════════════
# 28 — the era widget and the restyled chrome on /eth
# ══════════════════════════════════════════════════════════════════════
reset_rpc()
txt = cl.get("/eth").get_data(as_text=True)
for frag in ("Era batch", "era-presale", "era-frontier", "era-cryptojs",
             "era-tw", "st-frontier", "of-frontier", "startEra()",
             "watch('eth_era','Era')", "select scannable", "steps total",
             "Will NOT recover a presale wallet", "CVE-2023-46233",
             "year 2471", "const ERAS=", "eraWhole", "eraManual",
             "1,514,764,800,000", "1,577,836,800,000", "63,072,000,001"):
    assert frag in txt, frag
# per-era controls exist for every era, and only the scannable ones are ticked.
# (Server-built attributes are single-quoted, template ones double-quoted.)
for e in b.ETH_ERAS:
    for ctrl in ("ck-", "st-", "of-", "era-"):
        assert ("id='%s%s'" % (ctrl, e["id"])) in txt, (ctrl, e["id"])
    assert "eraWhole('%s')" % e["id"] in txt, e["id"]
    assert "eraManual('%s')" % e["id"] in txt, e["id"]
    ticked = ("id='ck-%s' value='%s' checked" % (e["id"], e["id"])) in txt
    assert ticked == bool(e["default"]), (e["id"], ticked)
    # the era row shows its recipe list and its warning pill where it has one
    assert e["era"] in txt and e["window"] in txt, e["id"]
# The 14-digit typo appears exactly once — inside the note that corrects it —
# and never as a scan value in the JSON the widget drives itself from.
assert txt.count("15778368000000") == 1 and "one digit too many" in txt
assert txt.count("CVE-2026-71851") == 1 and "does not exist" in txt
# the scale arithmetic on the page is computed from the table, not hand-typed
# prose: 63,072,000,001 / 24,000 candidates/s = 30 days of CPU, and at
# ETH_RPC_BATCH addresses per request it is 1.26 billion requests (~8 years at
# a sustainable 5 req/s). If any of those inputs change, these must follow.
span3 = 63_072_000_001
assert "%d days of pure" % round(span3 / 24000 / 86400) in txt, "CPU days"
assert format(int(span3 / b.ETH_RPC_BATCH), ",") in txt, "batch request count"
years3 = round(span3 / b.ETH_RPC_BATCH / 5 / 86400 / 365)
assert years3 >= 1, years3                     # never renders as "0 years"
assert "about %d years at a sustainable" % years3 in txt
assert "one timestamp in %s" % format(
    max(1, int(span3 / b.ETH_ERA_STEPS)), ",") in txt, "slice ratio"
assert not any(tok in txt for tok in
               ("{years}", "{days3}", "{reqs3}", "{rpcyears3}", "{ratio3}",
                "{cover3}", "{span3}", "{erasteps}", "{maxtotal}"))
eras_js = txt.split("const ERAS=", 1)[1].split(";", 1)[0]
assert "15778368000000" not in eras_js, eras_js[:200]
assert '"end": 1577836800000' in eras_js, eras_js[:200]
# the restyle: sticky locked header, 3D buttons, smooth scrolling, widgets
for frag in ("class=\"topbar\"", "id=\"jobs-chip\"", "scroll-behavior:smooth",
             "translateY(2px)", "linear-gradient(180deg,#6f9ad0",
             "position:sticky;top:var(--stick)", "class=\"card accent-green\"",
             "class='era", "class='pill", "backdrop-filter:blur",
             "refreshChip", "refreshSticky", "<nav class=\"nav\">",
             "--stick:112px", "id=\"era\""):
    assert frag in txt, frag
assert txt.count('class="on"') == 1           # exactly one active nav pill
for path in ("/", "/results", "/randstorm", "/brain", "/nonce", "/data"):
    other = cl.get(path).get_data(as_text=True)
    assert 'class="topbar"' in other and "refreshChip" in other, path
    assert "refreshSticky" in other and "--stick" in other, path
    assert other.count('class="on"') == 1, path
    assert not any(p in other for p in ("{nav}", "{build_id}", "{ec_backend}",
                                        "{keccak_backend}")), path
# the home page carries a launcher for the same batch, with the defaults
home = cl.get("/").get_data(as_text=True)
for frag in ("Ethereum era batch", "startEraHome()", "watch('eth_era','EraH')",
             'id="barEraH"', 'id="logEraH"', "not privkey-recoverable",
             "63,072,000,001", "ETH_ERA_STEPS", "configure eras"):
    assert frag in home, frag
assert '["frontier", "cryptojs", "tw"]' in home      # the ticked-by-default eras
assert 'id="presale"' not in home and "era-presale" not in home
assert '"presale"' not in home.split("startEraHome", 1)[1].split(";", 1)[0]
assert home.count("%%") == 0 and "{era_home}" not in home
# the manual sweep still works, and still rejects a unit mismatch
d = cl.post("/api/eth/timestamp", json={"start": "1669248000",
                                        "end": "1669248005", "unit": "s",
                                        "recipes": ["sha256_dec"]}).get_json()
assert d["ok"] is True, d
wait_job("eth_ts", 20)
print("28 ok  era widget + sticky header + 3D buttons on every page")

# ══════════════════════════════════════════════════════════════════════
# 29 — the headless era batch: --list-eras and --cli-eth-era
# ══════════════════════════════════════════════════════════════════════
import subprocess  # noqa: E402
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, DISK_PATH=DISK, APP_USER="", APP_PASSWORD="",
           ETH_VERIFY_BALANCES="0")       # no network: derive and count only


def cli(*argv):
    return subprocess.run([sys.executable, os.path.join(ROOT, "btc_hunt.py")]
                          + list(argv), capture_output=True, text=True,
                          env=ENV, timeout=180)


r = cli("--list-eras")
assert r.returncode == 0, r.stderr[-400:]
for frag in ("63,072,000,001", "13,391,999,001", "2,505,600",
             "NOT recoverable by a privkey sweep", "CVE-2023-46233",
             "default per-era steps: 1,000"):
    assert frag in r.stdout, frag
r = cli("--cli-eth-era", "tw:20,frontier:10@5", "--recipes", "sha256_dec")
assert r.returncode == 0, r.stderr[-400:]
assert "batch of 2 era(s)" in r.stdout, r.stdout[-400:]
assert "1669248000..1669248019 s: 20 of 2,505,600" in r.stdout, r.stdout[-400:]
assert "1438214400005..1438214400014 ms: 10 of 13,391,999,001" in r.stdout
assert "offset 5" in r.stdout and "batch done — 2 of 2 era(s)" in r.stdout
r = cli("--cli-eth-era", "presale:5", "--recipes", "sha256_dec")
assert r.returncode == 0 and "Will NOT recover a presale wallet" in r.stdout
r = cli("--cli-eth-era", "bogus")
assert r.returncode != 0 and "unknown era(s): bogus" in r.stderr, r.stderr[-300:]
r = cli("--cli-eth-era", "tw:notanumber")
assert r.returncode != 0 and "must be integers" in r.stderr, r.stderr[-300:]
r = cli("--cli-eth-era", "tw:99999999")
assert r.returncode != 0 and "ETH_MAX_TOTAL_STEPS" in r.stderr, r.stderr[-300:]
print("29 ok  --list-eras and --cli-eth-era slices, offsets and validation")

# ══════════════════════════════════════════════════════════════════════
# 30 — throughput, for the docs (informational)
# ══════════════════════════════════════════════════════════════════════
for rid, n in (("sha256_dec", 2000), ("tw_bip39_s", 60)):
    fn = b.ETH_RECIPES[rid]["fn"]
    t0 = time.time()
    for i in range(n):
        priv, _extra = fn(TS0 + i, "s")[0]
        b.eth_address(priv)
    el = (time.time() - t0) / n
    print("30 info  %-11s %6.2f ms/candidate -> %6.0f/s -> the 2,505,600-seed "
          "Trust Wallet window in %5.1f min"
          % (rid, el * 1000, 1 / el, 2_505_600 * el / 60))

b.requests.post = REAL_POST
b.requests.get = REAL_GET
shutil.rmtree(DISK, ignore_errors=True)
print("ALL TESTS PASSED")
