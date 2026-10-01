"""Oracle independen vektor tanda tangan kunci audit (kontrak/KONTRAK.md §3, core/docs/adr/0004).

Hanya memakai teks KONTRAK dan pustaka Python `cryptography` (OpenSSL), tanpa kode core maupun sodium PHP.
Menulis ulang *.json di direktori tujuan; Ed25519 deterministik, jadi keluarannya selalu identik.

    python3 kontrak/vectors/checkpoint/oracle.py kontrak/vectors/checkpoint
"""
import base64, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

PREFIX = b"sadmin-audit-checkpoint/1\n"

def jcs(obj):
    # Cukup untuk objek ini: kunci ASCII, nilai string ASCII & integer -> urut kunci, tanpa spasi.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def message(seq, h, created_at):
    return PREFIX + jcs({"seq": seq, "hash": h, "created_at": created_at})

seed = bytes(range(0x80, 0xA0))
sk = Ed25519PrivateKey.from_private_bytes(seed)
pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def b64(b): return base64.b64encode(b).decode()

cases = [
    ("01-first-checkpoint.json", "Checkpoint pertama: ujung rantai = entri vektor emas ADR 0001 (seq 1)",
     1, "0676afeb6ed67d29dd0b57eebf2b6c5d3817cb7a8cf0f8d21685d7f45da60695", "2026-09-30T02:26:12.345678Z"),
    ("02-max-seq-zero-micro.json", "seq = 2^53-1 (batas integer I-JSON) dan mikrodetik nol tetap 6 digit",
     9007199254740991, "f" * 64, "2026-10-01T00:00:00.000000Z"),
]
out = {}
for name, desc, seq, h, ts in cases:
    msg = message(seq, h, ts)
    sig = sk.sign(msg)
    out[name] = {
        "description": desc,
        "seed_hex": seed.hex(),
        "public_key": b64(pk),
        "checkpoint": {"seq": seq, "hash": h, "created_at": ts},
        "message": msg.decode(),
        "signature": b64(sig),
        "valid": True,
    }
# Vektor tolak: tanda tangan vektor 01 dipasang pada seq lain.
v1 = out["01-first-checkpoint.json"]
bad_msg = message(2, v1["checkpoint"]["hash"], v1["checkpoint"]["created_at"])
out["03-signature-for-other-seq.json"] = {
    "description": "Tanda tangan vektor 01 dipasang pada checkpoint seq 2: wajib ditolak",
    "seed_hex": seed.hex(),
    "public_key": b64(pk),
    "checkpoint": {"seq": 2, "hash": v1["checkpoint"]["hash"], "created_at": v1["checkpoint"]["created_at"]},
    "message": bad_msg.decode(),
    "signature": v1["signature"],
    "valid": False,
}
# Vektor tolak: byte tanda tangan vektor 01 identik, tetapi bit sisa karakter terakhir tak nol (RFC 4648 §3.5).
# Dekoder longgar (mis. Go base64.StdEncoding tanpa Strict()) menerimanya; KONTRAK §3 mewajibkan menolak.
noncanonical = v1["signature"][:85] + chr(ord(v1["signature"][85]) + 1) + "=="
assert base64.b64decode(noncanonical) == base64.b64decode(v1["signature"])
out["04-noncanonical-base64.json"] = {
    "description": "Tanda tangan vektor 01 dengan bit sisa base64 tak nol (byte sama): wajib ditolak karena tak kanonik",
    "seed_hex": seed.hex(),
    "public_key": b64(pk),
    "checkpoint": dict(v1["checkpoint"]),
    "message": v1["message"],
    "signature": noncanonical,
    "valid": False,
}

def canonical_bytes(text):
    raw = base64.b64decode(text, validate=True)
    return raw if base64.b64encode(raw).decode() == text else None

# Swa-periksa oracle
from cryptography.exceptions import InvalidSignature
for name, v in out.items():
    raw = canonical_bytes(v["signature"])
    try:
        ok = raw is not None
        if ok:
            sk.public_key().verify(raw, v["message"].encode())
    except InvalidSignature:
        ok = False
    assert ok == v["valid"], name
import sys, os
d = sys.argv[1]
os.makedirs(d, exist_ok=True)
for name, v in out.items():
    with open(os.path.join(d, name), "w") as f:
        json.dump(v, f, indent=2, ensure_ascii=False); f.write("\n")
    print(name, v["signature"])
print("public_key", b64(pk))
