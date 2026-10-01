"""Oracle independen vektor tanda tangan kunci layanan (`sig` bingkai core->agen), kontrak/KONTRAK.md §3.

Sumber satu-satunya: teks kontrak/KONTRAK.md (§2 bentuk bingkai, §3 kanonisasi & tanda tangan, §5 isi
pesan), vektor kontrak/vectors/jcs/*.json dan jcs-reject/*.json, serta kontrak/vectors/checkpoint/
01-first-checkpoint.json (badan CheckpointAnchor). Tidak membaca kode core (PHP) maupun edge (Go).
Pustaka: hanya pustaka standar Python dan `cryptography` (OpenSSL) untuk Ed25519. JCS (RFC 8785) dan
validasi I-JSON ditulis ulang di sini, lalu diswa-periksa terhadap vektor jcs bersama.

Aturan yang diwujudkan (ringkas, teks KONTRAK yang menang):
- pesan = byte ASCII `sadmin-service/1` + LF + byte UTF-8 JCS objek tepat {type, id, body} dari bingkai;
- bila `type` == "Envelope", anggota tingkat atas `secret_values` dikeluarkan dari `body` (bila ada);
  di jenis pesan lain anggota bernama `secret_values` ikut ditandatangani;
- Ed25519 murni (RFC 8032); `sig` 64 byte dan kunci publik 32 byte dalam base64 standar berpadding
  yang wajib kanonik (bit sisa nol); tak sah / tak kanonik / panjang salah = tanda tangan tidak sah.

Menulis ulang *.json di direktori tujuan. Semua ID, nonce, salt, dan waktu adalah konstanta tetap dan
Ed25519 deterministik, jadi keluarannya selalu identik byte-per-byte. Oracle gagal (AssertionError)
bila swa-periksa JCS, I-JSON, atau verifikasi vektor tidak cocok.

    python3 kontrak/vectors/service-sig/oracle.py kontrak/vectors/service-sig
"""
import base64
import copy
import glob
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.dirname(HERE)

PREFIX = b"sadmin-service/1\n"
MAX_INT = 2**53 - 1
MAX_DEPTH = 64


class Ditolak(ValueError):
    """Masukan bukan I-JSON menurut KONTRAK §3 (setara E_CANONICAL); args[0] = alasan seperti `reason` jcs-reject."""


# ---------------------------------------------------------------------------
# I-JSON (KONTRAK §3): validasi teks mentah dan nilai terurai
# ---------------------------------------------------------------------------

def _periksa_string(s):
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise Ditolak("utf8")  # surrogate tunggal (bentuk escape; byte mentah sudah ditolak dekoder)


def periksa_nilai(v, depth=0):
    """Periksa nilai terurai: integer ±(2^53-1) saja, tanpa surrogate tunggal, sarang <= 64, nama tanpa NUL."""
    if v is None or v is True or v is False:
        return
    if type(v) is int:
        if abs(v) > MAX_INT:
            raise Ditolak("number")
        return
    if isinstance(v, str):
        _periksa_string(v)
        return
    if isinstance(v, (list, dict)):
        depth += 1
        if depth > MAX_DEPTH:
            raise Ditolak("depth")
        if isinstance(v, dict):
            for k, x in v.items():
                if not isinstance(k, str):
                    raise Ditolak("syntax")
                if "\x00" in k:
                    raise Ditolak("nul_member_name")
                _periksa_string(k)
                periksa_nilai(x, depth)
        else:
            for x in v:
                periksa_nilai(x, depth)
        return
    raise Ditolak("number")  # float atau tipe lain: dilarang


def urai_ketat(raw):
    """Urai byte mentah sebagai I-JSON sAdmin; tolak (Ditolak), jangan perbaiki."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raise Ditolak("bom")
    try:
        text = raw.decode("utf-8")  # strict: menolak byte tak sah dan surrogate mentah (ED A0 80 ...)
    except UnicodeDecodeError:
        raise Ditolak("utf8")

    def pasangan(items):
        obj = {}
        for k, v in items:  # k sudah berupa teks setelah escape diurai, jadi "a" == "\u0061"
            if "\x00" in k:
                raise Ditolak("nul_member_name")
            if k in obj:
                raise Ditolak("duplicate_key")
            obj[k] = v
        return obj

    def tolak_angka(_):
        raise Ditolak("number")

    def integer(s):
        n = int(s)
        if abs(n) > MAX_INT:
            raise Ditolak("number")
        return n

    try:
        value = json.loads(text, object_pairs_hook=pasangan, parse_float=tolak_angka,
                           parse_int=integer, parse_constant=tolak_angka)
    except Ditolak:
        raise
    except (ValueError, RecursionError):
        raise Ditolak("syntax")
    periksa_nilai(value)
    return value


# ---------------------------------------------------------------------------
# JCS RFC 8785, ditulis sendiri (hanya integer; angka pecahan dilarang KONTRAK §3)
# ---------------------------------------------------------------------------

_ESC_PENDEK = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _jcs_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise Ditolak("utf8")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append(_ESC_PENDEK.get(ch) or "\\u%04x" % o)  # ECMAScript: heks huruf kecil
        else:
            out.append(ch)  # '/', DEL, U+2028/2029, non-ASCII, noncharacter: literal
    out.append('"')
    return "".join(out)


def _jcs(v, depth):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if type(v) is int:  # bool sudah tertangani di atas; bool bukan angka
        if abs(v) > MAX_INT:
            raise Ditolak("number")
        return str(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, (list, dict)):
        depth += 1
        if depth > MAX_DEPTH:
            raise Ditolak("depth")
        if isinstance(v, list):
            return "[" + ",".join(_jcs(x, depth) for x in v) + "]"
        for k in v:
            if not isinstance(k, str):
                raise Ditolak("syntax")
            _periksa_string(k)
        # RFC 8785 §3.2.3: urut menurut unit kode UTF-16; perbandingan byte UTF-16BE setara dengannya.
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(v[k], depth) for k in keys) + "}"
    raise Ditolak("number")  # float (termasuk NaN/Inf) dan tipe lain


def jcs(v):
    return _jcs(v, 0).encode("utf-8")


# ---------------------------------------------------------------------------
# Aturan tanda tangan kunci layanan (KONTRAK §3)
# ---------------------------------------------------------------------------

def pesan_layanan(frame):
    """Byte pesan yang ditandatangani untuk satu bingkai core->agen."""
    body = frame["body"]
    if frame["type"] == "Envelope" and isinstance(body, dict) and "secret_values" in body:
        body = {k: v for k, v in body.items() if k != "secret_values"}
    return PREFIX + jcs({"type": frame["type"], "id": frame["id"], "body": body})


def b64_kanonik(text, panjang):
    """Dekode base64 standar berpadding secara ketat; None bila tak sah, tak kanonik, atau panjang salah."""
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", text):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    if base64.b64encode(raw).decode("ascii") != text or len(raw) != panjang:
        return None
    return raw


def verifikasi(public_key_b64, frame):
    pk = b64_kanonik(public_key_b64, 32)
    sig = b64_kanonik(frame.get("sig"), 64)
    if pk is None or sig is None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, pesan_layanan(frame))
    except InvalidSignature:
        return False
    return True


# ---------------------------------------------------------------------------
# Swa-periksa 1: JCS & I-JSON terhadap vektor bersama
# ---------------------------------------------------------------------------

def swa_periksa_jcs():
    files = sorted(glob.glob(os.path.join(VECTORS, "jcs", "*.json")))
    assert files, "vektor jcs tidak ditemukan"
    for path in files:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
        name = os.path.basename(path)
        periksa_nilai(v["input"])
        got = jcs(v["input"])
        assert got.decode("utf-8") == v["canonical"], (name, got)
        assert hashlib.sha256(got).hexdigest() == v["sha256"], name
        if "input_base64" in v:
            parsed = urai_ketat(base64.b64decode(v["input_base64"], validate=True))
            assert jcs(parsed) == got, (name, "input_base64")
    rejects = sorted(glob.glob(os.path.join(VECTORS, "jcs-reject", "*.json")))
    for path in rejects:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
        name = os.path.basename(path)
        try:
            urai_ketat(base64.b64decode(v["input_base64"], validate=True))
        except Ditolak as e:
            assert e.args[0] == v["reason"], (name, e.args[0], v["reason"])
        else:
            raise AssertionError((name, "seharusnya ditolak"))
    return len(files), len(rejects)


# ---------------------------------------------------------------------------
# Konstanta (fiktif, tetap)
# ---------------------------------------------------------------------------

seed = bytes(range(0x40, 0x60))
sk = Ed25519PrivateKey.from_private_bytes(seed)
pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(b):
    return base64.b64encode(b).decode("ascii")


def b64url(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# KONTRAK §8: ULID huruf kecil, dibandingkan apa adanya; huruf besar atau campuran tidak sah.
ULID_RE = re.compile(r"[0-7][0-9a-hjkmnp-tv-z]{25}")
KONTRAK = "0.4"
PLATFORM = "ubuntu-24.04"

SERVER_ID = "01m1d7ntm0pfnctct37crva993"
ADMIN_ID = "01m1gj3k00hhmqdsdn8421bff9"
SECRET_ID = "01m2hcnr805ew0tmvv3phy72yk"
SECRET_ID_CANCEL = "01m3tswzg0f26k527mb8fgzt4d"

FRAME_01 = "01m3tpf3w09z7bmqzenzrs6wn3"
FRAME_02 = "01m3tpr8v0nvkqxycsmty8kpny"
FRAME_05 = "01m3r24gd00z3k173jj1zjgjr7"
FRAME_06 = "01m3tqkqr08b1qxwa347req3da"
FRAME_08_LAIN = "01m3tpf4v8adfgyzk3tcjbr8e9"
FRAME_10 = "01m3tswzg0xaedzq0r04cj41xf"

ENV_01, IDEM_01 = "01m3tpf3w0q6dk22dsdr1mxdn7", "01m3tpf3w00e9frdrkbxkdr542"
ENV_02, IDEM_02 = "01m3tpr8v06pwd2yndhfd6ks5m", "01m3tpr8v0nxm9prjtjdw9ty4t"
ENV_06, IDEM_06 = "01m3tqkqr07y0jtwqt9t5zevq5", "01m3tqkqr0bfz58y06z9cfb30e"

NONCE_01 = "E4frThyGl0EqytBcHEnNCKfAH80qrRHVbHQny5bcPYg"
NONCE_02 = "I04LoavKaSUnfsVBl0lbBmUUflxPTnKnL-Jekt0scN8"
NONCE_06 = "f40H5dTk3hTfMSrFOKbIOMTW5JEwUq5mJoiLG11MPmE"
SALT_02 = "x0VkuQZoSf1RFm-jTQFwuA"
PLAN_HASH_10 = "dfe6a90139829b3cd607f3afa69f29d4a038912f2c7a053c40f5da94e168bed7"

KUNCI_SSH_PALSU = (
    "-----BEGIN TEST-ONLY SSH KEY-----\n"
    "TEST-ONLY: bukan kunci nyata, hanya pengisi vektor uji service-sig\n"
    "deploy@git.example.test baris-kedua-palsu\n"
    "-----END TEST-ONLY SSH KEY-----\n"
)
KUNCI_SSH_PENGGANTI = (
    "-----BEGIN TEST-ONLY SSH KEY-----\n"
    "TEST-ONLY: kunci pengganti palsu yang disisipkan pihak ketiga\n"
    "-----END TEST-ONLY SSH KEY-----\n"
)

TEKS_UNICODE = (
    "aksen: café naïve Ålborg ñ ü | CJK: 日本語 中文 | emoji: 😀 𝄞"
    " | ls[\u2028] del[\u007f] soh[\u0001] tab[\t] lf[\n]"
    " | kutip[\"] miring[\\] garis[/]"
)


def unb64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def waktu(ts):
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ts), ts
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def tambah_menit(ts, menit):
    return (waktu(ts) + timedelta(minutes=menit)).strftime("%Y-%m-%dT%H:%M:%SZ")


def komitmen(salt_b64url, nilai):
    # Ilustratif (KONTRAK §5): sha256(byte salt mentah || byte UTF-8 nilai), heks huruf kecil.
    return hashlib.sha256(unb64url(salt_b64url) + nilai.encode("utf-8")).hexdigest()


def envelope(env_id, action_key, risk, params, nonce, issued_at, idem):
    return {
        "kontrak": KONTRAK,
        "envelope_id": env_id,
        "phase": "apply",
        "action_key": action_key,
        "action_version": 1,
        "target_server_id": SERVER_ID,
        "platform_id": PLATFORM,
        "params": params,
        "risk": risk,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": tambah_menit(issued_at, 10),
        "idempotency_key": idem,
        "plan_hash": None,
        "step_index": None,
    }


def bingkai(type_, id_, body, sig=None):
    frame = {"type": type_, "id": id_, "body": body}
    frame["sig"] = sig if sig is not None else b64(sk.sign(pesan_layanan(frame)))
    return frame


def vektor(desc, frame, valid):
    return {
        "description": desc,
        "seed_hex": seed.hex(),
        "public_key": b64(pk),
        "frame": frame,
        "message": pesan_layanan(frame).decode("utf-8"),
        "valid": valid,
    }


def placeholder_ids(v):
    out = set()
    if isinstance(v, dict):
        if "$secret" in v:
            out.add(v["$secret"])
        for x in v.values():
            out |= placeholder_ids(x)
    elif isinstance(v, list):
        for x in v:
            out |= placeholder_ids(x)
    return out


# ---------------------------------------------------------------------------
# Vektor
# ---------------------------------------------------------------------------

out = {}

f01 = bingkai("Envelope", FRAME_01, envelope(
    ENV_01, "server.inventory", "L0", {}, NONCE_01, "2026-10-01T03:00:00Z", IDEM_01))
out["01-envelope-l0-empty-params.json"] = vektor(
    "Envelope L0 server.inventory versi 1 dengan params objek kosong, plan_hash dan step_index null, tanpa plan "
    "dan tanpa secret_values: params wajib terkanonik sebagai {} (bukan []), null tetap literal null; "
    "pesan = 'sadmin-service/1' LF JCS {type,id,body} dengan kunci terurut body, id, type",
    f01, True)

placeholder = {"$secret": SECRET_ID, "salt": SALT_02, "commit": komitmen(SALT_02, KUNCI_SSH_PALSU)}
body02 = envelope(ENV_02, "source.fetch_git", "L1", {
    "repo_url": "ssh://git@git.example.test/contoh/aplikasi.git",
    "branch": "main",
    "deploy_key": placeholder,
}, NONCE_02, "2026-10-01T03:05:00Z", IDEM_02)
body02["secret_values"] = {SECRET_ID: KUNCI_SSH_PALSU}
f02 = bingkai("Envelope", FRAME_02, body02)
out["02-envelope-secret-values.json"] = vektor(
    "Envelope L1 source.fetch_git dengan placeholder $secret di params.deploy_key dan secret_values berisi kunci "
    "SSH palsu multi-baris: secret_values tingkat atas body dikeluarkan sebelum JCS, jadi pesan tidak memuatnya; "
    "placeholder (ID, salt, commit) tetap ikut ditandatangani lewat params",
    f02, True)

f03 = copy.deepcopy(f02)
f03["body"]["secret_values"][SECRET_ID] = KUNCI_SSH_PENGGANTI
out["03-envelope-secret-values-replaced.json"] = vektor(
    "Bingkai 02 dengan nilai secret_values diganti dan sig tetap: sig tetap sah karena secret_values di luar "
    "cakupan sig; penggantian ini wajib ditangkap agen lewat E_SECRET_COMMIT (commit placeholder tak cocok), "
    "bukan lewat sig",
    f03, True)

f04 = copy.deepcopy(f02)
del f04["body"]["secret_values"]
out["04-envelope-secret-values-absent.json"] = vektor(
    "Bingkai 02 tanpa anggota secret_values dan sig tetap: sah karena pesan identik dengan 02 (bila anggota itu "
    "tak ada, tak ada yang dikeluarkan); kekurangan kunci secret_values ditolak terpisah dengan E_SECRET_COMMIT",
    f04, True)

with open(os.path.join(VECTORS, "checkpoint", "01-first-checkpoint.json"), encoding="utf-8") as f:
    cp = json.load(f)
f05 = bingkai("CheckpointAnchor", FRAME_05, {
    "seq": cp["checkpoint"]["seq"],
    "hash": cp["checkpoint"]["hash"],
    "signature": cp["signature"],
    "created_at": cp["checkpoint"]["created_at"],
})
out["05-checkpoint-anchor.json"] = vektor(
    "CheckpointAnchor dari vektor checkpoint 01: bingkai membawa sig kunci layanan di samping signature kunci "
    "audit di badan; signature audit ikut ditandatangani sebagai string biasa, tanpa pengecualian apa pun",
    f05, True)

f06 = bingkai("Envelope", FRAME_06, envelope(ENV_06, "log.tail_redacted", "L0", {
    "unit": "aplikasi-contoh.service",
    "lines": 200,
    "grep": TEKS_UNICODE,
    "penanda": {"ﬁ": 1, "😀": 2, "é": 3, "z": 4},
}, NONCE_06, "2026-10-01T03:20:00Z", IDEM_06))
out["06-unicode-params.json"] = vektor(
    "Envelope L0 log.tail_redacted dengan params berisi huruf beraksen, CJK, emoji non-BMP, U+2028, U+007F, "
    "U+0001, tab, LF, kutip ganda, backslash, dan '/': hanya kutip, backslash, dan U+0000-U+001F yang di-escape "
    "(\\t \\n bentuk pendek, \\u0001 heks kecil), sisanya literal UTF-8; kunci params.penanda menguji urutan unit "
    "kode UTF-16 (😀 sebelum U+FB01, beda dari urutan byte UTF-8)",
    f06, True)

f07 = copy.deepcopy(f05)
f07["type"] = "Ack"
out["07-type-swapped.json"] = vektor(
    "Bingkai 05 dengan type diganti 'Ack' dan sig dari 05: type ikut ditandatangani, wajib tidak sah",
    f07, False)

f08 = copy.deepcopy(f01)
f08["id"] = FRAME_08_LAIN
out["08-id-swapped.json"] = vektor(
    "Bingkai 01 dengan id bingkai lain dan sig dari 01: id ikut ditandatangani, wajib tidak sah",
    f08, False)

f09 = copy.deepcopy(f01)
f09["body"]["action_key"] = "server.metrics"
out["09-body-tampered.json"] = vektor(
    "Bingkai 01 dengan action_key diganti server.metrics dan sig dari 01: body ikut ditandatangani, wajib tidak sah",
    f09, False)

f10 = bingkai("Cancel", FRAME_10, {
    "plan_hash": PLAN_HASH_10,
    "cancelled_by": {"kind": "admin", "ref": ADMIN_ID},
    "secret_values": {SECRET_ID_CANCEL: "nilai-uji-TEST-ONLY"},
})
out["10-secret-values-signed-outside-envelope.json"] = vektor(
    "Cancel yang badannya memuat anggota secret_values: ikut ditandatangani karena pengecualian hanya berlaku "
    "untuk type Envelope. Vektor ini hanya menguji aturan cakupan sig (skema pesan kelak boleh menolak anggota ini "
    "lebih dulu), sekaligus menangkap implementasi yang membuang secret_values di semua jenis pesan",
    f10, True)

f11 = copy.deepcopy(f10)
f11["body"]["secret_values"][SECRET_ID_CANCEL] = "nilai-lain-TEST-ONLY"
out["11-secret-values-tampered-outside-envelope.json"] = vektor(
    "Bingkai 10 dengan nilai secret_values diubah dan sig dari 10: di luar Envelope secret_values ditandatangani, "
    "wajib tidak sah",
    f11, False)

ALFABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
sig01 = f01["sig"]
assert len(sig01) == 88 and sig01.endswith("==")
idx = ALFABET.index(sig01[85])
assert idx & 0x0F == 0  # 64 byte -> karakter data terakhir membawa 2 bit data + 4 bit sisa nol
f12 = copy.deepcopy(f01)
f12["sig"] = sig01[:85] + ALFABET[idx | 1] + "=="
assert base64.b64decode(f12["sig"]) == base64.b64decode(sig01) and f12["sig"] != sig01
out["12-noncanonical-base64.json"] = vektor(
    "Bingkai 01 dengan sig yang byte hasil dekodenya sama tetapi bit sisa karakter terakhir tak nol "
    "(RFC 4648 §3.5): dekoder longgar menerimanya, KONTRAK §3 mewajibkan menolak karena tak kanonik",
    f12, False)

# ---------------------------------------------------------------------------
# Swa-periksa 2: vektor service-sig (pada teks yang akan ditulis, diurai ulang)
# ---------------------------------------------------------------------------

n_jcs, n_reject = swa_periksa_jcs()

teks = {}
for name, v in out.items():
    t = json.dumps(v, indent=2, ensure_ascii=False) + "\n"
    r = json.loads(t)
    fr = r["frame"]
    # Bentuk bingkai §2/§3: tepat empat anggota bertipe benar, id ULID.
    assert list(fr) == ["type", "id", "body", "sig"], name
    assert isinstance(fr["type"], str) and isinstance(fr["body"], dict) and isinstance(fr["sig"], str), name
    assert ULID_RE.fullmatch(fr["id"]), name
    # Teks bingkai harus I-JSON sah menurut pengurai ketat sendiri.
    assert urai_ketat(json.dumps(fr, ensure_ascii=False).encode("utf-8")) == fr, name
    assert r["seed_hex"] == seed.hex() and r["public_key"] == b64(pk), name
    assert r["message"].encode("utf-8") == pesan_layanan(fr), name
    assert verifikasi(r["public_key"], fr) == r["valid"], name
    if fr["type"] == "Envelope":
        b = fr["body"]
        assert b["kontrak"] == KONTRAK and ULID_RE.fullmatch(b["envelope_id"]), name
        assert len(unb64url(b["nonce"])) == 32 and b64url(unb64url(b["nonce"])) == b["nonce"], name
        assert waktu(b["issued_at"]) < waktu(b["expires_at"]) <= waktu(b["issued_at"]) + timedelta(minutes=10), name
    teks[name] = t

m = {k: v["message"] for k, v in out.items()}
assert '"params":{}' in m["01-envelope-l0-empty-params.json"]
assert '"plan_hash":null' in m["01-envelope-l0-empty-params.json"]
assert "secret_values" not in m["02-envelope-secret-values.json"]
assert "TEST-ONLY" not in m["02-envelope-secret-values.json"]
assert m["03-envelope-secret-values-replaced.json"] == m["02-envelope-secret-values.json"]
assert m["04-envelope-secret-values-absent.json"] == m["02-envelope-secret-values.json"]
assert f03["sig"] == f04["sig"] == f02["sig"]
assert set(f02["body"]["secret_values"]) == placeholder_ids(f02["body"]["params"])  # himpunan sama persis
assert placeholder["commit"] == komitmen(SALT_02, f02["body"]["secret_values"][SECRET_ID])
assert placeholder["commit"] != komitmen(SALT_02, f03["body"]["secret_values"][SECRET_ID])  # -> E_SECRET_COMMIT
assert len(unb64url(SALT_02)) == 16 and b64url(unb64url(SALT_02)) == SALT_02
assert '"secret_values":{' in m["10-secret-values-signed-outside-envelope.json"]
assert m["11-secret-values-tampered-outside-envelope.json"] != m["10-secret-values-signed-outside-envelope.json"]
assert m["06-unicode-params.json"].count("\\u0001") == 1 and "\u2028" in m["06-unicode-params.json"]
assert '"penanda":{"z":4,"é":3,"😀":2,"ﬁ":1}' in m["06-unicode-params.json"]
for a, b in [("07-type-swapped.json", "05-checkpoint-anchor.json"),
             ("08-id-swapped.json", "01-envelope-l0-empty-params.json"),
             ("09-body-tampered.json", "01-envelope-l0-empty-params.json")]:
    assert m[a] != m[b] and out[a]["frame"]["sig"] == out[b]["frame"]["sig"], a
for idv in [SERVER_ID, ADMIN_ID, SECRET_ID, SECRET_ID_CANCEL, ENV_01, ENV_02, ENV_06, IDEM_01, IDEM_02, IDEM_06]:
    assert ULID_RE.fullmatch(idv), idv

d = sys.argv[1]
os.makedirs(d, exist_ok=True)
for name, t in teks.items():
    with open(os.path.join(d, name), "w", encoding="utf-8") as f:
        f.write(t)
    print(name, "valid" if out[name]["valid"] else "tidak-sah", out[name]["frame"]["sig"])
print("public_key", b64(pk))
print("swa-periksa JCS: %d vektor jcs cocok, %d vektor jcs-reject ditolak dengan reason sama" % (n_jcs, n_reject))
