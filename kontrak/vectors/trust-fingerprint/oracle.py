"""Oracle independen vektor sidik jari kepercayaan enrolment, kontrak/KONTRAK.md §3 ("Dokumen kepercayaan awal
dan sidik jari kepercayaan").

Sumber satu-satunya: teks kontrak/KONTRAK.md (§3 sidik jari dan bentuk dokumen, §8 ULID), plus aturan JCS
RFC 8785. Tidak membaca kode core (PHP) maupun edge (Go). Pustaka: hanya pustaka standar Python.

Semua nilai dalam vektor ini ASCII (hex, base64, ULID, nama anggota), sehingga JCS cukup ditulis dengan
json.dumps(sort_keys, tanpa spasi, ensure_ascii=False): urutan kode UTF-16 sama dengan urutan kode ASCII.
Oracle memeriksa itu dan gagal (AssertionError) bila ada nilai non-ASCII.

Aturan yang diwujudkan:
- pesan = byte ASCII `sadmin-trust/1` + LF + JCS objek tepat lima anggota
  {roster_hash, policy_hash, service_pubkey, audit_pubkey, server_id};
- roster_hash dan policy_hash = SHA-256 JCS dokumen, 64 hex huruf kecil;
- service_pubkey dan audit_pubkey = base64 standar berpadding kanonik, 32 byte (44 karakter);
- server_id = ULID huruf kecil (KONTRAK §8);
- sidik jari = SHA-256 pesan, 64 hex huruf kecil; tampilan = 16 kelompok 4 karakter, 8 per baris, dua baris
  dipisah satu LF.

Menulis ulang *.json di direktori tujuan; keluarannya deterministik.

    python3 kontrak/vectors/trust-fingerprint/oracle.py kontrak/vectors/trust-fingerprint
"""
import base64
import binascii
import hashlib
import json
import os
import re
import sys

PREFIX = b"sadmin-trust/1\n"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ULID = re.compile(r"^[0-7][0-9a-hjkmnp-tv-z]{25}$")
MEMBERS = ["roster_hash", "policy_hash", "service_pubkey", "audit_pubkey", "server_id"]


def jcs(value):
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert text.isascii(), "oracle ini hanya untuk nilai ASCII"
    return text.encode("ascii")


def pubkey_ok(text):
    """32 byte, base64 standar berpadding, kanonik: mengodekan ulang hasil dekode harus identik."""
    if not isinstance(text, str) or len(text) != 44:
        return False
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode("ascii") == text


def periksa(inp):
    """Alasan penolakan (string) atau None bila masukan sah."""
    if sorted(inp.keys()) != sorted(MEMBERS):
        return "members"
    for k in ("roster_hash", "policy_hash"):
        if not isinstance(inp[k], str) or not HEX64.match(inp[k]):
            return k
    for k in ("service_pubkey", "audit_pubkey"):
        if not pubkey_ok(inp[k]):
            return k
    if not isinstance(inp["server_id"], str) or not ULID.match(inp["server_id"]):
        return "server_id"
    return None


def sidik_jari(inp):
    message = PREFIX + jcs(inp)
    fp = hashlib.sha256(message).hexdigest()
    groups = [fp[i : i + 4] for i in range(0, 64, 4)]
    display = " ".join(groups[:8]) + "\n" + " ".join(groups[8:])
    return message.decode("ascii"), fp, display


def b64(seed_text):
    return base64.b64encode(hashlib.sha256(seed_text.encode()).digest()).decode("ascii")


ROSTER = {
    "kontrak": "0.6",
    "version": 1,
    "tenant_id": "01m3r24gd00z3k173jj1zjgjr7",
    "rp_id": "sadmin.instansi.go.id",
    "origin": "https://sadmin.instansi.go.id",
    "credentials": [
        {"credential_id": "AQIDBAUGBwg", "public_key_cose": "pQECAyYgASFYIA", "alg": -7, "admin_id": "01m3r24gd00z3k173jj1zjgjs0"},
        {"credential_id": "CQoLDA0ODxA", "public_key_cose": "owEBAzgAIAI", "alg": -8, "admin_id": "01m3r24gd00z3k173jj1zjgjs0"},
    ],
}
POLICY = {
    "kontrak": "0.6",
    "version": 1,
    "tenant_id": "01m3r24gd00z3k173jj1zjgjr7",
    "actions": [
        {"key": "backup.list", "version": 1, "risk": "L0"},
        {"key": "server.inventory", "version": 1, "risk": "L0"},
    ],
    "approvals_required": {"L2": 1, "L3": 1},
    "l3_delay_seconds": 900,
}

SERVER = "01m3r24gd00z3k173jj1zjgjs1"
BASE = {
    "roster_hash": hashlib.sha256(jcs(ROSTER)).hexdigest(),
    "policy_hash": hashlib.sha256(jcs(POLICY)).hexdigest(),
    "service_pubkey": b64("service"),
    "audit_pubkey": b64("audit"),
    "server_id": SERVER,
}


def vektor(deskripsi, inp, **tambahan):
    alasan = periksa(inp)
    out = {"description": deskripsi, "input": inp}
    out.update(tambahan)
    if alasan is None:
        message, fp, display = sidik_jari(inp)
        out.update({"message": message, "fingerprint": fp, "display": display, "valid": True})
    else:
        out.update({"valid": False, "reason": alasan})
    return out


def ubah(**kw):
    d = dict(BASE)
    d.update(kw)
    return d


def main(target):
    fp_dasar = sidik_jari(BASE)[1]
    kasus = {
        "01-baseline.json": vektor(
            "Kasus dasar; dokumen roster/policy ikut sebagai bukti asal hash (JCS dokumen -> SHA-256)",
            BASE,
            roster_document=ROSTER,
            policy_document=POLICY,
        ),
        "02-other-server.json": vektor("server_id lain menghasilkan sidik jari lain", ubah(server_id="01m3r24gd00z3k173jj1zjgjs2")),
        "03-swapped-pubkeys.json": vektor("service_pubkey dan audit_pubkey bertukar menghasilkan sidik jari lain", ubah(service_pubkey=b64("audit"), audit_pubkey=b64("service"))),
        "04-zero-hashes.json": vektor("Hash nol di batas bawah", ubah(roster_hash="0" * 64, policy_hash="f" * 64)),
        "05-uppercase-hash.json": vektor("Hash berhuruf besar ditolak", ubah(roster_hash=BASE["roster_hash"].upper())),
        "06-noncanonical-base64.json": vektor("base64 tak kanonik (bit sisa karakter terakhir bukan nol) ditolak", ubah(service_pubkey=BASE["service_pubkey"][:-2] + "F=")),
        "07-short-pubkey.json": vektor("Kunci publik 31 byte ditolak", ubah(audit_pubkey=base64.b64encode(b"\x01" * 31).decode("ascii"))),
        "08-uppercase-ulid.json": vektor("server_id berhuruf besar ditolak", ubah(server_id=SERVER.upper())),
        "09-extra-member.json": vektor("Anggota tambahan ditolak", dict(BASE, extra="x")),
        "10-missing-member.json": vektor("Anggota hilang ditolak", {k: v for k, v in BASE.items() if k != "audit_pubkey"}),
    }
    # Swa-periksa: kasus yang sah harus berbeda satu sama lain, dan kasus "menolak" tak punya sidik jari.
    sah = [v["fingerprint"] for v in kasus.values() if v["valid"]]
    assert len(sah) == len(set(sah)) == 4, "sidik jari sah harus unik"
    assert kasus["01-baseline.json"]["fingerprint"] == fp_dasar
    assert kasus["06-noncanonical-base64.json"]["valid"] is False and kasus["06-noncanonical-base64.json"]["reason"] == "service_pubkey"
    for nama, isi in kasus.items():
        with open(os.path.join(target, nama), "w", encoding="utf-8") as f:
            json.dump(isi, f, ensure_ascii=False, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__)))
