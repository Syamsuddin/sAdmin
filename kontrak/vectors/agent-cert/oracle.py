"""Oracle independen vektor CSR agen dan sertifikat klien agen, kontrak/KONTRAK.md §2 (Sertifikat & pin CA).

Sumber satu-satunya: teks kontrak/KONTRAK.md §2 (profil CA, pin `--ca-sha256`, aturan CSR, profil sertifikat klien,
aturan penerimaan gateway) dan §8 (ULID huruf kecil). Tidak membaca kode core (PHP) maupun edge (Go). Pustaka: hanya
pustaka standar Python dan `cryptography` (OpenSSL) untuk X.509 dan ECDSA.

Aturan yang diwujudkan (ringkas, teks KONTRAK yang menang):
- CSR, diperiksa berurutan (alasan = aturan pertama yang dilanggar): `size` teks <= 4096 byte; `pem` tepat satu blok
  `CERTIFICATE REQUEST` berbaris LF berisi base64 standar berpadding yang kanonik, boleh diakhiri satu LF, tanpa teks
  lain; `structure` tata letak DER (minimal, tanpa sisa) SEQUENCE {CRI, AlgorithmIdentifier, BIT STRING} dengan CRI =
  SEQUENCE {INTEGER 0, Name, SPKI, [0] atribut}; `key` SPKI byte-identik P-256 berkurva bernama, titik tak
  terkompresi; `subject` Name = 30 00; `signature` AlgorithmIdentifier byte-identik ecdsa-with-SHA256 tanpa
  parameter, BIT STRING tanpa bit sisa, tanda tangan sah atas CRI. Lolos tata letak & `key` tetapi kunci tak terurai
  pustaka = `structure`. Atribut diabaikan.
- Sertifikat klien, diperiksa berurutan: `pem` (aturan blok yang sama, label `CERTIFICATE`); `structure` tata letak DER
  SEQUENCE {TBSCertificate, AlgorithmIdentifier, BIT STRING}; `key` SPKI byte-identik seperti CSR; lalu sertifikat yang
  tak terurai pustaka X.509 = `structure`; `issuer` penerbit = subjek CA (byte DER identik); `signature` sah dengan
  kunci CA; `validity` notBefore <= now <= notAfter, inklusif, untuk sertifikat klien DAN sertifikat CA;
  `basic_constraints` ada dan CA:FALSE; `eku` ada dan memuat clientAuth; `san` tepat satu nama, berupa URI
  `sadmin://server/<ULID huruf kecil>`. Identitas = server_id dari URI itu, bukan subjek.
- Pin CA = SHA-256 atas DER sertifikat CA, 64 hex huruf kecil.

Menulis ulang <akar>/agent-csr/*.json dan <akar>/agent-cert/*.json. Kunci diturunkan dari label tetap, waktu dan
serial konstanta, dan ECDSA deterministik (RFC 6979), jadi keluarannya selalu identik byte-per-byte (diswa-periksa
dengan membangun dua kali). Oracle gagal (AssertionError) bila hasil verifikasinya sendiri tak sama dengan niat
tiap vektor, atau sertifikat sah tak sesuai profil penerbitan.

    python3 kontrak/vectors/agent-cert/oracle.py kontrak/vectors
"""
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P384_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973

CSR_MAX_BYTES = 4096
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
ECDSA_SHA256_ALG = bytes.fromhex("300a06082a8648ce3d040302")
NAMED_P256_ALG = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
P256 = {
    "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
}
AGENT_CERT_SECONDS = 7 * 86400
CA_DAYS = 3650
SAN_RE = re.compile(r"sadmin://server/([0-7][0-9a-hjkmnp-tv-z]{25})")
ULID_RE = re.compile(r"[0-7][0-9a-hjkmnp-tv-z]{25}")

T0 = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 2, 0, 0, 0, tzinfo=timezone.utc)
SERVER_ID = "01k6f3h9m2q7r4s8t0v5w1x3y6"
CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sAdmin internal CA")])


# ---------------------------------------------------------------------------
# Kunci & pembangun (deterministik)
# ---------------------------------------------------------------------------

def kunci(label, curve=None):
    curve = curve or ec.SECP256R1()
    n = P384_N if isinstance(curve, ec.SECP384R1) else P256_N
    skalar = int.from_bytes(hashlib.sha512(b"sadmin-vector/agent-cert/" + label.encode()).digest(), "big") % (n - 1) + 1
    return ec.derive_private_key(skalar, curve)


def kunci_ed25519(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"sadmin-vector/agent-cert/" + label.encode()).digest())


def tandatangani(builder, key, algoritme=None):
    if isinstance(key, Ed25519PrivateKey):
        return builder.sign(key, None)
    return builder.sign(key, algoritme or hashes.SHA256(), ecdsa_deterministic=True)


def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM).decode("ascii")


def pem_dari_der(label, der):
    isi = base64.b64encode(der).decode("ascii")
    baris = "".join(isi[i:i + 64] + "\n" for i in range(0, len(isi), 64))
    return f"-----BEGIN {label}-----\n{baris}-----END {label}-----\n"


def balik_bit_terakhir(der):
    """Rusak byte terakhir nilai tanda tangan (s ECDSA); struktur DER tetap sah."""
    return der[:-1] + bytes([der[-1] ^ 0x01])


def bangun_ca(key, sejak=T0, sampai=None, nama=CA_NAME):
    b = (x509.CertificateBuilder()
         .subject_name(nama).issuer_name(nama)
         .public_key(key.public_key())
         .serial_number(0x1CA0000000000001)
         .not_valid_before(sejak)
         .not_valid_after(sampai or sejak + timedelta(days=CA_DAYS))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                      crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    return tandatangani(b, key)


def bangun_agen(ca_key, leaf_key, serial, sejak=T0, issuer=CA_NAME, subject=None, bc="false", eku=("client",),
                san=(("uri", "sadmin://server/" + SERVER_ID),)):
    """Sertifikat klien agen menurut profil penerbitan KONTRAK §2; parameter mengubah satu aturan per vektor."""
    b = (x509.CertificateBuilder()
         .subject_name(subject or x509.Name([])).issuer_name(issuer)
         .public_key(leaf_key.public_key())
         .serial_number(serial)
         .not_valid_before(sejak)
         .not_valid_after(sejak + timedelta(seconds=AGENT_CERT_SECONDS)))
    if san is not None:
        nama = [x509.UniformResourceIdentifier(v) if t == "uri" else x509.DNSName(v) for t, v in san]
        b = b.add_extension(x509.SubjectAlternativeName(nama), critical=True)
    if bc is not None:
        b = b.add_extension(x509.BasicConstraints(ca=(bc == "true"), path_length=None), critical=True)
    b = b.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    if eku is not None:
        oid = {"client": ExtendedKeyUsageOID.CLIENT_AUTH, "server": ExtendedKeyUsageOID.SERVER_AUTH}
        b = b.add_extension(x509.ExtendedKeyUsage([oid[e] for e in eku]), critical=False)
    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    return tandatangani(b, ca_key)


def bangun_csr(key, subject=None, algoritme=None, san_dns=None):
    b = x509.CertificateSigningRequestBuilder().subject_name(subject or x509.Name([]))
    if san_dns:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]), critical=False)
    return tandatangani(b, key, algoritme)


# ---------------------------------------------------------------------------
# DER mentah: pembaca (aturan `structure`) dan penyusun (vektor yang tak bisa dibuat pustaka)
# ---------------------------------------------------------------------------

def kepala(der, offset, batas):
    """(tag, awal_isi, akhir) TLV DER bentuk minimal, tag satu byte; None bila tak sah."""
    if offset + 2 > batas or der[offset] & 0x1F == 0x1F:
        return None
    tag, panjang, awal = der[offset], der[offset + 1], offset + 2
    if panjang > 0x7F:
        n = panjang & 0x7F
        if n == 0 or n > 3 or awal + n > batas or der[awal] == 0:
            return None
        panjang = int.from_bytes(der[awal:awal + n], "big")
        if panjang < 0x80:
            return None
        awal += n
    return None if awal + panjang > batas else (tag, awal, awal + panjang)


def anak(der):
    """TLV mentah anak-anak satu SEQUENCE yang mengisi der persis; None bila tak sah."""
    luar = kepala(der, 0, len(der))
    if luar is None or luar[0] != 0x30 or luar[2] != len(der):
        return None
    hasil, i = [], luar[1]
    while i < luar[2]:
        h = kepala(der, i, luar[2])
        if h is None:
            return None
        hasil.append(der[i:h[2]])
        i = h[2]
    return hasil


def tlv(tag, isi):
    n = len(isi)
    if n < 0x80:
        return bytes([tag, n]) + isi
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(b)]) + b + isi


def seq(*isi):
    return tlv(0x30, b"".join(isi))


def integer(n):
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return tlv(0x02, b)


def bit_string(isi, sisa=0):
    return tlv(0x03, bytes([sisa]) + isi)


def titik(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def spki_eksplisit(key):
    """SPKI P-256 dengan parameter kurva eksplisit (RFC 3279 ECParameters), bukan namedCurve."""
    q = lambda n: n.to_bytes(32, "big")
    params = seq(integer(1), seq(tlv(0x06, bytes.fromhex("2a8648ce3d0101")), integer(P256["p"])),
                 seq(tlv(0x04, q(P256["p"] - 3)), tlv(0x04, q(P256["b"]))),
                 tlv(0x04, b"\x04" + q(P256["gx"]) + q(P256["gy"])), integer(P256_N), integer(1))
    return seq(seq(tlv(0x06, bytes.fromhex("2a8648ce3d0201")), params), bit_string(titik(key)))


def spki_terkompresi(key):
    return seq(NAMED_P256_ALG, bit_string(key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)))


def sign_der(key, data):
    return key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))


def csr_mentah(key, versi=0, subjek=b"\x30\x00", spki=None, alg=ECDSA_SHA256_ALG, sisa=0):
    """CSR disusun byte demi byte, ditandatangani sah atas CRI-nya (bukti kepemilikan tetap benar)."""
    spki = spki or key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    cri = seq(integer(versi), subjek, spki, tlv(0xA0, b""))
    return seq(cri, alg, bit_string(sign_der(key, cri), sisa))


def ganti_tbs(sertifikat, ca_key, indeks, isi_baru):
    """Ganti satu medan TBS (indeks setelah [0] versi) lalu tandatangani ulang dengan kunci CA."""
    der = sertifikat.public_bytes(serialization.Encoding.DER)
    tbs = anak(anak(der)[0])
    versi, medan = tbs[0], tbs[1:]
    medan[indeks] = isi_baru
    tbs_baru = seq(versi, *medan)
    return seq(tbs_baru, ECDSA_SHA256_ALG, bit_string(sign_der(ca_key, tbs_baru)))


# ---------------------------------------------------------------------------
# Verifikator (teks KONTRAK §2)
# ---------------------------------------------------------------------------

def blok_pem(teks, label):
    m = re.fullmatch(rf"-----BEGIN {label}-----\n((?:[A-Za-z0-9+/=]+\n)+)-----END {label}-----\n?", teks)
    if not m:
        return None
    isi = m.group(1).replace("\n", "")
    try:
        der = base64.b64decode(isi, validate=True)
    except binascii.Error:
        return None
    return der if der and base64.b64encode(der).decode("ascii") == isi else None


def adalah_p256(pub):
    return isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name == "secp256r1"


def adalah_spki_p256(spki):
    return len(spki) == 91 and spki.startswith(P256_SPKI_PREFIX)


def periksa_csr(teks):
    """None bila CSR diterima; selain itu alasan (aturan pertama yang dilanggar)."""
    if len(teks.encode("utf-8")) > CSR_MAX_BYTES:
        return "size"
    der = blok_pem(teks, "CERTIFICATE REQUEST")
    if der is None:
        return "pem"
    bagian = anak(der)
    info = anak(bagian[0]) if bagian is not None and len(bagian) == 3 else None
    if (bagian is None or info is None or len(info) != 4 or info[0] != b"\x02\x01\x00"
            or info[3][0] != 0xA0 or bagian[1][0] != 0x30 or bagian[2][0] != 0x03):
        return "structure"
    if not adalah_spki_p256(info[2]):
        return "key"
    try:
        pub = serialization.load_der_public_key(info[2])
    except Exception:
        return "structure"
    if info[1] != b"\x30\x00":
        return "subject"
    ttd = kepala(bagian[2], 0, len(bagian[2]))
    if bagian[1] != ECDSA_SHA256_ALG or ttd is None or ttd[1] >= ttd[2] or bagian[2][ttd[1]] != 0:
        return "signature"
    try:
        pub.verify(bagian[2][ttd[1] + 1:], bagian[0], ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return "signature"
    return None


def dalam_masa(c, now):
    return c.not_valid_before_utc <= now <= c.not_valid_after_utc


def medan_tbs(der):
    """(issuer, subject, spki) mentah, atau None bila tata letaknya bukan sertifikat X.509."""
    sertifikat = anak(der)
    if sertifikat is None or len(sertifikat) != 3 or sertifikat[1][0] != 0x30 or sertifikat[2][0] != 0x03:
        return None
    tbs = anak(sertifikat[0])
    if tbs and tbs[0][0] == 0xA0:
        tbs = tbs[1:]
    if tbs is None or len(tbs) < 6 or tbs[2][0] != 0x30 or tbs[4][0] != 0x30 or tbs[5][0] != 0x30:
        return None
    return tbs[2], tbs[4], tbs[5]


def periksa_sertifikat(ca_pem, cert_pem, now):
    """(server_id, None) bila diterima gateway; selain itu (None, alasan)."""
    ca = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
    ca_subjek = medan_tbs(ca.public_bytes(serialization.Encoding.DER))[1]
    der = blok_pem(cert_pem, "CERTIFICATE")
    if der is None:
        return None, "pem"
    medan = medan_tbs(der)
    if medan is None:
        return None, "structure"
    if not adalah_spki_p256(medan[2]):
        return None, "key"
    try:
        c = x509.load_der_x509_certificate(der)
        c.public_key()
        c.not_valid_before_utc, c.not_valid_after_utc
        ekstensi = list(c.extensions)
    except Exception:
        return None, "structure"
    if medan[0] != ca_subjek:
        return None, "issuer"
    try:
        ca.public_key().verify(c.signature, c.tbs_certificate_bytes, ec.ECDSA(c.signature_hash_algorithm))
    except InvalidSignature:
        return None, "signature"
    if not (dalam_masa(c, now) and dalam_masa(ca, now)):
        return None, "validity"
    per_jenis = {type(e.value): e.value for e in ekstensi}
    bc = per_jenis.get(x509.BasicConstraints)
    if bc is None or bc.ca:
        return None, "basic_constraints"
    eku = per_jenis.get(x509.ExtendedKeyUsage)
    if eku is None or ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        return None, "eku"
    san = per_jenis.get(x509.SubjectAlternativeName)
    nama = list(san) if san is not None else []
    if len(nama) != 1 or not isinstance(nama[0], x509.UniformResourceIdentifier):
        return None, "san"
    m = SAN_RE.fullmatch(nama[0].value)
    if not m:
        return None, "san"
    return m.group(1), None


def sidik_jari(ca_pem):
    return hashlib.sha256(x509.load_pem_x509_certificate(ca_pem.encode("ascii")).public_bytes(serialization.Encoding.DER)).hexdigest()


# ---------------------------------------------------------------------------
# Vektor
# ---------------------------------------------------------------------------

def bangun_semua():
    ca_key = kunci("ca")
    ca = pem(bangun_ca(ca_key))
    agen = kunci("agen")
    lain = kunci("ca-lain")
    ca_basi_key = kunci("ca-kedaluwarsa")
    ca_basi = pem(bangun_ca(ca_basi_key, sejak=T0 - timedelta(days=30), sampai=T0 + timedelta(hours=12)))
    sah = bangun_agen(ca_key, agen, 0x5AD0000000000001)
    detik = timedelta(seconds=1)
    batas_akhir = T0 + timedelta(seconds=AGENT_CERT_SECONDS)
    dns_banyak = [f"host-{i:03d}.contoh.invalid" for i in range(120)]

    csr_sah = bangun_csr(agen)
    csr_sah_der = csr_sah.public_bytes(serialization.Encoding.DER)
    # Vektor tanpa padding butuh DER yang panjangnya bukan kelipatan 3 (hanya itu yang ber-padding).
    calon_csr = [csr_sah_der] + [bangun_csr(agen, san_dns=["x" * n + ".contoh.invalid"]).public_bytes(serialization.Encoding.DER)
                                 for n in range(1, 4)]
    csr_berpadding = next(d for d in calon_csr if len(d) % 3 != 0)
    sertifikat_berpadding = next(d for d in (bangun_agen(ca_key, agen, 0x5AD0000000000100 + i).public_bytes(serialization.Encoding.DER)
                                             for i in range(16)) if len(d) % 3 != 0)
    csr_batas = csr_tepat(agen, CSR_MAX_BYTES)

    csr = {
        "01-valid.json": ("CSR sah: ECDSA P-256, subjek kosong, tanpa atribut", pem(csr_sah), None),
        "02-extension-request-ignored.json": (
            "Permintaan ekstensi (SAN DNS) diabaikan, CSR tetap diterima; core tak pernah menyalinnya",
            pem(bangun_csr(agen, san_dns=["agen.contoh.invalid"])), None),
        "03-subject-not-empty.json": (
            "Subjek tak kosong ditolak: subjek CSR akan tersalin ke sertifikat",
            pem(bangun_csr(agen, subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agen")]))), "subject"),
        "04-key-p384.json": ("Kunci ECDSA P-384 ditolak", pem(bangun_csr(kunci("agen-p384", ec.SECP384R1()))), "key"),
        "05-key-ed25519.json": ("Kunci Ed25519 ditolak", pem(bangun_csr(kunci_ed25519("agen-ed25519"))), "key"),
        "06-signature-tampered.json": (
            "Tanda tangan CSR dirusak (DER tetap sah): bukti kepemilikan gagal",
            pem_dari_der("CERTIFICATE REQUEST", balik_bit_terakhir(csr_sah_der)), "signature"),
        "07-signature-sha384.json": (
            "Tanda tangan ecdsa-with-SHA384 ditolak: hanya ecdsa-with-SHA256",
            pem(bangun_csr(agen, algoritme=hashes.SHA384())), "signature"),
        "08-two-blocks.json": ("Dua blok PEM ditolak", pem(csr_sah) + pem(csr_sah), "pem"),
        "09-trailing-text.json": ("Teks setelah blok PEM ditolak", pem(csr_sah) + "x\n", "pem"),
        "10-not-pem.json": ("DER base64 tanpa pembungkus PEM ditolak", base64.b64encode(csr_sah_der).decode("ascii") + "\n", "pem"),
        "11-crlf.json": ("Akhir baris CRLF ditolak: PEM wajib berbaris LF", pem(csr_sah).replace("\n", "\r\n"), "pem"),
        "12-structure.json": (
            "PEM sah berisi DER yang bukan CSR ditolak",
            pem_dari_der("CERTIFICATE REQUEST", bytes.fromhex("3003020100")), "structure"),
        "14-key-explicit-curve.json": (
            "Kunci P-256 berparameter kurva eksplisit ditolak (bukan namedCurve; Go crypto/x509 menolaknya)",
            pem_dari_der("CERTIFICATE REQUEST", csr_mentah(agen, spki=spki_eksplisit(agen))), "key"),
        "15-key-compressed-point.json": (
            "Kunci P-256 bertitik terkompresi ditolak (Go crypto/x509 menolaknya)",
            pem_dari_der("CERTIFICATE REQUEST", csr_mentah(agen, spki=spki_terkompresi(agen))), "key"),
        "16-version-1.json": (
            "CSR versi selain 0 ditolak sebagai struktur, meski bertanda tangan sah",
            pem_dari_der("CERTIFICATE REQUEST", csr_mentah(agen, versi=1)), "structure"),
        "17-unpadded-base64.json": (
            "Base64 tanpa padding ditolak: wajib berpadding dan kanonik",
            tanpa_padding("CERTIFICATE REQUEST", csr_berpadding), "pem"),
        "18-signature-algorithm-null-params.json": (
            "AlgorithmIdentifier ecdsa-with-SHA256 berparameter NULL ditolak: parameter wajib absen",
            pem_dari_der("CERTIFICATE REQUEST", csr_mentah(agen, alg=seq(tlv(0x06, bytes.fromhex("2a8648ce3d040302")), b"\x05\x00"))),
            "signature"),
        "19-signature-unused-bits.json": (
            "BIT STRING tanda tangan dengan bit sisa ditolak",
            pem_dari_der("CERTIFICATE REQUEST", csr_mentah(agen, sisa=1)), "signature"),
        "20-subject-empty-rdn.json": (
            "Subjek berisi RDN kosong bukan subjek kosong",
            pem_dari_der("CERTIFICATE REQUEST", csr_mentah(agen, subjek=seq(tlv(0x31, b"")))), "subject"),
        "21-non-minimal-length.json": (
            "Panjang DER tak minimal (bentuk panjang berawalan nol) ditolak sebagai struktur",
            pem_dari_der("CERTIFICATE REQUEST", panjang_tak_minimal(csr_sah_der)), "structure"),
        "22-no-trailing-lf.json": ("Tanpa LF penutup tetap diterima", pem(csr_sah).rstrip("\n"), None),
        "23-two-trailing-lf.json": ("Dua LF penutup ditolak", pem(csr_sah) + "\n", "pem"),
        "24-pem-header.json": (
            "Header PEM (RFC 1421) ditolak",
            pem(csr_sah).replace("-----\n", "-----\nComment: agen\n", 1), "pem"),
        "25-size-limit-exact.json": ("Tepat 4096 byte diterima", csr_batas, None),
        "26-size-limit-plus-one.json": (
            "4097 byte ditolak karena ukuran, meski pelanggaran lain (dua LF) juga ada: ukuran diperiksa lebih dulu",
            csr_batas + "\n", "size"),
        "27-order-key-before-subject.json": (
            "Kunci P-384 dan subjek tak kosong sekaligus: alasan = key (urutan aturan)",
            pem(bangun_csr(kunci("agen-p384", ec.SECP384R1()), subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agen")]))),
            "key"),
        "13-oversized.json": (
            "CSR lebih dari 4096 byte ditolak sebelum diurai (meski sah)",
            pem(bangun_csr(agen, san_dns=dns_banyak)), "size"),
    }

    sertifikat = {
        "01-valid.json": ("Sertifikat klien sah: identitas dari SAN URI", ca, pem(sah), NOW, SERVER_ID, None),
        "02-valid-at-not-before.json": ("Batas notBefore inklusif", ca, pem(sah), T0, SERVER_ID, None),
        "03-valid-at-not-after.json": ("Batas notAfter inklusif", ca, pem(sah), batas_akhir, SERVER_ID, None),
        "04-expired.json": ("Satu detik setelah notAfter ditolak", ca, pem(sah), batas_akhir + detik, None, "validity"),
        "05-not-yet-valid.json": ("Satu detik sebelum notBefore ditolak", ca, pem(sah), T0 - detik, None, "validity"),
        "06-ca-expired.json": (
            "Sertifikat CA kedaluwarsa ditolak meski sertifikat klien masih berlaku",
            ca_basi, pem(bangun_agen(ca_basi_key, agen, 0x5AD0000000000006)), NOW, None, "validity"),
        "07-other-ca-key.json": (
            "Ditandatangani kunci lain dengan nama penerbit yang sama ditolak",
            ca, pem(bangun_agen(lain, agen, 0x5AD0000000000007)), NOW, None, "signature"),
        "08-issuer-mismatch.json": (
            "Ditandatangani kunci CA tetapi penerbit bukan subjek CA ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD0000000000008,
                                issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sAdmin internal CA 2")]))),
            NOW, None, "issuer"),
        "09-signature-tampered.json": (
            "Tanda tangan dirusak (DER tetap sah) ditolak",
            ca, pem_dari_der("CERTIFICATE", balik_bit_terakhir(sah.public_bytes(serialization.Encoding.DER))),
            NOW, None, "signature"),
        "10-key-p384.json": (
            "Kunci klien P-384 ditolak",
            ca, pem(bangun_agen(ca_key, kunci("agen-p384", ec.SECP384R1()), 0x5AD000000000000A)), NOW, None, "key"),
        "11-ca-true.json": (
            "basicConstraints CA:TRUE ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD000000000000B, bc="true")), NOW, None, "basic_constraints"),
        "12-no-basic-constraints.json": (
            "Tanpa basicConstraints ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD000000000000C, bc=None)), NOW, None, "basic_constraints"),
        "13-eku-server-only.json": (
            "extendedKeyUsage tanpa clientAuth ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD000000000000D, eku=("server",))), NOW, None, "eku"),
        "14-no-eku.json": (
            "Tanpa extendedKeyUsage ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD000000000000E, eku=None)), NOW, None, "eku"),
        "15-no-san.json": (
            "Tanpa subjectAltName ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD000000000000F, san=None)), NOW, None, "san"),
        "16-two-uris.json": (
            "Dua URI di SAN ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD0000000000010,
                                san=(("uri", "sadmin://server/" + SERVER_ID), ("uri", "sadmin://server/01k6f3h9m2q7r4s8t0v5w1x3y7")))),
            NOW, None, "san"),
        "17-uri-and-dns.json": (
            "URI sah ditambah nama DNS ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD0000000000011,
                                san=(("uri", "sadmin://server/" + SERVER_ID), ("dns", "agen.contoh.invalid")))),
            NOW, None, "san"),
        "18-uppercase-ulid.json": (
            "ULID berhuruf besar ditolak (KONTRAK §8)",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD0000000000012, san=(("uri", "sadmin://server/" + SERVER_ID.upper()),))),
            NOW, None, "san"),
        "19-other-scheme.json": (
            "Skema URI lain ditolak",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD0000000000013, san=(("uri", "spiffe://server/" + SERVER_ID),))),
            NOW, None, "san"),
        "20-subject-ignored.json": (
            "Subjek tak kosong tak dipakai sebagai identitas; identitas tetap dari SAN URI",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD0000000000014,
                                subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "01k6f3h9m2q7r4s8t0v5w1x3y7")]))),
            NOW, SERVER_ID, None),
        "21-not-pem.json": (
            "DER base64 tanpa pembungkus PEM ditolak",
            ca, base64.b64encode(sah.public_bytes(serialization.Encoding.DER)).decode("ascii") + "\n", NOW, None, "pem"),
        "22-structure.json": (
            "PEM sah berisi DER yang bukan sertifikat ditolak",
            ca, pem_dari_der("CERTIFICATE", bytes.fromhex("3003020100")), NOW, None, "structure"),
        "23-key-explicit-curve.json": (
            "Kunci P-256 berparameter kurva eksplisit ditolak (Go crypto/x509 tak bisa mengurainya)",
            ca, pem_dari_der("CERTIFICATE", ganti_tbs(sah, ca_key, 5, spki_eksplisit(agen))), NOW, None, "key"),
        "24-key-compressed-point.json": (
            "Kunci P-256 bertitik terkompresi ditolak (Go crypto/x509 tak bisa mengurainya)",
            ca, pem_dari_der("CERTIFICATE", ganti_tbs(sah, ca_key, 5, spki_terkompresi(agen))), NOW, None, "key"),
        "25-unparsable-time.json": (
            "Waktu berlaku yang tak terurai (bulan 13) ditolak sebagai struktur",
            ca, pem_dari_der("CERTIFICATE", ganti_tbs(sah, ca_key, 3, seq(tlv(0x17, b"261301000000Z"), tlv(0x17, b"261008000000Z")))),
            NOW, None, "structure"),
        "26-order-key-before-validity.json": (
            "Kunci P-384 dan kedaluwarsa sekaligus: alasan = key (urutan aturan)",
            ca, pem(bangun_agen(ca_key, kunci("agen-p384", ec.SECP384R1()), 0x5AD000000000001A)), batas_akhir + detik, None, "key"),
        "27-order-basic-constraints-before-eku.json": (
            "CA:TRUE dan tanpa extendedKeyUsage sekaligus: alasan = basic_constraints (urutan aturan)",
            ca, pem(bangun_agen(ca_key, agen, 0x5AD000000000001B, bc="true", eku=None)), NOW, None, "basic_constraints"),
        "28-unpadded-base64.json": (
            "Base64 tanpa padding ditolak: wajib berpadding dan kanonik",
            ca, tanpa_padding("CERTIFICATE", sertifikat_berpadding), NOW, None, "pem"),
    }
    return ca_key, ca, sah, csr, sertifikat


def tanpa_padding(label, der):
    teks = pem_dari_der(label, der)
    assert "=" in teks, label
    return teks.replace("=", "")


def panjang_tak_minimal(der):
    """Kodekan ulang panjang SEQUENCE terluar dengan satu byte nol berlebih di depan (bentuk panjang tak minimal)."""
    h = kepala(der, 0, len(der))
    n = h[2] - h[1]
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x30, 0x80 | (len(b) + 1), 0]) + b + der[h[1]:]


def csr_tepat(key, ukuran):
    """CSR sah yang teks PEM-nya tepat `ukuran` byte (boleh tanpa LF penutup), lewat panjang nama DNS pengisi."""
    for banyak in range(100, 125):
        dasar = [f"host-{i:03d}.contoh.invalid" for i in range(banyak)]
        for n in range(1, 64):
            teks = pem(bangun_csr(key, san_dns=dasar + ["x" * n + ".contoh.invalid"]))
            if len(teks) == ukuran:
                return teks
            if len(teks) == ukuran + 1:
                return teks.rstrip("\n")
            if len(teks) > ukuran + 1:
                break
    raise AssertionError("tak menemukan CSR sebesar batas")


def stempel(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def keluaran():
    ca_key, ca, sah, csr, sertifikat = bangun_semua()
    out = {"agent-csr": {}, "agent-cert": {}}
    for nama, (desc, teks, alasan) in csr.items():
        hasil = periksa_csr(teks)
        assert hasil == alasan, (nama, hasil, alasan)
        out["agent-csr"][nama] = {"description": desc, "csr_pem": teks, "valid": hasil is None, "reason": hasil}
    for nama, (desc, ca_pem, cert_pem, now, server_id, alasan) in sertifikat.items():
        sid, hasil = periksa_sertifikat(ca_pem, cert_pem, now)
        assert (sid, hasil) == (server_id, alasan), (nama, sid, hasil)
        out["agent-cert"][nama] = {
            "description": desc, "ca_pem": ca_pem, "ca_sha256": sidik_jari(ca_pem), "cert_pem": cert_pem,
            "now": stempel(now), "valid": hasil is None, "server_id": sid, "reason": hasil,
        }
    return ca_key, ca, sah, out


def swa_periksa_profil(ca_key, ca_pem, sah):
    """Sertifikat 01 wajib persis profil penerbitan KONTRAK §2; CA wajib persis profil CA."""
    ca = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
    assert ca.subject == ca.issuer == CA_NAME and adalah_p256(ca.public_key())
    assert ca.not_valid_after_utc - ca.not_valid_before_utc == timedelta(days=CA_DAYS)
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).critical
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(ca=True, path_length=0)
    ku = ca.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical and ku.value.key_cert_sign and ku.value.crl_sign and not ku.value.digital_signature
    assert ca.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256

    assert sah.version == x509.Version.v3 and len(sah.subject) == 0
    assert 0 < sah.serial_number <= 2**63 - 1
    assert sah.not_valid_after_utc - sah.not_valid_before_utc == timedelta(seconds=AGENT_CERT_SECONDS)
    assert sah.signature_algorithm_oid == SignatureAlgorithmOID.ECDSA_WITH_SHA256
    eks = {e.oid._name: e for e in sah.extensions}
    assert set(eks) == {"subjectAltName", "basicConstraints", "keyUsage", "extendedKeyUsage", "authorityKeyIdentifier"}, set(eks)
    assert eks["subjectAltName"].critical and list(eks["subjectAltName"].value) == [x509.UniformResourceIdentifier("sadmin://server/" + SERVER_ID)]
    assert eks["basicConstraints"].critical and eks["basicConstraints"].value.ca is False
    assert eks["keyUsage"].critical and eks["keyUsage"].value.digital_signature and not eks["keyUsage"].value.key_cert_sign
    assert list(eks["extendedKeyUsage"].value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert eks["authorityKeyIdentifier"].value.key_identifier == x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()).digest
    assert ULID_RE.fullmatch(SERVER_ID)


ca_key, ca_pem, sah, out = keluaran()
swa_periksa_profil(ca_key, ca_pem, sah)
assert keluaran()[3] == out, "Keluaran oracle tidak deterministik."
assert len(sidik_jari(ca_pem)) == 64 and sidik_jari(ca_pem) == sidik_jari(ca_pem).lower()
assert all(v["ca_sha256"] == sidik_jari(ca_pem) for n, v in out["agent-cert"].items() if n != "06-ca-expired.json")
assert len(out["agent-csr"]["13-oversized.json"]["csr_pem"].encode()) > CSR_MAX_BYTES
assert x509.load_pem_x509_csr(out["agent-csr"]["13-oversized.json"]["csr_pem"].encode()).is_signature_valid

# Vektor satu-pelanggaran yang disusun byte demi byte tetap bertanda tangan sah: yang dilanggar hanya aturan yang dituju.
agen_pub = kunci("agen").public_key()
for nama in ["14-key-explicit-curve.json", "15-key-compressed-point.json", "16-version-1.json",
             "18-signature-algorithm-null-params.json", "20-subject-empty-rdn.json"]:
    bagian = anak(blok_pem(out["agent-csr"][nama]["csr_pem"], "CERTIFICATE REQUEST"))
    agen_pub.verify(bagian[2][3:] if bagian[2][1] < 0x80 else bagian[2][4:], bagian[0], ec.ECDSA(hashes.SHA256()))
for nama in ["23-key-explicit-curve.json", "24-key-compressed-point.json", "25-unparsable-time.json"]:
    bagian = anak(blok_pem(out["agent-cert"][nama]["cert_pem"], "CERTIFICATE"))
    ca_key.public_key().verify(bagian[2][3:] if bagian[2][1] < 0x80 else bagian[2][4:], bagian[0], ec.ECDSA(hashes.SHA256()))
assert len(out["agent-csr"]["25-size-limit-exact.json"]["csr_pem"].encode()) == CSR_MAX_BYTES
assert len(out["agent-csr"]["26-size-limit-plus-one.json"]["csr_pem"].encode()) == CSR_MAX_BYTES + 1

akar = sys.argv[1]
for sub, vektor in out.items():
    d = os.path.join(akar, sub)
    os.makedirs(d, exist_ok=True)
    for nama, v in vektor.items():
        with open(os.path.join(d, nama), "w", encoding="utf-8") as f:
            f.write(json.dumps(v, indent=2, ensure_ascii=False) + "\n")
        print(sub, nama, "sah" if v["valid"] else "tolak:" + v["reason"])
print("ca_sha256", sidik_jari(ca_pem))
