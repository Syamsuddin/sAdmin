"""Oracle independen vektor CSR agen dan sertifikat klien agen, kontrak/KONTRAK.md §2 (Sertifikat & pin CA).

Sumber satu-satunya: teks kontrak/KONTRAK.md §2 (profil CA, pin `--ca-sha256`, aturan CSR, profil sertifikat klien,
aturan penerimaan gateway) dan §8 (ULID huruf kecil). Tidak membaca kode core (PHP) maupun edge (Go). Pustaka: hanya
pustaka standar Python dan `cryptography` (OpenSSL) untuk X.509 dan ECDSA.

Aturan yang diwujudkan (ringkas, teks KONTRAK yang menang):
- CSR, diperiksa berurutan (alasan = aturan pertama yang dilanggar): `size` teks <= 4096 byte; `pem` tepat satu blok
  `CERTIFICATE REQUEST` berbaris LF, boleh diakhiri satu LF, tanpa teks lain; `structure` DER CSR yang sah; `key`
  ECDSA P-256; `subject` kosong; `signature` `ecdsa-with-SHA256` yang sah (bukti kepemilikan). Atribut diabaikan.
- Sertifikat klien, diperiksa berurutan: `pem` tepat satu blok `CERTIFICATE`; `structure` DER sertifikat yang sah;
  `issuer` penerbit = subjek CA (byte DER identik); `signature` sah dengan kunci CA; `validity` notBefore <= now <=
  notAfter, inklusif, untuk sertifikat klien DAN sertifikat CA; `key` ECDSA P-256; `basic_constraints` ada dan
  CA:FALSE; `eku` ada dan memuat clientAuth; `san` tepat satu nama, berupa URI `sadmin://server/<ULID huruf kecil>`.
  Identitas = server_id dari URI itu, bukan subjek.
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
# Verifikator (teks KONTRAK §2)
# ---------------------------------------------------------------------------

def blok_pem(teks, label):
    m = re.fullmatch(rf"-----BEGIN {label}-----\n((?:[A-Za-z0-9+/=]+\n)+)-----END {label}-----\n?", teks)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1).replace("\n", ""), validate=True)
    except binascii.Error:
        return None


def adalah_p256(pub):
    return isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name == "secp256r1"


def periksa_csr(teks):
    """None bila CSR diterima; selain itu alasan (aturan pertama yang dilanggar)."""
    if len(teks.encode("utf-8")) > CSR_MAX_BYTES:
        return "size"
    der = blok_pem(teks, "CERTIFICATE REQUEST")
    if der is None:
        return "pem"
    try:
        csr = x509.load_der_x509_csr(der)
        pub = csr.public_key()
    except Exception:
        return "structure"
    if not adalah_p256(pub):
        return "key"
    if len(csr.subject) != 0:
        return "subject"
    if csr.signature_algorithm_oid != SignatureAlgorithmOID.ECDSA_WITH_SHA256 or not csr.is_signature_valid:
        return "signature"
    return None


def dalam_masa(c, now):
    return c.not_valid_before_utc <= now <= c.not_valid_after_utc


def periksa_sertifikat(ca_pem, cert_pem, now):
    """(server_id, None) bila diterima gateway; selain itu (None, alasan)."""
    ca = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
    der = blok_pem(cert_pem, "CERTIFICATE")
    if der is None:
        return None, "pem"
    try:
        c = x509.load_der_x509_certificate(der)
        pub = c.public_key()
    except Exception:
        return None, "structure"
    if c.issuer.public_bytes() != ca.subject.public_bytes():
        return None, "issuer"
    try:
        ca.public_key().verify(c.signature, c.tbs_certificate_bytes, ec.ECDSA(c.signature_hash_algorithm))
    except InvalidSignature:
        return None, "signature"
    if not (dalam_masa(c, now) and dalam_masa(ca, now)):
        return None, "validity"
    if not adalah_p256(pub):
        return None, "key"
    try:
        if c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return None, "basic_constraints"
    except x509.ExtensionNotFound:
        return None, "basic_constraints"
    try:
        if ExtendedKeyUsageOID.CLIENT_AUTH not in c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            return None, "eku"
    except x509.ExtensionNotFound:
        return None, "eku"
    try:
        nama = list(c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return None, "san"
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
    }
    return ca_key, ca, sah, csr, sertifikat


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

akar = sys.argv[1]
for sub, vektor in out.items():
    d = os.path.join(akar, sub)
    os.makedirs(d, exist_ok=True)
    for nama, v in vektor.items():
        with open(os.path.join(d, nama), "w", encoding="utf-8") as f:
            f.write(json.dumps(v, indent=2, ensure_ascii=False) + "\n")
        print(sub, nama, "sah" if v["valid"] else "tolak:" + v["reason"])
print("ca_sha256", sidik_jari(ca_pem))
