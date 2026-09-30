# 21 — Security Rules (agen & gateway)

Pemilik aturan keamanan edge — terutama **siapa yang dipercaya agen**. Level risiko: `../catalog/CATALOG.md` §1. Kripto & format: `../kontrak/KONTRAK.md`. Peran manusia: `../core/docs/05_USER_ROLE.md`.

## Rantai kepercayaan agen
| Sumber | Dipercaya untuk | Disematkan kapan |
|---|---|---|
| CA internal (`tls/ca.crt`) | identitas gateway | enrolment (sidik jari dicocokkan `--ca-sha256`) |
| Kunci layanan core | L0/L1, `Cancel`, `CheckpointAnchor` (kunci audit) | enrolment |
| Roster passkey | L2/L3, roster & kebijakan baru | enrolment; sidik jari dicocokkan admin di terminal & console |
| Kebijakan | aksi yang dikenal, risiko, jeda, jumlah tanda tangan, kanal notifikasi | enrolment; perubahan = passkey + jeda 24 jam |
| Kunci rilis | pembaruan biner agen | tertanam di biner saat build |
| Root lokal | mode darurat, `roster-reset` dengan kunci pemulihan | — (root sudah menguasai server) |

Control plane yang dibobol **tidak** dapat: menjalankan L2/L3, menurunkan risiko, memperpendek jeda, mengganti roster tanpa jeda 24 jam + notifikasi, atau mengganti biner agen dengan biner tak bertanda tangan.

## Verifikasi
Urutan & kode galat: docs/06_BUSINESS_PROCESS.md E1. Tambahan: pembanding konstan-waktu untuk hash/HMAC; `sign_count` WebAuthn dicatat (peringatan bila mundur, bukan penolakan — banyak passkey sinkron selalu 0).

## Eksekusi aman
- Proses turunan lewat `internal/sysexec`: argumen slice, lingkungan minimal (`PATH` tetap, `LANG=C.UTF-8`), batas waktu wajib, keluaran dibatasi 1 MiB.
- Build aplikasi (`app.build`, `app.migrate`) berjalan sebagai user situs via `systemd-run --uid=<user> -p CPUQuota=… -p MemoryMax=… -p RuntimeMaxSec=…`.
- Ekstraksi ZIP: tolak path absolut, `..`, symlink/hardlink keluar, rasio > 20×, ukuran > batas; ekstrak ke direktori rilis milik user situs.
- Berkas yang ditulis agen: atomik (tulis sementara → `fsync` → rename), izin eksplisit.
- Konten repo, ZIP, log = data tak tepercaya; tak pernah dievaluasi sebagai konfigurasi agen.

## Jaringan
- Agen hanya koneksi keluar; tak ada port dengar.
- Gateway: TLS 1.3 saja; sertifikat klien wajib kecuali endpoint enrolment (token sekali pakai 15 menit, batas laju 5/menit/IP); batas laju pesan per agen; ukuran bingkai ≤ 1 MiB.
- Socket UDS gateway↔core: grup `sadmin`, mode 0660, HMAC tiap permintaan.

## Rahasia di server
Kunci klien mTLS dan `secrets/notifier.json` mode 0600 root; nilai `secret_values` hanya di memori selama eksekusi, dan terenkripsi (kunci lokal agen) bila harus menunggu jeda L3.

## Audit lokal
Setiap amplop (diterima/ditolak), jeda, timer, mode darurat, pembaruan kepercayaan, dan pembaruan agen tercatat sebelum/bersamaan efeknya; `+a`; checkpoint core disimpan di `anchors-*.jsonl`; `sadmin-agent audit verify` memeriksa rantai.
