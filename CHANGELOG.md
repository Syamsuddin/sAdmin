# Changelog

Semua perubahan penting sAdmin (paket `core`, `edge`, dan rumah bersama `kontrak/`, `catalog/`, `capsules/`) dicatat di sini. Format mengikuti [Keep a Changelog 1.1.0](https://keepachangelog.com/id-ID/1.1.0/). Skema versi diatur di `core/docs/22_CHANGE_POLICY.md` §Git.

Tag pra-rilis (`-alpha.N`) menandai kemajuan pengembangan dan **bukan rilis**. Tag seperti ini belum melewati `core/docs/25_RELEASE_CHECKLIST.md` dan tidak boleh dipasang di instansi.

## [Belum dirilis]

## [0.1.0-alpha.1] — 2026-09-30

Tonggak **M1 Kerangka**, slice 1: rantai audit sisi core (F-04). Kriteria AC-03 baru terpenuhi sebagian (lihat *Belum tercakup*).

### Ditambahkan
- Paket blueprint VCBD `core` (induk produk) dan `edge`, rumah bersama `kontrak/`, `catalog/`, `capsules/`, peta monorepo `README.md`, serta lisensi MIT.
- core: kerangka Laravel 13.34 untuk PHP 8.3 dan PostgreSQL, dengan antrean dan cache memakai driver `database`. Tanpa Tailwind, CDN, Redis, maupun dependensi yang tak tercantum di docs/09.
- core: tabel `tenants` dan `audit_entries`. `audit_entries` bersifat append-only: trigger DB menolak UPDATE, DELETE, dan TRUNCATE.
- core: `AppendAuditEntry` membangun rantai hash `SHA-256(prev_hash ∥ JCS(entri))`. Nomor urut dijamin tanpa celah lewat kunci advisory, dan entri ikut batal bila transaksi pemanggil batal. Masukan berisi byte NUL atau sarang lebih dari 64 tingkat ditolak. Setiap entri juga dibaca ulang sebelum commit, sehingga entri yang berhasil tertulis selalu bisa diverifikasi.
- core: `php artisan sadmin:audit-verify` (exit 0 = rantai utuh; saat rusak mencatat log `critical` `audit_mismatch`), dijadwalkan harian. Baris yang dimanipulasi dalam bentuk apa pun dilaporkan sebagai `audit_mismatch`, tidak pernah berakhir sebagai crash.
- core: `php artisan sadmin:forbidden-scan` sebagai tripwire eksekusi OS/SSH di kode core, termasuk bentuk alias `use function`, `namespace\`, dan FFI.
- core: kanonisasi RFC 8785 (JCS) internal di `app/Infrastructure/Jcs`.
- kontrak: tujuh vektor uji JCS bersama PHP↔Go di `kontrak/vectors/jcs/`, termasuk penjaga escape HTML bawaan Go.
- core: ADR 0001 tentang format hash rantai audit beserta batas masukannya, berstatus *diusulkan* dan menunggu tinjauan pemilik produk.
- core: 63 tes (Unit, Feature, Contract, grup `redaction`), termasuk vektor emas format rantai dan tes manipulasi per kolom. Sebelum merge, slice ini melewati review adversarial (docs/22), dan semua temuan yang mematahkan invarian audit sudah ditambal dengan tes regresi.

### Diubah
- `core/docs/09_STACK.md`: versi Laravel 13.x, PHPUnit 12, dan Larastan (analisis statis) kini terverifikasi.
- `core/docs/22_CHANGE_POLICY.md`: skema versi produk dan kewajiban changelog.

### Catatan migrasi
- Migrasi baru, semuanya **non-destruktif**: `2026_09_30_000100_create_tenants_table`, `2026_09_30_000200_create_audit_entries_table`, ditambah migrasi bawaan Laravel `cache` dan `jobs`.
- Rilis ini menetapkan format rantai audit untuk pertama kali. Setelah ada data produksi, format tersebut hanya boleh diubah lewat gerbang manusia (docs/22).

### Belum tercakup
- AC-03: alert `audit_mismatch` critical belum terkirim ≤ 60 detik, karena tabel `alerts` dan kanal notifikasi belum ada.
- Checkpoint audit bertanda tangan dan jangkar ke agen, offsite, serta digest.
- Pencabutan hak UPDATE/DELETE/TRUNCATE dari role aplikasi (menunggu `install.sh`).
- Fitur M1 lain yang belum dikerjakan: `install.sh` (F-01), login passkey (F-03), inventaris, dan tema console (F-17).
- `sadmin:forbidden-scan` belum mencakup `mail()` dan transport `sendmail` di `config/mail.php`, maupun berkas Blade. Cakupan path di docs/09 ("di `core/`") dan docs/11 (`app`, `routes`, `config`) juga belum selaras; keduanya menunggu keputusan.
