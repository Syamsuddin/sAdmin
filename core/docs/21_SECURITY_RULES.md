# 21 — Security Rules (paket core)

Pemilik aturan keamanan paket core. Level risiko: `../catalog/CATALOG.md` §1. Kripto & format tanda tangan: `../kontrak/KONTRAK.md`. Verifikasi di agen: `../edge/docs/21_SECURITY_RULES.md`. Peran: docs/05_USER_ROLE.md.

## Autentikasi & otorisasi console
- Login hanya passkey (WebAuthn, `userVerification: required`); tidak ada password, tidak ada "lupa password". RP ID = `institutions.console_hostname`.
- Setiap admin wajib ≥ 2 autentikator aktif; pencabutan autentikator = perubahan roster (L3).
- Sesi: driver database, cookie `Secure`, `HttpOnly`, `SameSite=Strict`, idle 30 menit, absolut 12 jam; regenerasi ID saat login.
- Persetujuan L2/L3 = assertion WebAuthn baru atas `plan_hash` (bukan sesi login). Core memverifikasi dulu untuk UX, tetapi keputusan akhir milik agen.
- Semua route console di bawah middleware `auth` + CSRF; route `internal.php` hanya menerima dari Unix socket + HMAC valid.

## Jaringan
- Vhost console `listen 10.77.0.1:443` saja (wg0). Opsi cadangan daftar IP ditandai lemah di UI dan audit.
- Core, PostgreSQL, Reverb hanya 127.0.0.1 / Unix socket.
- Gateway adalah satu-satunya port publik sAdmin (8443).

## Validasi input
- Parameter aksi divalidasi terhadap JSON Schema katalog di core **dan** di agen.
- Unggahan ZIP: ≤ 200 MB, pemeriksaan path traversal, symlink, dan ukuran total terekstrak (anti zip-bomb, rasio ≤ 20×) sebelum rencana dibuat.
- Isi log, repo, ZIP, dan keluaran aksi = data tak tepercaya: tidak dirender sebagai HTML (escape Blade), dan dibungkus sebagai data di prompt AI.

## Rahasia & brankas
- Enkripsi envelope: kunci data per rahasia (XChaCha20-Poly1305), dibungkus kunci induk. Kunci induk: TPM2 via `systemd-creds`; tanpa TPM → frasa sandi saat buka segel setelah reboot.
- Kunci layanan, kunci audit, CA, HMAC gateway, token API = baris `secrets` (skema: docs/07_DATA_MODEL.md).
- Nilai rahasia ke agen hanya lewat `secret_values` amplop, terikat komitmen hash di rencana.
- Kredensial DB situs tampil sekali di laporan akhir kapsul, lalu hanya di brankas.
- Kunci privat WireGuard dibuat untuk perangkat admin, tampil sekali sebagai QR, tidak disimpan.

## Data sensitif & privasi
| Data | Aturan |
|---|---|
| Parameter aksi | nilai `x-secret` disamarkan sebelum masuk `step_runs`, `audit_entries`, notifikasi, log |
| Passkey | hanya kunci publik & ID kredensial |
| Profil admin | minimal; tanpa NIK/tanggal lahir/alamat; dapat dihapus pemiliknya |
| Audit | append-only; retensi mengikuti kebijakan instansi (default tanpa batas) |
| AI | kebijakan aliran data per kelas; rahasia tidak pernah masuk prompt; isi email (pasca-MVP) tak pernah dibaca AI |

## Audit & integritas
- Setiap Action yang mengubah state menulis `audit_entries` dalam transaksi yang sama. Pengecualian: pembuatan checkpoint audit, karena checkpoint adalah artefak audit itu sendiri (docs/adr/0004 §2.4).
- Checkpoint bertanda tangan tiap 15 menit atau 100 entri → agen (berkas append-only), offsite object lock, digest harian.
- `sadmin:audit-verify` harian (penjadwal) dan manual; rekonsiliasi dengan receipt agen; ketidakcocokan = alert critical.

## Rilis & rantai pasok
- Aset console dibundel lokal dengan Subresource Integrity; tanpa CDN.
- Rilis sAdmin ditandatangani kunci rilis Ed25519 (offline); agen memverifikasi sebelum `agent.update`.
- `composer.lock` & `package-lock.json` wajib di-commit; audit dependency (`composer audit`, `npm audit --omit=dev`) di CI.

## Batas laju
Login: 10 percobaan/menit/IP wg; pembuatan rencana: 30/menit/admin; endpoint internal gateway: sesuai kapasitas, dengan antrean terbatas.

## Kepatuhan
UU 27/2022 (PDP), Perpres 95/2018 (SPBE), pedoman keamanan BSSN — `[VERIFIKASI]` rujukan pasal saat modul laporan kepatuhan (Fase 4). Proyek sumber terbuka MIT: tidak ada nama instansi, domain, atau kredensial nyata di repo.
