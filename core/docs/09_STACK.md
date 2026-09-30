# 09 — Stack (paket core)

Pemilik daftar teknologi & versi paket core. Stack agen/gateway: `../edge/docs/09_STACK.md`. Prinsip: paket dari repositori Ubuntu 24.04 bila tersedia; tambah dependency hanya dengan alasan tertulis (docs/22_CHANGE_POLICY.md).

| Lapisan | Teknologi | Versi |
|---|---|---|
| OS host | Ubuntu Server | 24.04 LTS |
| Runtime | PHP-FPM (paket Ubuntu), ekstensi: pgsql, sodium, intl, mbstring, openssl, bcmath | 8.3 |
| Framework | Laravel | 13.x (dimulai 13.34.0, 2026-09-30); `composer.json` mengunci platform PHP 8.3 |
| UI | Livewire | rilis stabil terbaru yang kompatibel `[VERIFIKASI]` |
| Komponen UI | Tabler (Bootstrap 5, MIT) + Tabler Icons | 1.x `[VERIFIKASI]`; dibundel lokal via Vite, tanpa CDN |
| Real-time console | Laravel Reverb | ikut rilis Laravel `[VERIFIKASI]`; hanya 127.0.0.1 |
| Basis data | PostgreSQL (paket Ubuntu) | 16; pgvector pasca-MVP |
| WebAuthn | `laragear/webauthn` | `[VERIFIKASI]` |
| JSON Schema | `opis/json-schema` | `[VERIFIKASI]` |
| Kanonisasi JCS | implementasi internal `app/Infrastructure/Jcs` (± 150 baris) + vektor bersama | — (menghindari pustaka kecil tak terawat) |
| Kripto | ext-sodium (Ed25519, XChaCha20-Poly1305), ext-openssl (CA ECDSA P-256) | bawaan PHP |
| Build aset | Node.js LTS + Vite (hanya saat build/rilis) | `[VERIFIKASI]` |
| Tes | PHPUnit (bawaan Laravel) | 12.x |
| Analisis statis | Larastan (PHPStan) — alasan: perintah lint `docs/11_COMMANDS.md` | 3.x (PHPStan 2.x), level 6, hanya dev |
| Web server | Nginx (paket Ubuntu) | 1.24 |
| Jaringan admin | WireGuard | paket Ubuntu |

## Teknologi terlarang
| Larangan | Alasan |
|---|---|
| `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, `pcntl_exec`, backtick, `mail`, `mb_send_mail`, `imap_mail`, `error_log` bertujuan (tipe 1 = email), FFI, `Process` facade/Symfony Process, pustaka SSH (phpseclib, dsb.); transport mail yang berujung sendmail (`sendmail`, `mail`, huruf apa pun, lewat config, `MAIL_URL`, failover, maupun creator kustom — ditolak `SendmailRefusingMailManager`; `native` memang tak didukung Laravel), akses langsung transport Symfony Mailer, Monolog `NativeMailerHandler` — di semua kode PHP milik proyek di `core/` (termasuk Blade, berkas tersembunyi, direktori symlink; tanpa `vendor/`, `tests/`, `storage/`, `node_modules/`, `bootstrap/cache/`) | P1 — semua eksekusi lewat agen. Satu-satunya pengecualian: tidak ada. (Pengecualian *pemindaian*, bukan pengecualian P1: `SendmailRefusingMailManager` boleh menyebut kelas transport yang ditolaknya.) `mail()`/sendmail menjalankan biner `sendmail` (dan parameter ke-5 `mail()` = injeksi flag); notifikasi cukup SMTP via soket jaringan |
| React, Vue, Inertia, SPA terpisah | Livewire cukup; menghindari paket UI terpisah |
| Redis, Horizon, Memcached | A7: driver database cukup untuk skala target |
| CDN untuk aset console | console di zona privat + SRI; aset dibundel |
| Pustaka UI selain Tabler, set ikon selain Tabler Icons | konsistensi (`docs/26_UI_CONVENTIONS.md`) |
| Paket Composer/npm baru tanpa alasan tertulis di PR | perangkat lunak berhak root = permukaan serangan |
| Enkripsi `Crypt::` Laravel untuk rahasia | rahasia hanya lewat brankas (`app/Infrastructure/Vault`) |
