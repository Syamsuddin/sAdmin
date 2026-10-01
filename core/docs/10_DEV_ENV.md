# 10 — Dev Env (paket core)

Pemilik setup lingkungan pengembangan core. Perintah: `docs/11_COMMANDS.md`. Stack & versi: `docs/09_STACK.md`.

## Prasyarat laptop
PHP 8.3 + ekstensi di `docs/09_STACK.md`, Composer, Node.js LTS, PostgreSQL 16 lokal (atau kontainer), LXD atau Multipass (VM agen), Go (untuk membangun agen — lihat `../edge/docs/10_DEV_ENV.md`), `make`.

## Langkah setup
1. Klon monorepo; `cd core`.
2. `cp .env.example .env`, isi variabel di bawah; buat DB `sadmin_dev`; buat kunci brankas dev di luar repo: `(umask 077; head -c 32 /dev/urandom > <path>)`, lalu isi `SADMIN_VAULT_DEV_KEY=<path>`.
3. Pasang dependensi & migrasi (`docs/11_COMMANDS.md`).
4. Dari root: `make dev` — membangun gateway & agen, menjalankan gateway lokal di `127.0.0.1:8443`, meluncurkan satu VM LXD berisi agen yang ter-enrol ke core lokal.
5. Passkey di lokal: akses console lewat `https://sadmin.localhost` (RP ID `sadmin.localhost`, sertifikat dev dari `mkcert`); WireGuard tidak dipakai di dev.

## Variabel `.env` (nama saja)
| Variabel | Fungsi |
|---|---|
| `APP_KEY`, `APP_URL`, `APP_ENV` | standar Laravel (`APP_KEY` bukan kunci brankas) |
| `DB_CONNECTION=pgsql`, `DB_HOST`, `DB_PORT`, `DB_DATABASE`, `DB_USERNAME`, `DB_PASSWORD` | PostgreSQL |
| `QUEUE_CONNECTION=database`, `CACHE_STORE=database`, `SESSION_DRIVER=database` | A7 |
| `SADMIN_RP_ID`, `SADMIN_ORIGIN` | WebAuthn: RP ID sebenarnya = `institutions.console_hostname`; `SADMIN_RP_ID` hanya nilai bawaan `sadmin:institution-init`; `SADMIN_ORIGIN` kosong = `https://<hostname>`, diisi hanya di dev bila ada port (ADR 0002) |
| `SADMIN_GATEWAY_SOCKET`, `SADMIN_INBOX_SOCKET` | Unix socket ke/dari gateway |
| `SADMIN_VAULT_CRED` | nama kredensial `systemd-creds` kunci induk (bawaan `sadmin-vault-master`), dibaca dari `$CREDENTIALS_DIRECTORY` saat runtime |
| `SADMIN_VAULT_DEV_KEY` | dev/tes saja: path berkas kunci induk 32 byte mentah bermode 0600; **ditolak** bila `APP_ENV=production` (ADR 0003) |
| `REVERB_APP_ID`, `REVERB_APP_KEY`, `REVERB_APP_SECRET`, `REVERB_HOST`, `REVERB_PORT` | Reverb |
| `SADMIN_TEST_PASSKEY_SEED` | hanya `testing`: kunci passkey uji deterministik (docs/13_TESTING.md) |
