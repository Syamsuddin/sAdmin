# 11 — Commands (paket core)

Pemilik perintah paket core. Jalankan dari `core/`. Perintah lintas-paket (`make …`): `../README.md`. Perintah agen/gateway: `../edge/docs/11_COMMANDS.md`.

| Tujuan | Perintah | Catatan |
|---|---|---|
| Pasang dependensi | `composer install && npm ci && npm run build` | |
| Server dev | `php artisan serve --host=sadmin.localhost` | atau Nginx lokal |
| Tes semua | `php artisan test` | |
| Tes terfokus | `php artisan test --filter=<NamaTes>` | |
| Tes kontrak sisi PHP | `php artisan test --testsuite=Contract` | vektor dari `../kontrak/vectors/` |
| Lint & analisis statis | `vendor/bin/pint --test && vendor/bin/phpstan analyse` | |
| Pindai larangan eksekusi | `php artisan sadmin:forbidden-scan` | gagal bila ada fungsi terlarang (docs/09_STACK.md) di `app/`, `bootstrap/` (tanpa `cache/`), `config/`, `database/`, `lang/`, `public/`, `resources/views/` (Blade dikompilasi dulu; nomor baris = hasil kompilasi), `routes/`, `artisan` — termasuk berkas tersembunyi dan direktori symlink (kecuali `public/storage`); import group & alias diurai ke nama lengkap; tes invarian menjaga tak ada berkas PHP proyek di luar daftar ini |
| Migrasi ⚠️ | `php artisan migrate` | produksi: hanya lewat langkah rilis (docs/25_RELEASE_CHECKLIST.md) |
| Migrasi segar (dev saja) | `php artisan migrate:fresh --seed` | dilarang di produksi |
| Sinkron katalog & kapsul | `php artisan sadmin:catalog-sync` | memuat `../catalog`, `../capsules` ke tabel cermin |
| Runner kapsul | `php artisan sadmin:runner` | produksi: unit `sadmin-runner.service` |
| Worker antrean | `php artisan queue:work --queue=default,notify` | produksi: `sadmin-queue.service` |
| WebSocket console | `php artisan reverb:start --host=127.0.0.1 --port=8080` | |
| Penjadwal | `php artisan schedule:work` | produksi: systemd timer `sadmin-schedule.timer` |
| Inisialisasi instansi | `php artisan sadmin:institution-init <hostname>` | sekali; hostname = RP ID WebAuthn permanen (menolak bila sudah ada) |
| Undang admin | `php artisan sadmin:admin-invite "<nama panggilan>"` | mencetak tautan bertanda tangan 15 menit untuk mendaftarkan 2 passkey |
| Verifikasi audit | `php artisan sadmin:audit-verify` (dibungkus `sadmin audit verify`) | rantai + checkpoint; exit 0 = hijau, 1 = rusak (`audit_mismatch`), 2 = checkpoint tak dapat diperiksa karena brankas tak tersedia (ADR 0004); exit 1 juga membuka alert `audit_mismatch` critical dan langsung mengirimnya ke semua kanal aktif (ADR 0005) |
| Buat kunci audit | `php artisan sadmin:audit-key-init` | sekali, setelah `sadmin:institution-init`; seed Ed25519 di brankas, mencetak kunci publik untuk kit pemulihan; menolak bila sudah ada (rotasi = docs/22) |
| Buat checkpoint audit manual | `php artisan sadmin:audit-checkpoint` | `--if-due` = hanya bila jatuh tempo (15 menit atau 100 entri), dijalankan penjadwal tiap menit (`withoutOverlapping`); rantai rusak atau kunci audit yang gagal dibuka juga membuka alert `audit_mismatch` (ADR 0005) |
| Tambah kanal notifikasi | `php artisan sadmin:notify-channel-add telegram --chat-id=<id>` · `php artisan sadmin:notify-channel-add smtp --host=<host> --port=587 --tls=starttls --username=<akun> --from=<alamat> --to=<alamat>` | token bot / kata sandi SMTP dari prompt tersembunyi, tak pernah argumen; butuh instansi + brankas (ADR 0005 §2.5) |
| Uji kanal notifikasi | `php artisan sadmin:notify-test` | kirim pesan uji ke semua kanal aktif; exit 0 = semua menerima |
| Periksa brankas | `php artisan sadmin:vault-check` | exit 0 = kunci induk termuat dan semua kunci data rahasia aktif terbuka; tak membuka nilai (ADR 0003) |
| Tanya status langkah ke agen | `php artisan sadmin:status-query <idempotency_key>` | diagnosa; tidak mengirim ulang amplop |
| Pindai token UI | `php artisan sadmin:ui-token-scan` | gagal bila ada hex/px/font di luar `resources/css/tokens.css` |
| Pangkas partisi metrik | `php artisan sadmin:metrics-prune` | terjadwal harian |
| Uji redaksi rahasia | `php artisan test --group=redaction` | |
| Instalasi produksi | `sudo ../deploy/install.sh` | di host Ubuntu 24.04 bersih |
| Pemulihan | `sudo ../deploy/install.sh --restore` | P7 docs/06_BUSINESS_PROCESS.md |
