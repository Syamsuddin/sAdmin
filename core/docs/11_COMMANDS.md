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
| Pindai larangan eksekusi | `php artisan sadmin:forbidden-scan` | gagal bila ada fungsi terlarang (docs/09_STACK.md) di `app/`, `routes/`, `config/` |
| Migrasi ⚠️ | `php artisan migrate` | produksi: hanya lewat langkah rilis (docs/25_RELEASE_CHECKLIST.md) |
| Migrasi segar (dev saja) | `php artisan migrate:fresh --seed` | dilarang di produksi |
| Sinkron katalog & kapsul | `php artisan sadmin:catalog-sync` | memuat `../catalog`, `../capsules` ke tabel cermin |
| Runner kapsul | `php artisan sadmin:runner` | produksi: unit `sadmin-runner.service` |
| Worker antrean | `php artisan queue:work --queue=default,notify` | produksi: `sadmin-queue.service` |
| WebSocket console | `php artisan reverb:start --host=127.0.0.1 --port=8080` | |
| Penjadwal | `php artisan schedule:work` | produksi: systemd timer `sadmin-schedule.timer` |
| Verifikasi audit | `php artisan sadmin:audit-verify` (dibungkus `sadmin audit verify`) | exit 0 = hijau |
| Buat checkpoint audit manual | `php artisan sadmin:audit-checkpoint` | |
| Tanya status langkah ke agen | `php artisan sadmin:status-query <idempotency_key>` | diagnosa; tidak mengirim ulang amplop |
| Pindai token UI | `php artisan sadmin:ui-token-scan` | gagal bila ada hex/px/font di luar `resources/css/tokens.css` |
| Pangkas partisi metrik | `php artisan sadmin:metrics-prune` | terjadwal harian |
| Uji redaksi rahasia | `php artisan test --group=redaction` | |
| Instalasi produksi | `sudo ../deploy/install.sh` | di host Ubuntu 24.04 bersih |
| Pemulihan | `sudo ../deploy/install.sh --restore` | P7 docs/06_BUSINESS_PROCESS.md |
