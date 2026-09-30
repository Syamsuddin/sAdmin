# 25 — Release Checklist (seluruh produk)

Berurutan; berhenti di langkah pertama yang gagal. Kebijakan & rollback: docs/22_CHANGE_POLICY.md. Perintah core: docs/11_COMMANDS.md; lintas-paket: `../README.md`.

| # | Langkah | Lulus bila |
|---|---|---|
| 1 | CI penuh di tag kandidat: tes core & edge, `make catalog-validate contract-test`, `make harness`, `make harness-security` | semua hijau |
| 2 | Bila rilis menambah/mengubah aksi: siapkan `PolicyBundle` baru | ditandatangani passkey; jadwal jeda 24 jam masuk rencana rilis |
| 3 | Changelog + catatan migrasi (tandai migrasi destruktif ⚠️) | ditinjau pemilik produk |
| 4 | Bangun & tanda tangani artefak (core tarball, biner agen/gateway, aset console + SRI) dengan kunci rilis | `.sig` terverifikasi dengan kunci publik rilis |
| 5 | `sadmin.backup_run` di instansi target | snapshot `ok` < 1 jam |
| 6 | Perbarui core: artefak → `php artisan migrate` ⚠️ → restart `sadmin-runner`, `sadmin-queue`, Reverb, PHP-FPM | `/up` sehat; `sadmin audit verify` hijau |
| 7 | Perbarui gateway | agen tersambung ulang ≤ 60 detik |
| 8 | Agen kenari: `agent.update` di satu server (bukan host sAdmin) | Heartbeat versi baru ≤ 2 menit; bila tidak, biner lama kembali otomatis |
| 9 | Agen lainnya satu per satu | semua Heartbeat versi baru |
| 10 | Smoke test: aksi L0 di semua server, `site.redeploy` satu situs staging | sukses |
| 11 | Rencana rollback tetap siap 24 jam (artefak lama + snapshot langkah 5) | tercatat di catatan rilis |
