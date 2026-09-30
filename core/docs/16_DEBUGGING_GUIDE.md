# 16 — Debugging Guide (paket core)

Log: docs/15_OBSERVABILITY.md. Perintah: docs/11_COMMANDS.md. Galat: docs/14_ERROR_HANDLING.md. Sisi agen: `../edge/docs/16_DEBUGGING_GUIDE.md`.

## Gejala → diagnosa
| Gejala | Langkah |
|---|---|
| Run macet di `running` | cek `step_runs` status `dispatched`; cari `envelope_id` di log core & gateway; `StatusQuery` manual lewat `php artisan sadmin:status-query <idempotency_key>`; cek `agents.connection` |
| Agen menolak `E_SIG_PASSKEY` | bandingkan `rosters.version` aktif vs `agents.roster_version`; cek origin/RP ID console = `institutions.console_hostname` |
| `E_PLAN_MISMATCH` | JCS PHP≠Go: jalankan `make contract-test`; cari angka pecahan atau karakter unicode di `params` |
| Passkey tak muncul di peramban | akses bukan lewat hostname console (IP tidak didukung WebAuthn) atau sertifikat tak valid |
| Console tak terjangkau | WireGuard tidak aktif di perangkat admin; `wg show` di host; vhost hanya `listen 10.77.0.1:443` |
| Audit verify merah | jangan perbaiki data; buka alert, bandingkan `audit_checkpoints` dengan jangkar offsite dan receipt agen |
| Runner dobel memajukan | pastikan query memakai `FOR UPDATE SKIP LOCKED` di dalam transaksi |

## Jebakan proyek
- **RP ID permanen.** `institutions.console_hostname` = RP ID yang tersemat di roster semua agen. Mengganti hostname = semua passkey harus didaftar ulang = perubahan roster L3 + jeda 24 jam. Jangan buat fitur "ganti hostname" sederhana.
- **JCS lintas bahasa.** Dilarang angka pecahan di badan bertanda tangan; `json_encode` bawaan PHP BUKAN JCS — selalu lewat `app/Infrastructure/Jcs`.
- **Mode Tunggal.** Host sAdmin juga server terkelola: aksi `firewall.apply`/`nginx.*` pada host ini menyentuh console & gateway sendiri; aturan dasar firewall wajib mempertahankan 8443 dan UDP WireGuard.
- **Partisi metrik.** Retensi = `DROP` partisi; `DELETE FROM metric_samples` akan sangat lambat dan membengkakkan tabel.
- **Rencana immutable.** Mengedit `plans.body` akan ditolak trigger — itu disengaja; buat rencana baru.
- **Kebijakan butuh 24 jam.** Rilis yang menambah aksi baru memerlukan `PolicyBundle` baru (L3, jeda 24 jam) sebelum aksi itu bisa dipakai.
