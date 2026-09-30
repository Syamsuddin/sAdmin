# 15 — Observability (agen & gateway)

Pemilik logging & metrik edge. Peringatan & retensi di core: `../core/docs/15_OBSERVABILITY.md`.

| Log | Lokasi | Format |
|---|---|---|
| Agen | journald `sadmin-agent.service` | `slog` JSON: `ts`, `level`, `msg`, `server_id`, `envelope_id`, `idempotency_key`, `run_id`, `step_index`, `action_key` |
| Gateway | journald `sadmin-gateway.service` | JSON: `ts`, `level`, `msg`, `server_id`, `msg_type`, `msg_id`, `remote_addr` |
| Keluaran perintah aksi | `/var/log/sadmin-agent/actions/<idempotency_key>.log` (0600, retensi 30 hari) | teks; disamarkan |

Level: `info` transisi pipa & aksi; `warn` percobaan ulang, koneksi putus; `error` galat aksi; `error` + `Event` untuk penolakan tanda tangan & kegagalan audit. Rahasia (`secret_values`, parameter `x-secret`, token notifier) tidak pernah dilog — diuji dengan pemindaian nilai canary di harness.

## Metrik agen (per menit, dikirim sebagai `Event kind=metrics`)
`cpu_pct`, `mem_pct`, `swap_pct`, `load1`, `disk_pct:<mount>`, `inode_pct:<mount>`, status layanan (nginx, php-fpm per versi, mariadb, crowdsec), umur sertifikat terdekat, umur snapshot backup terakhir. Pemeriksaan lokal yang memicu notifikasi darurat langsung (tanpa core): terputus > 15 menit, disk ≥ 95%, backup gagal saat core tak terhubung.
