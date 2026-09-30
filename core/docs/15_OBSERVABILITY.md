# 15 — Observability (paket core)

Pemilik logging, metrik, dan peringatan paket core. Log & metrik agen: `../edge/docs/15_OBSERVABILITY.md`.

## Log
| Log | Lokasi | Format |
|---|---|---|
| Aplikasi core & console | `storage/logs/sadmin.log` (+ journald via unit systemd) | JSON satu baris: `ts`, `level`, `msg`, `run_id`, `step_index`, `envelope_id`, `admin_id`, `request_id` |
| Runner | journald `sadmin-runner.service` | JSON sama |
| Nginx console | `/var/log/nginx/sadmin-console.{access,error}.log` | bawaan |

Level: `debug` (dev saja), `info` (transisi status run/langkah), `warning` (percobaan ulang, jeda dibatalkan), `error` (galat permanen), `critical` (integritas, penolakan tanda tangan). Rahasia disamarkan sebelum log (tes grup `redaction`).

## Metrik
Sampel per menit dari agen masuk `metric_samples` (skema: docs/07_DATA_MODEL.md), retensi 30 hari. VictoriaMetrics/Prometheus dipertimbangkan Fase 3.

## Peringatan (alert_rules bawaan)
| Aturan | Ambang default |
|---|---|
| `disk_low` | ≥ 85% (warning), ≥ 95% (critical) |
| `mem_high` | ≥ 90% selama 10 menit |
| `service_down` | layanan situs/Nginx/PHP-FPM/MariaDB mati |
| `cert_expiring` | < 14 hari |
| `backup_failed` | snapshot gagal atau tak ada snapshot > 26 jam |
| `agent_disconnected` | tanpa Heartbeat > 5 menit |
| `audit_mismatch` | verify merah atau rekonsiliasi tak cocok (selalu critical) |

Kanal: Telegram & SMTP (`notification_channels`), menghormati jam tenang profil admin kecuali critical. Ringkasan harian ke admin memuat digest checkpoint audit.
