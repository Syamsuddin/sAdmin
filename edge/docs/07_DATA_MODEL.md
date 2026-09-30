# 07 — Data Model (state lokal agen)

Sumber kebenaran state yang disimpan agen di setiap server. Skema DB core: `../core/docs/07_DATA_MODEL.md`. Format pesan: `../kontrak/KONTRAK.md`. Gateway tidak menyimpan state tahan lama.

## Berkas & direktori
| Path | Mode | Isi |
|---|---|---|
| `/etc/sadmin/agent.yaml` | 0640 root:sadmin | `server_id`, `gateway_url`, `platform_id` terdeteksi, batas laju |
| `/var/lib/sadmin-agent/tls/{agent.key,agent.crt,ca.crt}` | 0600 / 0644 | sertifikat klien mTLS (ECDSA P-256) |
| `/var/lib/sadmin-agent/trust/roster.json` | 0644, ditulis atomik | roster aktif + `approvals` penerbitnya |
| `/var/lib/sadmin-agent/trust/policy.json` | 0644, atomik | kebijakan aktif (aksi, versi, risiko, platform, jeda, kanal notifikasi) |
| `/var/lib/sadmin-agent/trust/keys.json` | 0644 | `service_pubkey`, `audit_pubkey`, `release_pubkey` |
| `/var/lib/sadmin-agent/state.db` | 0600 | bbolt (bucket di bawah) |
| `/var/lib/sadmin-agent/rollback/<idempotency_key>/` | 0700 | salinan konfigurasi untuk pembatalan bertimer & compensate |
| `/var/lib/sadmin-agent/secrets/notifier.json` | 0600 | token bot Telegram & kredensial SMTP (kirim-saja) |
| `/var/log/sadmin-agent/audit-<n>.jsonl` | 0600, `chattr +a` | audit lokal append-only |
| `/var/log/sadmin-agent/anchors-<n>.jsonl` | 0600, `chattr +a` | `CheckpointAnchor` yang diterima |

## Bucket bbolt `state.db`
| Bucket | Kunci | Nilai (JSON) | Retensi |
|---|---|---|---|
| `journal` | `idempotency_key` | `{envelope_id, action_key, action_version, phase, status, result, started_at, finished_at}` | 90 hari |
| `nonces` | `nonce` | `expires_at` | hingga `expires_at` + 1 hari |
| `pending_delays` | `plan_hash:step_index` | amplop utuh (tanpa `secret_values` dalam teks jelas — dienkripsi dengan kunci lokal agen), `execute_at`, `cancel_code_hash` | sampai eksekusi/batal |
| `timers` | `idempotency_key` | `{kind: ssh\|firewall, deadline, rollback_dir, confirm_code_hash}` | sampai konfirmasi/rollback |
| `outbox` | seq urut | pesan `Result`/`Event`/`AuditReceipt` yang belum di-`Ack` | sampai `Ack` |
| `locks` | resource key | `idempotency_key` pemegang | sampai langkah selesai |
| `meta` | `audit_head`, `roster_version`, `policy_version`, `pending_trust` | nilai | — |
| `pending_trust` | `roster:<v>` / `policy:<v>` | dokumen baru + `effective_at` (jeda 24 jam) | sampai berlaku/batal |

## Entri audit lokal (satu baris JSONL)
| Field | Keterangan |
|---|---|
| `seq` | naik monoton per agen |
| `prev_hash`, `hash` | `hash = SHA-256(prev_hash ∥ JCS(entri tanpa hash))`, genesis 64 nol |
| `ts` | UTC |
| `kind` | `envelope`, `rejected`, `delay_started`, `delay_cancelled`, `timer_confirmed`, `timer_rolled_back`, `emergency_local`, `trust_update`, `enrolled`, `agent_updated` |
| `envelope` | amplop utuh **tanpa** `secret_values`, termasuk `plan` & `approvals` (bukti untuk rekonsiliasi) |
| `result_status`, `error_code` | |
| `emergency_local` | bool |

Rotasi: berkas baru `audit-<n+1>.jsonl` saat > 50 MB; entri pertama berkas baru menyambung `prev_hash`. Berkas lama tidak di-truncate (atribut `+a`).
