# 08 — Architecture (agen & gateway)

Pemilik arsitektur paket edge. Gambaran sistem & keputusan produk: `../core/docs/08_ARCHITECTURE.md`. Teknologi: `docs/09_STACK.md`. Protokol: `../kontrak/KONTRAK.md`.

## Dua biner
| Biner | Tempat | Tanggung jawab | Tidak boleh |
|---|---|---|---|
| `sadmin-agent` | tiap server terkelola, root, unit `sadmin-agent.service` | koneksi keluar ke gateway, pipa verifikasi (docs/06_BUSINESS_PROCESS.md), eksekusi aksi, jurnal, audit lokal, jeda L3, timer rollback, notifikasi darurat, mode darurat lokal, pengumpul metrik per menit | membuka port dengar; menjalankan apa pun di luar aksi kebijakan |
| `sadmin-gateway` | host sAdmin, user `sadmin-gw` tanpa shell, unit `sadmin-gateway.service` | terminasi mTLS 8443, enrolment, unduh blob, penerus pesan agen↔core via Unix socket | kredensial DB, rahasia selain kunci TLS server & HMAC, logika aksi, penyimpanan pesan |

## Lapisan di agen
| Lapisan | Paket | Aturan |
|---|---|---|
| Transport | `internal/transport` | WebSocket mTLS, backoff, outbox |
| Protokol | `internal/protocol` | tipe pesan dari `../kontrak/schemas` (codegen), JCS, validasi skema |
| Kepercayaan | `internal/trust` | roster, kebijakan, verifikasi Ed25519 & WebAuthn, nonce, komitmen rahasia |
| Orkestrasi | `internal/executor` | pipa E1–E4, jurnal, kunci lokal, jeda, timer |
| Aksi | `internal/actions/<kelompok>/<aksi>` | satu paket per aksi; antarmuka `Check/Apply/Verify/Compensate`; hanya memanggil antarmuka platform |
| Adaptor platform | `internal/platform` + `internal/platform/ubuntu2404` | `PackageManager`, `ServiceManager`, `FirewallProvider`, `WebServerLayout`, `PhpProvider`, `MacProvider`, `AutoUpdateProvider`, `Paths`; **satu** implementasi di MVP |
| Pelaksana proses | `internal/sysexec` | satu-satunya tempat `os/exec`; argumen sebagai slice, tanpa `sh -c`, lingkungan minimal, batas waktu wajib |
| Audit & notifikasi | `internal/audit`, `internal/notify` | JSONL berantai; `Notifier` (Telegram, SMTP) |

## Keputusan kunci
| # | Keputusan | Alasan |
|---|---|---|
| E-A1 | Go, biner statis `CGO_ENABLED=0` | jejak kecil, tak bergantung Python/libc sistem, jalan di distro mana pun |
| E-A2 | Risiko & syarat diambil dari kebijakan tersemat, bukan dari amplop | core dibobol tak bisa menurunkan risiko |
| E-A3 | Notifikasi L3 disusun & dikirim agen | console palsu terdeteksi |
| E-A4 | bbolt + JSONL, bukan SQLite | tanpa cgo; append-only via `chattr +a` |
| E-A5 | Satu implementasi per antarmuka platform | anti abstraksi spekulatif (`../core/docs/02_SCOPE.md`) |
| E-A6 | Semua `os/exec` lewat `internal/sysexec` | satu titik audit untuk injeksi perintah |
| E-A7 | Timer rutin (certbot, restic, logrotate, unattended-upgrades) dipasang sebagai unit systemd biasa oleh aksi `timer.install` | server tetap sehat tanpa agen maupun core |
| E-A8 | Konfigurasi Nginx milik sAdmin di `/etc/nginx/sadmin.d/` | tidak bercampur dengan konfigurasi lain; siap untuk brownfield Fase 3 |
