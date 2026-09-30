# 02 — Scope

Pemilik batas untuk seluruh produk (kedua paket). Out-of-scope → berhenti & tanya.

## In-scope MVP
- Fitur F-01…F-17 (`docs/01_PRD.md`).
- Satu platform terkelola: `ubuntu-24.04` dengan Nginx, PHP-FPM, MariaDB. Host sAdmin: Ubuntu 24.04 saja.
- Mode Tunggal (control plane menumpang di server terkelola pertama), ≤ 3 server.
- Situs Laravel dan PHP native dari GitHub (deploy key, read-only) atau ZIP.
- DNS otomatis hanya via Cloudflare API; domain lain lewat instruksi manual + status menunggu.

## Out-of-scope MVP
| Tidak dibangun | Alasan |
|---|---|
| Modul email hosting (mail server atau relay yang dikelola sAdmin) | Beban perawatan tinggi; butuh modul DNS/keamanan/backup stabil dulu. **Catatan:** agen *mengirim* notifikasi via SMTP eksternal milik instansi — itu kanal notifikasi, bukan modul email |
| Server lama/brownfield, adopsi situs, Apache | Target awal server baru (keputusan pemilik) |
| Webhook dan GitHub App | Deploy cukup dari tombol + deploy key; mengecilkan permukaan publik |
| MCP, AI yang menyusun/menjalankan rencana | AI MVP hanya membaca & menjelaskan |
| Platform selain `ubuntu-24.04` (terkelola) dan selain Ubuntu (host) | Setiap distro menggandakan beban uji; server lain ditolak di pemeriksaan awal |
| Profil platform/abstraksi untuk distro yang belum dijadwalkan | Abstraksi diperkaya hanya saat implementasi kedua benar-benar ditulis |
| Aksi "jalankan perintah bebas" / terminal web | Melanggar P1: hanya aksi katalog |
| High availability control plane | Pemulihan ≤ 1 jam cukup untuk skala target |
| Multi-tenant aktif | Kolom `tenant_id` disiapkan, fitur tidak |
| Aplikasi seluler | Console responsif hingga 375 px cukup |
| Registrasi domain | Butuh API registrar & pembayaran; `.go.id` proses administratif |
| Kontainer (Docker/Podman) | Fase 2 (`app.create_container`) |

## Asumsi & batasan
- Server terkelola punya egress ke internet (repositori paket, GitHub, Cloudflare, penyimpanan offsite, gateway 8443) `[ASUMSI]`.
- Tersedia penyimpanan offsite kompatibel S3 dengan object lock `[ASUMSI]`.
- Saksi = kontak notifikasi, bukan akun console `[ASUMSI]`.
- Risiko Mode Tunggal diterima sadar: root pada host sAdmin = kendali control plane; dicatat di wawancara awal dengan anjuran Mode Armada saat server bertambah.
