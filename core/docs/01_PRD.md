# 01 — PRD

Pemilik fitur & user story untuk seluruh produk (paket `core` dan `edge`). Kriteria terima: `docs/23_ACCEPTANCE_CRITERIA.md` (core) dan `../edge/docs/23_ACCEPTANCE_CRITERIA.md`.

## Daftar fitur
| ID | Fitur | Tonggak | Paket utama |
|---|---|---|---|
| F-01 | Instalasi sAdmin Mode Tunggal (`deploy/install.sh`), segel kunci induk, kit pemulihan | M1 | core |
| F-02 | Agen + gateway, enrolment, inventaris & metrik dasar | M1 | edge |
| F-03 | Login console passkey di balik WireGuard | M1 | core |
| F-04 | Audit berantai hash + jangkar (agen, offsite, ringkasan harian) + `sadmin audit verify` | M1 | core+edge |
| F-05 | Harness VM sekali pakai | M1 | edge |
| F-06 | ±30 aksi tulis katalog (`catalog/CATALOG.md`) dengan check/apply/verify/compensate | M2 | edge |
| F-07 | Rencana, persetujuan passkey, roster & kebijakan tersemat, jeda L3 + notifikasi dari agen | M2 | core+edge |
| F-08 | Runner kapsul (saga, tunggu, kompensasi, kunci sumber daya) | M2 | core |
| F-09 | Pembatalan bertimer SSH/firewall | M2 | edge |
| F-10 | Kapsul `server.onboard`, `site.create`, `site.redeploy`, `site.archive` (`capsules/CAPSULES.md`) | M3 | core |
| F-11 | Backup restic situs + timer rutin lokal (SSL, backup, logrotate, patch) | M3 | edge |
| F-12 | Monitoring dasar + peringatan (Telegram, SMTP eksternal) | M3 | core+edge |
| F-13 | Kapsul `sadmin.backup` (otomatis) & `sadmin.restore` | M4 | core |
| F-14 | Mode darurat lokal `sadmin-agent local run` | M4 | edge |
| F-15 | Memori dasar: kejadian otomatis, catatan manual, wawancara awal, profil admin | M4 | core |
| F-16 | Asisten AI read-only opsional dengan kebijakan aliran data & anggaran | M4 | core |
| F-17 | Console light/dark (ikut OS, override per admin) | M1 | core |
| — | Fitur Fase 2–4 | nanti | lihat `docs/03_ROADMAP.md` |

## User story MVP
- F-01: Sebagai admin, saya ingin memasang sAdmin di server Ubuntu baru dengan satu skrip agar control plane siap tanpa konfigurasi manual.
- F-03: Sebagai admin, saya ingin masuk console hanya dengan passkey melalui WireGuard agar tidak ada password yang bisa dicuri dan console tak terlihat dari internet.
- F-04: Sebagai admin, saya ingin membuktikan kepada auditor bahwa riwayat aksi tidak diubah agar sAdmin layak dipakai di instansi.
- F-07: Sebagai admin, saya ingin meninjau rencana lengkap lalu menyetujuinya sekali dengan passkey agar tak ada perubahan berbahaya yang terjadi tanpa saya.
- F-07: Sebagai saksi, saya ingin menerima notifikasi aksi L3 dan bisa membatalkannya selama jeda agar admin tunggal tetap diawasi.
- F-09: Sebagai admin, saya ingin perubahan SSH/firewall kembali otomatis bila saya tak mengonfirmasi agar saya tak terkunci dari server.
- F-10: Sebagai admin, saya ingin menjawab domain, sumber, dan branch lalu mendapat situs Laravel ber-HTTPS agar pemasangan seragam dan cepat.
- F-10: Sebagai admin, saya ingin mengarsipkan situs dan melihat server kembali bersih agar tidak ada sisa konfigurasi yatim.
- F-13: Sebagai admin, saya ingin memulihkan control plane di server baru dari backup dan kit pemulihan dalam ≤ 1 jam agar kehilangan server sAdmin bukan bencana.
- F-14: Sebagai pemegang root, saya ingin menjalankan aksi katalog langsung di server saat core mati agar insiden tetap tertangani dan tetap tercatat.
- F-15: Sebagai admin pengganti, saya ingin membaca alasan dan keputusan masa lalu tentang server agar pengetahuan tidak hilang.
- F-16: Sebagai admin, saya ingin bertanya "kenapa situs X lambat" dan mendapat jawaban berbukti dari data L0 tanpa rahasia keluar instansi.

## Kebutuhan non-fungsional
| Aspek | Target |
|---|---|
| Ketahanan | Control plane mati ≠ server mati; pemulihan ≤ 60 menit |
| Keamanan | Aksi L2/L3 hanya dengan passkey terverifikasi agen; console tak terjangkau dari IP publik |
| Skala MVP | Mode Tunggal, ≤ 3 server terkelola `[ASUMSI]` |
| Bahasa | UI Bahasa Indonesia; istilah teknis lazim tetap Inggris |
| Tanpa AI | Semua fungsi inti berjalan dengan AI nonaktif |
