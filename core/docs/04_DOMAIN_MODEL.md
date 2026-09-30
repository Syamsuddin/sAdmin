# 04 — Domain Model

Pemilik bahasa domain untuk kedua paket. Skema fisik: `docs/07_DATA_MODEL.md` (core) dan `../edge/docs/07_DATA_MODEL.md` (state lokal agen). Format pesan: `../kontrak/KONTRAK.md`.

## Glosarium
| Istilah | Makna |
|---|---|
| Aksi | Operasi atomik bertipe di katalog: skema parameter, level risiko, sumber daya, kontrak `check/apply/verify/compensate` |
| Katalog aksi | Kumpulan definisi aksi berversi (`../catalog/`); satu-satunya jalur eksekusi |
| Level risiko | L0–L3; menentukan syarat persetujuan (`../catalog/CATALOG.md` §1) |
| Kapsul | Resep yang merangkai aksi menjadi satu pekerjaan utuh dengan pertanyaan minimum (`../capsules/`) |
| Run | Satu eksekusi kapsul (`CapsuleRun`) beserta langkah-langkahnya (`StepRun`) |
| Rencana (Plan) | Daftar lengkap langkah + parameter yang ditandatangani admin sekali; berlaku ≤ 24 jam |
| Amplop (Envelope) | Pesan aksi ke agen: aksi, versi, target, parameter, risiko, nonce, kedaluwarsa, rujukan rencana |
| Persetujuan (Approval) | Assertion WebAuthn passkey admin atas hash rencana |
| Roster | Daftar kunci publik passkey admin yang dipercaya agen; perubahannya L3 + jeda 24 jam |
| Kebijakan (PolicyBundle) | Dokumen bertanda tangan di agen: aksi yang dikenal, level risiko, syarat persetujuan, jeda |
| Jeda L3 | Waktu tunggu yang dapat dibatalkan antara persetujuan dan eksekusi L3 |
| Saksi | Kontak yang menerima notifikasi L3/roster dan dapat membatalkan |
| Agen | Proses Go di setiap server; satu-satunya pengeksekusi aksi |
| Gateway | Proses Go publik (8443) penerima koneksi agen; tanpa UI, rahasia, atau DB |
| Runner | Worker core yang memajukan run satu langkah per giliran |
| Enrolment | Pendaftaran agen baru memakai token sekali pakai yang dijalankan admin sendiri |
| Jangkar audit | Checkpoint hash audit bertanda tangan yang disalin ke luar DB core (agen, offsite, ringkasan harian) |
| Rekonsiliasi dua sisi | Pencocokan audit core dengan audit lokal agen |
| Mode Tunggal / Armada | Control plane menumpang di server terkelola / di server khusus (Fase 3) |
| Platform | Distro+versi server terkelola, mis. `ubuntu-24.04`; dilaporkan agen |
| Profil platform | Fakta beda-per-distro di agen, dipakai aksi lewat antarmuka adaptor |
| Kit pemulihan | Kunci pemulihan + petunjuk; dokumen institusi yang dicetak dan disimpan fisik |
| Brankas | Penyimpanan rahasia terenkripsi envelope di core; kunci induk tersegel |
| Mode darurat lokal | Eksekusi aksi katalog langsung via `sadmin-agent local run` oleh pemegang root |
| Pembatalan bertimer | Perubahan SSH/firewall yang otomatis dikembalikan bila tak dikonfirmasi dalam 5 menit |
| Jejak nol | Kondisi server persis seperti sebelum aksi setelah kompensasi |
| Dikelola / Diamati / Diabaikan | Status kepemilikan sumber daya oleh sAdmin (MVP: semua yang dibuat sAdmin = Dikelola) |
| Memori | Pengetahuan tak-turunan (alasan, keputusan, pelajaran, preferensi) beserta asal-usulnya |
| Fakta hidup | Kondisi yang selalu diambil langsung dari agen; tidak pernah disimpan sebagai memori |
| Kebijakan aliran data | Aturan per kelas data (log, konfigurasi, metadata, memori): cloud / lokal saja / tidak sama sekali |

## Entitas inti & relasi konseptual
- Tenant (satu di MVP) memiliki Institution, Admin, Contact, Server, Memory.
- Admin memiliki ≥ 2 Authenticator dan WireguardPeer; Roster adalah potret kunci publik Authenticator yang disematkan ke agen.
- Server memiliki satu Agent, banyak Site, snapshot inventaris, dan sampel metrik.
- Site memiliki SiteSource, banyak Release, 0..1 AppDatabase, Certificate, EnvSet (rujukan ke Secret).
- CapsuleRun memiliki banyak StepRun dan satu Plan yang disetujui lewat Approval; tiap StepRun mengirim ActionEnvelope; langkah memegang ResourceLock.
- Setiap aksi menghasilkan AuditEntry; AuditCheckpoint menjangkarkan rantai; AgentAuditReceipt membuktikan sisi agen.
- Memory tertaut (MemoryLink) ke institusi, server, situs, run, atau audit.
