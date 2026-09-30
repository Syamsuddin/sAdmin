# 06 — Business Process

Pemilik alur proses tingkat produk dan mesin kapsul. Alur internal agen (pipa verifikasi, jeda, timer, sangga): `../edge/docs/06_BUSINESS_PROCESS.md`. Peran: `docs/05_USER_ROLE.md`. Data: `docs/07_DATA_MODEL.md`. Resep: `../capsules/CAPSULES.md`.

## P1 Instalasi sAdmin (Mode Tunggal)
1. Admin menjalankan `deploy/install.sh` sebagai root di Ubuntu 24.04 baru (tolak platform lain).
2. Pemasang memasang Nginx, PHP-FPM 8.3, PostgreSQL 16, WireGuard, core, gateway, agen; menyegel kunci induk (TPM2 via `systemd-creds`; tanpa TPM → frasa sandi).
3. Pemasang menanyakan hostname console (subdomain instansi, RP ID WebAuthn permanen) dan menerbitkan sertifikatnya via DNS-01.
4. Admin mendaftarkan dua autentikator passkey dan memindai QR profil WireGuard.
5. Kit pemulihan tampil sekali; admin mengonfirmasi lokasi penyimpanan fisiknya.
6. Wawancara awal (formulir): instansi, zona waktu, DNS/registrar, jam pemeliharaan, kebijakan data & AI, retensi backup, kontak saksi, kanal notifikasi, profil admin.
7. `sadmin.backup` aktif; host di-enrol lokal sebagai server terkelola pertama.

Gagal: tanpa TPM & frasa sandi ditolak → berhenti dengan penjelasan. Kit belum dikonfirmasi → banner peringatan di setiap halaman sampai terjawab. Platform bukan Ubuntu 24.04 → berhenti sebelum mengubah apa pun.

## P2 Run kapsul (umum)
Formulir pertanyaan minimum → `detect` → `preflight` (read-only) → penyusunan rencana (termasuk "Memori yang dipertimbangkan") → admin menyetujui dengan passkey (L2/L3) → runner memajukan langkah → laporan akhir + tombol kapsul pembalik.

### Status `capsule_runs.status`
`planned` → `awaiting_approval` → (`delayed` bila L3) → `running` ⇄ `waiting` → `succeeded`; atau `running` → `compensating` → `compensated` | `needs_attention`; atau `cancelled` (dari `awaiting_approval`/`delayed`/`waiting`).

### Status `step_runs.status`
`pending` → `dispatched` → `succeeded` | `skipped` | `failed`; langkah sukses saat run berkompensasi: `compensating` → `compensated` | `compensation_failed`.

### Aturan eksekusi
| Aturan | Isi |
|---|---|
| Satu langkah per giliran | runner mengambil run siap maju dengan `SELECT … FOR UPDATE SKIP LOCKED`, memajukan tepat satu langkah, melepas kunci baris |
| Idempotensi | `idempotency_key = {run_id}:{step_index}:{phase}`; sama di setiap percobaan |
| Hasil tak diketahui | dilarang mengulang buta; kirim `StatusQuery`; agen yang restart melapor `interrupted` lalu menjalankan `check` |
| Galat sementara | ulang dengan jeda bertahap 5 s → 30 s → 2 m → 10 m, maksimal 5 kali; lalu jadi galat permanen |
| Galat permanen | run → `compensating`: kompensasi langkah sukses dalam urutan terbalik |
| Menunggu | `wait_condition` + `next_check_at` + `wait_deadline` (default 48 jam; `agent.connected` 30 menit); habis → admin memilih tunggu lagi atau batalkan |
| Kompensasi gagal | `needs_attention`: bekukan otomasi atas sumber daya terkait, peringatan ke admin, tampilkan langkah manual + kondisi terakhir |
| Kunci sumber daya | langkah memegang `resource_locks` sesuai `resources` aksi; run lain yang bertabrakan antre |
| Versi | run mematok `capsule_version` & `action_version` saat rencana dibuat |
| Restart core | runner memindai run `running`, merekonsiliasi langkah `dispatched` lewat `StatusQuery` |
| Perubahan rencana | rencana tak boleh berubah setelah disetujui; perubahan = rencana baru + persetujuan ulang |

## P3 `server.onboard`
Urutan langkah & enrolment: `../capsules/CAPSULES.md` §4. Gagal: token kedaluwarsa atau agen tak terhubung dalam 30 menit → run `cancelled`, tidak ada perubahan server. Tak dikonfirmasi 5 menit → agen mengembalikan SSH/firewall, langkah `failed`, run berkompensasi.

## P4 `site.create`
Resep: `../capsules/CAPSULES.md` §3. Gagal: DNS belum mengarah → `waiting` sampai 48 jam lalu admin ditanya; build/migrasi gagal → kompensasi, situs lain tak tersentuh; ZIP berisi path traversal/symlink keluar/melebihi ukuran → ditolak di preflight tanpa rencana.

## P5 Persetujuan L3
1. Admin meninjau rencana (risiko tertinggi L3 disorot) dan menyentuh passkey.
2. Runner mengirim amplop; agen memverifikasi lalu memulai jeda (lama jeda: `../catalog/CATALOG.md` §1) — run `delayed`.
3. Agen mengirim notifikasi ke admin dan saksi berisi ringkasan dari isi amplop (bukan dari console).
4. Tanpa pembatalan → agen mengeksekusi → run `running`. Ada pembatalan (console, balasan bot, atau `sadmin-agent`) → `cancelled`, tercatat di audit dua sisi.

## P6 `site.archive`
Hentikan layanan situs → backup akhir → `nginx.server_block_remove` → `phpfpm.pool_remove` → sumber daya ditandai `archived`. Setelah masa tunggu 7 hari: rencana L3 menghapus DB, user Linux, direktori (jejak nol kecuali arsip backup).

## P7 Pemulihan control plane (`sadmin.restore`)
Pemegang root di server kosong Ubuntu 24.04: `deploy/install.sh --restore` → masukkan lokasi backup + kunci pemulihan → core, brankas, audit, memori, roster dipulihkan → agen tersambung kembali memakai CA yang sama → rekonsiliasi audit dua sisi. Target ≤ 60 menit. Gagal rekonsiliasi → peringatan keamanan; console tetap hidup dalam mode baca sampai admin meninjau.

## P8 Wawancara awal & memori
Jawaban wawancara menjadi `memories` lingkup institusi (`source=admin_stated`). Setiap run selesai, rollback, dan peringatan keamanan menulis memori kejadian terstruktur (`source=observed`). Memori hanya memengaruhi saran & default formulir, tidak pernah izin atau risiko.
