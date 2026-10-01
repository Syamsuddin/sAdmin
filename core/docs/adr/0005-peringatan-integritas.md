# ADR 0005 — Peringatan integritas dan kanal notifikasi core

| | |
|---|---|
| Status | **Diusulkan** — menunggu keputusan pemilik produk |
| Tanggal | 2026-10-01 |
| Pemutus | Pemilik produk. Ini perubahan keamanan (gerbang manusia, docs/22_CHANGE_POLICY.md): ADR ini menambah titik pakai nilai rahasia di luar brankas dan menentukan apakah insiden integritas sampai ke admin. Dua pilihan inti (§2.3 sinkron, §2.6 titik pakai) sudah dipilih pemilik produk pada 2026-10-01 |
| Lingkup | Kapan core membuka alert `audit_mismatch`, deduplikasi dan pencatatannya, pengiriman ke kanal notifikasi (Telegram, SMTP instansi), penyimpanan kanal beserta rahasianya, dan titik pakai `SecretValue::expose()` |
| Di luar lingkup | Alert non-critical dan aturan monitoring lain (`disk_low`, `service_down`, dst.; F-12, M3) beserta antrean `notify`. Antarmuka peringatan (lonceng topbar, `Alerts\Index`, banner "audit merah"; docs/26). Notifikasi yang dikirim agen (L3, roster; `../edge/docs/08_ARCHITECTURE.md` `Notifier`). Alert untuk `VaultIntegrityError` di luar jalur audit. Jam tenang profil admin dan ringkasan harian. Kanal sebagai bagian dokumen kebijakan bertanda tangan (M2) |
| Rujukan | docs/07_DATA_MODEL.md §Notifikasi · docs/14_ERROR_HANDLING.md (kelas Integritas) · docs/15_OBSERVABILITY.md §Peringatan · docs/21_SECURITY_RULES.md §Audit & integritas · docs/09_STACK.md (larangan `mail()`/sendmail) · docs/adr/0003-format-brankas.md · docs/adr/0004-checkpoint-audit.md |

## 1. Konteks
AC-03 (docs/23) mensyaratkan bahwa perubahan baris audit lewat SQL superuser membuat verify gagal **dan** alert `audit_mismatch` critical terkirim paling lambat 60 detik. docs/14 menggolongkan audit yang merah sebagai kelas *Integritas*: `alerts` critical dan notifikasi ke semua kanal, tanpa disembunyikan. Sampai F-04b, `sadmin:audit-verify` dan `sadmin:audit-checkpoint` hanya menulis log `critical`, sehingga admin baru tahu bila membaca log.

docs/07 sudah menetapkan tabel `notification_channels`, `alert_rules`, dan `alerts`, tetapi belum merinci:
- siapa yang membuka alert dan bagaimana mencegah satu insiden berbunyi tiap menit;
- apakah pengiriman lewat antrean atau langsung, padahal penyerang yang mengubah audit juga bisa mengubah tabel antrean;
- isi `config` kanal dan letak tokennya;
- bagaimana adaptor pengirim memegang token bot dan kata sandi SMTP, padahal ADR 0004 §2.1 hanya mengizinkan `SecretValue::expose()` di `app/Infrastructure/Vault`.

Bagian 2 bersifat **normatif**.

## 2. Keputusan (normatif)

### 2.1 Pemicu `audit_mismatch`
Alert `audit_mismatch` (severity `critical`) dibuka pada setiap kejadian berikut:

| Pendeteksi | Kejadian | `seq` alert |
|---|---|---|
| `sadmin:audit-verify` | rantai rusak (ADR 0001) | `brokenAtSeq` rantai |
| `sadmin:audit-verify` | checkpoint terbukti rusak (ADR 0004 §2.5, exit 1) | `brokenAtSeq` checkpoint |
| `sadmin:audit-checkpoint` | checkpoint ditolak karena rantai atau checkpoint terakhir rusak (status `refused`) | `brokenAtSeq` |
| `sadmin:audit-checkpoint` | checkpoint tertulis tetapi tak terverifikasi ulang (ADR 0004 §2.4 no. 7) | tidak ada |

Exit 2 `sadmin:audit-verify` (brankas tak tersedia) **bukan** `audit_mismatch` dan tidak membuka alert. Kode exit kedua perintah tidak berubah oleh ADR ini; kegagalan membuka atau mengirim alert tidak pernah mengubah exit 1 menjadi 0.

### 2.2 Penyimpanan dan deduplikasi
- Satu baris `alert_rules` per `(tenant_id, kind)` (`UNIQUE`). Baris `audit_mismatch` dibuat saat pertama dibutuhkan dengan `threshold` = `{}` dan `enabled` = true. Aturan `audit_mismatch` tidak bisa dinonaktifkan: CHECK `kind <> 'audit_mismatch' OR enabled`.
- Alert disimpan dengan `rule_id` aturan itu, `server_id` NULL, `severity` `critical`, `status` `open`, `title` dari `lang/id/alerts.php`, dan `detail` jsonb `{"detector", "check", "seq", "reason"}`. `detector` = nama perintah artisan, `check` ∈ `chain`, `checkpoint`, `checkpoint_create`, `checkpoint_readback`. `detail` tidak pernah memuat nilai rahasia.
- Kunci deduplikasi `alerts.dedup_key`: `audit_mismatch:seq:<seq>`, atau `audit_mismatch:checkpoint_readback` bila tidak ada `seq`. Indeks unik parsial `(tenant_id, dedup_key) WHERE dedup_key IS NOT NULL AND status <> 'resolved'` menjamin paling banyak satu alert belum selesai per kunci, juga bila verify harian dan checkpoint tiap menit mendeteksi bersamaan. Kerusakan di `seq` lain = alert baru, sehingga alert lama yang belum diselesaikan tidak membungkam kerusakan baru.
- Membuka alert = `INSERT … ON CONFLICT DO NOTHING`. Hanya alert yang benar-benar baru menulis entri audit `alert.open` (aktor `system`, target `alert:<id>`, `params_redacted` = `{"kind", "severity", "seq"}`) dalam transaksi yang sama (docs/21).
- ID alert (ULID) dibuat sebelum transaksi. Bila penyimpanan gagal (DB rusak atau ditolak), kegagalan dicatat log `critical` `alert_store_failed` dan pengiriman **tetap** dijalankan dengan ID itu sebagai ID korelasi.

### 2.3 Pengiriman sinkron
- Alert integritas dikirim **langsung oleh proses pendeteksi**, sesudah transaksi penyimpanan selesai, tidak lewat antrean. Batas 60 detik dengan begitu tidak bergantung pada worker antrean, dan penyerang berhak SQL tidak bisa membungkamnya dengan menghapus baris tabel `jobs`.
- Dikirim bila alert baru, atau alert lama dengan kunci yang sama masih ber-`notified_at` NULL (pengiriman sebelumnya gagal total). Alert yang sudah terkirim tidak dikirim ulang.
- Tujuan: semua `notification_channels` tenant itu yang berstatus `active` (docs/14 "semua kanal"). Jam tenang diabaikan karena severity `critical` (docs/15).
- Anggaran waktu: 50 detik sejak pengiriman dimulai. Putaran pertama mencoba tiap kanal sekali; kanal yang gagal dicoba sekali lagi setelah jeda 2 detik. Timeout satu percobaan = min(10 detik, sisa anggaran); percobaan tidak dimulai bila sisa anggaran < 1 detik. Kegagalan satu kanal tidak menghentikan kanal lain.
- Bila sedikitnya satu kanal berhasil: `notified_at` diisi dan entri audit `alert.notify` ditulis (aktor `system`, target `alert:<id>`, `params_redacted` = `{"delivered", "failed"}` berisi jumlah kanal) dalam satu transaksi. Hanya keberhasilan yang diaudit, sehingga percobaan ulang tidak menumbuhkan audit tanpa batas.
- Bila tak satu kanal pun berhasil, termasuk bila tak ada kanal aktif: log `critical` `alert_undelivered`, `notified_at` tetap NULL, dan pengiriman dicoba lagi pada deteksi berikutnya. Kegagalan per kanal dicatat log `error` `alert_notify_failed` (ID alert, ID kanal, jenis, kelas galat, pesan yang sudah dibersihkan).

### 2.4 Isi pesan
- Teks polos Bahasa Indonesia dengan tiga bagian docs/14 (langkah, penyebab, tindakan) dan ID korelasi = ID alert, diawali `[CRITICAL]` dan hostname console (`institutions.console_hostname`) agar admin tahu instalasi mana. Teks bakunya ada di `lang/id/alerts.php`.
- `reason` dari verifier dipotong ke 500 karakter. Telegram dikirim tanpa `parse_mode` sehingga tak ada teks yang ditafsirkan sebagai markup, dan dengan `disable_web_page_preview`. Email bertipe `text/plain`.

### 2.5 Kanal
- `notification_channels.status` ∈ `active`, `inactive`. `secret_id` wajib dan menunjuk rahasia ber-`purpose` sesuai jenis kanal. Isi `config` (tanpa rahasia):

| `kind` | `config` | Rahasia (`purpose`) |
|---|---|---|
| `telegram` | `{"chat_id": "<string>"}`: bilangan bulat bertanda (`^-?[0-9]{1,20}$`) atau `@nama_kanal` (`^@[A-Za-z0-9_]{5,32}$`) | token bot (`telegram_token`), `^[0-9]{5,20}:[A-Za-z0-9_-]{30,64}$` |
| `smtp` | `{"host", "port" (1–65535), "tls" ∈ "implicit"/"starttls", "username", "from", "to": [1–10 alamat]}` | kata sandi akun SMTP (`smtp`) |

- SMTP selalu terenkripsi: `implicit` = skema `smtps`, `starttls` = skema `smtp` dengan `require_tls`. Transport dibangun lewat `SendmailRefusingMailManager` sehingga jalur sendmail tetap tertolak (docs/09).
- Di M1, kanal hanya ditambah lewat `php artisan sadmin:notify-channel-add` oleh root di host (aktor `local_root`). Token atau kata sandi dibaca dari prompt tersembunyi, tidak pernah dari argumen baris perintah (riwayat shell, `ps`). Rahasia disimpan lewat `StoreSecret` (ADR 0003), lalu baris kanal dan entri audit `notification_channel.create` (target `notification_channel:<id>`, `params_redacted` = `{"kind"}`) ditulis dalam satu transaksi. `chat_id` dan alamat email tidak masuk audit, karena audit tidak bisa dihapus sedangkan data pribadi harus bisa dihapus (docs/21).
- `php artisan sadmin:notify-test` mengirim pesan uji ke semua kanal aktif lewat jalur yang sama dengan §2.3, lalu mencetak hasil per kanal. Perintah ini tidak membuka alert dan tidak menulis audit karena tidak mengubah state.

### 2.6 Titik pakai nilai rahasia
- `SecretValue::expose()` hanya boleh dipanggil di `app/Infrastructure/Vault` dan `app/Infrastructure/Notify`. Kode domain, perintah artisan, Livewire, HTTP, dan model tetap dilarang. Ini **mengubah** kalimat terakhir ADR 0004 §2.1. Seed Ed25519 tetap tidak bisa sampai ke Notify karena `Vault::reveal()` menolak purpose `audit_key` dan `service_key`.
- Adaptor Notify membuka rahasia sendiri lewat `Vault::reveal(secret_id, purpose sesuai jenis kanal, tenant_id)`, tepat sebelum koneksi. Kode domain hanya memegang ID kanal, tidak pernah nilainya. `secret_id` yang ditukar ke rahasia ber-purpose lain gagal dengan `VaultIntegrityError`.
- Token Telegram berada di path URL Bot API. Karena itu adaptor menangkap setiap galat dari pustaka HTTP/SMTP, menghapus nilai rahasia dan pola `/bot<…>/` dari pesannya, lalu melempar `NotifyFailed` **tanpa** merantai galat aslinya. Galat asli tidak pernah dicatat atau dilempar ke luar.

## 3. Alternatif yang dipertimbangkan
| Alternatif | Ditolak karena |
|---|---|
| Kirim lewat antrean `notify` (driver database) | Bergantung worker yang hidup, dan baris `jobs` bisa dihapus penyerang yang sama dengan pengubah audit. Tetap dipakai untuk alert non-critical F-12 |
| Metode brankas ber-callback (`Vault::use(…, fn($nilai) => …)`) | Nilai polos tetap sampai ke kode Notify. Pola ini hanya memindahkan titik buka dan menyamarkan aturan, bukan mengamankannya |
| Satu alert `audit_mismatch` terbuka per tenant | Alert lama yang belum diselesaikan (UI belum ada) membungkam kerusakan baru di tempat lain |
| Tanpa deduplikasi | Checkpoint tiap menit akan mengirim notifikasi dan menulis audit tiap menit selama rantai rusak |
| Audit tiap percobaan kirim | Kanal yang mati membuat audit tumbuh tiap menit. Keberhasilan saja yang bermakna sebagai bukti |
| Penerima dari `admins.email` dan `contacts` | `contacts` adalah saksi L3 yang dilayani agen; `admins.email` opsional. Penerima eksplisit per kanal lebih bisa diperkirakan |
| Telegram `parse_mode` HTML/Markdown | Alasan dari verifier harus di-escape. Teks polos tidak bisa salah tafsir |
| Halaman pengaturan kanal di console sekarang | Menunggu inventaris `Settings\*` (docs/26) dan kebijakan bertanda tangan (M2). Perintah artisan cocok dengan pola bootstrap `install.sh` |

## 4. Konsekuensi
- AC-03 butir 2 terpenuhi bila kanal merespons: deteksi ditambah paling lama 50 detik pengiriman. Bila semua kanal mati, alert tetap tersimpan dan dicoba lagi pada deteksi berikutnya. Itu terjadi paling lambat 1 menit untuk pemotongan atau penulisan ulang ujung rantai (pemeriksaan awal checkpoint), paling lambat 15 menit untuk segmen sesudah checkpoint terakhir, dan paling lambat sehari (verify harian) untuk kerusakan sebelum checkpoint terakhir.
- Alert belum bisa diakui atau diselesaikan karena UI-nya belum ada, sehingga status tetap `open`. Kerusakan di `seq` lain tetap membuka alert baru.
- Penyerang berhak superuser masih bisa menonaktifkan kanal atau mengubah baris alert sebelum dikirim. Pertahanan sesungguhnya ada di luar DB core: jangkar audit di agen dan `Notifier` agen (paket edge, ADR 0004 §4).
- Kanal belum termasuk kebijakan bertanda tangan. Saat `policy_bundles` hadir (M2), mengubah kanal menjadi perubahan kebijakan L3 dengan jeda 24 jam, dan perintah tambah kanal harus mengikuti jalur itu.
- Titik pakai rahasia kini dua direktori. Menambah direktori ketiga (mis. `Infrastructure/Ai` untuk kunci API) butuh revisi ADR ini.

## 5. Penegakan
| Klausul | Dijaga oleh |
|---|---|
| 2.1 pemicu dan kode exit | `AuditMismatchAlertTest` |
| 2.2 aturan tak bisa dinonaktifkan, satu aturan per jenis, CHECK enum, indeks deduplikasi | `AlertSchemaTest` |
| 2.2 deduplikasi, audit `alert.open`, kirim walau penyimpanan gagal | `RaiseIntegrityAlertTest` |
| 2.3 sinkron, semua kanal, anggaran waktu, ulang sekali, `notified_at`, audit `alert.notify` | `RaiseIntegrityAlertTest`, `AuditMismatchAlertTest` |
| 2.4 isi pesan, teks polos | `NotifierTest` |
| 2.5 validasi kanal, rahasia lewat prompt, audit tanpa data pribadi, TLS wajib, sendmail tertolak | `NotificationChannelCommandsTest`, `NotifierTest` |
| 2.6 titik pakai `expose()`, galat dibersihkan, rahasia tak bocor ke log/audit/alert | `VaultBoundaryTest`, `NotifyRedactionTest` (grup `redaction`) |

## 6. Riwayat
- 2026-10-01: diusulkan bersama slice F-04c Alert audit_mismatch (M1). Pengiriman sinkron (§2.3) dan titik pakai di `Infrastructure/Notify` (§2.6) dipilih pemilik produk sebelum implementasi.
