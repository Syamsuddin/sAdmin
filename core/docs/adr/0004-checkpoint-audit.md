# ADR 0004 — Checkpoint audit bertanda tangan

| | |
|---|---|
| Status | **Diusulkan** — menunggu keputusan pemilik produk |
| Tanggal | 2026-10-01 |
| Pemutus | Pemilik produk. Format checkpoint dan isi yang ditandatangani termasuk gerbang manusia (docs/22_CHANGE_POLICY.md, "perubahan format rantai audit atau checkpoint"; `../kontrak/KONTRAK.md` §1). Setelah checkpoint produksi pertama dijangkarkan ke agen, mengubah format memutus verifikasi riwayat |
| Lingkup | Kunci audit (pembuatan, penyimpanan, kunci publik), format tanda tangan checkpoint, penyimpanan `audit_checkpoints`, kapan checkpoint dibuat, dan cara `sadmin:audit-verify` memakainya |
| Di luar lingkup | Jangkar ke agen, offsite, dan digest harian (`anchored_to`), yang menunggu paket edge, backup offsite, dan notifikasi. Alert `audit_mismatch` (slice Alerts). Rotasi kunci audit. Pencabutan hak `UPDATE/DELETE/TRUNCATE` dari role aplikasi (slice `install.sh`) |
| Rujukan | docs/07_DATA_MODEL.md §Audit, §Rahasia · docs/21_SECURITY_RULES.md §Audit & integritas · `../kontrak/KONTRAK.md` §3 (format tanda tangan, normatif di sana) · docs/adr/0001-format-rantai-audit.md · docs/adr/0003-format-brankas.md |

## 1. Konteks
ADR 0001 §4 mencatat dua serangan yang tidak terdeteksi `sadmin:audit-verify` jika hanya memeriksa rantai: **pemotongan ujung rantai** dan **penulisan ulang seluruh rantai dari suatu titik** oleh pihak berhak superuser. Keduanya tetap menghasilkan rantai yang konsisten. docs/21 menjawabnya dengan checkpoint bertanda tangan tiap 15 menit atau 100 entri, docs/07 menetapkan tabel `audit_checkpoints`, dan KONTRAK menetapkan kunci audit Ed25519 yang terpisah dari kunci layanan.

Namun dokumen-dokumen itu belum merinci hal-hal berikut:
- byte yang ditandatangani dan pengodeannya;
- di mana kunci audit disimpan, bagaimana core menemukannya, dan siapa yang membuatnya;
- kapan checkpoint dibuat tanpa membebani jalur tulis audit;
- bagaimana mencegah checkpoint baru "mencuci" rantai yang sudah diubah;
- bagaimana verify memakai checkpoint, dan apa yang terjadi bila brankas tidak tersedia.

Begitu checkpoint pertama dijangkarkan ke agen (`CheckpointAnchor`), rincian ini tak dapat diubah tanpa memutus verifikasi. Karena itu rincian dikunci di sini. Bagian 2 bersifat **normatif**.

## 2. Keputusan (normatif)

### 2.1 Kunci audit
- Kunci audit adalah kunci Ed25519. Bagian privatnya disimpan sebagai *seed* 32 byte (RFC 8032) di satu baris `secrets` ber-`purpose` `audit_key`, sehingga terenkripsi envelope oleh brankas (ADR 0003). Seed tidak pernah disimpan di tempat lain. Kunci publik diturunkan dari seed.
- Setiap tenant punya **tepat satu** kunci audit aktif. Ini dijaga indeks unik parsial `secrets_one_active_audit_key` pada `secrets (tenant_id) WHERE purpose = 'audit_key' AND status = 'active'`.
- Kunci audit hanya dibuat oleh `php artisan sadmin:audit-key-init`, yang kelak dipanggil `install.sh` (F-01):
  1. instansi wajib sudah diinisialisasi, karena kunci terikat ke tenant instansi;
  2. bila sudah ada kunci audit aktif, perintah menolak. Mengganti kunci audit adalah rotasi, yang butuh gerbang manusia (docs/22) dan ADR baru;
  3. dalam satu transaksi: seed dibuat dengan CSPRNG lalu disimpan lewat brankas (entri audit `secret.store`), kemudian entri audit `audit.key_initialize` ditulis (aktor `local_root`, target `secret:<id>`, `params_redacted` = `{"public_key": "<base64>"}`);
  4. perintah mencetak kunci publik (base64 standar, 44 karakter). Admin mencatatnya di kit pemulihan dan menyerahkannya kepada auditor.
- Core **tidak pernah** membuat kunci audit secara implisit, misalnya saat checkpoint pertama. Dengan begitu, kunci yang hilang atau dihancurkan tidak diam-diam terganti kunci baru.
- Seed hanya dibuka di dalam `App\Infrastructure\Vault` (`Vault::signEd25519()` dan `Vault::ed25519PublicKey()`). Kode domain tidak pernah memegang byte seed. Fungsi `sodium_crypto_sign_*` hanya dipanggil di `app/Infrastructure/Vault`.
- Di dalam core, akar kepercayaan verifikasi adalah kunci publik yang **diturunkan dari seed di brankas**, bukan kunci publik yang tercatat di DB. Memalsukan checkpoint menuntut kunci induk brankas, bukan sekadar akses tulis ke DB. Di luar core, akar kepercayaannya adalah salinan kunci publik di kit pemulihan dan di agen (`audit_pubkey`).

### 2.2 Format tanda tangan
Normatif di `../kontrak/KONTRAK.md` §3 (satu rumah untuk protokol, karena agen menerima dan menyimpan `CheckpointAnchor`). Ringkasnya:

```
signature = base64( Ed25519_sign( seed, "sadmin-audit-checkpoint/1" ∥ 0x0A ∥ JCS({"created_at", "hash", "seq"}) ) )
```

Vektor emas `../kontrak/vectors/checkpoint/*.json` dihitung oleh oracle independen yang hanya memakai teks KONTRAK dan pustaka Python `cryptography` (OpenSSL), tanpa kode core maupun sodium PHP.

### 2.3 Penyimpanan (`audit_checkpoints`)
- Satu baris per checkpoint. `seq` (PK) adalah `seq` entri terakhir yang dicakup. Kolom ini sengaja **tanpa** FK ke `audit_entries.seq`: FK membuat PostgreSQL menolak `TRUNCATE audit_entries` lewat pemeriksaan FK sebelum trigger append-only ADR 0001 §2.5 berjalan, dan pihak yang bisa mematikan trigger juga bisa membuang FK. Keberadaan entri diperiksa verify (§2.5). `hash` adalah `hash` entri itu. `signature` adalah tanda tangan §2.2 (88 karakter). `created_at` bertipe `timestamptz(6)` dan berisi waktu yang ikut ditandatangani.
- `tenant_id` adalah tenant instansi (MVP satu tenant). Kunci yang memverifikasi adalah kunci audit aktif tenant itu.
- `anchored_to` adalah himpunan bagian `{agents, offsite, digest}` dan bernilai `{}` saat dibuat. Slice jangkar kelak menambah anggotanya.
- Constraint `CHECK`: `hash` 64 hex huruf kecil, `signature` berbentuk base64 standar 88 karakter, `anchored_to` himpunan bagian nilai sah.
- Trigger menolak `DELETE` dan `TRUNCATE`. `UPDATE` juga ditolak, kecuali bila hanya `anchored_to` yang berubah dan nilai barunya mencakup nilai lama (jangkar hanya bertambah).

### 2.4 Pembuatan checkpoint
`php artisan sadmin:audit-checkpoint` menjalankan langkah berikut dalam satu transaksi:
1. Ambil `pg_advisory_xact_lock(7301002)`. Kunci ini menyerialkan pembuat checkpoint tanpa memblokir penulis audit (kunci rantai 7301001).
2. Baca checkpoint terakhir (`seq` terbesar) dan ujung rantai (entri `seq` terbesar yang sudah di-commit).
3. Bila tidak ada entri baru sejak checkpoint terakhir, selesai tanpa membuat apa pun.
4. Dengan opsi `--if-due` (dipakai penjadwal), checkpoint hanya dibuat bila **jatuh tempo**: belum ada checkpoint sama sekali, **atau** ujung rantai minus `seq` checkpoint terakhir ≥ 100, **atau** sudah ≥ 15 menit sejak `created_at` checkpoint terakhir.
5. Sebelum menandatangani, buktikan segmen yang akan dicakup:
   - tanda tangan checkpoint terakhir sah;
   - entri ber-`seq` itu ada, `hash` tersimpannya sama dengan `hash` checkpoint, dan hash hasil hitung ulang dari isinya cocok;
   - setiap entri sesudahnya sampai ujung lolos pemeriksaan ADR 0001 §2.7 dan menyambung.

   Tanpa checkpoint sebelumnya, segmen yang dibuktikan adalah seluruh rantai sejak genesis. Bila pembuktian gagal, checkpoint **tidak** ditandatangani, log `critical` `audit_mismatch` ditulis, dan perintah exit 1. Alasannya: checkpoint baru tidak boleh mengesahkan rantai yang sudah diubah.
6. Tandatangani (`seq` ujung, `hash` ujung, `created_at` = waktu sekarang UTC presisi mikrodetik), lalu sisipkan baris dengan `anchored_to` = `{}`.
7. **Tertulis ⇒ terverifikasi:** baca ulang baris itu dan verifikasi tanda tangannya dengan kunci publik dari brankas. Bila tidak cocok, transaksi dibatalkan.

Aturan tambahan:
- Membuat checkpoint **tidak** menulis entri audit. Checkpoint adalah artefak audit itu sendiri. Bila setiap checkpoint menulis entri, rantai tak pernah sepi dan setiap checkpoint memicu checkpoint berikutnya.
- Penjadwal menjalankan `sadmin:audit-checkpoint --if-due` tiap menit. Janji "tiap 15 menit atau 100 entri" docs/21 dipenuhi dengan resolusi satu menit.
- Checkpoint tidak dibuat di dalam transaksi `AppendAuditEntry`, supaya brankas dan penandatanganan tidak masuk jalur tulis audit. Brankas yang tidak tersedia tidak boleh menggagalkan login atau aksi lain.
- Bila instansi belum diinisialisasi, kunci audit belum ada, atau brankas tidak tersedia, perintah gagal (exit 1, log `error` `audit_checkpoint_failed`) tanpa membuat checkpoint. Bila kunci audit di brankas gagal dibuka (`VaultIntegrityError`), log yang sama ditulis sebagai `critical` (kelas *Integritas* docs/14).

### 2.5 Verifikasi
`php artisan sadmin:audit-verify` lebih dulu memeriksa rantai persis seperti ADR 0001 §2.7. Bila rantai utuh, checkpoint diperiksa urut `seq` dan berhenti di pelanggaran pertama:

| Urutan | Pemeriksaan | Bila gagal |
|---|---|---|
| 1 | Kunci audit aktif milik tenant checkpoint ada | "kunci audit aktif tenant tidak ada padahal checkpoint ada" |
| 2 | Tanda tangan sah atas (`seq`, `hash`, `created_at`) | "tanda tangan checkpoint tidak sah" |
| 3 | `seq` ≤ ujung rantai | "rantai berakhir sebelum checkpoint (ujung rantai terpotong)" |
| 4 | `hash` = `hash` entri ber-`seq` itu | "hash entri berbeda dengan checkpoint (rantai ditulis ulang)" |

- **Exit 0:** rantai utuh dan semua checkpoint sah, atau rantai utuh dan belum ada checkpoint. Keluaran menyebut jumlah checkpoint, `seq` checkpoint terakhir, dan jumlah entri sesudahnya yang belum tercakup.
- **Exit 1:** rantai atau checkpoint rusak. Log `critical` `audit_mismatch` berisi `reason`, `last_intact_seq`, serta `broken_at_seq` (rantai) atau `checkpoint_seq` (checkpoint). Kelas *Integritas* docs/14.
- **Exit 2:** rantai utuh, tetapi checkpoint tidak dapat diperiksa karena brankas tidak tersedia. Log `error` `audit_verify_incomplete`. Kelas *Galat infrastruktur core* docs/14.
- Brankas hanya dimuat bila ada checkpoint. Rantai tanpa checkpoint tetap bisa diverifikasi tanpa kunci induk.
- Seperti ADR 0001 §2.7, alasan yang tampil maupun tercatat tidak pernah menggemakan isi entri.

## 3. Alternatif yang dipertimbangkan
| Alternatif | Ditolak karena |
|---|---|
| Tanda tangan per entri | Sudah ditolak ADR 0001 §3: mahal dan menaruh kunci di jalur tulis |
| HMAC dengan kunci rahasia, bukan tanda tangan | Agen, alat offsite, dan auditor harus memegang kunci rahasia untuk memverifikasi |
| Memakai kunci layanan core | KONTRAK memisahkan keduanya. Kunci layanan dipakai di setiap amplop; kebocorannya tidak boleh sekaligus memungkinkan pemalsuan riwayat |
| Pesan = JCS objek dengan anggota `format` | Setara amannya. Awalan tetap sudah memisahkan domain tanpa menambah anggota yang harus dibawa `CheckpointAnchor` |
| `tenant_id` ikut ditandatangani | `CheckpointAnchor` tidak membawa `tenant_id`. Kunci audit per tenant sudah mengikat checkpoint ke tenantnya |
| Ed25519ph atau Ed25519ctx | Pesannya pendek. Ed25519 murni didukung sodium PHP dan `crypto/ed25519` Go apa adanya |
| Kunci publik di kolom DB sebagai akar kepercayaan | Pihak berhak tulis DB bisa mengganti kunci publik lalu menandatangani ulang dengan kuncinya sendiri. Kunci turunan dari brankas menuntut kunci induk |
| Kunci audit dibuat otomatis saat checkpoint pertama | Kunci yang hilang atau dihancurkan akan diam-diam terganti. Gagal tertutup lebih aman |
| Checkpoint di dalam transaksi `AppendAuditEntry` tiap 100 entri | Brankas dan penandatanganan masuk jalur tulis. Brankas yang tidak tersedia akan menggagalkan setiap aksi, termasuk login |
| Checkpoint menulis entri audit | Rantai tak pernah sepi, sehingga setiap checkpoint memicu checkpoint berikutnya tanpa henti |

## 4. Konsekuensi
- **Kini terdeteksi tanpa jangkar:** pemotongan ujung rantai di bawah `seq` checkpoint mana pun, penulisan ulang rantai dari titik ≤ `seq` checkpoint mana pun, serta checkpoint yang dipalsukan atau diubah. Memalsukan checkpoint menuntut kunci induk brankas.
- **Belum terdeteksi sampai jangkar ada:**
  - penghapusan checkpoint (trigger dimatikan superuser) yang disertai pemotongan atau penulisan ulang;
  - perubahan pada entri sesudah checkpoint terakhir, yang paling lama mencakup 15 menit atau 100 entri. Entri ini hanya dilindungi rantai;
  - penyerang yang memegang kunci induk (root di host sAdmin).

  Ketiganya hanya bisa dibantah oleh salinan di luar DB core: jangkar agen, offsite, dan digest (slice berikutnya, kolom `anchored_to`).
- Verifikasi checkpoint membutuhkan brankas, sehingga unit penjadwal wajib memuat kredensial kunci induk (ADR 0003 §4).
- Rotasi kunci audit belum didukung. Checkpoint tidak menyimpan identitas kunci, jadi rotasi butuh ADR baru (menambah rujukan kunci per checkpoint) dan gerbang docs/22.
- Mengubah §2.2 atau KONTRAK §3 setelah checkpoint produksi pertama adalah perubahan major kontrak dan butuh gerbang manusia.
- Biaya: setiap checkpoint membuktikan entri sejak checkpoint sebelumnya (paling banyak sekitar 100 entri per menit penjadwal). Verify harian tetap O(jumlah entri) ditambah O(jumlah checkpoint).

## 5. Penegakan
| Klausul | Dijaga oleh |
|---|---|
| 2.1 satu kunci aktif, pembuatan eksplisit, kunci tidak bocor | `InitializeAuditKeyTest` (termasuk grup `redaction`), indeks `secrets_one_active_audit_key` |
| 2.1 satu pintu `sodium_crypto_sign_*` | `VaultBoundaryTest` |
| 2.2 format tanda tangan | `CheckpointSignatureVectorsTest` (suite Contract), `Ed25519Test` (vektor RFC 8032) |
| 2.3 trigger, FK, CHECK | `CreateAuditCheckpointTest` |
| 2.4 jatuh tempo, pembuktian segmen, tertulis ⇒ terverifikasi, gagal tertutup | `CreateAuditCheckpointTest` |
| 2.5 verifikasi dan kode exit | `AuditCheckpointTamperTest` |

## 6. Riwayat
- 2026-10-01: diusulkan bersama slice F-04b Checkpoint audit (M1).
