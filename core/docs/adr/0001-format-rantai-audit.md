# ADR 0001 — Format hash rantai audit

| | |
|---|---|
| Status | **Diterima** — disetujui pemilik produk, 2026-09-30 |
| Tanggal | 2026-09-30 (disusun ulang 2026-09-30) |
| Pemutus | Pemilik produk. Mengubah format setelah ada data produksi = gerbang manusia (docs/22_CHANGE_POLICY.md, "perubahan format rantai audit atau checkpoint") |
| Lingkup | Rantai `audit_entries` di core: cara entri di-hash, disimpan, ditulis, dan diverifikasi |
| Di luar lingkup | Checkpoint bertanda tangan dan jangkar (slice F-04 berikutnya); rantai audit lokal agen (`../edge/docs/07_DATA_MODEL.md`) |
| Rujukan | docs/07_DATA_MODEL.md §Audit · docs/21_SECURITY_RULES.md §Audit & integritas · `../kontrak/KONTRAK.md` §3 · docs/_archive/23-audit.md (AC-03, diterima) |

## 1. Konteks
docs/07 menetapkan rumus `hash = SHA-256(prev_hash ∥ JCS(entri tanpa hash))`, tetapi tidak merinci bentuk tiap field di dalam JCS. Rincian itu menentukan setiap byte yang di-hash, sehingga:
- dua implementasi yang berbeda sedikit saja (mis. presisi waktu, `{}` lawan `[]`) menghasilkan hash berbeda dan saling menuduh rantai rusak;
- begitu entri produksi pertama tertulis, rincian ini tak dapat diubah tanpa memutus verifikasi seluruh riwayat;
- verifikator independen (tool offsite, auditor, paket lain) harus bisa menghitung ulang hash tanpa membaca kode core.

Karena itu rincian dikunci di sini sebelum ada data produksi. Bagian 2 bersifat **normatif**: kata "wajib" berarti implementasi yang menyimpang menghasilkan rantai yang tak terverifikasi.

## 2. Keputusan (normatif)

### 2.1 Rantai
- Satu rantai global untuk seluruh `audit_entries` (MVP satu tenant; `tenant_id` ikut di-hash).
- `seq` dimulai dari 1 dan naik tepat 1 per entri, tanpa celah dan tanpa cabang.
- Entri genesis (`seq` = 1) memiliki `prev_hash` berupa 64 karakter `0`.
- Setiap entri berikutnya memiliki `prev_hash` = `hash` entri sebelumnya.

### 2.2 Badan entri yang di-hash
Badan entri adalah satu objek JSON berisi **tepat dua belas** anggota di bawah, bernama persis seperti kolom `audit_entries`. Kolom `hash` tidak ikut. Anggota bernilai kosong tetap hadir dengan nilai `null`, tidak dihilangkan.

| Anggota | Tipe JSON | Aturan nilai |
|---|---|---|
| `seq` | integer | ≥ 1 |
| `tenant_id` | string | ULID 26 karakter, persis seperti tersimpan (tanpa normalisasi huruf) |
| `prev_hash` | string | 64 karakter hex huruf kecil |
| `occurred_at` | string | RFC 3339 UTC berakhiran `Z`, tepat 6 digit mikrodetik: `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `actor_type` | string | salah satu: `admin`, `witness`, `runner`, `agent`, `system`, `ai`, `local_root` |
| `actor_id` | string atau `null` | teks bebas tanpa byte NUL |
| `action_key` | string | tak kosong, tanpa byte NUL (mis. `console.login`) |
| `target` | string atau `null` | teks bebas tanpa byte NUL (mis. `admin:<ULID>`) |
| `params_redacted` | objek, larik, atau `null` | sudah disamarkan pemanggil (docs/21); tanpa byte NUL di kunci maupun nilai |
| `outcome` | string | salah satu: `ok`, `rejected`, `failed`, `cancelled` |
| `envelope_ref` | string atau `null` | ULID 26 karakter |
| `emergency_local` | boolean | `true` atau `false` |

### 2.3 Kanonisasi
- Badan entri dikanonisasi dengan **RFC 8785 (JCS)** di bawah aturan masukan `../kontrak/KONTRAK.md` §3 (I-JSON). Artinya: UTF-8 sah, tanpa nama anggota ganda, nama anggota tanpa U+0000, angka hanya integer dengan |n| ≤ 2^53−1, dan tanpa angka pecahan.
- Kedalaman sarang maksimal 64 tingkat, dihitung dari objek badan itu sendiri. Dengan demikian `params_redacted` maksimal 63 tingkat.
- Implementasi core: `app/Infrastructure/Jcs`, diuji terhadap vektor bersama `../kontrak/vectors/jcs` dan `../kontrak/vectors/jcs-reject`.

### 2.4 Hash
```
hash = lowercase_hex( SHA-256( prev_hash ∥ JCS(badan) ) )
```
`prev_hash` disambung sebagai 64 byte ASCII, langsung diikuti byte UTF-8 hasil JCS, tanpa pemisah. Karena itu `prev_hash` sengaja ikut dua kali: sebagai awalan, dan sebagai anggota badan.

### 2.5 Penyimpanan
- `occurred_at` disimpan di kolom `timestamptz(6)`, sehingga nilai yang dibaca ulang identik sampai mikrodetik. Sesi basis data wajib ber-zona UTC.
- `params_redacted` dikirim ke kolom `jsonb` sebagai teks kanonik, tetapi **jsonb menormalkan ulang penyimpanannya**: urutan kunci diubah dan spasi disisipkan. Verifikator mana pun **wajib** mendekode nilai itu dengan objek tetap sebagai objek, lalu mengkanonisasi ulang. Teks `params_redacted::text` **tidak boleh** di-hash apa adanya.
- Byte NUL dilarang di semua field teks dan di `params_redacted`, karena PostgreSQL memotong `text` di NUL secara diam-diam dan menolak `\u0000` di `jsonb`.
- Tabel bersifat append-only. Trigger menolak `UPDATE`, `DELETE`, dan `TRUNCATE`, dan kolom `hash` bersifat `UNIQUE`.

### 2.6 Penulisan
1. Penulisan berlangsung di dalam transaksi Action pemilik perubahan state, sehingga entri dan perubahannya jadi atau batal bersama (docs/21).
2. Sebelum membaca ujung rantai, penulis mengambil `pg_advisory_xact_lock(7301001)`. Kunci ini menjamin `seq` tanpa celah dan tanpa cabang walau penulisan berjalan paralel.
3. Penulis membentuk badan (§2.2), menghitung hash (§2.4), lalu menyisipkan baris.
4. **Invarian "tertulis ⇒ terverifikasi":** sebelum commit, penulis membaca ulang baris itu, lalu mencocokkan kolom `hash` yang tersimpan dan hash hasil hitung ulang dari isi baris. Bila keduanya tidak identik, penulisan dibatalkan.
   - Alasannya: rantai tak bisa diperbaiki (append-only), dan verifikasi berhenti di kerusakan pertama. Satu entri yang tak terverifikasi akan membutakan pemeriksaan semua entri sesudahnya.

### 2.7 Verifikasi
`php artisan sadmin:audit-verify` menelusuri seluruh baris urut `seq` dari genesis, dan berhenti di pelanggaran pertama:

| Urutan | Pemeriksaan | Bila gagal |
|---|---|---|
| 1 | `seq` = `seq` sebelumnya + 1 (genesis: 1) | "entri seq N hilang (rantai bercelah)" |
| 2 | `prev_hash` = `hash` entri sebelumnya (genesis: 64 nol) | "prev_hash tak sama dengan hash entri sebelumnya" |
| 3 | Badan dapat dibentuk ulang dari baris (§2.2–2.5) | "isi entri tak dapat dikanonisasi" |
| 4 | Hash hasil hitung ulang = kolom `hash` | "hash tak cocok dengan isi entri" |

- Hasil utuh: exit 0, mencetak jumlah entri dan ujung rantai (`seq`, `hash`).
- Hasil rusak: exit 1, log `critical` `audit_mismatch` berisi `broken_at_seq`, `reason`, dan `last_intact_seq`.
- Verifikasi **tidak pernah crash** karena isi baris. Alasan yang tampil maupun tercatat tidak pernah menggemakan isi entri: hanya pesan JCS/JSON yang tetap, atau nama kelas galat.

### 2.8 Vektor emas
Implementasi apa pun wajib menghasilkan hash yang sama untuk masukan ini:

```
badan (sebelum kanonisasi)
  seq 1 · tenant_id "01k6d4v8m2q9x7c3b5n1r0t6yz" · prev_hash 64×"0"
  occurred_at "2026-09-30T02:11:12.345678Z" (masukan 10:11:12.345678+08:00)
  actor_type "admin" · actor_id "admin-1" · action_key "console.login" · target null
  params_redacted {"b": [], "a": {"ok": true}} · outcome "ok" · envelope_ref null · emergency_local false

JCS(badan)
{"action_key":"console.login","actor_id":"admin-1","actor_type":"admin","emergency_local":false,"envelope_ref":null,"occurred_at":"2026-09-30T02:11:12.345678Z","outcome":"ok","params_redacted":{"a":{"ok":true},"b":[]},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","seq":1,"target":null,"tenant_id":"01k6d4v8m2q9x7c3b5n1r0t6yz"}

hash
0676afeb6ed67d29dd0b57eebf2b6c5d3817cb7a8cf0f8d21685d7f45da60695
```

## 3. Alternatif yang dipertimbangkan

| Alternatif | Ditolak karena |
|---|---|
| Hash hanya `JCS(badan)`, tanpa awalan `prev_hash` | Menyimpang dari rumus docs/07. Awalan juga membuat tautan rantai eksplisit tanpa bergantung pada isi badan |
| `occurred_at` presisi detik | Kolom `timestamptz(6)` menyimpan mikrodetik; memotongnya membuat nilai tersimpan ≠ nilai yang di-hash, kecuali ada konversi tambahan yang rawan salah |
| Meng-hash teks `jsonb` apa adanya | jsonb menormalkan ulang urutan kunci dan spasi, jadi teks yang dibaca ulang tidak pernah sama dengan teks yang di-hash |
| Nomor `seq` dari SEQUENCE PostgreSQL | Transaksi yang batal meninggalkan celah, sehingga celah sah tak dapat dibedakan dari penghapusan |
| Tanda tangan per entri | Mahal di setiap tulis dan butuh kunci di jalur panas. Checkpoint bertanda tangan per 15 menit atau 100 entri (docs/21) memberi jaminan yang sama lebih murah |

## 4. Konsekuensi
- **Terdeteksi oleh verify:** perubahan isi kolom mana pun, penghapusan entri di tengah (sebagai celah), dan penggantian satu entri beserta hash hasil hitung ulang (tautan ke entri berikutnya putus).
- **Tidak terdeteksi oleh verify saja:** pemotongan ujung rantai, dan penulisan ulang seluruh rantai dari suatu titik oleh pihak berhak superuser. Keduanya ditangani checkpoint bertanda tangan dan jangkar ke agen, offsite, serta digest harian (slice F-04 berikutnya).
- **Tertunda:** pencabutan hak `UPDATE`/`DELETE`/`TRUNCATE` dari role aplikasi (docs/07) menunggu pemisahan role pemilik-migrasi dan role runtime oleh `install.sh` (F-01). Sampai saat itu, pertahanan di lapis DB berupa trigger.
- **Mengubah format:** setiap perubahan pada bagian 2 setelah ada data produksi adalah perubahan major. Perubahan itu butuh gerbang manusia dan rencana migrasi rantai, misalnya checkpoint penutup rantai lama lalu genesis baru yang merujuknya.
- Rantai lokal agen memakai rumus yang sama tetapi dengan field sendiri (`../edge/docs/07_DATA_MODEL.md`). Rincian formatnya diputuskan oleh paket edge, bukan ADR ini.

## 5. Penegakan

| Klausul | Dijaga oleh |
|---|---|
| §2.2–2.4 bentuk badan dan hash | `AppendAuditEntryTest::test_hash_matches_golden_vector_of_documented_format` (vektor §2.8, dihitung oracle independen) |
| §2.3 kanonisasi | `JcsTest`, `JcsVectorsTest`, `JcsRejectVectorsTest` |
| §2.5 append-only, NUL, jsonb, UTC | `AppendAuditEntryTest` (trigger, NUL, round-trip), `DatabaseTimezoneTest` |
| §2.6 kunci dan baca-ulang | `AppendAuditEntryTest` (kunci advisory, divergensi saat simpan) |
| §2.7 verifikasi | `AuditChainTamperTest` (≥ 200 entri, manipulasi per kolom, celah, skalar, redaksi) |

Tes-tes ini merah bila format berubah. Tes yang merah karena itu berarti gerbang manusia, bukan tes yang perlu disesuaikan.

## 6. Riwayat
- 2026-09-30: diusulkan bersama slice M1/S1.
- 2026-09-30: diperketat setelah review adversarial. §2.5 dikoreksi (jsonb menormalkan ulang), ditambah batas NUL dan kedalaman, invarian "tertulis ⇒ terverifikasi", serta verifikasi yang tidak pernah crash.
- 2026-09-30: disusun ulang ke format ADR lengkap atas permintaan pemilik produk. Isi normatif tidak berubah; vektor §2.8 tetap sama.
- 2026-09-30: **diterima** pemilik produk. Mulai saat ini, setiap perubahan pada bagian 2 wajib lewat gerbang manusia (docs/22).
