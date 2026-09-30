# ADR 0001 — Format hash rantai audit

Status: **diusulkan** — menunggu tinjauan pemilik produk (gerbang manusia: docs/22_CHANGE_POLICY.md, "perubahan format rantai audit").
Tanggal: 2026-09-30 · Slice: M1/S1 (F-04 sisi core, AC-03).

## Konteks
docs/07_DATA_MODEL.md menetapkan `hash = SHA-256(prev_hash ∥ JCS(entri tanpa hash))`, tetapi tidak merinci bentuk tiap field di dalam JCS. Begitu entri produksi pertama tertulis, rincian ini tak bisa diubah tanpa memutus verifikasi seluruh riwayat. Karena itu rincian dikunci di sini sebelum ada data.

## Keputusan
1. **Isi yang di-hash** adalah satu objek JSON berisi semua kolom `audit_entries` kecuali `hash`, dengan nama kunci sama dengan nama kolom: `seq`, `tenant_id`, `prev_hash`, `occurred_at`, `actor_type`, `actor_id`, `action_key`, `target`, `params_redacted`, `outcome`, `envelope_ref`, `emergency_local`. Kolom bernilai NULL tetap hadir sebagai `null`.
2. **Kanonisasi** memakai RFC 8785 lewat `app/Infrastructure/Jcs` (vektor bersama `../kontrak/vectors/jcs`). Sesuai `../kontrak/KONTRAK.md` §3, angka pecahan ditolak dan integer dibatasi ±(2^53−1).
3. **Hash** adalah SHA-256 heksadesimal huruf kecil atas byte UTF-8 dari `prev_hash` (64 karakter hex) yang langsung disambung dengan bentuk kanonik, tanpa pemisah.
4. **Tipe JSON**: `seq` integer, `emergency_local` boolean, `params_redacted` objek/larik/null, sisanya string atau null.
5. **`occurred_at`** ditulis dalam RFC 3339 UTC berakhiran `Z` dengan tepat 6 digit mikrodetik (`2026-09-30T02:11:12.345678Z`). Kolomnya `timestamptz(6)`, sehingga nilai yang dibaca ulang identik.
6. **`params_redacted`** dikirim ke DB sebagai teks kanonik, tetapi jsonb **menormalkan ulang** penyimpanannya: urutan kunci diubah dan spasi disisipkan. Karena itu nilainya hanya setara secara semantik, bukan identik per byte. Verifikator mana pun (core, tool offsite, Go) **wajib** mendekode nilai itu sebagai objek, lalu mengkanonisasi ulang, sehingga `{}` dan `[]` tetap dibedakan. Teks `params_redacted::text` tidak boleh di-hash apa adanya.
7. **Genesis**: `prev_hash` entri pertama berisi 64 nol, dan `seq` dimulai dari 1 tanpa celah. Penulisan berlangsung di bawah `pg_advisory_xact_lock` bersama, di dalam transaksi Action pemilik perubahan state.
8. **Batas masukan**:
   - Byte NUL dilarang di semua field teks dan di `params_redacted`, karena PostgreSQL memotong text di NUL dan menolak `\u0000` di jsonb.
   - Sarang objek/larik dibatasi 64 tingkat (`Jcs::MAX_DEPTH`).
9. **Invarian "tertulis ⇒ terverifikasi"**: sebelum commit, `AppendAuditEntry` membaca ulang baris yang baru ditulis dan menghitung ulang hash-nya. Bila hasilnya tidak identik, penulisan dibatalkan. Alasannya: rantai bersifat append-only dan verifikasi berhenti di kerusakan pertama, sehingga satu entri yang tak terverifikasi akan membutakan pemeriksaan semua entri sesudahnya.
10. **Verifikasi tidak pernah crash** karena isi baris. Baris yang tak dapat dibentuk ulang (tipe salah, JSON rusak) dilaporkan sebagai `audit_mismatch` pada seq tersebut, dengan alasan yang tidak menggemakan isi entri.

## Konsekuensi
- `sadmin:audit-verify` mendeteksi perubahan isi kolom mana pun, penghapusan entri di tengah (sebagai celah), dan penggantian satu entri beserta hash hasil hitung ulang (karena tautan ke entri berikutnya putus).
- Verify saja **tidak** mendeteksi pemotongan ujung rantai, atau penulisan ulang seluruh rantai dari suatu titik oleh pihak berhak superuser. Keduanya ditangani oleh checkpoint bertanda tangan dan jangkar (agen, offsite, digest) di slice F-04 berikutnya.
- Pertahanan di lapis DB: trigger menolak UPDATE/DELETE/TRUNCATE. Pencabutan hak UPDATE/DELETE/TRUNCATE dari role aplikasi (docs/07) menunggu pemisahan role pemilik-migrasi dan role runtime oleh `install.sh` (F-01).
- Vektor emas `AppendAuditEntryTest::test_hash_matches_golden_vector_of_documented_format` dihitung oleh oracle independen. Bila tes ini merah, artinya format berubah, dan itu wajib lewat gerbang manusia, bukan dengan menyesuaikan tesnya.
