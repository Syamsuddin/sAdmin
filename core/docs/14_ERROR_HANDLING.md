# 14 — Error Handling (paket core)

Pemilik pola galat paket core. Kode galat protokol: `../kontrak/KONTRAK.md` §7.

## Klasifikasi
| Kelas | Contoh | Perlakuan |
|---|---|---|
| Validasi input | domain tak valid, field wajib kosong | pesan per-field di formulir; tanpa log error |
| Galat aksi sementara (`transient`) | apt lock, jaringan ke GitHub | runner mengulang sesuai docs/06_BUSINESS_PROCESS.md; tampil di linimasa sebagai "mencoba lagi (n/5)" |
| Galat aksi permanen / penolakan agen (`E_SIG_*`, `E_PLAN_*`, `E_POLICY_*`) | tanda tangan tak sah | run berkompensasi; penolakan tanda tangan juga membuka `alerts` critical (indikasi manipulasi) |
| Hasil tak diketahui | koneksi putus setelah dispatch | `StatusQuery`; tidak pernah dianggap gagal/sukses tanpa jawaban agen |
| Galat infrastruktur core | DB, socket gateway | log + halaman galat umum; runner berhenti aman dan melanjutkan saat pulih |
| Integritas | audit verify merah, rekonsiliasi tak cocok | `alerts` critical + notifikasi semua kanal; tidak disembunyikan |

## Tampil ke admin vs dicatat
- Ke admin: Bahasa Indonesia, tiga bagian tetap — **langkah** (nama aksi manusiawi), **penyebab**, **tindakan berikutnya** — plus ID korelasi. Contoh: "Langkah *Terbitkan sertifikat SSL* gagal: DNS `app.hss.go.id` belum mengarah ke server ini. Tindakan: periksa rekaman A lalu klik *Coba lagi*. (ID: 01J…:12)".
- Ke log: detail teknis, kode galat, `run_id`/`step_index`, `envelope_id` (format: docs/15_OBSERVABILITY.md).
- Pesan manusiawi per kode galat disimpan di `lang/id/errors.php` (satu rumah teks).

## Larangan
- Tidak pernah menampilkan stack trace, SQL, atau isi amplop mentah ke admin (`APP_DEBUG=false` di produksi, dicek install.sh).
- Tidak menelan exception (`catch` kosong); setiap `catch` mencatat atau melempar ulang.
- Tidak mengubah status run menjadi `succeeded` tanpa `Result` sukses dari agen.
