# 14 — Error Handling (agen & gateway)

Pemilik pola galat edge. Kode galat protokol: `../kontrak/KONTRAK.md` §7. Tampilan ke admin: `../core/docs/14_ERROR_HANDLING.md`.

| Situasi | Perlakuan |
|---|---|
| Penolakan pipa verifikasi | `Result rejected` + kode; audit lokal; tanda tangan tak sah → `Event security.signature_rejected` |
| Galat aksi | dibungkus `errs.Transient`/`errs.Permanent` sesuai `errors` definisi aksi; galat tak terklasifikasi = permanen |
| Panic di aksi | di-recover di `executor`, dicatat dengan stack ke log lokal, dilaporkan sebagai `E_PERMANENT`; tidak pernah mematikan agen |
| Hasil tak pasti setelah crash | saat start, entri jurnal `running` → `interrupted` → jalankan `check` sebelum melapor |
| Gagal menulis audit lokal / jurnal | aksi TIDAK dijalankan (tulis dulu, eksekusi kemudian); `Event critical` |
| Gateway: core tak tersedia | `E_CORE_UNAVAILABLE` ke agen; agen menyangga |

Larangan: menelan galat (`_ = err` pada operasi I/O), mengirim stack trace atau keluaran perintah mentah ke core (hanya `detail_id` + log lokal), menandai `succeeded` tanpa `Verify` sukses.
