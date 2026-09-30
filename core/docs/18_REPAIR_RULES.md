# 18 — Repair Rules (berlaku kedua paket)

Pemilik aturan perbaikan bug untuk `core` dan `edge`.

## Alur
1. **Reproduksi** dengan tes gagal (unit/feature di paket terkait; untuk aksi atau kapsul: `make harness ACTION=…`/`CAPSULE=…`).
2. **Akar masalah** — tulis satu kalimat di deskripsi PR; bedakan bug kode vs dokumen basi (kode aktual menang untuk fakta berpadanan kode; lapor selisihnya).
3. **Perbaikan minimal** di lapisan tempat akar berada.
4. **Tes regresi** tetap di suite; untuk aksi, tambahkan skenario ke harness.
5. Jalankan DoD (docs/24_DEFINITION_OF_DONE.md).

## Larangan
- Perbaikan tidak melebihi scope bug; refactor luas butuh izin terpisah.
- Dilarang "memperbaiki" dengan melonggarkan verifikasi tanda tangan, kebijakan, level risiko, validasi skema, atau asersi tes.
- Dilarang mengubah data audit, rencana yang disetujui, atau `resource_locks` secara manual untuk "membuka" kemacetan — gunakan alur `needs_attention`.
- Bug di aksi yang sudah dirilis: naikkan `version` aksi bila perilaku berubah (`../catalog/CATALOG.md`).
- Bug yang menyentuh kanonisasi, format amplop, atau rantai audit = gerbang manusia (docs/22_CHANGE_POLICY.md).
