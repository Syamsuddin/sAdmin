# 20 — Guardrails (paket core)

Pemilik larangan operasional paket core. Keamanan rinci: docs/21_SECURITY_RULES.md. Guardrail agen: `../edge/docs/20_GUARDRAILS.md`.

- JANGAN mengeksekusi perintah OS, shell, atau SSH dari core dalam bentuk apa pun (daftar fungsi: docs/09_STACK.md). Butuh sesuatu dilakukan di server → aksi katalog.
- JANGAN mengirim apa pun ke agen di luar `Domain/Execution/Dispatch`.
- JANGAN menonaktifkan, melewati, atau me-mock verifikasi tanda tangan/WebAuthn — termasuk di tes (pakai kunci uji).
- JANGAN menyimpan rahasia di luar brankas: tidak di `.env` aplikasi, log, `jsonb` parameter, audit, memori, notifikasi, prompt AI, atau fixture tes berisi nilai nyata.
- JANGAN mengubah atau menghapus baris `audit_entries`, `approvals`, `plans` yang sudah disetujui.
- JANGAN menurunkan level risiko aksi atau jeda L3 tanpa ADR dan gerbang manusia.
- JANGAN menambah aksi yang tidak ada di `../catalog`, atau menulis ulang nama/skema aksi sebagai konstanta PHP.
- JANGAN memberi AI kemampuan menandatangani, menjalankan aksi, menaikkan/menurunkan risiko, atau menulis memori permanen.
- JANGAN membuka console di antarmuka selain `wg0` (kecuali opsi daftar IP yang eksplisit dan ditandai lemah).
- JANGAN menambah dependency Composer/npm tanpa alasan tertulis di PR.
- JANGAN menghijaukan tes dengan melonggarkannya.
- JANGAN membangun fitur di luar docs/02_SCOPE.md.
