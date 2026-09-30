# 20 — Guardrails (agen & gateway)

Pemilik larangan operasional edge. Keamanan rinci: docs/21_SECURITY_RULES.md. Guardrail core: `../core/docs/20_GUARDRAILS.md`.

- JANGAN membuat aksi, subperintah, atau parameter yang menjalankan perintah/skrip bebas (termasuk "hook" berisi shell dari pengguna).
- JANGAN memakai `os/exec` di luar `internal/sysexec`, dan JANGAN memakai `sh -c`/`bash -c` dengan nilai parameter.
- JANGAN menambah flag, env, atau build tag yang melewati verifikasi tanda tangan, nonce, kedaluwarsa, atau jeda — termasuk untuk tes.
- JANGAN mengambil risiko, jeda, atau syarat tanda tangan dari amplop; hanya dari kebijakan tersemat.
- JANGAN menambah aksi tanpa definisi di `../catalog` (dengan `platforms` & `compensate`) dan tanpa skenario harness.
- JANGAN menulis fakta distro di dalam paket aksi; JANGAN menambah profil platform atau abstraksi untuk distro yang belum dijadwalkan.
- JANGAN membuka port dengar di agen.
- JANGAN memberi gateway akses DB, rahasia aplikasi, atau kemampuan menandatangani.
- JANGAN menulis rahasia ke log, audit lokal, jurnal (teks jelas), atau pesan ke core.
- JANGAN melepas `chattr +a` atau menulis ulang berkas audit lokal.
- JANGAN menambah modul Go tanpa alasan tertulis di PR.
- JANGAN menghijaukan tes/harness dengan melonggarkannya.
