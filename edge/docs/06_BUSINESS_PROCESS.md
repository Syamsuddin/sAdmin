# 06 — Business Process (agen & gateway)

Pemilik alur internal agen dan gateway. Alur produk & mesin kapsul (sisi core): `../core/docs/06_BUSINESS_PROCESS.md`. Pesan & kode galat: `../kontrak/KONTRAK.md`. State: `docs/07_DATA_MODEL.md`. Aturan kepercayaan: `docs/21_SECURITY_RULES.md`.

## E1 Pipa verifikasi amplop (urutan wajib, berhenti di pemeriksaan pertama yang gagal)
1. Parse & validasi skema pesan (`E_SCHEMA`); major kontrak dikenal (`E_KONTRAK_VERSION`).
2. `sig` layanan sah terhadap `service_pubkey` tersemat (`E_SIG_SERVICE`).
3. `target_server_id` = server ini; `platform_id` = platform agen dan tercantum di `platforms` aksi (`E_PLATFORM`).
4. Aksi + versi dikenal kebijakan tersemat; risiko diambil **dari kebijakan**, bukan dari amplop (`E_POLICY_UNKNOWN_ACTION`).
5. `expires_at` belum lewat (`E_EXPIRED`); nonce belum pernah dipakai (`E_NONCE_REPLAY`) — nonce dicatat SEBELUM eksekusi.
6. Bila risiko kebijakan ≥ L2: `plan_hash` = SHA-256 JCS `plan.body`; rencana belum kedaluwarsa; `plan.steps[step_index]` cocok dengan aksi/versi/target/`params_hash`; assertion WebAuthn sah terhadap roster (`E_PLAN_*`, `E_SIG_PASSKEY`).
7. Komitmen rahasia cocok dengan `secret_values` (`E_SECRET_COMMIT`); parameter sah terhadap skema aksi.
8. Idempotensi: `idempotency_key` sudah ada di jurnal → kirim `Result` tersimpan, jangan eksekusi.
9. Kunci sumber daya lokal (`E_LOCKED` bila dipegang).
10. Risiko L3 → E2; selain itu → E3.
Setiap penolakan: tulis audit lokal (`outcome=rejected`) + `Result status=rejected`. Penolakan tanda tangan juga memicu `Event kind=security.signature_rejected`.

## E2 Jeda L3
1. Simpan amplop di `pending_delays` dengan `execute_at = sekarang + delay_seconds` (dari **kebijakan**, bukan amplop bila kebijakan lebih ketat).
2. Kirim notifikasi lewat `Notifier` ke admin & saksi (daftar kanal dari kebijakan) berisi ringkasan dari amplop: aksi, target, parameter tersamarkan, waktu eksekusi, cara membatalkan. Kirim `Result status=delayed`.
3. Pembatalan sah: `Cancel` dari core (bertanda tangan layanan), balasan `/batal <kode>` ke bot Telegram, tautan batal dalam email (token acak sekali pakai yang diverifikasi agen via gateway), atau `sadmin-agent cancel <kode>` oleh root lokal.
4. Habis jeda tanpa pembatalan → E3. Dibatalkan → `Result status=failed error=E_DELAY_CANCELLED`, audit lokal.
5. Agen restart → `pending_delays` dimuat ulang; jeda tidak pernah di-reset atau dipercepat, kecuali mode darurat lokal.

## E3 Eksekusi aksi
`check` → sudah tercapai? `Result skipped` : `apply` → `verify` → `Result succeeded`. Galat diklasifikasikan `transient`/`permanent` sesuai definisi aksi. Fase `compensate` menjalankan `Compensate` langkah yang sama. Hasil ditulis ke jurnal sebelum `Result` dikirim.

## E4 Pembatalan bertimer (`ssh.harden`, `firewall.apply`)
1. Simpan salinan konfigurasi lama di `/var/lib/sadmin-agent/rollback/<idempotency_key>/`.
2. `apply` + `verify`, lalu daftarkan timer (`timed_confirm_s` definisi aksi) di `timers` dan kirim `Result status=awaiting_confirmation` beserta kode 6 digit.
3. Admin menjalankan `sadmin-agent confirm <kode>` dari sesi SSH **baru** → timer dihapus → `Result succeeded`.
4. Timer habis → pulihkan konfigurasi lama, `verify` pemulihan, `Event timer.rolled_back`, `Result failed` (galat permanen) → core berkompensasi.
5. Agen restart → timer dimuat ulang; bila sudah lewat, langsung rollback.

## E5 Koneksi & sangga
- Sambung ke gateway dengan backoff 1 s → 60 s (jitter). Saat terhubung: `Hello`, lalu kirim sangga (`outbox`) berurutan dan tunggu `Ack` per pesan.
- Terputus > 15 menit → notifikasi darurat langsung via `Notifier` ("agen X tak terhubung ke control plane"); diulang tiap 6 jam.
- Sertifikat klien diperbarui via `CertRenew` pada 2/3 umurnya; kedaluwarsa → agen hanya bisa diperbaiki lewat enrolment ulang (token baru).

## E6 Mode darurat lokal
`sudo sadmin-agent local run <aksi> --param k=v …`: hanya root; aksi & versi harus ada di kebijakan tersemat; verifikasi passkey dan jeda L3 dilewati (root sudah menguasai server); audit lokal `emergency_local=true`; `Event emergency_local` masuk sangga dan tersinkron saat core hidup. Juga: `sadmin-agent local roster-reset --recovery-key <berkas>` menerbitkan roster baru saat semua autentikator hilang (butuh kunci pemulihan dari kit).

## E7 Pembaruan agen (`agent.update`)
Unduh biner → verifikasi tanda tangan rilis Ed25519 → simpan biner lama → ganti atomik → restart via systemd → bila tak ada Heartbeat sukses dalam 120 dtk, unit `sadmin-agent-rollback.timer` memulihkan biner lama.

## E8 Gateway
Terima WebSocket mTLS di 8443 → validasi sertifikat klien (CA internal, belum kedaluwarsa, tidak dicabut) → teruskan setiap pesan agen ke `/run/sadmin/core-inbox.sock` dengan HMAC → teruskan pesan core ke koneksi agen yang sesuai `server_id`. Agen tak terhubung → balas core `404 agent_offline` (runner memakai `wait_condition` / ulang). Endpoint enrolment dan unduhan blob adalah satu-satunya rute lain.
