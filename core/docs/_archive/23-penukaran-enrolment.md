# Arsip AC-18 Penukaran enrolment (F-02, sisi core) — diterima 2026-10-02

Kriteria ini sudah terpenuhi dan tesnya hijau, sehingga dipindah dari `docs/23_ACCEPTANCE_CRITERIA.md` (aturan emas #6 INDEX). Penegakannya kini ada di suite tes; mengubah perilaku di bawah ini berarti mengubah tes penegaknya lewat docs/22.

Diterima lewat slice M1 F-02d (ADR 0008, kontrak 0.6.0), setelah review adversarial (docs/22). Transport (inbox gateway), `Hello`/`Heartbeat`, tampilan sidik jari di console, dan sisi agen bukan bagian kriteria ini.

## AC-18 Penukaran enrolment (F-02, sisi core)
- Given server `enrolling` bertoken sah, CA, kunci layanan, dan kunci audit tersedia, dan ada admin aktif dengan dua passkey aktif, When badan `Enroll` yang sah ditukar, Then dijawab `EnrollAccept` bertanda tangan kunci layanan (lolos `ServiceSigner::verifyFrame`) berisi sertifikat klien untuk server itu (lolos aturan penerimaan gateway), `ca_cert` yang pinnya sama dengan `--ca-sha256`, roster v1 dan kebijakan v1 (ADR 0008 §2.4–2.5), kunci publik layanan dan audit; token habis, server `offline`, baris `agents` tercipta dengan sidik jari kepercayaan, dan audit `server.enroll` tercatat tanpa token maupun CSR.
- Given token salah, kedaluwarsa, sudah dipakai, tak berbentuk, atau milik server yang tak lagi `enrolling`, Then ditolak `E_ENROLL_TOKEN` dengan alasan yang tak dibedakan dan tanpa perubahan apa pun.
- Given CSR melanggar aturan KONTRAK §2, platform selain `ubuntu-24.04`, versi kontrak tak dikenal, badan tak sesuai skema, atau prasyarat roster/kebijakan/kunci belum siap, Then ditolak (`E_CSR` + alasan, `E_PLATFORM`, `E_KONTRAK_VERSION`, `E_SCHEMA`, `E_CORE_UNAVAILABLE`), semua perubahan dibatalkan (termasuk roster dan kebijakan yang sempat dibuat), dan token yang sama masih bisa dipakai setelah agen memperbaiki masukannya.
- Given enrolment kedua di tenant yang sama, Then roster dan kebijakan yang dikirim identik dengan yang pertama (versi 1, hash sama), sidik jari berbeda (memuat `server_id`), dan passkey yang ditambah setelah roster v1 tidak mengubahnya; baris dokumen yang diubah di luar core tak pernah dikirim; DB menolak dua dokumen aktif per tenant.
- Given `Enroll.hostname` berbeda dari hostname terdaftar, Then enrolment tetap berjalan dan selisihnya hanya tercatat di audit.
- Given sidik jari kepercayaan dihitung dari lima anggota (KONTRAK §3), Then hasilnya identik dengan vektor bersama `../kontrak/vectors/trust-fingerprint` (oracle independen), dan `TrustDocuments::CONTRACT` sama dengan `major.minor` `../kontrak/VERSION`.
```bash
php artisan test --filter='AcceptEnrollment|TrustFingerprint|ServerSchema'   # Tests: … passed
php artisan test --group=redaction   # token dan CSR tak muncul di audit
python3 ../kontrak/vectors/trust-fingerprint/oracle.py ../kontrak/vectors/trust-fingerprint && git diff --exit-code ../kontrak/vectors   # oracle deterministik
```
