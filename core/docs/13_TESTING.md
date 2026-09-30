# 13 — Testing (paket core)

Pemilik strategi tes paket core. Harness VM, injeksi gangguan, uji keamanan agen: `../edge/docs/13_TESTING.md`. Perintah: `docs/11_COMMANDS.md`.

| Jenis | Cakupan | Target |
|---|---|---|
| Unit | penyusun rencana, `plan_hash`, JCS, komitmen rahasia, state machine run/langkah, kunci sumber daya, redaksi, rantai hash audit, verifikasi assertion WebAuthn sisi core | tiap Action/Service domain punya tes; ≥ 80% baris `app/Domain` |
| Feature | login passkey, pendaftaran autentikator (≥ 2), formulir kapsul, peninjauan rencana, persetujuan, pembatalan jeda, halaman memori, empat state halaman ber-data | setiap halaman di docs/26 |
| Kontrak | pesan buatan PHP tervalidasi `../kontrak/schemas`; vektor JCS identik | wajib hijau (`--testsuite=Contract`) |
| Redaksi | tidak ada nilai rahasia di log, `step_runs`, `audit_entries`, notifikasi, payload AI (injeksi nilai canary lalu pindai) | grup `redaction` |
| Larangan | `sadmin:forbidden-scan` | wajib di CI |
| End-to-end | via harness (`make harness CAPSULE=…`), dimiliki edge | AC di docs/23 |

## Wajib dites (alur kritikal)
- Rencana yang sudah disetujui tidak bisa diubah (trigger + tes).
- Runner: dua proses runner paralel tidak pernah memajukan langkah yang sama (uji konkurensi dengan dua koneksi DB).
- Hasil tak diketahui → `StatusQuery`, bukan kirim ulang amplop baru.
- Audit: mengubah satu baris lewat SQL mentah (role superuser tes) membuat `sadmin:audit-verify` gagal.
- AI nonaktif: seluruh suite hijau tanpa konfigurasi AI.

## Aturan tes
- Passkey di tes memakai autentikator virtual dengan kunci dari `SADMIN_TEST_PASSKEY_SEED`; **dilarang** mem-bypass verifikasi.
- Agen di tes feature diganti fake gateway `tests/Fakes/FakeGateway` yang memvalidasi amplop terhadap skema kontrak; tes end-to-end memakai agen asli di VM.
- Tes yang gagal diperbaiki kodenya, bukan dilonggarkan asersinya.
