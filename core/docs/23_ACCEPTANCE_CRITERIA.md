# 23 — Acceptance Criteria (paket core)

Kriteria terima fitur yang dimiliki paket core (`docs/01_PRD.md`). AC yang dimiliki edge: `../edge/docs/23_ACCEPTANCE_CRITERIA.md` (AC-02, 04, 05, 06, 07, 09, 12, 13, 16). Patokan selesai = kriteria di sini + DoD (docs/24_DEFINITION_OF_DONE.md). Fitur yang sudah diterima dipindah ke `docs/_archive/23-<fitur>.md`.

## AC-01 Instalasi (F-01, F-03, F-17)
- Given VM Ubuntu 24.04 bersih, When `sudo deploy/install.sh` dijalankan, Then selesai exit 0 dan dua passkey + profil WG terdaftar.
- Given instalasi selesai, When console diakses dari IP publik, Then tidak ada respons (koneksi ditolak/timeout); via `wg0` → halaman login.
- Given VM Debian 12, When install.sh dijalankan, Then berhenti sebelum mengubah apa pun dengan pesan platform tak didukung.
- Given admin memilih tema `dark`, When halaman dimuat ulang, Then atribut `data-bs-theme="dark"` dan token gelap (docs/26) aktif; `system` mengikuti OS.
- Given kunci induk termuat dari kredensial systemd, When rahasia disimpan lalu dibaca, Then nilainya kembali utuh dan audit hanya mencatat `purpose`; baris yang diubah lewat SQL atau kunci induk yang salah membuat pembukaan gagal, dan nilai tak pernah muncul di log/audit (ADR 0003).
```bash
make harness SCENARIO=install               # hijau
curl -m 5 https://<ip-publik-vm>/ ; echo $?  # bukan 0
php artisan test --filter=ThemePreferenceTest
php artisan test --filter='Vault|SecretValue'   # Tests: … passed
php artisan sadmin:vault-check                  # exit 0
```

## AC-03 Audit (F-04)
- Given rantai audit berisi ≥ 200 entri, When `sadmin audit verify`, Then exit 0.
- Given satu `audit_entries.params_redacted` diubah via SQL superuser, When verify, Then exit ≠ 0 dan alert `audit_mismatch` critical terkirim ≤ 60 detik.
- Given checkpoint bertanda tangan kunci audit sudah ada (F-04b Checkpoint audit), When ujung rantai dipotong atau rantai ditulis ulang dari suatu titik dengan hash dihitung ulang lewat SQL superuser, Then verify exit ≠ 0 dengan `audit_mismatch` yang menyebut checkpoint yang dilanggar, dan checkpoint baru tak pernah ditandatangani di atas rantai yang rusak (ADR 0004).
```bash
php artisan test --filter=AuditChainTamperTest   # Tests: … passed
php artisan test --filter='AuditCheckpointTamperTest|CreateAuditCheckpointTest|InitializeAuditKeyTest'   # Tests: … passed
php artisan test --testsuite=Contract            # termasuk vektor ../kontrak/vectors/checkpoint
```

## AC-08 `site.create` (F-10)
- Given VM hasil `server.onboard` dan repo Laravel contoh, When kapsul disetujui dengan satu passkey, Then `curl -sI https://<domain>` → `HTTP/2 200` dan median waktu `approved_at→succeeded_at` ≤ 5 menit atas 5 run (tanpa tunggu DNS).
- Given ZIP berisi `../../etc/passwd`, When diunggah, Then ditolak di preflight, tidak ada rencana, tidak ada perubahan server.
```bash
make harness CAPSULE=site.create RUNS=5 REPORT=timing   # median_s <= 300
```

## AC-10 `site.archive` (F-10)
- Given situs aktif, When `site.archive` lalu rencana penghapusan L3 setelah masa tunggu (dipercepat di harness), Then pemeriksaan jejak nol hijau kecuali snapshot backup.
```bash
make harness CAPSULE=site.archive   # zero_trace=ok
```

## AC-11 `sadmin.restore` (F-13)
- Given backup offsite + kit pemulihan, When VM core dihancurkan dan `install.sh --restore` dijalankan di VM baru, Then ≤ 60 menit console pulih, agen tersambung ulang, `sadmin audit verify` dan rekonsiliasi hijau.
```bash
make harness SCENARIO=restore   # duration_s <= 3600, reconcile=ok
```

## AC-14 Memori dasar (F-15)
- Given run `site.create` sukses, Then satu `memories` (type=incident/source=observed atau type=fact) tertaut ke situs tercipta otomatis.
- Given admin membuat, menyunting, lalu menghapus catatan manual, Then ketiganya tercatat di `audit_entries` (`memory.create|update|delete`).
- Given catatan berisi pola rahasia (mis. `password=`), Then ditolak dengan pesan validasi.
```bash
php artisan test --filter=Memory
```

## AC-15 AI opsional (F-16)
- Given AI nonaktif, Then seluruh suite core dan harness AC-01…AC-14 hijau.
- Given AI aktif dengan penyedia palsu perekam, When admin bertanya tentang situs yang `.env`-nya berisi nilai canary, Then payload terekam tidak memuat canary maupun nilai `secrets` apa pun; kelas data `never` tidak terkirim.
```bash
php artisan test --group=redaction --filter=AiPayload
make harness-ai-eval
```

## Kriteria UI (semua halaman docs/26)
- Setiap halaman ber-data punya tes feature untuk state kosong, memuat, gagal, sukses.
- `php artisan sadmin:ui-token-scan` hijau: tidak ada nilai warna/ukuran di luar `resources/css/tokens.css`.
