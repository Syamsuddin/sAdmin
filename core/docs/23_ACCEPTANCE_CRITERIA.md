# 23 — Acceptance Criteria (paket core)

Kriteria terima fitur yang dimiliki paket core (`docs/01_PRD.md`). AC yang dimiliki edge: `../edge/docs/23_ACCEPTANCE_CRITERIA.md` (AC-02, 04, 05, 06, 07, 09, 12, 13, 16). Patokan selesai = kriteria di sini + DoD (docs/24_DEFINITION_OF_DONE.md). Fitur yang sudah diterima dipindah ke `docs/_archive/23-<fitur>.md`.

## AC-01 Instalasi (F-01, F-03, F-17)
- Given VM Ubuntu 24.04 bersih, When `sudo deploy/install.sh` dijalankan, Then selesai exit 0 dan dua passkey + profil WG terdaftar.
- Given instalasi selesai, When console diakses dari IP publik, Then tidak ada respons (koneksi ditolak/timeout); via `wg0` → halaman login.
- Given VM Debian 12, When install.sh dijalankan, Then berhenti sebelum mengubah apa pun dengan pesan platform tak didukung.
- Given admin memilih tema `dark`, When halaman dimuat ulang, Then atribut `data-bs-theme="dark"` dan token gelap (docs/26) aktif; `system` mengikuti OS.
- Given kunci induk termuat dari kredensial systemd, When rahasia disimpan lalu dibaca, Then nilainya kembali utuh dan audit hanya mencatat `purpose`; baris yang diubah lewat SQL atau kunci induk yang salah membuat pembukaan gagal, dan nilai tak pernah muncul di log/audit (ADR 0003).
- Given instansi sudah diinisialisasi dan brankas termuat, When `sadmin:service-key-init` dijalankan, Then tepat satu kunci layanan aktif dibuat (seed hanya di brankas), kunci publiknya tercetak dan tercatat di audit `service.key_initialize`, dan pemanggilan kedua (juga setelah kunci dihancurkan) ditolak sebagai rotasi; bingkai core→agen yang disusun core lolos verifikasi `sig` dengan kunci itu dan identik dengan vektor bersama `../kontrak/vectors/service-sig` (ADR 0006).
- Given instansi sudah diinisialisasi dan brankas termuat, When `sadmin:ca-init` dijalankan, Then tepat satu CA internal aktif dibuat (kunci privat dan sertifikat hanya di brankas), pin `--ca-sha256` tercetak dan tercatat di audit `ca.initialize`, dan pemanggilan kedua (juga setelah CA dihancurkan) ditolak sebagai rotasi; sertifikat klien agen yang diterbitkan core dari CSR sah lolos aturan penerimaan gateway KONTRAK §2, sedangkan CSR dan sertifikat pada vektor bersama `../kontrak/vectors/agent-csr` dan `agent-cert` diputus persis seperti oracle (ADR 0007).
```bash
make harness SCENARIO=install               # hijau
curl -m 5 https://<ip-publik-vm>/ ; echo $?  # bukan 0
php artisan test --filter=ThemePreferenceTest
php artisan test --filter='Vault|SecretValue'   # Tests: … passed
php artisan sadmin:vault-check                  # exit 0
php artisan test --filter='ServiceSigner|InitializeServiceKey|ServiceSignature'   # Tests: … passed
php artisan test --filter='CertificateAuthority|AgentCertificate'   # Tests: … passed
```

## AC-17 Tambah server & inventaris (F-02, sisi core)
- Given CA internal dan `SADMIN_GATEWAY_HOST` tersedia, When admin menyimpan formulir *Tambah server* (nama, hostname, alamat IP yang sah), Then server `enrolling` tercipta dan console menampilkan sekali perintah `sudo sadmin-agent enroll --gateway <host>:8443 --ca-sha256 <pin> --token <token>`; token 256 bit berlaku 15 menit, basis data hanya menyimpan SHA-256-nya, dan audit mencatat `server.register` + `server.enroll_token_issue` tanpa token.
- Given server masih `enrolling`, When admin menerbitkan token baru, Then token lama langsung tak berlaku; server berstatus lain atau milik tenant lain ditolak tanpa perubahan.
- Given masukan tak sah (nama bukan label DNS huruf kecil, hostname bukan nama host DNS, alamat IP loopback/tak spesifik/link-local) atau nama yang pernah dipakai, When disimpan, Then pesan per field tampil dan tidak ada server maupun audit tertulis.
- Given tiga server belum dipensiunkan (Mode Tunggal, docs/02), When admin menambah server keempat, Then ditolak; tanpa CA, gateway, atau brankas, formulir tak tampil dan state Gagal menjelaskan tindakannya.
- Given daftar server, When halaman dibuka, Then empat state docs/26 terpenuhi dan setiap status tampil sebagai teks.
```bash
php artisan test --filter='RegisterServer|IssueEnrollmentToken|ServerSchema|ServersPage|EnrollServerPage'   # Tests: … passed
php artisan test --group=redaction   # token tak muncul di audit/log
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
