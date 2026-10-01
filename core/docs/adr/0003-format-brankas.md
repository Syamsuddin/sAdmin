# ADR 0003 — Format brankas: enkripsi envelope dan kunci induk

| | |
|---|---|
| Status | **Diusulkan** — menunggu keputusan pemilik produk |
| Tanggal | 2026-10-01 |
| Pemutus | Pemilik produk. Ini perubahan keamanan (gerbang manusia, docs/22_CHANGE_POLICY.md). Setelah rahasia produksi pertama tertulis, mengubah format berarti mengenkripsi ulang seluruh brankas |
| Lingkup | Cara core menyimpan, membuka, dan menghancurkan baris `secrets`/`key_wraps`, serta cara core membaca kunci induk |
| Di luar lingkup | Penyegelan kunci induk (TPM2 lewat `systemd-creds`, atau frasa sandi) dan pembukaan segel setelah reboot, yang menjadi tugas slice `install.sh`. Isi kit pemulihan, yang menjadi slice tersendiri. Rotasi kunci induk. Pengiriman nilai ke agen lewat `secret_values` amplop (`../kontrak/KONTRAK.md`) |
| Rujukan | docs/07_DATA_MODEL.md §Rahasia · docs/21_SECURITY_RULES.md §Rahasia & brankas · docs/09_STACK.md (ext-sodium; `Crypt::` terlarang) · docs/10_DEV_ENV.md (`SADMIN_VAULT_CRED`, `SADMIN_VAULT_DEV_KEY`) · docs/12_PROJECT_STRUCTURE.md |

## 1. Konteks
docs/21 menetapkan enkripsi envelope: setiap rahasia punya kunci data sendiri (XChaCha20-Poly1305), lalu kunci data itu dibungkus kunci induk yang disegel `systemd-creds`. docs/07 menetapkan kolom `secrets` dan `key_wraps`. Namun dokumen-dokumen itu belum merinci hal-hal berikut:
- letak nonce pembungkus, karena `key_wraps` tidak punya kolom nonce;
- data terasosiasi (AAD) yang mengikat ciphertext ke barisnya. Tanpa AAD, siapa pun yang bisa menulis ke DB dapat menukar ciphertext antarbaris atau mengganti `purpose`, dan core akan membuka nilai yang salah tanpa menyadarinya;
- bentuk dan sumber kunci induk yang dibaca core, serta perilaku core bila kunci itu tidak ada;
- arti `destroyed` untuk kunci data.

Begitu rahasia produksi pertama tertulis, rincian ini tidak dapat diubah tanpa mengenkripsi ulang seluruh brankas. Alat pemulihan (F-13) juga harus bisa membuka brankas tanpa membaca kode core. Karena itu rincian dikunci di sini. Bagian 2 bersifat **normatif**.

## 2. Keputusan (normatif)

### 2.1 Kunci induk
- Panjangnya tepat 32 byte acak (CSPRNG), disimpan sebagai byte mentah tanpa pengodean dan tanpa baris baru.
- Hanya satu kunci yang aktif, yaitu `master_key_version` = `1`. Baris dengan versi lain wajib ditolak (gagal tertutup). Mendukung versi lain berarti rotasi kunci induk, yang butuh ADR baru.
- Sumber kunci diperiksa berurutan:
  1. Bila `SADMIN_VAULT_DEV_KEY` diisi, isinya adalah path berkas lokal berisi kunci. Berkas itu wajib tidak bisa dibaca grup maupun pengguna lain (`mode & 0o077 = 0`, mis. `0600`). Sumber ini **ditolak** bila `APP_ENV=production`, meskipun berkasnya sah.
  2. Bila tidak, core membaca berkas `$CREDENTIALS_DIRECTORY/<nama>`. `<nama>` = `SADMIN_VAULT_CRED` (bawaan `sadmin-vault-master`) dan wajib cocok dengan `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`. `CREDENTIALS_DIRECTORY` diisi systemd untuk unit yang memakai `LoadCredential=`/`LoadCredentialEncrypted=`. Variabel ini dibaca dari lingkungan proses **saat runtime**, bukan dari konfigurasi, supaya `config:cache` tidak membekukannya.
  3. Bila tidak ada sumber yang sah, brankas berstatus *tak tersedia*. Semua operasi rahasia gagal tertutup, sedangkan bagian console yang tidak memakai rahasia tetap berjalan.
- Core tidak pernah menulis kunci induk ke DB, log, cache, atau berkas, dan tidak pernah membuatnya. Kunci dibuat dan disegel oleh `install.sh`.

### 2.2 Kunci data dan pembungkusnya
- Setiap baris `secrets` punya kunci data (DEK) 32 byte acak sendiri dan tepat satu baris `key_wraps`. Hubungannya 1:1, dijaga `secrets.key_wrap_id` UNIQUE. DEK tidak pernah dipakai ulang.
- `key_wraps.wrapped_dek` = `nonce_w ∥ XChaCha20-Poly1305-IETF(kunci = kunci induk, nonce = nonce_w, teks = DEK, ad = AAD_w)`. `nonce_w` berupa 24 byte acak, sehingga panjang totalnya tepat 72 byte (24 + 32 + 16).
- `AAD_w` = byte UTF-8 dari `sadmin-vault/1/key_wrap/{tenant_id}/{key_wrap_id}/{master_key_version}`. ULID ditulis persis seperti tersimpan (huruf kecil, `HasUlids`), dan versi ditulis sebagai integer desimal tanpa nol di depan. Angka `1` setelah `sadmin-vault/` adalah versi format ini.

### 2.3 Nilai rahasia
- `secrets.nonce` berupa 24 byte acak.
- `secrets.ciphertext` = `XChaCha20-Poly1305-IETF(kunci = DEK, nonce = secrets.nonce, teks = nilai, ad = AAD_s)`, sehingga panjangnya = panjang nilai + 16.
- `AAD_s` = byte UTF-8 dari `sadmin-vault/1/secret/{tenant_id}/{secret_id}/{purpose}/{key_wrap_id}`.
- Nilai boleh berupa string byte apa pun asalkan tidak kosong. Biner, termasuk byte NUL, diperbolehkan.
- Akibat AAD, perubahan lewat SQL berikut membuat pembukaan **gagal**, bukan menghasilkan nilai yang salah:
  - memindahkan ciphertext atau nonce ke baris lain;
  - mengganti `purpose`, `tenant_id`, `key_wrap_id`, atau `master_key_version`;
  - memakai kunci induk yang salah.

### 2.4 Penulisan dan penghancuran
- **Simpan.** ID, DEK, dan nonce dibuat lebih dulu, lalu enkripsi dilakukan di memori. Satu transaksi menulis `key_wraps`, `secrets` (status `active`), dan entri audit `secret.store` (target `secret:<id>`, `params_redacted` = `{"purpose": …}`). Di transaksi yang sama, baris yang baru ditulis dibaca ulang dan dibuka. Bila hasilnya tidak identik dengan nilai asal, transaksi dibatalkan.
- **Hancurkan.** Ciphertext ditimpa byte nol sepanjang aslinya, dan `wrapped_dek` pada pasangan `key_wraps`-nya juga ditimpa byte nol (72 byte). Status menjadi `destroyed` dan entri audit `secret.destroy` dicatat, semuanya dalam satu transaksi. Barisnya tetap ada (docs/07). Menghancurkan rahasia yang sudah hancur adalah no-op tanpa entri audit.
- Penimpaan nol menjamin rahasia tidak bisa lagi dibuka lewat brankas. Ini bukan penghapusan forensik: salinan lama tetap ada di tuple mati dan WAL PostgreSQL sampai VACUUM, serta di backup.
- `rotated` disiapkan untuk rotasi nilai dan baru dipakai oleh slice yang membutuhkannya. Rahasia `rotated` masih bisa dibuka.
- Nilai rahasia tidak pernah masuk audit, log, pesan exception, maupun jejak tumpukan:
  - setiap parameter bernilai rahasia diberi `#[\SensitiveParameter]`;
  - nilai dibawa objek `SecretValue` yang tidak dapat diserialisasi, tampil tersamar di `var_dump`/`print_r`/`var_export`/`json_encode`, dan hanya membuka nilainya lewat `expose()`.

### 2.5 Pembacaan
- Rahasia hanya dibaca lewat `App\Infrastructure\Vault\Vault::reveal()`, dengan urutan berikut:
  1. tolak bila status `destroyed`;
  2. muat kunci induk;
  3. pastikan `master_key_version` = versi aktif;
  4. buka DEK dengan `AAD_w`;
  5. buka nilai dengan `AAD_s`;
  6. hapus DEK dari memori (`sodium_memzero`).
- Kegagalan tag AEAD atau panjang yang tidak sah memunculkan `VaultIntegrityError`, yang masuk kelas *Integritas* docs/14. Kunci yang tidak tersedia atau versi lain memunculkan `VaultUnavailable` (*Galat infrastruktur core*). Keduanya tidak memuat nilai rahasia maupun kunci.
- Di MVP pembacaan tidak diaudit karena bukan perubahan state. Jejaknya tercatat di langkah atau amplop yang memakai nilai itu.

### 2.6 Pemeriksaan
`php artisan sadmin:vault-check` memuat kunci induk, menguji enkripsi bolak-balik di memori, lalu membuka setiap `key_wraps` milik rahasia yang belum `destroyed`. Nilai rahasianya sendiri tidak dibuka. Perintah ini exit 0 hanya bila semua kunci data terbuka. `install.sh` dan pemulihan (F-13) memakainya untuk membuktikan bahwa kunci induk yang dimuat systemd adalah kunci yang benar.

### 2.7 Satu pintu
- Hanya `app/Infrastructure/Vault` yang boleh memanggil `sodium_crypto_aead_xchacha20poly1305_ietf_*` dan membaca kredensial kunci induk.
- `Crypt::`, `Illuminate\Contracts\Encryption\*`, helper `encrypt()`/`decrypt()`, dan cast Eloquent `encrypted*` dilarang di `app/` (docs/09).

### 2.8 Vektor emas
Implementasi dan alat pemulihan wajib membuka baris berikut menjadi nilai `rahasia-uji-ADR-0003` (UTF-8, 20 byte). Semua nilai ditulis dalam hex.

| Data | Nilai |
|---|---|
| kunci induk (versi 1) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| `tenant_id` | `01k6gz7t0000000000000000t1` |
| `key_wraps.id` | `01k6gz7t0000000000000000w1` |
| `secrets.id` | `01k6gz7t0000000000000000s1` |
| `purpose` | `api_token` |
| `wrapped_dek` (72 B; DEK = `202122…3f`, `nonce_w` = `404142…57`) | `404142434445464748494a4b4c4d4e4f5051525354555657f4182753f4c55f31a7ddad9583b14bbda28b9ff7276c65ad5208c77e35391daf4bb77814e72375c562a3f794bc4f9d08` |
| `nonce` | `606162636465666768696a6b6c6d6e6f7071727374757677` |
| `ciphertext` (36 B) | `9a462847f618faecdf6bfc2253e57db447dc9c26ea8c5dca6e53712219fdbe33b0697793` |

Vektor ini dihitung oleh skrip independen yang hanya memakai fungsi sodium dan teks ADR ini, tanpa kode core.

## 3. Alternatif yang dipertimbangkan
| Alternatif | Ditolak karena |
|---|---|
| `Crypt::` Laravel (`APP_KEY`) | Dilarang docs/09. `APP_KEY` bukan kunci brankas dan tersimpan di `.env` |
| Semua rahasia dienkripsi langsung dengan kunci induk | Rotasi kunci induk berarti mengenkripsi ulang semua rahasia, dan satu rahasia tidak bisa dihancurkan secara kriptografis tersendiri |
| `crypto_secretbox` (XSalsa20-Poly1305) | Tidak punya data terasosiasi, sehingga pertukaran baris antarrahasia tidak terdeteksi |
| AES-256-GCM | Nonce acak 96 bit berisiko bertabrakan, bergantung pada AES-NI, dan docs/21 sudah menetapkan XChaCha20-Poly1305 |
| pgcrypto di PostgreSQL | Kunci harus ikut terkirim dalam kueri, sehingga bisa terekam di log kueri dan `pg_stat_statements` |
| Layanan brankas eksternal (HashiCorp Vault, KMS awan) | Menambah layanan yang harus dirawat, dan KMS awan bertentangan dengan kedaulatan data |
| AAD berupa JCS objek | Sama amannya, tetapi rangkaian bergaris miring sudah tidak ambigu karena ULID tidak memuat `/` dan `purpose` dibatasi CHECK. Bentuk ini juga lebih mudah diimplementasikan ulang di alat pemulihan |

## 4. Konsekuensi
- Rotasi kunci induk kelak cukup membungkus ulang `key_wraps` (72 byte per rahasia) tanpa menyentuh `secrets`. Rotasi itu butuh ADR baru karena versi selain 1 belum didukung.
- **Kunci yang disegel TPM2 terikat ke host-nya.** Tanpa salinan kunci induk di luar TPM, pemulihan di VM baru (F-13) mustahil. Karena itu kit pemulihan **wajib** memuat kunci induk atau kunci yang bisa membukanya. Bentuknya diputuskan di slice kit pemulihan.
- Setiap unit systemd yang menjalankan PHP core (FPM, runner, antrean, penjadwal) wajib memuat kredensial ini dan berjalan sebagai pengguna yang bisa membacanya. FPM juga wajib meneruskan `CREDENTIALS_DIRECTORY` ke worker. Rinciannya diatur di slice `install.sh`.
- Setelah rahasia produksi pertama tertulis, format ini mengikat. Mengubahnya berarti mengenkripsi ulang seluruh brankas dan wajib lewat gerbang manusia.
- Bila brankas tidak tersedia, console tidak ikut jatuh: login dan halaman tanpa rahasia tetap berjalan.

## 5. Penegakan
| Klausul | Dijaga oleh |
|---|---|
| 2.1 sumber dan validasi kunci induk | `MasterKeyLoaderTest` |
| 2.2–2.3 format, AAD, 1:1 | `StoreSecretTest`, `VaultTamperTest`, constraint UNIQUE `secrets.key_wrap_id` |
| 2.4 transaksi, audit, penghancuran | `StoreSecretTest`, `DestroySecretTest` |
| 2.4 nilai tidak bocor | `VaultRedactionTest` (grup `redaction`), `SecretValueTest` |
| 2.5 gagal tertutup | `VaultTamperTest` |
| 2.6 pemeriksaan | `VaultCheckCommandTest` |
| 2.7 satu pintu | `VaultBoundaryTest` |
| 2.8 vektor emas | `VaultTamperTest::test_golden_vector_opens` |

## 6. Riwayat
- 2026-10-01: diusulkan bersama slice F-01a Brankas (M1).
