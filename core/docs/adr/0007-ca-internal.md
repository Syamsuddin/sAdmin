# ADR 0007 — CA internal: kunci, pin, dan sertifikat klien agen

| | |
|---|---|
| Status | **Diusulkan**. Menunggu penerimaan pemilik produk sebagai syarat merge |
| Tanggal | 2026-10-01 |
| Pemutus | Pemilik produk. Pin CA dan profil sertifikat adalah bagian protokol (`../kontrak/KONTRAK.md` §2, kontrak 0.5.0). Setelah agen pertama menyematkan pin, mengganti CA berarti rotasi, dan rotasi termasuk gerbang manusia docs/22 ("rotasi CA internal, kunci layanan, atau kunci audit") |
| Lingkup | Pembuatan dan penyimpanan kunci serta sertifikat CA, sidik jari pin `--ca-sha256`, aturan CSR agen, profil sertifikat klien agen, penerbitan di core beserta verifikasi sendiri, dan aturan penerimaan sertifikat klien yang dipakai bersama gateway |
| Di luar lingkup | Sertifikat server TLS gateway (slice gateway/`install.sh`). `CertRenew`. Pencabutan sertifikat. Pesan `Enroll`/`EnrollAccept` serta tabel `servers` dan `agents` (slice enrolment). HMAC gateway↔core. Rotasi CA |
| Rujukan | `../kontrak/KONTRAK.md` §2 (normatif), §3 (tabel kunci), §7 (`E_CSR`), §8 · docs/07_DATA_MODEL.md §Rahasia, §Armada · docs/09_STACK.md (ext-openssl untuk CA ECDSA P-256) · docs/21_SECURITY_RULES.md §Rahasia & brankas · `../capsules/CAPSULES.md` §4 · `../edge/docs/06_BUSINESS_PROCESS.md` (gateway) · docs/adr/0003-format-brankas.md · docs/adr/0006-tanda-tangan-layanan.md |

## 1. Konteks
KONTRAK §2 dan §3 menetapkan bahwa agen tersambung lewat mTLS dengan sertifikat klien dari CA internal, berupa ECDSA P-256 berumur 7 hari yang kuncinya disimpan di brankas. Perintah enrolment (CAPSULES §4) memuat `--ca-sha256 <sidik-jari-CA>`. Namun belum ada dokumen yang merinci hal-hal berikut:
- apa yang di-hash sebagai pin, dan dalam format apa;
- isi dan ekstensi sertifikat CA serta sertifikat klien;
- bagaimana gateway memetakan sertifikat ke `server_id`, padahal agen belum mengetahui `server_id`-nya saat mengirim CSR di `Enroll`;
- syarat CSR yang diterima;
- di mana kunci dan sertifikat CA disimpan, dan bagaimana core memastikan sertifikat yang diterbitkannya memang lolos pemeriksaan gateway.

Tanpa rincian ini, enrolment, gateway, dan perintah enrolment di console tidak bisa dibangun. Begitu agen pertama menyematkan pin, rincian ini tak dapat diubah tanpa enrolment ulang semua agen. Bagian 2 bersifat **normatif**. Aturan protokolnya hanya berumah di KONTRAK §2, dan ADR ini mengatur sisi core.

## 2. Keputusan (normatif)

### 2.1 Kunci dan sertifikat CA
- Setiap tenant punya **tepat satu** CA aktif. Kunci privat ECDSA P-256 **dan** sertifikat CA disimpan bersama di satu baris `secrets` ber-`purpose` `ca_key`, sehingga keduanya terenkripsi envelope oleh brankas (ADR 0003). Isi rahasianya adalah blok PEM kunci privat tanpa frasa sandi yang langsung disusul blok PEM `CERTIFICATE`, masing-masing diakhiri LF, tanpa teks lain. Kunci privat ditulis apa adanya dari ekspor OpenSSL, yaitu PKCS#8 `PRIVATE KEY` atau SEC1 `EC PRIVATE KEY` pada build PHP yang mengekspor format itu. Keduanya diterima saat dibuka, supaya rahasia yang sudah tersimpan tetap terbaca setelah PHP diperbarui.
- Saat dibuka, brankas memeriksa beberapa hal: bentuk isi tepat seperti di atas, kunci berjenis P-256, kunci privat cocok dengan kunci publik sertifikat, dan tanda tangan sertifikat sah dengan kuncinya sendiri. Kegagalan apa pun berarti `VaultIntegrityError`.
- Sertifikat CA disimpan di brankas karena tanda tangan ECDSA acak, sehingga sertifikat yang sama tak bisa dibangun ulang dari kuncinya. Kolom DB biasa bisa ditukar oleh pihak yang menguasai DB. Bila sertifikat ditukar, console akan menampilkan pin milik penyerang di perintah enrolment. Di brankas, penukaran semacam itu justru membuat pembukaan gagal.
- Ketunggalan dijaga indeks unik parsial `secrets_one_active_ca_key` pada `secrets (tenant_id) WHERE purpose = 'ca_key' AND status = 'active'`.
- CA hanya dibuat oleh `php artisan sadmin:ca-init`, yang kelak dipanggil `install.sh` (F-01):
  1. instansi wajib sudah diinisialisasi;
  2. bila tenant itu **pernah** punya baris `ca_key` dengan status apa pun, perintah menolak, karena CA baru adalah rotasi (docs/22) yang butuh ADR baru;
  3. dalam satu transaksi ber-`pg_advisory_xact_lock(7301006)`, kunci dan sertifikat CA dibuat lalu disimpan lewat brankas (audit `secret.store`). Setelah itu sertifikat dibuka ulang dari brankas, dan entri audit `ca.initialize` ditulis dengan aktor `local_root`, target `secret:<id>`, dan `params_redacted` = `{"ca_sha256": "<64 hex>", "not_after": "<RFC 3339 UTC>"}`;
  4. perintah mencetak `ca_sha256` dan `not_after`. Keduanya dihitung dari sertifikat yang dibuka ulang dari brankas, bukan dari nilai di memori sebelum disimpan.
- Profil sertifikat CA mengikuti KONTRAK §2. Serialnya bilangan bulat positif acak (1 … 2^63−1). `notBefore` adalah saat pembuatan, karena OpenSSL lewat PHP tidak bisa memundurkannya, dan `notAfter` = `notBefore` + 3650 hari. Selisihnya bisa lebih 1 detik, karena OpenSSL mengisi kedua waktu dari dua pembacaan jam (lihat §2.3 langkah 5).
- Core **tidak pernah** membuat CA secara implisit, misalnya saat enrolment pertama. CA yang hilang atau dihancurkan tidak boleh diam-diam terganti.
- Kunci privat CA hanya dipakai di dalam `App\Infrastructure\Vault`. `Vault::reveal()` menolak purpose `ca_key`. Sertifikat CA dibaca lewat `Vault::caCertificate()`, dan penandatanganan dilakukan lewat `Vault::signCertificateRequest()`. Hanya `Infrastructure/Vault/X509Authority` yang memanggil fungsi OpenSSL yang memegang kunci privat (`openssl_pkey_new`, `openssl_csr_new`, `openssl_csr_sign`, `openssl_pkey_export`, `openssl_pkey_get_private`).
- Pertahanan berlapis di sisi brankas:
  - `X509Authority::sign()` hanya menerima teks satu blok PEM `CERTIFICATE REQUEST`, sehingga path `file://…` tak pernah sampai ke OpenSSL. Ekstensi yang menjadikan sertifikat sebagai CA (`CA:TRUE`, `keyCertSign`, `cRLSign`) juga ditolak.
  - `Vault::signCertificateRequest()` hanya boleh dipanggil dari `Domain/Fleet/Services/CertificateAuthority` (`VaultBoundaryTest`).
  - Warning PHP dan galat OpenSSL ikut dalam pesan exception. Isinya kode dan alasan pustaka, tanpa material kunci.

### 2.2 Pin CA
`ca_sha256` = SHA-256 atas byte DER sertifikat CA, ditulis 64 hex huruf kecil (KONTRAK §2). Nilai yang ditampilkan core, baik di keluaran `sadmin:ca-init` maupun kelak di perintah enrolment console, selalu dihitung dari sertifikat yang dibuka dari brankas pada saat itu. Core tidak mengambilnya dari entri audit `ca.initialize` atau dari kolom DB mana pun (prinsip yang sama dengan ADR 0006 §2.1).

### 2.3 Penerbitan sertifikat klien agen
`App\Domain\Fleet\Services\CertificateAuthority::issueAgentCertificate(tenant, server_id, csr)` adalah satu-satunya penerbit sertifikat klien. Langkahnya:
1. `server_id` wajib ULID huruf kecil (KONTRAK §8). Bila tidak, ditolak sebagai masukan (`InvalidArgumentException`).
2. CSR diperiksa menurut aturan CSR KONTRAK §2 secara berurutan (`size`, `pem`, `structure`, `key`, `subject`, `signature`). Pelanggaran dilempar sebagai `CertificateRequestRejected` yang membawa `reason`, dan slice enrolment kelak memetakannya ke `E_CSR`.
   - Tata letak DER, versi 0, byte SPKI (P-256 berkurva bernama, titik tak terkompresi), dan byte Name subjek diperiksa atas byte mentah sebelum OpenSSL mengurai apa pun. OpenSSL menerima kurva eksplisit, titik terkompresi, dan CSR versi lain, padahal Go `crypto/x509` dan OpenSSL sendiri saat menandatangani menolaknya.
   - Tanda tangan CSR diverifikasi eksplisit dengan `openssl_verify` atas byte DER `CertificationRequestInfo`, sehingga pemeriksaan ini tidak bergantung pada perilaku internal `openssl_csr_sign`.
3. Bila tenant tak punya CA aktif, penerbitan gagal tertutup dengan `DomainException` yang menyebut `sadmin:ca-init`.
4. Serial acak dibuat (1 … 2^63−1). Sertifikat ditandatangani di brankas dengan profil KONTRAK §2 dan masa berlaku 7 hari. Ekstensi dituliskan ke berkas config OpenSSL sementara (mode 0600, langsung dihapus setelah dipakai). Berkas itu hanya berisi nama ekstensi, `server_id` yang sudah divalidasi, dan `default_bits = 2048`, tanpa rahasia. Baris `default_bits` wajib ada karena PHP 8.3 menolak `openssl_pkey_new` bila panjang kunci dari config kurang dari 384 bit, termasuk untuk kunci EC yang tidak memakainya. Brankas menolak nama dan nilai ekstensi di luar himpunan karakter aman (`\A…\z`, tanpa LF), sehingga config tak bisa disisipi bagian baru.
5. **Tertulis ⇒ terverifikasi.** Sebelum dikembalikan, sertifikat diperiksa dengan aturan penerimaan gateway KONTRAK §2 (`AgentCertificateProfile::verify`, fungsi yang sama dengan yang diuji vektor bersama) pada waktu `notBefore`-nya sendiri. Hasilnya wajib `server_id` yang diminta. Selain itu dicek pula profil penerbitan yang lebih ketat:
   - subjek kosong;
   - `notAfter` − `notBefore` = 604800 detik, atau 604801 detik (`AgentCertificateProfile::issuedValidityConforms`). `openssl_csr_sign` mengisi `notBefore` dan `notAfter` dari dua pembacaan jam terpisah, sehingga detik bisa berganti di antaranya. Terukur 1 dari 50.563 penandatanganan, dan tanpa toleransi ini penerbitan akan gagal secara acak;
   - kunci publik sama dengan kunci CSR;
   - serial sama dengan yang dibuat;
   - tanda tangan `ecdsa-with-SHA256`;
   - tepat lima ekstensi profil dengan flag kritis yang benar, dibaca langsung dari DER karena `openssl_x509_parse` tidak menampilkan flag kritis.

   Waktu berlaku diurai sendiri dari byte DER `Validity` secara ketat (KONTRAK §2). Konversi waktu bawaan PHP menormalkan tanggal mustahil, misalnya bulan 13 menjadi Januari tahun berikutnya, padahal Go dan Python menolaknya. Bila ada yang gagal, sertifikat tidak dikembalikan (`LogicException`).
6. Hasilnya `IssuedCertificate`: PEM sertifikat, serial dalam hex huruf kecil tanpa nol di depan (kelak `agents.cert_serial`), `notBefore`, `notAfter`, dan `server_id`.

Penerbitan tidak menulis audit sendiri, karena tidak mengubah state core. Action pemanggilnya, yaitu enrolment dan kelak `CertRenew`, yang mengubah `agents` dan mencatat serial di auditnya (docs/21).

### 2.4 Identitas di sertifikat
Identitas agen = `server_id` di **satu** URI `subjectAltName` kritis `sadmin://server/<server_id>`, dan subjeknya kosong. Agen tidak tahu `server_id`-nya saat menyusun CSR `Enroll` (`server_id` baru dikirim di `EnrollAccept`). Selain itu `openssl_csr_sign` PHP selalu menyalin subjek CSR. Karena itu CSR wajib bersubjek kosong, dan identitas ditambahkan core sebagai ekstensi.

## 3. Alternatif yang dipertimbangkan
| Alternatif | Ditolak karena |
|---|---|
| `server_id` di `CN` subjek | Subjek berasal dari CSR (PHP tak bisa menggantinya), padahal agen belum tahu `server_id` saat `Enroll`. Menerima subjek apa pun dari CSR berarti nilai pilihan agen tersalin ke sertifikat |
| Identitas lewat serial atau sidik jari sertifikat yang dipetakan core | Gateway harus bertanya ke core untuk setiap koneksi sebelum bisa meneruskan pesan core→agen. Identitas di sertifikat bisa diperiksa gateway sendiri |
| URI `urn:sadmin:server:<id>` | Ruang nama URN `sadmin` tidak terdaftar (RFC 8141). Skema `sadmin://` tidak mengklaim hal itu dan diurai pustaka standar Go maupun OpenSSL |
| Sertifikat CA di kolom/tabel DB | Pihak yang menguasai DB bisa menukarnya, sehingga console menampilkan pin penyerang. Memeriksa kecocokannya dengan kunci di brankas menambah jalur kode tanpa manfaat dibanding menyimpannya di brankas |
| phpseclib atau `spomky-labs/pki-framework` untuk membangun sertifikat bebas subjek | phpseclib termasuk pustaka SSH terlarang (docs/09). pki-framework hanya dependensi transitif WebAuthn, dan menjadikannya dependensi langsung adalah perubahan stack (docs/22). ext-openssl sudah ditetapkan docs/09 dan cukup |
| Memverifikasi tanda tangan CSR lewat efek samping `openssl_csr_sign` | PHP memang memeriksa tanda tangan CSR saat menandatangani, tetapi perilaku itu tidak terdokumentasi. Verifikasi eksplisit atas DER lebih jelas dan sekaligus mengunci algoritme `ecdsa-with-SHA256` |
| Pin atas kunci publik (SPKI) alih-alih sertifikat | Pin sertifikat sudah lazim (`--ca-sha256`), langsung dibandingkan dengan sertifikat yang dikirim gateway, dan ikut mengunci profil serta masa berlaku CA |
| CA berumur pendek dengan rotasi otomatis | Rotasi butuh pesan kepercayaan bertanda passkey dan berjeda yang belum ada. 3650 hari memberi waktu untuk ADR rotasi |

## 4. Konsekuensi
- Enrolment kini punya pin dan penerbit sertifikat yang terbukti lolos aturan penerimaan gateway. Edge mendapat spesifikasi dan vektor bersama untuk CSR (`agent-csr`) maupun sertifikat (`agent-cert`). Kontrak naik ke 0.5.0. Selama 0.x kenaikan minor bersifat memutus, tetapi belum ada implementasi agen yang terdampak.
- Pihak yang menguasai DB tetapi tidak memegang kunci induk tidak bisa menerbitkan sertifikat atau mengganti pin yang ditampilkan core. Pemegang kunci induk (root di host sAdmin) bisa menerbitkan sertifikat klien untuk `server_id` mana pun, sehingga ia bisa menyamar sebagai agen di hadapan core. Ia tetap tidak bisa menjalankan L2/L3 di agen tanpa passkey (A2). Risiko ini diterima sadar di Mode Tunggal (docs/02).
- `notBefore` CA dan sertifikat klien sama dengan saat pembuatan. Sertifikat klien diverifikasi gateway yang berjalan di host yang sama, jadi selisih jam tidak berpengaruh. Lain halnya dengan agen yang jamnya tertinggal dari host sAdmin dan melakukan enrolment beberapa saat setelah `sadmin:ca-init`. Agen itu menolak rantai server gateway karena CA "belum berlaku", dan perbaikannya adalah sinkronisasi jam (NTP).
- CA kedaluwarsa setelah 3650 hari. Sebelum itu wajib ada ADR rotasi CA, yaitu pin baru yang dikirim lewat pesan kepercayaan bertanda passkey dan berjeda. Pemantauan umur CA ditambahkan bersama slice peringatan umum (F-12).
- CA yang sama menandatangani sertifikat klien agen dan, kelak, sertifikat server gateway. Agen yang dibobol memegang sertifikat sah dari CA ini. Bila agen lain hanya memeriksa "rantai berakhir pada CA ber-pin", agen yang dibobol itu bisa menyamar sebagai gateway. Karena itu KONTRAK §2 mewajibkan agen memeriksa EKU `serverAuth` dan nama host gateway, serta menolak sertifikat ber-URI `sadmin://server/…`.
- Runtime produksi adalah PHP 8.3, sedangkan dev memakai 8.4. Perilaku ext-openssl berbeda antarversi (`default_bits`, format ekspor kunci EC), jadi gerbang slice ini menjalankan suite pada kedua versi.
- Pencabutan sertifikat belum ada. Sampai slice enrolment menetapkannya, satu-satunya pembatas sertifikat yang bocor adalah umurnya yang 7 hari.
- Biaya per penerbitan: satu verifikasi ECDSA CSR, satu tanda tangan, satu verifikasi sertifikat, dan satu berkas config sementara, jauh di bawah 10 ms.

## 5. Penegakan
| Klausul | Dijaga oleh |
|---|---|
| 2.1 satu CA aktif, pembuatan eksplisit sekali, penolakan bila pernah ada, isolasi tenant, audit `ca.initialize`, kunci privat tidak bocor (konsol, log, audit) | `InitializeCertificateAuthorityTest` (termasuk grup `redaction`), indeks `secrets_one_active_ca_key` |
| 2.1 bentuk isi rahasia dan kecocokan kunci–sertifikat diperiksa saat dibuka | `CertificateAuthorityTest` (isi rahasia ditukar lewat brankas → `VaultIntegrityError`) |
| 2.1 kunci privat hanya di `Infrastructure/Vault` | `VaultBoundaryTest` |
| 2.2 pin = SHA-256 DER, dihitung dari brankas | `InitializeCertificateAuthorityTest`, `AgentCertificateVectorsTest` (`ca_sha256`) |
| 2.3 aturan CSR (urutan dan alasan) | `AgentCertificateVectorsTest` (vektor `agent-csr`, suite Contract), `CertificateAuthorityTest` |
| 2.3 profil penerbitan (termasuk flag kritis dan toleransi 1 detik), gagal tertutup tanpa CA, tenant, atribut CSR tidak tersalin | `CertificateAuthorityTest` |
| 2.3 langkah 5 dan aturan penerimaan gateway | `AgentCertificateVectorsTest` (vektor `agent-cert`). Profil penerbitan (`conformingIssued`) dijaga tes unit negatif untuk subjek, kunci, durasi, himpunan ekstensi, dan flag kritis (`CertificateAuthorityTest`). Hanya cabang `LogicException` di `issueAgentCertificate` yang tak terjangkau tanpa regresi atau galat perangkat, karena semua masukan agen yang lolos aturan CSR kini diterima OpenSSL. Cabang itu dijaga tinjauan kode |

## 6. Riwayat
- 2026-10-01: diusulkan bersama slice F-02b CA internal (M1) dan kontrak 0.5.0 (`../kontrak/KONTRAK.md` §2, §7).
- 2026-10-01: direvisi setelah review adversarial (1 kritis, 4 sedang, 6 rendah). Perubahannya:
  - `default_bits` di config agar `sadmin:ca-init` berjalan di PHP 8.3.
  - Aturan `key` atas byte SPKI mentah, menolak kurva eksplisit dan titik terkompresi yang tak bisa diurai Go.
  - CSR wajib versi 0.
  - Base64 PEM wajib berpadding dan kanonik.
  - AlgorithmIdentifier tanpa parameter, dan bit sisa masuk aturan `signature`.
  - Waktu berlaku diurai ketat dari DER.
  - Di KONTRAK, aturan `key` sertifikat dipindah sebelum `issuer`.
  - Agen wajib memeriksa identitas gateway.
  - Pertahanan berlapis di `X509Authority::sign()`, dan pesan galat OpenSSL kini menyertakan akar masalahnya.
  - Vektor bertambah 20, termasuk vektor batas dan multi-pelanggaran.
