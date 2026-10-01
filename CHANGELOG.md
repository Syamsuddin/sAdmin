# Changelog

Semua perubahan penting sAdmin (paket `core`, `edge`, dan rumah bersama `kontrak/`, `catalog/`, `capsules/`) dicatat di sini. Format mengikuti [Keep a Changelog 1.1.0](https://keepachangelog.com/id-ID/1.1.0/). Skema versi diatur di `core/docs/22_CHANGE_POLICY.md` §Git.

Tag pra-rilis (`-alpha.N`) menandai kemajuan pengembangan dan **bukan rilis**. Tag seperti ini belum melewati `core/docs/25_RELEASE_CHECKLIST.md` dan tidak boleh dipasang di instansi.

## [Belum dirilis]

Tonggak **M1 Kerangka**, slice 7: kunci layanan dan tanda tangan `sig` bingkai core→agen (F-02 sisi core, bagian pertama). ADR 0006 dan kontrak 0.4.0 berstatus **diusulkan** dan menunggu penerimaan pemilik produk sebelum digabung.

### Diubah
- kontrak 0.4.0: KONTRAK §3 kini merinci tanda tangan kunci layanan (`sig`) pada setiap bingkai core→agen. Algoritmenya Ed25519 murni atas awalan `sadmin-service/1` dan JCS objek `{type, id, body}`, sehingga jenis dan ID bingkai ikut terikat. Pada `Envelope`, `secret_values` tingkat atas dikeluarkan dari cakupan, dan agen wajib menolak `secret_values` yang kuncinya tidak sama persis dengan placeholder `$secret` di `params` (`E_SECRET_COMMIT`). Bingkai core→agen terdiri dari tepat empat anggota. `sig` membuktikan asal, bukan kesegaran. Karena itu dokumen kepercayaan hanya diterima bila versinya naik, pesan lain wajib idempoten, dan pesan untuk satu agen diperiksa terhadap identitas penerimanya. `EnrollAccept` diverifikasi dengan `service_pubkey` di badannya sendiri, dan sidik jari yang dicocokkan admin saat enrolment wajib mencakup roster, `service_pubkey`, dan `audit_pubkey`. KONTRAK §8 kini menetapkan ID sebagai ULID huruf kecil yang dibandingkan apa adanya, sesuai ID yang dibuat core. Vektor bersama beserta oracle independennya ada di `kontrak/vectors/service-sig/`. Oracle itu ditulis hanya dari teks KONTRAK, dan JCS-nya diuji terhadap vektor `jcs`/`jcs-reject`. Selama 0.x, kenaikan minor bersifat memutus, tetapi belum ada implementasi agen yang terdampak.

### Ditambahkan
- core: `php artisan sadmin:service-key-init` membuat kunci layanan Ed25519 instansi sekali. *Seed*-nya hanya disimpan di brankas, sedangkan kunci publiknya dicetak dan dicatat di audit (`service.key_initialize`). Perintah menolak bila kunci pernah ada, termasuk yang sudah dihancurkan, karena kunci baru berarti rotasi dan semua agen yang sudah tersemat akan menolak bingkai. Format ini dikunci di ADR 0006 (diusulkan).
- core: `ServiceSigner` di `Execution/Dispatch` menyusun bingkai core→agen bertanda tangan kunci layanan aktif tenant. Badan bingkai wajib objek JSON, dan objek kosong tetap `{}`. Tanpa kunci aktif, penyusunan gagal tertutup dan kunci tidak pernah dibuat diam-diam. Bingkai lebih dari 1 MiB ditolak. Sebelum dikembalikan, setiap bingkai diurai ulang dengan pengurai I-JSON ketat dan diverifikasi dengan kunci publik turunan brankas, sama seperti pemeriksaan agen. Pengiriman lewat socket gateway menyusul di slice berikutnya.

### Keamanan
- core: sebelum digabung, slice ini melewati review adversarial (docs/22) dengan hasil 0 kritis dan 0 tinggi. Temuan yang ditambal, masing-masing dengan tes regresi yang terbukti merah tanpa tambalannya:
  - `secret_values` yang bukan I-JSON, dan badan yang menjadi larik setelah `secret_values` dikeluarkan, kini ditolak sebagai masukan, tidak lagi lolos sampai verifikasi sendiri;
  - huruf ULID kini ditetapkan;
  - teks kontrak tentang putar ulang dan enrolment diperketat;
  - kasus tes base64 tak kanonik diperbaiki;
  - jalur larik asosiatif kini diuji terhadap vektor.

  Komitmen placeholder rahasia, penolakan tanda tangan oleh kunci yang di-*rotate* di brankas, galat tak tertangkap pada perintah init kunci, dan pipa verifikasi pesan non-`Envelope` di agen ditunda ke slice pemiliknya.

### Catatan migrasi
- Migrasi baru, non-destruktif: indeks unik parsial `secrets_one_active_service_key` (satu kunci layanan aktif per tenant).

## [0.1.0-alpha.5] — 2026-10-01

Tonggak **M1 Kerangka**, slice 3–6: tema console (F-17), brankas rahasia (F-01 bagian pertama), checkpoint audit bertanda tangan (F-04 bagian kedua), dan alert `audit_mismatch` (F-04 bagian ketiga). Kriteria AC-03 (audit) kini diterima seluruhnya. ADR 0003, 0004, dan 0005 beserta kontrak 0.3.0 diterima pemilik produk.

### Diubah
- core: ADR 0001 (format hash rantai audit) disusun ulang menjadi spesifikasi normatif yang lengkap: tabel dua belas anggota badan entri, kanonisasi, rumus hash, penyimpanan, penulisan, algoritme verifikasi, vektor emas, alternatif yang ditolak, konsekuensi, dan tes penegak. Spesifikasinya diuji dengan implementasi independen yang ditulis hanya dari teks ADR, dan hasilnya sama persis dengan vektor emas. Isi normatif tidak berubah. ADR ini kemudian **diterima** pemilik produk, sehingga format rantai audit kini mengikat: mengubahnya wajib lewat gerbang manusia (docs/22).
- core: `docs/adr/README.md` berisi indeks dan templat ADR; ADR 0002 diselaraskan dengan templat itu.
- kontrak 0.3.0: KONTRAK §3 kini merinci isi yang ditandatangani kunci audit (`CheckpointAnchor.signature`): Ed25519 murni atas awalan `sadmin-audit-checkpoint/1` dan JCS `{created_at, hash, seq}`, dengan pengodean base64 standar. Pengodean base64 wajib kanonik (bit sisa nol). Vektor bersama beserta oracle independennya ada di `kontrak/vectors/checkpoint/`. Format ini ditetapkan di ADR 0004 (**diterima** pemilik produk). Selama 0.x, kenaikan minor bersifat memutus, tetapi belum ada implementasi agen yang terdampak.
- Roadmap M1: Subresource Integrity aset console dijadwalkan di slice `install.sh` (F-01), sesuai keputusan pemilik produk.
- core: ADR 0004 §2.1 kini mengizinkan `SecretValue::expose()` di adaptor pengirim `app/Infrastructure/Notify` selain brankas (ADR 0005 §2.6, dipilih pemilik produk). Kode domain, perintah, Livewire, HTTP, dan model tetap tak boleh membuka nilai rahasia, dan seed Ed25519 tetap tak pernah keluar dari brankas.
- core: kriteria AC-03 (audit) diterima seluruhnya dan diarsipkan ke `core/docs/_archive/23-audit.md`.

### Ditambahkan
- core: `WebAuthnBoundaryTest` menegakkan aturan satu pintu ADR 0002, yaitu hanya adaptor `app/Infrastructure/WebAuthn` yang memakai pustaka WebAuthn/COSE/CBOR.
- core: tema console light/dark per admin (F-17, M1). Pengalih tema *Ikuti sistem / Terang / Gelap* di topbar menyimpan pilihan ke `admins.theme`. Pilihan `light`/`dark` dirender server sebagai `data-bs-theme` pada `<html>` sehingga tidak berkedip saat dimuat, sedangkan `system` mengikuti `prefers-color-scheme` OS, termasuk ketika OS berganti mode tanpa muat ulang. Setiap perubahan tercatat di audit sebagai `admin.theme_change` dengan nilai lama dan baru. Pilihan yang tidak dikenal ditolak dengan pesan berformat docs/14. Halaman tamu (*Masuk*) selalu mengikuti OS.
- core: brankas rahasia (F-01 bagian pertama, M1). Setiap rahasia dienkripsi dengan kunci data XChaCha20-Poly1305 miliknya sendiri, dan kunci data itu dibungkus kunci induk. Kunci induk dibaca dari kredensial systemd (`$CREDENTIALS_DIRECTORY/sadmin-vault-master`). Hanya di dev, kunci boleh diambil dari berkas bermode 0600 lewat `SADMIN_VAULT_DEV_KEY`. Sumber ini hanya diterima bila `APP_ENV` = `local`/`testing`, dan di luar itu `CREDENTIALS_DIRECTORY` wajib berada di bawah `/run/credentials/`. Data terasosiasi mengikat ciphertext ke tenant, ID, *purpose*, dan kunci datanya, sehingga baris yang ditukar atau dilabel ulang lewat SQL gagal dibuka alih-alih menghasilkan nilai yang salah. Pembaca rahasia wajib menyebut *purpose* dan tenant yang ia harapkan, sehingga penunjuk yang ditukar di tabel lain tidak membuka rahasia untuk keperluan yang salah. Menyimpan dan menghancurkan rahasia tercatat di audit (`secret.store`, `secret.destroy`) dengan *purpose* saja. Menghancurkan rahasia menimpa ciphertext dan kunci datanya dengan nol. Nilai rahasia dibawa objek yang tidak tercetak saat di-dump dan tidak bisa diserialisasi. Format ini dikunci di ADR 0003 (**diterima** pemilik produk) beserta vektor emasnya.
- core: `php artisan sadmin:vault-check` membuktikan bahwa kunci induk yang termuat bisa membuka semua kunci data rahasia aktif, tanpa membuka nilai rahasianya. Perintah ini dipakai `install.sh` dan pemulihan.
- core: checkpoint audit bertanda tangan (F-04 bagian kedua, M1). `php artisan sadmin:audit-key-init` membuat kunci audit Ed25519 instansi sekali: *seed*-nya hanya disimpan di brankas, kunci publiknya dicetak untuk kit pemulihan dan dicatat di audit (`audit.key_initialize`). `php artisan sadmin:audit-checkpoint` menandatangani ujung rantai audit. Penjadwal menjalankannya tiap menit dengan `--if-due`, sehingga checkpoint dibuat tiap 15 menit atau 100 entri. Sebelum menandatangani, segmen sejak checkpoint terakhir dibuktikan utuh lebih dulu, jadi checkpoint tak pernah mengesahkan rantai yang sudah diubah. Baris `audit_checkpoints` dijaga trigger: hanya `anchored_to` yang boleh bertambah.
- core: `sadmin:audit-verify` kini juga memeriksa checkpoint, sehingga dua serangan yang sebelumnya lolos kini terdeteksi: pemotongan ujung rantai dan penulisan ulang rantai dari suatu titik dengan hash dihitung ulang. Kode exit: 0 utuh, 1 rusak (`audit_mismatch`), 2 checkpoint tak dapat diperiksa karena brankas tak tersedia. Rantai tanpa checkpoint tetap terverifikasi tanpa kunci induk.
- core: seed kunci Ed25519 (`audit_key`, `service_key`) kini tak pernah keluar dari brankas: `Vault::reveal()` menolaknya, dan pembacaan ulang saat menyimpan rahasia memakai `Vault::matches()` yang membandingkan nilai di dalam brankas (ADR 0003 §2.5).

- core: alert `audit_mismatch` critical (F-04 bagian ketiga, M1). Ketika `sadmin:audit-verify` menemukan rantai atau checkpoint rusak, atau `sadmin:audit-checkpoint` menolak menandatangani atau gagal membuka kunci audit, core membuka alert di tabel `alerts` dan langsung mengirimnya ke semua kanal aktif (Telegram dan SMTP instansi). Pengiriman berlangsung sinkron di proses pendeteksi, tidak lewat antrean, sehingga batas 60 detik tak bergantung pada worker dan tak bisa dibungkam dengan menghapus baris `jobs`. Pengiriman dibatasi anggaran 50 detik, dan kanal yang gagal dicoba sekali lagi. Satu kejadian (lokasi kerusakan yang sama) dikirim sekali, lalu diingatkan ulang tiap 24 jam selama kerusakannya masih terdeteksi; alert yang gagal terkirim dicoba lagi pada deteksi berikutnya. Kegagalan apa pun di satu kanal tidak menghentikan kanal lain, dan proses lain yang memegang kunci kejadian hanya ditunggu sekitar 5 detik. Pembukaan dan keberhasilan kirim tercatat di audit (`alert.open`, `alert.notify`). Kode exit verify tidak berubah. Format ini dikunci di ADR 0005 (**diterima** pemilik produk).
- core: `php artisan sadmin:notify-channel-add telegram|smtp` menambah kanal notifikasi. Token bot dan kata sandi SMTP dibaca dari prompt tersembunyi, tidak pernah dari argumen, lalu disimpan di brankas. SMTP selalu terenkripsi: TLS langsung, atau STARTTLS yang harus terbukti di transkrip SMTP agar kiriman dihitung terkirim. Audit hanya mencatat jenis kanal, tanpa chat ID atau alamat email. `php artisan sadmin:notify-test` mengirim pesan uji ke semua kanal aktif dan melaporkan hasil per kanal.

### Keamanan
- core: galat dari pustaka HTTP/SMTP dibersihkan dari token dan kata sandi sebelum dicatat, termasuk URL Bot API yang memuat token (juga dalam bentuk ter-encode), dan galat aslinya tidak dirantai. Tes grup `redaction` menyalurkan token dan kata sandi canary lewat galat cURL dan galat SMTP yang menggemakan kata sandi, lalu memindai keluaran perintah, log, audit, alert, dan config kanal. Argumen jejak exception pengirim ditandai `#[SensitiveParameter]`.
- core: sebelum digabung, slice ini melewati review adversarial (docs/22) dengan hasil 0 kritis dan 0 tinggi. Empat temuan sedang dan tiga temuan rendah sudah ditambal, masing-masing dengan tes regresi yang terbukti merah tanpa tambalannya. Temuan itu adalah: STARTTLS yang dilucuti tercatat sebagai terkirim; penantian tanpa batas pada kunci advisory dan penjadwal; satu kanal rusak menggagalkan semua kanal; kerusakan sesudah kerusakan pertama tak pernah diingatkan; argumen jejak exception membawa token; regex menerima baris baru di akhir; dan kunci audit yang gagal dibuka tak membuka alert. Penjadwal kini menjalankan verify dan checkpoint dengan `withoutOverlapping`.

### Catatan migrasi
- Migrasi baru, semuanya non-destruktif: `notification_channels`, `alert_rules` (`UNIQUE(tenant_id, kind)`; aturan `audit_mismatch` tak bisa dinonaktifkan), dan `alerts` (indeks unik parsial `alerts_unresolved_dedup`; FK `server_id` menyusul bersama tabel `servers`).
- Migrasi baru, keduanya non-destruktif: `key_wraps` dan `secrets` (`secrets.key_wrap_id` UNIQUE, satu kunci data per rahasia).
- Migrasi baru, keduanya non-destruktif: tabel `audit_checkpoints` dan indeks unik parsial `secrets_one_active_audit_key` (satu kunci audit aktif per tenant).

### Belum tercakup
- Penyegelan kunci induk (TPM2 lewat `systemd-creds`, atau frasa sandi) dan unit systemd yang memuat kredensialnya menunggu slice `install.sh`. Sebelum itu, brankas di produksi berstatus tak tersedia dan gagal tertutup.
- Kit pemulihan wajib memuat salinan kunci induk, karena kunci yang tersegel TPM2 tidak bisa dibawa ke VM baru (ADR 0003 §4).
- Checkpoint belum dijangkarkan ke luar DB core (`anchored_to` masih kosong). Jangkar ke agen, offsite, dan digest harian menunggu paket edge, backup offsite, dan notifikasi. Sampai saat itu, penghapusan checkpoint bersama pemotongan rantai oleh superuser, serta penyerang yang memegang kunci induk, belum terdeteksi (ADR 0004 §4).
- Alert belum bisa diakui atau diselesaikan, dan belum tampil di console (lonceng, halaman *Peringatan*, banner "audit merah" docs/26). Antarmuka itu menunggu slice UI peringatan.
- Kanal notifikasi belum menjadi bagian kebijakan bertanda tangan. Saat `policy_bundles` hadir (M2), mengubah kanal menjadi perubahan L3 dengan jeda 24 jam (ADR 0005 §4).
- Alert untuk `VaultIntegrityError` di luar jalur audit, alert non-critical (F-12), dan ringkasan harian belum ada.
- Sebelum `sadmin:audit-key-init` dijalankan, penjadwal mencatat log `error` `audit_checkpoint_failed` tiap menit. `install.sh` (F-01) akan membuat kunci audit sebelum mengaktifkan penjadwal.

## [0.1.0-alpha.4] — 2026-09-30

Tonggak **M1 Kerangka**, slice 2: login console dengan passkey (F-03).

### Ditambahkan
- core: tabel `institutions`, `admins`, dan `authenticators` sesuai docs/07, serta tabel `sessions` berkunci ULID.
- core: `php artisan sadmin:institution-init <hostname>` menetapkan RP ID permanen; hostname wajib FQDN dan tidak boleh alamat IP. `php artisan sadmin:admin-invite "<nama>"` mencetak tautan bertanda tangan 15 menit untuk mendaftarkan tepat dua passkey.
- core: login passkey tanpa nama pengguna (passkey dapat-ditemukan). Aturannya: algoritme ES256/EdDSA, verifikasi pengguna wajib, attestation `none`, origin eksplisit (wajib HTTPS, subdomain ditolak), tipe clientData sesuai ceremony, ceremony lintas origin ditolak, counter anti-klon, dan challenge sekali pakai yang kedaluwarsa dalam 5 menit. Satu ID korelasi menghubungkan pesan di layar, log detail, dan audit penolakan.
- core: halaman *Masuk*, *Daftarkan passkey*, dan *Passkey Anda*, lengkap dengan empat state wajib.
- core: sesi console memakai cookie Secure/HttpOnly/SameSite=Strict, batas idle 30 menit dan mutlak 12 jam, ID sesi diregenerasi saat login, dan batas 10 percobaan login per menit per IP. Admin yang dinonaktifkan kehilangan sesinya pada permintaan berikutnya.
- core: entri audit untuk `console.login` (ok maupun ditolak), `console.logout`, `admin.invite`, `institution.initialize`, dan `authenticator.register`.
- core: Livewire 4, Tabler 1.6, `resources/css/tokens.css` (docs/26), dan `php artisan sadmin:ui-token-scan`. Tabler Icons disalin apa adanya dan dijaga tes asal-usul.
- core: autentikator virtual deterministik untuk tes, sehingga verifikasi WebAuthn tidak pernah di-bypass (docs/13).

### Diubah
- WebAuthn memakai `web-auth/webauthn-lib` lewat adaptor tunggal `app/Infrastructure/WebAuthn` (ADR 0002, dipilih pemilik produk), menggantikan `laragear/webauthn` yang bertentangan dengan skema docs/07.
- docs/09: Livewire 4.x, Tabler 1.6.x, Node 22/Vite 8, dan WebAuthn kini terverifikasi. docs/08, 10, 11, dan 12 disesuaikan. Komponen Ikon (Tabler Icons tervendor) ditambahkan ke inventaris docs/26.

### Keamanan
- Rute `storage/{path}` bawaan Laravel 13 ditutup, termasuk rute PUT unggah bertanda tangan: disk `local` kini memakai `serve: false`.
- Sebelum merge, slice ini melewati audit keamanan adversarial (docs/22) dengan hasil 0 kritis dan 0 tinggi. Dua temuan sedang dan dua temuan rendah sudah ditambal; setiap mutan dari laporan audit kini terbukti membuat tes merah.

### Diperbaiki
- Zona waktu sesi PostgreSQL kini dipaksa UTC. Sebelumnya stempel waktu Eloquent tersimpan bergeser mengikuti zona server PostgreSQL (di dev +8 jam), padahal docs/07 mewajibkan UTC. Rantai audit tidak terdampak karena selalu ditulis dengan akhiran `Z`.

### Catatan migrasi
- Migrasi baru, semuanya non-destruktif: `institutions`, `admins`, `authenticators`, `sessions`.
- Setelah `sadmin:institution-init` dijalankan, hostname console (RP ID) bersifat permanen.

### Belum tercakup
- Tema per admin (F-17), WireGuard dan `install.sh` (F-01), serta menambah atau mencabut passkey (perubahan roster L3).
- `passkey.js` baru diverifikasi lewat Node terhadap server PHP; uji browser sungguhan dengan autentikator nyata belum dilakukan.
- Aset console belum memakai Subresource Integrity yang diwajibkan docs/21 §Rilis. Menambahkannya butuh plugin Vite baru sebagai dependensi, sehingga menunggu keputusan pemilik produk.

## [0.1.0-alpha.3] — 2026-09-30

Menutup keputusan terbuka 3 dari 0.1.0-alpha.1: aturan masukan kanonisasi di kontrak protokol. **Kontrak naik ke 0.2.0.**

### Diubah
- kontrak 0.2.0 (`kontrak/KONTRAK.md` §3): seluruh teks bingkai yang diterima wajib I-JSON (RFC 7493) dan diperiksa pada byte mentah sebelum pengurai apa pun dan sebelum verifikasi `sig`. Artinya UTF-8 sah tanpa BOM, tanpa nama anggota ganda, nama anggota tanpa U+0000, angka hanya integer desimal ≤ ±(2^53−1) tanpa titik dan eksponen, dan sarang paling dalam 64 tingkat. Noncharacter sengaja diterima, menyimpang dari RFC 7493 §2.1. Setiap pihak menolak masukan yang melanggar, termasuk JSON yang sintaksnya rusak, dan tidak memperbaikinya.
- kontrak §1: selama 0.x, minor berlaku sebagai major dan field `kontrak` berisi `major.minor`, supaya pihak 0.1 dan 0.2 saling mengenali ketidakcocokan.
- kontrak §7: kode galat baru `E_CANONICAL`.
- kontrak: berkas `kontrak/VERSION` kini ada (sebelumnya dirujuk KONTRAK.md tetapi tidak ada).

### Ditambahkan
- kontrak: 20 vektor tolak di `kontrak/vectors/jcs-reject/` (byte mentah dalam base64, masing-masing dengan `reason` yang diuji) dan enam vektor terima baru. Vektor terima boleh membawa `input_base64` agar PHP dan Go menguji byte yang sama; kasusnya antara lain `-0`, noncharacter, sarang objek 64 tingkat, dan U+0000 di nilai string.
- edge: langkah 1 pipa verifikasi E1 kini memeriksa I-JSON pada byte mentah (`E_CANONICAL`). `edge/docs/09_STACK.md` mencatat hasil uji `gowebpki/jcs` v1.0.2: pustaka itu menolak UTF-8 tak sah, surrogate, dan kunci ganda, tetapi menerima angka di luar aturan, sarang lebih dari 64, dan nama anggota ber-U+0000, sehingga ketiganya wajib divalidasi sendiri.
- core: `Jcs::decode()`, pengurai ketat yang menolak BOM, UTF-8 tak sah, surrogate tunggal, JSON rusak, kunci ganda (termasuk yang disamarkan escape), U+0000 di nama anggota, angka di luar aturan, dan sarang lebih dari 64. Verifier audit kini memakainya. `Jcs::canonicalize()` juga menolak U+0000 di nama anggota, sehingga core tidak menghasilkan teks yang akan ditolaknya sendiri.
- Sebelum merge, slice ini melewati review adversarial (docs/22) dengan vonis "layak merge dengan catatan"; semua catatan sudah ditambal.

### Catatan migrasi
- Tidak ada migrasi database.
- Perubahan kontrak ini aman karena belum ada implementasi Go maupun agen terpasang. Implementasi Go di paket edge (pustaka `gowebpki/jcs`, masih `[VERIFIKASI]` di `edge/docs/09_STACK.md`) wajib lulus vektor tolak, dan bila pustaka itu tidak menolak dengan sendirinya, validasi harus ditambahkan secara eksplisit.

## [0.1.0-alpha.2] — 2026-09-30

Menutup keputusan terbuka 1 dan 2 dari 0.1.0-alpha.1: cakupan larangan eksekusi OS di core.

### Keamanan
- core: `mail()`, `mb_send_mail()`, `imap_mail()`, `error_log()` bertujuan email, dan transport mail yang berujung sendmail kini dilarang (docs/09), karena semuanya menjalankan biner `sendmail` dan parameter ke-5 `mail()` bisa dipakai menyisipkan flag.
- core: `SendmailRefusingMailManager` menolak setiap transport yang berujung `SendmailTransport`. Yang diperiksa objek hasil, bukan nama, termasuk anak di dalam transport gabungan, sehingga penolakan berlaku untuk `sendmail`, `mail`, huruf kapital, `MAIL_URL` (termasuk `?path=` berisi perintah pilihan penyerang), failover, creator kustom, maupun `Mail::build()`. Adapun `native://` memang tidak didukung Laravel.
- core: `sadmin:forbidden-scan` kini memindai semua kode PHP milik proyek yang berjalan di produksi, yaitu `app`, `bootstrap` (tanpa `cache`), `config`, `database`, `lang`, `public`, `resources/views`, `routes`, dan `artisan`, termasuk berkas tersembunyi, ekstensi berhuruf kapital, dan direktori symlink (kecuali `public/storage` hasil `storage:link`). Import group (`A\{B}`) dan alias namespace (`use A as X; X\B`) diurai ke nama lengkap, sehingga larangan `Process` yang sudah ada juga tak bisa disamarkan. Blade dikompilasi lebih dulu sehingga blok `@php` dan `{{ }}` ikut terpindai. Pemindai juga menandai DSN `sendmail:`/`mail:`/`native:`, akses langsung transport Symfony Mailer, dan Monolog `NativeMailerHandler`. Satu-satunya pengecualian tercatat adalah penjaga yang menyebut `SendmailTransport` untuk menolaknya.
- Sebelum merge, slice ini melewati review adversarial (docs/22). Putaran pertama menemukan bahwa penjaga awal, yang mencocokkan nama transport, bisa dilewati lewat `mail`, `Sendmail://`, dan `MAIL_URL`. Putaran kedua menemukan pemindai bisa dilewati lewat import group dan alias namespace. Keduanya ditutup sebelum tag ini dibuat.

### Diubah
- `core/docs/09_STACK.md`: daftar teknologi terlarang ditambah `mail`, `mb_send_mail`, `imap_mail`, `error_log` bertujuan, transport sendmail/`mail`/`native`, akses langsung transport Symfony Mailer, `NativeMailerHandler`, `pcntl_exec`, dan FFI; cakupannya kini "semua kode PHP milik proyek di `core/`".
- `core/docs/11_COMMANDS.md`: cakupan `sadmin:forbidden-scan` diselaraskan dengan docs/09.
- `core/config/mail.php`: mailer `sendmail` dihapus.

### Catatan migrasi
- Tidak ada migrasi database.
- Konfigurasi apa pun yang memilih transport sendmail (misalnya `MAIL_MAILER=sendmail`, `MAIL_URL=sendmail://…`, `mail://…`, `native://…`) kini menggagalkan pengiriman dengan pesan yang jelas. Gunakan SMTP.

### Belum tercakup
- `disable_functions` di PHP-FPM produksi, dan pilihan penjadwal: scheduler Laravel menjalankan tiap tugas lewat `proc_open`, sedangkan systemd timer per tugas tidak. Keduanya diputuskan di slice `install.sh` (F-01).

## [0.1.0-alpha.1] — 2026-09-30

Tonggak **M1 Kerangka**, slice 1: rantai audit sisi core (F-04). Kriteria AC-03 baru terpenuhi sebagian (lihat *Belum tercakup*).

### Ditambahkan
- Paket blueprint VCBD `core` (induk produk) dan `edge`, rumah bersama `kontrak/`, `catalog/`, `capsules/`, peta monorepo `README.md`, serta lisensi MIT.
- core: kerangka Laravel 13.34 untuk PHP 8.3 dan PostgreSQL, dengan antrean dan cache memakai driver `database`. Tanpa Tailwind, CDN, Redis, maupun dependensi yang tak tercantum di docs/09.
- core: tabel `tenants` dan `audit_entries`. `audit_entries` bersifat append-only: trigger DB menolak UPDATE, DELETE, dan TRUNCATE.
- core: `AppendAuditEntry` membangun rantai hash `SHA-256(prev_hash ∥ JCS(entri))`. Nomor urut dijamin tanpa celah lewat kunci advisory, dan entri ikut batal bila transaksi pemanggil batal. Masukan berisi byte NUL atau sarang lebih dari 64 tingkat ditolak. Setiap entri juga dibaca ulang sebelum commit, sehingga entri yang berhasil tertulis selalu bisa diverifikasi.
- core: `php artisan sadmin:audit-verify` (exit 0 = rantai utuh; saat rusak mencatat log `critical` `audit_mismatch`), dijadwalkan harian. Baris yang dimanipulasi dalam bentuk apa pun dilaporkan sebagai `audit_mismatch`, tidak pernah berakhir sebagai crash.
- core: `php artisan sadmin:forbidden-scan` sebagai tripwire eksekusi OS/SSH di kode core, termasuk bentuk alias `use function`, `namespace\`, dan FFI.
- core: kanonisasi RFC 8785 (JCS) internal di `app/Infrastructure/Jcs`.
- kontrak: tujuh vektor uji JCS bersama PHP↔Go di `kontrak/vectors/jcs/`, termasuk penjaga escape HTML bawaan Go.
- core: ADR 0001 tentang format hash rantai audit beserta batas masukannya, berstatus *diusulkan* dan menunggu tinjauan pemilik produk.
- core: 64 tes (Unit, Feature, Contract, grup `redaction`), termasuk vektor emas format rantai dan tes manipulasi per kolom. Sebelum merge, slice ini melewati review adversarial (docs/22), dan semua temuan yang mematahkan invarian audit sudah ditambal dengan tes regresi.

### Diubah
- `core/docs/09_STACK.md`: versi Laravel 13.x, PHPUnit 12, dan Larastan (analisis statis) kini terverifikasi.
- `core/docs/22_CHANGE_POLICY.md`: skema versi produk dan kewajiban changelog.

### Catatan migrasi
- Migrasi baru, semuanya **non-destruktif**: `2026_09_30_000100_create_tenants_table`, `2026_09_30_000200_create_audit_entries_table`, ditambah migrasi bawaan Laravel `cache` dan `jobs`.
- Rilis ini menetapkan format rantai audit untuk pertama kali. Setelah ada data produksi, format tersebut hanya boleh diubah lewat gerbang manusia (docs/22).

### Belum tercakup
- AC-03: alert `audit_mismatch` critical belum terkirim ≤ 60 detik, karena tabel `alerts` dan kanal notifikasi belum ada.
- Checkpoint audit bertanda tangan dan jangkar ke agen, offsite, serta digest.
- Pencabutan hak UPDATE/DELETE/TRUNCATE dari role aplikasi (menunggu `install.sh`).
- Fitur M1 lain yang belum dikerjakan: `install.sh` (F-01), login passkey (F-03), inventaris, dan tema console (F-17).
- `sadmin:forbidden-scan` belum mencakup `mail()` dan transport `sendmail` di `config/mail.php`, maupun berkas Blade. Cakupan path di docs/09 ("di `core/`") dan docs/11 (`app`, `routes`, `config`) juga belum selaras; keduanya menunggu keputusan.
- Batas sarang JCS 64 tingkat (`Jcs::MAX_DEPTH`) berlaku untuk semua pemakaian JCS di core, tetapi belum tercatat di `kontrak/KONTRAK.md` §3, begitu pula aturan penolakan UTF-8 tak sah. Perubahan kontrak memerlukan gerbang manusia.
