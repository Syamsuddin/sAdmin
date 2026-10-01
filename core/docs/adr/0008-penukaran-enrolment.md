# ADR 0008 — Penukaran enrolment: `Enroll`→`EnrollAccept`, roster dan kebijakan awal, sidik jari kepercayaan

| | |
|---|---|
| Status | **Diusulkan** — menunggu keputusan pemilik produk. Belum ada kode yang bergantung pada ADR ini |
| Tanggal | 2026-10-02 |
| Pemutus | Pemilik produk. Ini perubahan kontrak (KONTRAK §3, §5; usulan kontrak 0.6.0) sekaligus keputusan keamanan (apa yang dipercaya agen untuk selamanya). Docs/22: gerbang manusia |
| Lingkup | Cara core menukar token enrolment menjadi `EnrollAccept`; isi dan bentuk roster v1 dan kebijakan v1; format sidik jari kepercayaan; status server dan baris `agents` setelah enrolment; urutan pemeriksaan dan kode galat |
| Di luar lingkup | Transport (inbox gateway UDS + HMAC, mTLS, TLS server gateway) — slice gateway. `Hello`/`Heartbeat` dan inventaris. `CertRenew`. `RosterUpdate`/`PolicyBundle` bertanda tangan passkey dan jeda 24 jam (M2). Sisi agen (edge). Pensiunkan server |
| Rujukan | `../kontrak/KONTRAK.md` §2, §3 (`EnrollAccept`), §4, §5, §7 · docs/07_DATA_MODEL.md §rosters, §policy_bundles, §servers, §agents · docs/21_SECURITY_RULES.md · docs/adr/0006, 0007 · `../catalog/CATALOG.md` §1, §3 · `../edge/docs/21_SECURITY_RULES.md` · `../capsules/CAPSULES.md` §4 |

## 1. Konteks
Slice F-02a–c sudah menyediakan kunci layanan (`sig`), CA internal dengan penerbit sertifikat klien, serta server `enrolling` dengan token sekali pakai. Yang belum ada adalah langkah yang menyatukannya: agen mengirim `Enroll`, core menjawab `EnrollAccept` {`server_id`, `cert`, `roster`, `policy`, `service_pubkey`, `audit_pubkey`}.

KONTRAK §3 menyatakan kepercayaan saat enrolment berasal dari pin CA, token, dan **sidik jari kepercayaan** yang dicocokkan admin di terminal dan di console, mencakup roster, `service_pubkey`, dan `audit_pubkey`, dengan "format ditetapkan bersama enrolment". Setelah agen menyematkan ketiganya, mengubahnya berarti enrolment ulang atau `RosterUpdate` ber-jeda. Selain format sidik jari, tiga hal belum punya rumah:
1. bentuk dokumen roster v1 dan siapa yang membuatnya, padahal roster seharusnya lahir dari persetujuan passkey (M2);
2. bentuk dokumen kebijakan v1 di M1, saat aksi tulis belum ada;
3. perilaku penukaran token: urutan pemeriksaan, atomisitas, dan apa yang terjadi bila CSR salah.

## 2. Keputusan (normatif, bila diterima)

### 2.1 Pemanggil dan batas
Penukaran dijalankan oleh `App\Domain\Fleet\Actions\AcceptEnrollment`. Aksi ini menerima badan `Enroll` yang sudah lolos skema di gateway, dan mengembalikan badan `EnrollAccept` lengkap dengan `sig` (disusun lewat `ServiceSigner`, ADR 0006). Aksi tidak melakukan I/O jaringan apa pun. Inbox gateway yang memanggilnya adalah slice berikutnya. Penerbitan sertifikat hanya lewat `CertificateAuthority::issueAgentCertificate` (ADR 0007). Amplop ke agen tetap hanya lewat `Execution/Dispatch`. `EnrollAccept` bukan amplop aksi, dan ADR ini menetapkannya sebagai satu-satunya bingkai core→agen yang disusun di luar `Dispatch`, karena agen belum punya identitas.

### 2.2 Urutan dan atomisitas
Seluruh langkah berjalan dalam **satu transaksi** yang menahan baris server (`SELECT … FOR UPDATE`). Kegagalan di langkah mana pun membatalkan semuanya, sehingga token tidak terbakar oleh CSR yang salah. Urutannya:
1. `kontrak` bermayor sama, lain-lain → `E_KONTRAK_VERSION`.
2. Token: cari server `enrolling` dengan `enroll_token_hash` = SHA-256 token dan `enroll_token_expires_at` > sekarang. Token salah, kedaluwarsa, sudah dipakai, atau milik server yang bukan `enrolling` **semuanya** menghasilkan `E_ENROLL_TOKEN` dengan pesan identik, tanpa menyebut sebabnya.
3. `platform_id` harus `ubuntu-24.04` (satu-satunya platform MVP, docs/02). Lainnya → `E_PLATFORM`.
4. CSR → `CertificateAuthority::issueAgentCertificate` (ADR 0007 §2.3). Pelanggaran → `E_CSR` dengan `reason`.
5. Token dikosongkan (hash dan kedaluwarsa menjadi NULL), status server menjadi `offline`, baris `agents` dibuat (serial, `not_after`, sidik jari kepercayaan), dan entri audit `server.enroll` ditulis. Semua dalam transaksi yang sama.
6. `EnrollAccept` disusun dan ditandatangani **setelah** commit. Kegagalan menyusun bingkai tidak boleh membakar token, sehingga bingkai disusun dulu dalam transaksi dan hanya dikirim setelah commit.

Percobaan penukaran yang gagal tidak menulis audit (mencegah banjir audit oleh pihak tak berotoritas), tetapi dihitung di metrik `enroll_rejected_total{reason}` (docs/15). Pembatasan laju adalah tugas gateway.

Audit `server.enroll`: aktor `agent` dengan ref `server_id`, `params_redacted` = {`serial`, `cert_expires_at`, `agent_version`, `platform_id`, `reported_hostname`, `trust_fingerprint`}. Tanpa token dan tanpa CSR.

### 2.3 Hostname yang dilaporkan
`Enroll.hostname` **tidak** diblokir bila berbeda dari `servers.hostname`. Admin yang mengetik nama itu, dan agen melaporkan hostname VM apa adanya, sehingga selisih lazim (mis. alias DNS). Selisihnya dicatat di audit (`reported_hostname`) dan ditampilkan di detail server kelak. Identitas dipegang token + CSR, bukan hostname.

### 2.4 Roster v1
- Roster v1 dibuat core **saat penukaran pertama** di tenant itu bila belum ada roster aktif, dan hanya bila ada ≥ 1 admin aktif dengan ≥ 2 passkey `active` (docs/05). Bila tidak terpenuhi, penukaran dibatalkan dengan galat internal yang membuat gateway menjawab `E_CORE_UNAVAILABLE` (sementara) dan token tetap utuh (transaksi dibatalkan, §2.2). Syarat ini juga diperiksa di halaman Tambah server sebagai prasyarat state Gagal (slice implementasi).
- Roster v1 berstatus `active`, `effective_at` = saat pembuatan, tanpa jeda 24 jam, dengan `approvals` berupa array kosong. Ia dipercaya karena sidik jari (§2.6) dicocokkan admin, bukan karena persetujuan passkey. Ini satu-satunya dokumen kepercayaan yang boleh lahir tanpa passkey. Versi berikutnya wajib lewat `RosterUpdate` (M2).
- Bentuk `document` (objek JSON, dikanonkan JCS): `kontrak`, `version` (integer, 1), `tenant_id`, `rp_id`, `origin`, `credentials[]`. Tiap kredensial: `credential_id` (base64url), `public_key_cose` (base64url), `alg` (-7 atau -8), `admin_id`. Urutan array = urutan byte `credential_id` menaik. Label dan data profil admin **tidak** ikut. `rp_id` dan `origin` diambil dari konfigurasi instansi yang sama dengan yang dipakai verifikasi WebAuthn console (ADR 0002).
- `document_hash` = SHA-256 byte JCS `document`, 64 hex huruf kecil.
- Roster yang sudah aktif (versi ≥ 1) dikirim apa adanya pada penukaran berikutnya, bersama `approvals[]`-nya.
- **Konsekuensi yang disengaja:** passkey yang didaftarkan atau dicabut di console setelah roster v1 terbit tidak mengubah apa yang dipercaya agen sampai `RosterUpdate` (M2) tersedia. Halaman passkey harus menampilkan peringatan itu setelah roster ada (slice terpisah).

### 2.5 Kebijakan v1
Kebijakan v1 dibuat dengan cara yang sama (saat penukaran pertama bila belum ada). `document`: `kontrak`, `version` (1), `tenant_id`, `actions[]`, `approvals_required`, `l3_delay_seconds`.
- `actions[]` = tiap aksi katalog yang **platformnya memuat `ubuntu-24.04` dan berstatus dipakai di milestone ini**: pada M1 hanya aksi **L0** (`../catalog/CATALOG.md` §3). Tiap entri: `key`, `version`, `risk`. Daftar dibaca dari katalog saat penerbitan, tidak ditulis ulang di PHP (CLAUDE.md). Aksi L1+ masuk lewat `PolicyBundle` berikutnya (M2).
- `approvals_required`: {`L2`: 1, `L3`: 1} **[VERIFIKASI pemilik]**. Dokumen yang ada hanya menyebut "satu passkey" untuk `site.create` (AC-08) dan tidak menetapkan angka untuk L3. Nilai ini ikut tersemat selamanya sampai `PolicyBundle`.
- `l3_delay_seconds`: 900 **[VERIFIKASI pemilik]** (KONTRAK §4 memberi rentang 900–7200).
- Seperti roster, kebijakan v1 dipercaya karena sidik jari. `document_hash` sama dengan aturan roster.

### 2.6 Sidik jari kepercayaan
`trust_fingerprint` = SHA-256 atas byte: ASCII `sadmin-trust/1`, satu byte LF, lalu JCS objek **tepat lima** anggota: `roster_hash` (64 hex), `policy_hash` (64 hex), `service_pubkey` (base64 baku berpadding, 44 karakter), `audit_pubkey` (idem), dan `server_id` (ULID huruf kecil). Hasilnya 64 hex huruf kecil.
- Tampilan manusia: 64 hex dipecah menjadi 16 kelompok 4 karakter dipisah spasi, dalam dua baris. Agen mencetak ini di terminal dan console menampilkannya di halaman server; admin mencocokkan.
- `server_id` ikut agar sidik jari satu server tak bisa dipakai menyetujui server lain, dan agar dua enrolment dengan kunci yang sama tetap berbeda.
- Pencocokan manual adalah kontrol keamanan. Agen **tidak** menyematkan apa pun sebelum admin mengonfirmasi (perilaku di sisi edge, di luar ADR ini). Core menyimpan sidik jari di `agents.trust_fingerprint` dan menampilkannya tanpa menghitung ulang dari kolom DB lain: ia dihitung dari dokumen yang benar-benar dikirim.
- Karena `service_pubkey` dan `audit_pubkey` dibaca dari brankas saat penukaran (bukan dari kolom DB), penukaran di DB tidak mengubah apa yang dikirim tanpa membuat pembukaan brankas gagal (prinsip ADR 0006 §2.1).

### 2.7 Bentuk `EnrollAccept`
Badan: `server_id`, `cert` (PEM sertifikat klien), `roster` {`document`, `document_hash`, `approvals`: []}, `policy` (idem), `service_pubkey`, `audit_pubkey`, `ca_cert` **[usulan field baru, minor]** (PEM CA, agar agen bisa memverifikasi rantai tanpa mengunduh terpisah; hash-nya wajib sama dengan `--ca-sha256` yang sudah dicocokkan agen). Disusun dalam bingkai {`type`:"EnrollAccept", `id`, `body`, `sig`} menurut KONTRAK §3.

### 2.8 Status
`servers.status`: `enrolling` → `offline` setelah penukaran; `online` oleh `Hello` pertama (slice gateway). `agents`: `connection` = `disconnected`, `cert_serial`, `cert_expires_at`, `agent_version`, `roster_version` = 1, `policy_version` = 1. **Usulan perubahan skema (non-destruktif, docs/07 belum memilikinya):** kolom `trust_fingerprint` char(64) NOT NULL dengan CHECK hex huruf kecil di `agents`, agar sidik jari bisa ditampilkan di console.

## 3. Alternatif yang dipertimbangkan
| Alternatif | Ditolak karena |
|---|---|
| Roster v1 hanya lahir lewat persetujuan passkey (tanpa roster tak ada enrolment) | Menuntut jalur persetujuan roster sebelum M2 ada; enrolment M1 tak bisa didemokan. Tetap pilihan bila pemilik ingin M1 lebih ketat |
| Sidik jari hanya atas roster | Bertentangan KONTRAK §3: gateway bobol bisa menukar kunci layanan/audit |
| Membakar token pada CSR salah | Agen yang bugnya bisa dibetulkan harus menunggu token baru; tak menambah keamanan karena penyerang yang memegang token tetap bisa mencoba |
| Memblokir bila hostname laporan ≠ terdaftar | Alias DNS dan hostname VM memang sering beda; kontrol palsu yang mengganggu. Identitas sudah dipegang token+CSR |
| Kebijakan v1 memuat seluruh katalog MVP | Memberi agen izin aksi yang belum ada jalur persetujuannya; memperluas permukaan sebelum M2 |
| Mengirim roster dari tabel `admin_passkeys` langsung tiap enrolment | Roster berubah diam-diam antar server; melanggar "naik monoton" dan jeda 24 jam |

## 4. Konsekuensi
- Memungkinkan: slice implementasi `AcceptEnrollment` + tes (token tunggal-pakai di bawah paralel, CSR salah tak membakar token, sidik jari = vektor bersama, roster/kebijakan deterministik) dan vektor kontrak `trust-fingerprint` dengan oracle independen.
- Menunda: inbox gateway, `Hello`, tampilan sidik jari di console (halaman server), perilaku edge.
- Biaya mengubah kelak: format sidik jari dan bentuk dokumen v1 **tersemat di agen**. Mengubahnya setelah agen pertama terpasang = enrolment ulang semua agen (kontrak mayor).
- Roster v1 melemahkan satu hal secara sadar: sebelum M2, daftar passkey di agen bisa tertinggal dari console (lihat §2.4).

## 5. Penegakan
Akan ditetapkan saat diterima: tes `AcceptEnrollment*`, vektor `kontrak/vectors/trust-fingerprint/` beserta oracle, `ForbiddenScanTest` tetap hijau (tanpa eksekusi shell), dan `VaultBoundaryTest` tetap melarang pembacaan kunci di luar `Infrastructure/Vault`.

## 6. Pertanyaan untuk pemilik produk
1. Roster/kebijakan v1 dibuat core saat enrolment pertama dan dipercaya lewat sidik jari (§2.4–2.5), atau wajib lewat persetujuan passkey (alternatif pertama, menggeser demo enrolment ke setelah M2)?
2. `approvals_required` dan `l3_delay_seconds` kebijakan v1 (§2.5): 1/1 dan 900 detik sudah benar?
3. Menambahkan `ca_cert` ke `EnrollAccept` (§2.7) diterima sebagai kenaikan minor kontrak 0.6.0?
4. Hostname tidak memblokir (§2.3): setuju?
