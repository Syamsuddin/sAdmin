# KONTRAK — Protokol core ↔ gateway ↔ agen

Versi kontrak: **0.5.0** (berkas `kontrak/VERSION`). Rumah tunggal lintas-paket untuk nama pesan, field, kanonisasi, algoritme tanda tangan, dan kode galat. Paket `core` dan `edge` **merujuk**, tidak menyalin. Begitu `kontrak/schemas/*.json` ada (M1), skema JSON menang atas tabel di berkas ini; berkas ini lalu hanya memuat aturan yang tak bisa diekspresikan JSON Schema.

## 1. Presedensi & perubahan
- Kontrak menang. Kode yang tak sesuai kontrak = bug paket itu. Selisih → berhenti, laporkan, gerbang manusia.
- SemVer: field opsional baru = minor; apa pun yang mengubah hasil kanonisasi, isi yang ditandatangani, algoritme, atau makna field = **major** + gerbang manusia (`core/docs/22_CHANGE_POLICY.md`).
- Alur: ubah `kontrak/` dulu (bukan kode) → review → bump `VERSION` → implementasi kedua sisi → `make contract-test` (lihat `README.md` root).
- Field `kontrak` di setiap badan pesan = versi **major**. Agen menolak major yang tak dikenalnya (`E_KONTRAK_VERSION`).
- Selama **0.x**, versi minor berlaku sebagai major: kenaikan minor boleh memutus kompatibilitas, dan field `kontrak` berisi `major.minor` (mis. `"0.2"`), supaya pihak 0.1 dan 0.2 saling mengenali ketidakcocokan. Mulai 1.0 field itu hanya berisi major.

## 2. Transport
| Ruas | Transport | Autentikasi |
|---|---|---|
| Agen → gateway | WebSocket (`wss://<host-sadmin>:8443/agent/v1`), dibuka **dari agen** | mTLS: sertifikat klien agen dari CA internal (ECDSA P-256, masa berlaku 7 hari, diperbarui otomatis pada 2/3 umur via `CertRenew`) |
| Gateway ↔ core | HTTP/1.1 di atas Unix domain socket, dua arah: gateway→core `/run/sadmin/core-inbox.sock`, core→gateway `/run/sadmin/gateway.sock` | Izin berkas socket (grup `sadmin`) + header `X-Sadmin-Hmac` (HMAC-SHA256, kunci di brankas, dibaca gateway dari `systemd-creds`) |

Gateway **tidak** punya kredensial DB, tidak menyimpan pesan secara tahan lama, dan tidak menandatangani apa pun. Bila core tidak tersedia, gateway menolak dengan `E_CORE_UNAVAILABLE`; agen menyangga lalu mengulang.

Bingkai WebSocket: satu pesan JSON teks per bingkai: `{"type": "<NamaPesan>", "id": "<ULID>", "body": {…}, "sig": "<base64>"?}`. `sig` wajib di setiap bingkai core→agen dan tidak ada di bingkai agen→core (§3, tanda tangan kunci layanan). Batas ukuran bingkai 1 MiB (unggahan ZIP tidak lewat kanal ini — lihat §6).

Sertifikat & pin CA, normatif:
- **CA internal**: satu per tenant, kunci ECDSA P-256 di brankas core. Sertifikatnya X.509 v3 swa-tanda-tangan, subjek = penerbit = `CN=sAdmin internal CA`, masa berlaku 3650 hari (boleh lebih 1 detik, dengan alasan yang sama seperti sertifikat klien di bawah), `basicConstraints` kritis `CA:TRUE, pathlen:0`, `keyUsage` kritis `keyCertSign, cRLSign`, tanda tangan `ecdsa-with-SHA256`. Mengganti CA adalah rotasi dan butuh gerbang manusia (`core/docs/22_CHANGE_POLICY.md`).
- **Pin CA** (`--ca-sha256` saat enrolment) = SHA-256 atas byte DER sertifikat CA, ditulis 64 hex huruf kecil. Agen hanya menerima server TLS gateway yang rantainya berakhir pada sertifikat CA dengan sidik jari persis sama dengan pin. Profil sertifikat server gateway ditetapkan bersama slice gateway.
- **CSR agen** (`Enroll.csr`, `CertRenew`) diperiksa berurutan, dan alasan penolakannya adalah aturan pertama yang dilanggar. Semua pelanggaran ditolak `E_CSR`.
  1. `size`: teks paling banyak 4096 byte.
  2. `pem`: tepat satu blok `-----BEGIN CERTIFICATE REQUEST-----` … `-----END CERTIFICATE REQUEST-----` berisi baris base64 standar yang diakhiri LF. Teks boleh diakhiri satu LF, tanpa teks lain, CRLF, atau header PEM.
  3. `structure`: isinya DER CSR (PKCS#10) yang sah.
  4. `key`: kunci publiknya ECDSA P-256.
  5. `subject`: subjeknya kosong, karena subjek CSR akan tersalin ke sertifikat.
  6. `signature`: tanda tangan `ecdsa-with-SHA256` sah atas `CertificationRequestInfo`, sebagai bukti kepemilikan kunci privat.

  Atribut CSR, misalnya permintaan ekstensi, diabaikan dan tak pernah disalin ke sertifikat.
- **Sertifikat klien agen** diterbitkan core dari CSR yang lolos aturan di atas. Profilnya X.509 v3 dengan rincian berikut:
  - serial berupa bilangan bulat positif acak, paling besar 2^63−1;
  - penerbit = subjek CA, dan subjeknya kosong;
  - `notAfter` − `notBefore` = 604800 detik (7 hari). Penerbit yang mengisi kedua waktu dari dua pembacaan jam boleh menghasilkan 604801 detik bila detik berganti di antaranya. Gateway tidak memeriksa durasi ini;
  - kunci publiknya kunci CSR, dan tanda tangannya `ecdsa-with-SHA256`;
  - ekstensinya tepat lima: `subjectAltName` kritis berisi tepat satu URI `sadmin://server/<server_id>`, `basicConstraints` kritis `CA:FALSE`, `keyUsage` kritis `digitalSignature`, `extendedKeyUsage` `clientAuth`, dan `authorityKeyIdentifier` (keyid CA).

  Core mencatat serial sebagai hex huruf kecil tanpa nol di depan (`agents.cert_serial`).
- **Penerimaan sertifikat klien di gateway** diperiksa berurutan, dan alasannya adalah aturan pertama yang dilanggar.
  1. `pem`: berlaku untuk vektor, dengan aturan blok yang sama seperti CSR tetapi berlabel `CERTIFICATE`. Di TLS, sertifikat datang sebagai DER.
  2. `structure`: isinya DER sertifikat X.509 yang sah.
  3. `issuer`: penerbit = subjek CA, dengan byte DER identik.
  4. `signature`: tanda tangannya sah dengan kunci CA.
  5. `validity`: `notBefore` ≤ sekarang ≤ `notAfter`, kedua batas inklusif, untuk sertifikat klien **dan** sertifikat CA.
  6. `key`: kunci publiknya ECDSA P-256.
  7. `basic_constraints`: ada dan `CA:FALSE`.
  8. `eku`: `extendedKeyUsage` ada dan memuat `clientAuth`.
  9. `san`: `subjectAltName` berisi tepat satu nama, yaitu URI yang seluruhnya cocok dengan `sadmin://server/<ULID>` (ULID huruf kecil, §8).
  10. Sertifikat belum dicabut. Mekanisme pencabutan ditetapkan bersama enrolment.

  Identitas koneksi = `server_id` dari URI itu, bukan subjek atau nama lain. Gateway memakai identitas ini untuk meneruskan pesan.
- Vektor bersama dihasilkan oracle independen `kontrak/vectors/agent-cert/oracle.py` (pustaka Python `cryptography`, ECDSA deterministik RFC 6979, keluaran identik bila dijalankan ulang). Aturan pencabutan di luar vektor.
  - `kontrak/vectors/agent-csr/*.json` berisi `csr_pem` → `valid` dan `reason`.
  - `kontrak/vectors/agent-cert/*.json` berisi `ca_pem`, `ca_sha256`, `cert_pem`, dan `now` → `valid`, `server_id`, dan `reason`.

  Alasan dan aturan penyimpanan di core ada di `core/docs/adr/0007-ca-internal.md`.

## 3. Kanonisasi & tanda tangan
- Kanonisasi: **RFC 8785 (JCS)** terhadap `body`, kecuali tanda tangan kunci layanan yang mengkanonisasi objek `{type, id, body}` (lihat di bawah). Dilarang angka pecahan di badan yang ditandatangani (pakai integer atau string) — sumber selisih PHP↔Go paling umum.
- Hash: SHA-256, dikodekan hex huruf kecil di field `*_hash`.
- Masukan kanonisasi wajib **I-JSON** (RFC 7493, prasyarat RFC 8785) dengan batas sAdmin. Aturan ini berlaku untuk **seluruh teks bingkai** yang diterima (bukan hanya `body`), diperiksa pada byte mentah sebelum pengurai apa pun dan sebelum verifikasi `sig`. Setiap pihak (core, gateway, agen) **menolak, tidak memperbaiki**, teks yang melanggar, termasuk JSON yang sintaksnya rusak, dengan `E_CANONICAL`. Aturannya:
  - teks UTF-8 sah tanpa BOM: tanpa byte tak sah dan tanpa surrogate tunggal (`\uD800`–`\uDFFF` yang tak berpasangan, dalam bentuk escape maupun byte mentah);
  - tanpa nama anggota ganda di satu objek, dibandingkan setelah escape diurai (`"a"` sama dengan `"\u0061"`);
  - nama anggota tidak boleh memuat U+0000 (nilai string boleh);
  - angka hanya integer desimal tanpa titik dan eksponen, dengan |n| ≤ 2^53−1; nilai lain dikirim sebagai string;
  - sarang objek/larik paling dalam 64 tingkat.
  - Menyimpang dari RFC 7493 §2.1: noncharacter (mis. U+FFFF, U+FDD0, U+10FFFF) **diterima** apa adanya.
- Pengurai JSON bawaan bahasa sering diam-diam "memperbaiki" masukan: `encoding/json` Go mengganti UTF-8 tak sah dengan U+FFFD dan menerima kunci ganda, sedangkan `json_decode` PHP juga menerima kunci ganda. Karena itu setiap implementasi wajib memvalidasi aturan di atas secara eksplisit.
- Vektor uji bersama, dipakai tes PHP dan Go:
  - `kontrak/vectors/jcs/*.json`: `input` → `canonical` → `sha256`, wajib identik byte-per-byte; bila ada `input_base64` (teks mentah), teks itu wajib diterima dan menghasilkan `canonical` yang sama;
  - `kontrak/vectors/jcs-reject/*.json`: `input_base64` (byte mentah) wajib ditolak dengan `E_CANONICAL`; `reason` menyebut aturan yang dilanggar.

| Kunci | Algoritme | Penyimpanan | Menandatangani |
|---|---|---|---|
| Kunci layanan core | Ed25519 | brankas | semua pesan core→agen (`sig`) |
| Kunci audit | Ed25519 (terpisah dari kunci layanan) | brankas | `CheckpointAnchor` |
| Passkey admin | WebAuthn ES256 atau EdDSA | kunci privat hanya di autentikator | `Plan`, `RosterUpdate`, `PolicyBundle` |
| CA internal | ECDSA P-256 | brankas | sertifikat agen & gateway |
| Kunci rilis | Ed25519, offline di pemelihara | di luar server | biner agen/gateway & aset console |

Tanda tangan kunci audit (`CheckpointAnchor.signature`), normatif:
- Algoritme Ed25519 murni (RFC 8032, bukan Ed25519ph/ctx). Satu kunci audit per tenant, sehingga kunci itu sendiri yang mengikat checkpoint ke tenant.
- Pesan yang ditandatangani = byte ASCII `sadmin-audit-checkpoint/1`, satu byte LF (`0x0A`), lalu byte UTF-8 hasil JCS objek **tepat tiga** anggota: `seq` (integer ≥ 1), `hash` (`hash` entri audit ber-`seq` itu, 64 hex huruf kecil), dan `created_at` (RFC 3339 UTC berakhiran `Z`, tepat 6 digit mikrodetik: `YYYY-MM-DDTHH:MM:SS.ffffffZ`). `signature` tidak ikut.
- `signature` = 64 byte tanda tangan, dikodekan base64 standar berpadding (RFC 4648 §4, 88 karakter). Kunci publik audit (mis. `audit_pubkey` di `EnrollAccept`) = 32 byte mentah, base64 standar berpadding (44 karakter).
- Pengodean base64 wajib **kanonik**: bit sisa karakter terakhir bernilai nol (RFC 4648 §3.5), sehingga satu tanda tangan hanya punya satu teks. Verifikator menolak teks yang tak kanonik meski byte hasil dekodenya sama (Go: `base64.StdEncoding.Strict()`). Base64 yang tak sah, tak kanonik, atau panjang byte yang salah = tanda tangan tidak sah.
- Vektor bersama `kontrak/vectors/checkpoint/*.json`: `seed_hex` → `public_key`; `checkpoint` → `message` → `signature`; `valid` = hasil verifikasi yang wajib. Vektor dihasilkan oracle independen `kontrak/vectors/checkpoint/oracle.py` (pustaka Python `cryptography`). Alasan dan aturan penyimpanan di core: `core/docs/adr/0004-checkpoint-audit.md`.

Tanda tangan kunci layanan (`sig` bingkai core→agen), normatif:
- Cakupan: **setiap** bingkai core→agen membawa `sig`, termasuk `EnrollAccept`, `Ack`, dan `CheckpointAnchor`. `CheckpointAnchor` tetap membawa `signature` kunci audit di badannya. Bingkai agen→core tidak membawa `sig`, karena identitasnya berasal dari mTLS di gateway dan HMAC gateway↔core (§2). Bingkai agen→core yang membawa `sig` ditolak `E_SCHEMA`.
- Bentuk bingkai core→agen adalah objek dengan **tepat** empat anggota: `type` (string), `id` (ULID), `body` (objek), dan `sig` (string). Anggota tambahan, anggota selain `sig` yang hilang, atau tipe yang salah ditolak `E_SCHEMA` pada langkah skema. `sig` yang hilang atau bukan string ditolak `E_SIG_SERVICE` pada langkah tanda tangan. Langkah skema berjalan lebih dulu (urutan: `edge/docs/06_BUSINESS_PROCESS.md` E1).
- Pesan yang ditandatangani terdiri dari byte ASCII `sadmin-service/1`, satu byte LF (`0x0A`), lalu byte UTF-8 hasil JCS objek **tepat tiga** anggota: `type`, `id`, dan `body`, dengan nilai persis seperti di bingkai. `sig` tidak ikut ditandatangani.
- Ada satu pengecualian. Bila `type` = `Envelope`, anggota tingkat atas `secret_values` dikeluarkan dari `body` sebelum kanonisasi. Jika anggota itu tidak ada, tidak ada yang dikeluarkan. Nilainya terikat lewat komitmen placeholder di `params` (§5), dan `params` ikut ditandatangani. Pengecualian ini tidak berlaku untuk jenis pesan lain: di pesan lain, anggota bernama `secret_values` ikut ditandatangani. Karena `secret_values` tidak ditandatangani, verifikator `Envelope` wajib memastikan himpunan kunci `secret_values` **sama persis** dengan himpunan ID `$secret` placeholder di `params`. Kunci yang berlebih atau kurang ditolak `E_SECRET_COMMIT`, sama seperti nilai yang tidak cocok dengan komitmennya.
- Algoritmenya Ed25519 murni (RFC 8032), dengan satu kunci layanan aktif per tenant. `sig` adalah 64 byte tanda tangan, dan `service_pubkey` (di `EnrollAccept`) adalah 32 byte kunci publik mentah. Keduanya dikodekan base64 standar berpadding (88 dan 44 karakter) yang wajib **kanonik**, dengan aturan yang sama seperti tanda tangan kunci audit di atas.
- `sig` membuktikan asal dan keutuhan bingkai, **bukan** kesegarannya. Kesegaran `Envelope` dijamin `nonce` dan `expires_at` (E1 agen). Dokumen kepercayaan (`RosterUpdate`, `PolicyBundle`) hanya diterima bila versinya lebih tinggi daripada versi yang berlaku, sehingga dokumen lama yang diputar ulang tidak bisa menurunkan versi. Pesan core→agen lainnya wajib aman bila diterima ulang (idempoten), misalnya `Cancel` atas `plan_hash` yang sama atau `CheckpointAnchor` dengan `seq` yang sama. Pesan yang hanya bermakna bagi satu agen diperiksa terhadap identitas penerimanya: `Envelope` lewat `target_server_id`, dan balasan `CertRenew` lewat kecocokan kunci publik sertifikat dengan kunci privat agen. `sig` yang sah tidak membuat bingkai lama dianggap baru, dan tidak membuat bingkai untuk agen lain menjadi milik penerima.
- `EnrollAccept`: agen memverifikasi `sig` dengan `service_pubkey` di badan `EnrollAccept` itu sendiri sebelum menyematkan apa pun. Langkah ini hanya membuktikan bahwa core memegang seed kunci tersebut, bukan bahwa kunci itu tepercaya. Kepercayaan saat enrolment berasal dari pin CA (`--ca-sha256`), token sekali pakai, dan sidik jari kepercayaan yang dicocokkan admin di terminal dan console. Sidik jari itu wajib mencakup roster, `service_pubkey`, dan `audit_pubkey`. Tanpa itu, gateway yang dibobol saat enrolment bisa menukar kedua kunci dengan kuncinya sendiri lalu menandatangani `EnrollAccept` sendiri. Format sidik jari ditetapkan bersama enrolment. Setelah tersemat, setiap bingkai berikutnya diverifikasi dengan kunci tersemat.
- Vektor bersama `kontrak/vectors/service-sig/*.json` berisi `seed_hex` → `public_key` dan `frame` → `message`, ditambah `valid` = hasil wajib verifikasi `frame.sig` atas `message` dengan `public_key`. Vektor dihasilkan oracle independen `kontrak/vectors/service-sig/oracle.py` (pustaka Python `cryptography`). Alasan dan aturan penyimpanan kunci di core ada di `core/docs/adr/0006-tanda-tangan-layanan.md`.

## 4. Rencana (yang ditandatangani passkey)
Semua aksi **L2/L3** hanya berjalan di bawah sebuah `Plan`; aksi L2/L3 tunggal dari console = rencana satu langkah. Aksi L0/L1 cukup tanda tangan layanan (`plan_hash` = null).

`Plan.body`: `kontrak`, `plan_id` (ULID), `tenant_id`, `capsule_key`, `capsule_version`, `created_at`, `expires_at` (≤ `created_at` + 24 jam), `risk_max` (`L0`–`L3`), `delay_seconds` (wajib bila `risk_max`=L3; 900–7200, roster/kebijakan 86400), `steps[]`.
`steps[i]`: `index`, `action_key`, `action_version`, `target_server_id`, `params_hash` (= SHA-256 JCS `params` berplaceholder rahasia), `risk`, `compensable` (bool).

Tantangan WebAuthn = byte mentah SHA-256(JCS(`Plan.body`)). `Approval`: `credential_id`, `authenticator_data`, `client_data_json`, `signature` (semua base64url). Agen memverifikasi: kredensial ada di roster tersemat; `challenge` di `client_data_json` = `plan_hash`; `type`=`webauthn.get`; `origin` dan `rpIdHash` cocok dengan roster; flag UP dan UV menyala; jumlah tanda tangan ≥ syarat level di kebijakan.

## 5. Pesan
| Pesan | Arah | Isi `body` (field wajib) |
|---|---|---|
| `Enroll` | agen→core, sekali | `kontrak`, `token` (sekali pakai, 15 menit), `csr` (PEM), `platform_id`, `hostname`, `agent_version`; dijawab `EnrollAccept` {`server_id`, `cert`, `roster`, `policy`, `service_pubkey`, `audit_pubkey`} atau galat. Satu-satunya pesan yang boleh tanpa sertifikat klien; server TLS gateway dipin via `--ca-sha256` |
| `Hello` | agen→core | `kontrak`, `server_id`, `agent_version`, `platform_id` (dari `/etc/os-release`, mis. `ubuntu-24.04`), `roster_version`, `policy_version`, `audit_head` {`seq`,`hash`} |
| `Heartbeat` | agen→core, tiap 30 dtk | `server_id`, `agent_version`, `platform_id`, `uptime_s`, `pending_delays`, `pending_timers`, `buffered`, `audit_head` |
| `Envelope` | core→agen | `kontrak`, `envelope_id`, `phase` (`apply`\|`compensate`), `action_key`, `action_version`, `target_server_id`, `platform_id`, `params`, `risk`, `nonce` (32 byte acak, base64url), `issued_at`, `expires_at` (≤ `issued_at`+10 menit), `idempotency_key`, `plan_hash`\|null, `step_index`\|null, `plan` (objek `Plan` utuh + `approvals[]`, bila L2/L3), `secret_values` {placeholder_id → nilai} — **di luar** cakupan `sig` (§3) |
| `Result` | agen→core | `envelope_id`, `idempotency_key`, `status` (`succeeded`\|`skipped`\|`failed`\|`rejected`\|`delayed`\|`awaiting_confirmation`\|`interrupted`\|`compensated`\|`compensation_failed`), `error`? {`code`,`class`: `transient`\|`permanent`, `detail_id`}, `output` (disamarkan), `started_at`, `finished_at`, `agent_audit_seq` |
| `StatusQuery` | core→agen | `idempotency_key` → dijawab `Result` terakhir dari jurnal, atau `status`=`unknown` |
| `Cancel` | core→agen | `plan_hash`, `cancelled_by` {`kind`: `admin`\|`witness`, `ref`} — tanpa passkey; hanya membatalkan L3 yang masih dalam jeda |
| `Event` | agen→core | `event_id`, `kind` (mis. `service.down`, `disk.low`, `cert.expiring`, `backup.failed`, `timer.rolled_back`, `emergency_local`), `severity`, `data`, `occurred_at` |
| `AuditReceipt` | agen→core | `agent_seq`, `entry_hash`, `envelope_id`\|null, `emergency_local` |
| `CheckpointAnchor` | core→agen | `seq`, `hash`, `signature` (kunci audit), `created_at` |
| `RosterUpdate` / `PolicyBundle` | core→agen | dokumen baru + `approvals[]`; berlaku setelah jeda 24 jam kecuali dibatalkan |
| `CertRenew` | agen↔core | CSR dari agen, sertifikat dari core |
| `Ack` | dua arah | `id` pesan yang diterima |

**Placeholder rahasia** di `params`: `{"$secret": "<ULID secret>", "salt": "<16 byte base64url>", "commit": "<sha256(salt ∥ nilai) hex>"}`. Nilai asli dikirim di `secret_values`; agen menolak (`E_SECRET_COMMIT`) bila hash tak cocok. Dengan begitu passkey mengikat rahasia tanpa admin melihat atau core bisa menukarnya.

## 6. Unggahan berkas
ZIP sumber diunggah admin ke core, disimpan terenkripsi di brankas, lalu diambil agen lewat HTTPS gateway `GET /agent/v1/blob/<id>` (mTLS) dengan `sha256` yang ikut di `params` (masuk `params_hash`, jadi ikut ditandatangani).

## 7. Kode galat
| Kode | Kelas | Arti |
|---|---|---|
| `E_SCHEMA` | permanen | badan tak sesuai skema pesan/aksi |
| `E_CANONICAL` | permanen | teks bingkai bukan I-JSON sesuai §3 (sintaks rusak, BOM, UTF-8 tak sah, kunci ganda, NUL di nama anggota, angka di luar aturan, sarang > 64) |
| `E_KONTRAK_VERSION` | permanen | major kontrak tak dikenal |
| `E_POLICY_UNKNOWN_ACTION` | permanen | aksi/versi tak ada di kebijakan tersemat |
| `E_PLATFORM` | permanen | aksi tak mendukung `platform_id` agen |
| `E_SIG_SERVICE` | permanen | `sig` layanan tak sah |
| `E_SIG_PASSKEY` | permanen | assertion tak sah / kredensial di luar roster / tanda tangan kurang |
| `E_PLAN_MISMATCH` | permanen | langkah ≠ `plan.steps[step_index]`, atau `plan_hash` salah |
| `E_PLAN_EXPIRED` / `E_EXPIRED` | permanen | rencana / amplop kedaluwarsa |
| `E_NONCE_REPLAY` | permanen | nonce sudah dipakai |
| `E_SECRET_COMMIT` | permanen | nilai rahasia tak cocok komitmen |
| `E_DELAY_CANCELLED` | permanen | L3 dibatalkan selama jeda |
| `E_LOCKED` | sementara | sumber daya sedang dipegang langkah lain di agen |
| `E_TRANSIENT` | sementara | galat sementara aksi (jaringan, apt lock) |
| `E_PERMANENT` | permanen | galat aksi yang tak akan sembuh dengan mengulang |
| `E_ENROLL_TOKEN` | permanen | token enrolment salah, kedaluwarsa, atau sudah dipakai |
| `E_CSR` | permanen | CSR `Enroll`/`CertRenew` melanggar aturan CSR di §2 |
| `E_CORE_UNAVAILABLE` | sementara | gateway tak bisa meneruskan ke core |

## 8. Konvensi
Nama field `snake_case`; ID = ULID string 26 karakter dalam huruf kecil (alfabet Crockford base32 huruf kecil, karakter pertama `0`–`7`), dibandingkan byte-per-byte apa adanya; ULID berhuruf besar atau campuran ditolak `E_SCHEMA`; waktu = RFC 3339 UTC berakhiran `Z` (tampilan zona waktu instansi urusan console); ukuran dalam byte integer; durasi dalam detik integer.
