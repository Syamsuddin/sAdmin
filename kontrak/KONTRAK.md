# KONTRAK — Protokol core ↔ gateway ↔ agen

Versi kontrak: **0.3.0** (berkas `kontrak/VERSION`). Rumah tunggal lintas-paket untuk nama pesan, field, kanonisasi, algoritme tanda tangan, dan kode galat. Paket `core` dan `edge` **merujuk**, tidak menyalin. Begitu `kontrak/schemas/*.json` ada (M1), skema JSON menang atas tabel di berkas ini; berkas ini lalu hanya memuat aturan yang tak bisa diekspresikan JSON Schema.

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

Bingkai WebSocket: satu pesan JSON teks per bingkai: `{"type": "<NamaPesan>", "id": "<ULID>", "body": {…}, "sig": "<base64>"?}`. Batas ukuran bingkai 1 MiB (unggahan ZIP tidak lewat kanal ini — lihat §6).

## 3. Kanonisasi & tanda tangan
- Kanonisasi: **RFC 8785 (JCS)** terhadap `body`. Dilarang angka pecahan di badan yang ditandatangani (pakai integer atau string) — sumber selisih PHP↔Go paling umum.
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
- `signature` = 64 byte tanda tangan, dikodekan base64 standar berpadding (RFC 4648 §4, 88 karakter). Kunci publik audit (mis. `audit_pubkey` di `EnrollAccept`) = 32 byte mentah, base64 standar berpadding (44 karakter). Base64 yang tak sah atau panjang byte yang salah = tanda tangan tidak sah.
- Vektor bersama `kontrak/vectors/checkpoint/*.json`: `seed_hex` → `public_key`; `checkpoint` → `message` → `signature`; `valid` = hasil verifikasi yang wajib. Alasan dan aturan penyimpanan di core: `core/docs/adr/0004-checkpoint-audit.md`.

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
| `Envelope` | core→agen | `kontrak`, `envelope_id`, `phase` (`apply`\|`compensate`), `action_key`, `action_version`, `target_server_id`, `platform_id`, `params`, `risk`, `nonce` (32 byte acak, base64url), `issued_at`, `expires_at` (≤ `issued_at`+10 menit), `idempotency_key`, `plan_hash`\|null, `step_index`\|null, `plan` (objek `Plan` utuh + `approvals[]`, bila L2/L3), `secret_values` {placeholder_id → nilai} — **di luar** cakupan `sig` |
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
| `E_CORE_UNAVAILABLE` | sementara | gateway tak bisa meneruskan ke core |

## 8. Konvensi
Nama field `snake_case`; ID = ULID string 26 karakter; waktu = RFC 3339 UTC berakhiran `Z` (tampilan zona waktu instansi urusan console); ukuran dalam byte integer; durasi dalam detik integer.
