# ADR 0006 — Tanda tangan kunci layanan pada bingkai core→agen

| | |
|---|---|
| Status | **Diterima** — disetujui pemilik produk, 2026-10-02 |
| Tanggal | 2026-10-01 |
| Pemutus | Pemilik produk. Isi yang ditandatangani kunci layanan adalah bagian format amplop, sehingga termasuk gerbang manusia (docs/22_CHANGE_POLICY.md, "perubahan format amplop, rencana, atau kanonisasi"; `../kontrak/KONTRAK.md` §1). Setelah agen pertama menyematkan `service_pubkey` dan menerima bingkai, mengubah format ini memutus verifikasi di semua agen |
| Lingkup | Kunci layanan (pembuatan, penyimpanan, kunci publik), isi yang ditandatangani `sig` bingkai core→agen, penyusunan bingkai bertanda tangan di core, dan verifikasi sendiri sebelum bingkai dikembalikan ke pengirim |
| Di luar lingkup | Pengiriman bingkai lewat socket gateway dan HMAC gateway↔core (slice inbox/Dispatch). CA internal. Format roster dan kebijakan. Penyusunan `EnrollAccept` (slice enrolment). Skema JSON pesan (`kontrak/schemas`). Rotasi kunci layanan |
| Rujukan | `../kontrak/KONTRAK.md` §2, §3 (format, normatif di sana), §5 · docs/07_DATA_MODEL.md §Rahasia · docs/08_ARCHITECTURE.md §Lapisan core · docs/21_SECURITY_RULES.md §Rahasia & brankas · `../edge/docs/06_BUSINESS_PROCESS.md` E1 · `../edge/docs/21_SECURITY_RULES.md` · docs/adr/0003-format-brankas.md · docs/adr/0004-checkpoint-audit.md |

## 1. Konteks
KONTRAK §3 menetapkan kunci layanan core (Ed25519, di brankas) yang menandatangani "semua pesan core→agen (`sig`)". Langkah 2 pipa verifikasi agen (edge E1) menolak bingkai yang `sig`-nya tidak sah dengan `E_SIG_SERVICE`. KONTRAK §5 juga menyatakan `secret_values` di luar cakupan `sig`.

Namun belum ada dokumen yang merinci hal-hal berikut:
- byte yang ditandatangani, termasuk apakah `type` dan `id` bingkai ikut terikat;
- cara `secret_values` dikeluarkan, dan untuk jenis pesan apa saja;
- pengodean `sig` dan `service_pubkey`;
- di mana kunci layanan disimpan, siapa yang membuatnya, dan bagaimana core memastikan bingkai yang dikirimnya memang lolos verifikasi agen.

Tanpa rincian ini, edge tidak bisa mengimplementasikan langkah E1-2, dan core tidak bisa membangun Dispatch. Begitu agen pertama menyematkan `service_pubkey` dan menerima bingkai bertanda tangan, rincian ini tak dapat diubah tanpa memutus semua agen. Karena itu rincian dikunci di sini. Bagian 2 bersifat **normatif**.

## 2. Keputusan (normatif)

### 2.1 Kunci layanan
- Kunci layanan adalah kunci Ed25519. Bagian privatnya disimpan sebagai *seed* 32 byte (RFC 8032) di satu baris `secrets` ber-`purpose` `service_key`, sehingga terenkripsi envelope oleh brankas (ADR 0003). Kunci publik diturunkan dari seed.
- Setiap tenant punya **tepat satu** kunci layanan aktif. Ini dijaga indeks unik parsial `secrets_one_active_service_key` pada `secrets (tenant_id) WHERE purpose = 'service_key' AND status = 'active'`.
- Kunci layanan hanya dibuat oleh `php artisan sadmin:service-key-init`, yang kelak dipanggil `install.sh` (F-01):
  1. instansi wajib sudah diinisialisasi, karena kunci terikat ke tenant instansi;
  2. bila tenant itu **pernah** punya baris `service_key` (status apa pun, termasuk `destroyed`), perintah menolak. Kunci baru dalam keadaan itu adalah rotasi, karena setiap agen yang sudah menyematkan kunci lama akan menolak semua bingkai. Rotasi butuh gerbang manusia (docs/22, "rotasi CA internal, kunci layanan, atau kunci audit") dan ADR baru;
  3. dalam satu transaksi ber-`pg_advisory_xact_lock(7301004)`: seed dibuat dengan CSPRNG lalu disimpan lewat brankas (entri audit `secret.store`), kemudian entri audit `service.key_initialize` ditulis (aktor `local_root`, target `secret:<id>`, `params_redacted` = `{"public_key": "<base64>"}`);
  4. perintah mencetak kunci publik (base64 standar, 44 karakter) untuk diagnosa, misalnya untuk dicocokkan dengan `trust/keys.json` agen (`../edge/docs/16_DEBUGGING_GUIDE.md`).
- Core **tidak pernah** membuat kunci layanan secara implisit, misalnya saat bingkai pertama disusun atau saat enrolment. Kunci yang hilang atau dihancurkan tidak boleh diam-diam terganti, karena agen yang sudah tersemat akan menolak semua bingkai tanpa penjelasan.
- Seed hanya dibuka di dalam `App\Infrastructure\Vault`, sama seperti kunci audit (ADR 0004 §2.1). `Vault::reveal()` sudah menolak purpose `service_key` (ADR 0003 §2.5). Penandatanganan memakai `Vault::signEd25519()`, dan kunci publik memakai `Vault::ed25519PublicKey()`.
- Kunci publik yang dikirim ke agen (`EnrollAccept.service_pubkey`, slice enrolment) dan yang dipakai core untuk memverifikasi bingkainya sendiri (§2.3) selalu **diturunkan dari seed di brankas** pada saat itu. Core tidak mengambilnya dari kolom DB atau dari entri audit `service.key_initialize`, karena pihak yang berhak menulis DB bisa mengganti nilai di sana.

### 2.2 Isi yang ditandatangani
Normatif di `../kontrak/KONTRAK.md` §3, satu rumah untuk protokol, karena agen yang memverifikasinya. Ringkasnya:

```
sig = base64( Ed25519_sign( seed, "sadmin-service/1" ∥ 0x0A ∥ JCS({"type", "id", "body"}) ) )
      dengan body tanpa anggota tingkat atas secret_values bila type = "Envelope"
```

- Seluruh bingkai kecuali `sig` ikut ditandatangani, sehingga badan yang sah untuk satu jenis pesan tidak bisa dipasang pada jenis pesan lain.
- Awalan `sadmin-service/1` berbeda dari awalan checkpoint `sadmin-audit-checkpoint/1`. Dengan begitu, pesan untuk dua tujuan ini tidak pernah bertabrakan, meski kuncinya tetap dipisah.
- `secret_values` dikeluarkan **hanya** dari badan `Envelope`. Agen wajib menolak `Envelope` yang himpunan kunci `secret_values`-nya berbeda dari himpunan placeholder `$secret` di `params` (`E_SECRET_COMMIT`), karena anggota itu sendiri tidak bertanda tangan.
- `sig` dan `service_pubkey` memakai base64 standar berpadding yang kanonik, dengan aturan yang sama seperti tanda tangan checkpoint.

Vektor emas `../kontrak/vectors/service-sig/*.json` dihitung oracle independen yang hanya memakai teks KONTRAK dan pustaka Python `cryptography` (OpenSSL), tanpa kode core maupun sodium PHP. Kanonisasi JCS oracle itu sendiri diuji terhadap `../kontrak/vectors/jcs/`.

### 2.3 Penyusunan bingkai di core
`App\Domain\Execution\Dispatch\ServiceSigner` adalah **satu-satunya** penyusun bingkai core→agen. Kelas ini berada di Dispatch karena Dispatch adalah satu-satunya jalur ke agen (docs/08). Masukannya adalah tenant, `type` (tak kosong), `id` (ULID huruf kecil, KONTRAK §8), dan `body`. Langkahnya:
1. `body` wajib objek JSON. Larik PHP berbentuk *list*, termasuk `[]` kosong, ditolak karena PHP mengodekannya sebagai larik JSON. Larik non-*list* diperlakukan sebagai objek di tingkat atas, sama seperti `json_encode` mengodekannya. Dengan begitu, badan yang tersisa setelah `secret_values` dikeluarkan tetap objek, meskipun kosong atau berkunci `0..n-1`. Seluruh badan, termasuk `secret_values` yang tidak ditandatangani, wajib I-JSON (KONTRAK §3) dan ditolak sebagai masukan (`InvalidArgumentException`) bila tidak. Objek kosong ditulis `new stdClass`. Aturan yang sama berlaku untuk objek kosong di dalam badan (mis. `params` tanpa parameter). Di level dalam, JCS dan `json_encode` memperlakukan `[]` dengan cara yang sama, jadi `sig` tetap konsisten, tetapi agen akan menolaknya di langkah skema.
2. Cari kunci layanan aktif tenant. Bila tidak ada, proses gagal tertutup (`DomainException` yang menyebut `sadmin:service-key-init`) dan kunci tidak pernah dibuat (§2.1).
3. Susun pesan §2.2, lalu tandatangani lewat brankas.
4. Teks bingkai = `json_encode` objek `{type, id, body, sig}` (UTF-8 apa adanya, garis miring tidak di-escape).
5. **Tertulis ⇒ terverifikasi.** Teks bingkai diurai ulang dengan pengurai ketat I-JSON (`Jcs::decode`, KONTRAK §3). Bentuk bingkai dan `sig` lalu diverifikasi dengan kunci publik turunan brankas, sama seperti langkah E1-1 dan E1-2 agen. Bila gagal, bingkai tidak dikembalikan (`LogicException`), sehingga core tidak pernah mengirim bingkai yang ia tahu akan ditolak agen. Ini pertahanan berlapis. Dengan kode sekarang, seluruh badan diperiksa I-JSON lebih dulu (langkah 1) dan `sig` dihitung atas struktur yang sama dengan yang dikodekan. Cabang gagal ini hanya terjangkau oleh regresi kelak pada penyusunan teks bingkai atau oleh galat perangkat saat menandatangani.
6. Bingkai yang lebih besar dari 1 MiB (1.048.576 byte, KONTRAK §2) ditolak sebelum dikembalikan.

Aturan tambahan:
- Teks bingkai `Envelope` memuat nilai rahasia (`secret_values`). Teks ini hanya boleh hidup di memori sampai dikirim. Ia tidak boleh dicatat ke log, audit, `step_runs`, atau tabel mana pun (docs/21). `action_envelopes` menyimpan kolom terstruktur tanpa nilai rahasia (docs/07).
- `VaultUnavailable` dan `VaultIntegrityError` diteruskan apa adanya ke pemanggil. Dispatch kelak mengklasifikasikannya menurut docs/14.
- `ServiceSigner::verifyFrame()` memeriksa I-JSON, bentuk bingkai, dan `sig` dengan urutan yang sama seperti agen. Fungsi ini dipakai langkah 5 dan tes kontrak. Keputusan akhir menerima atau menolak tetap milik agen.

## 3. Alternatif yang dipertimbangkan
| Alternatif | Ditolak karena |
|---|---|
| `sig` hanya atas JCS(`body`) | `type` tidak terikat, sehingga badan yang sah untuk satu jenis pesan bisa dipasang pada jenis lain yang skemanya kebetulan menerimanya. Mengikat seluruh bingkai menutup kelas serangan ini tanpa harus menalar skema tiap pesan |
| Awalan berbeda per jenis pesan (`sadmin-envelope/1`, …) | Setara amannya. Satu awalan dengan `type` di dalam JCS lebih sederhana dan otomatis berlaku untuk jenis pesan baru |
| `secret_values` ikut ditandatangani | KONTRAK §5 sudah menetapkannya di luar cakupan. Rahasia sudah diikat lewat komitmen hash di `params`, dan untuk L2/L3 lewat `params_hash` di rencana yang ditandatangani passkey. Pesan yang ditandatangani dan diperiksa ulang tidak perlu memuat rahasia |
| `secret_values` dikeluarkan dari semua jenis pesan | Melebarkan anggota tak bertanda tangan ke pesan yang tidak punya mekanisme komitmen |
| Menandatangani teks bingkai mentah, bukan JCS | Gateway dan pustaka WebSocket wajib meneruskan byte persis, padahal pengurai dan pengode JSON bebas mengubah spasi dan escape. JCS sudah menjadi dasar semua tanda tangan di kontrak |
| HMAC dengan kunci bersama | Setiap agen harus memegang kunci rahasia, sehingga satu agen yang dibobol bisa memalsukan pesan core ke agen lain |
| Memakai kunci audit | KONTRAK dan ADR 0004 §3 memisahkan keduanya. Kebocoran kunci yang dipakai di setiap amplop tidak boleh sekaligus memungkinkan pemalsuan riwayat |
| Ed25519ph atau Ed25519ctx | Ed25519 murni didukung sodium PHP dan `crypto/ed25519` Go apa adanya. Awalan domain sudah memisahkan konteks |
| Kunci dibuat otomatis saat pertama dibutuhkan | Kunci yang hilang atau dihancurkan akan diam-diam terganti, dan agen yang sudah tersemat menolak semua bingkai tanpa penjelasan. Gagal tertutup lebih aman |
| Nonce dan cap waktu di setiap bingkai | Kesegaran hanya kritis untuk `Envelope`, yang sudah punya `nonce` dan `expires_at`. Menjadikan pesan lain idempoten lebih sederhana daripada mengelola jendela waktu dan penyimpanan nonce untuk semua jenis pesan |
| Tanpa verifikasi sendiri sebelum dikirim | Regresi kelak pada penyusunan teks bingkai (mis. anggota bingkai, pengodean) atau tanda tangan yang rusak karena galat perangkat baru akan ketahuan sebagai `E_SIG_SERVICE` di agen. Memverifikasi sendiri hanya menambah satu parse dan satu verifikasi per bingkai |

## 4. Konsekuensi
- Edge kini punya spesifikasi lengkap untuk langkah E1-2 beserta vektor bersama. Kontrak naik ke 0.4.0. Selama 0.x, kenaikan minor bersifat memutus, tetapi belum ada implementasi agen yang terdampak.
- Core bisa menyusun bingkai bertanda tangan yang terbukti lolos verifikasinya sendiri. Pengiriman lewat socket gateway menunggu slice inbox/Dispatch.
- Pihak yang menguasai DB tetapi tidak memegang kunci induk tidak bisa memalsukan bingkai. Pihak yang memegang kunci induk (root di host sAdmin) bisa menandatangani bingkai L0/L1. Risiko ini diterima sadar di Mode Tunggal (docs/02), dan L2/L3 tetap menuntut passkey yang diverifikasi agen (A2).
- Setelah enrolment, gateway yang dibobol bisa memutar ulang bingkai lama, tetapi tidak bisa memalsukannya. `Envelope` ditolak lewat nonce, dokumen kepercayaan hanya diterima bila versinya naik, pesan lain wajib idempoten, dan pesan untuk satu agen diperiksa terhadap identitas penerimanya. Syarat ini kini tertulis di KONTRAK §3 untuk sisi edge.
- **Saat** enrolment, gateway yang dibobol (pemegang kunci TLS di bawah CA yang dipin dan pelihat token) bisa menukar `service_pubkey` dan `audit_pubkey` lalu menandatangani `EnrollAccept` sendiri. Satu-satunya pertahanan adalah sidik jari kepercayaan yang dicocokkan admin, sehingga sidik jari itu wajib mencakup kedua kunci (KONTRAK §3). Formatnya ditetapkan di slice enrolment.
- Keutuhan `secret_values` kini sepenuhnya bertumpu pada komitmen placeholder (KONTRAK §5), yang belum normatif: byte `salt`, pengodean nilai, dan posisi placeholder. Slice amplop/rencana wajib menetapkannya beserta vektor bersama `secret-commit/` sebelum amplop ber-rahasia pertama dikirim.
- ID protokol kini ULID huruf kecil yang dibandingkan apa adanya (KONTRAK §8), sesuai ID yang dibuat core (ADR 0003 §2.2). Agen yang menormalkan huruf atau hanya menerima huruf besar akan menolak setiap bingkai core, dan vektor `service-sig` kini memakai huruf kecil.
- Rotasi kunci layanan belum didukung, karena agen menyematkan satu `service_pubkey`. Rotasi butuh ADR baru (pesan kepercayaan bertanda passkey dan berjeda, seperti `RosterUpdate`) dan gerbang docs/22.
- Mengubah §2.2 atau KONTRAK §3 setelah agen pertama menerima bingkai adalah perubahan major kontrak dan butuh gerbang manusia.
- Pustaka Ed25519 (sodium PHP, `crypto/ed25519` Go, OpenSSL) berbeda dalam menyikapi tanda tangan yang sengaja dibuat janggal, misalnya `R` atau kunci publik tak kanonik dan titik berorde kecil. Perbedaan ini hanya bisa dimunculkan oleh pemegang kunci, yaitu core sendiri, sehingga tidak membuka jalan pemalsuan. Tanda tangan jujur sah di semua pustaka, dan vektor bersama hanya memuat tanda tangan jujur.
- Biaya per bingkai: satu tanda tangan, satu parse, dan satu verifikasi Ed25519, jauh di bawah 1 ms untuk bingkai biasa.

## 5. Penegakan
| Klausul | Dijaga oleh |
|---|---|
| 2.1 satu kunci aktif, pembuatan eksplisit sekali, penolakan bila pernah ada, kunci lintas tenant, kunci tidak bocor (konsol, log, audit) | `InitializeServiceKeyTest` (termasuk grup `redaction`), indeks `secrets_one_active_service_key` |
| 2.1 seed tak keluar brankas | `VaultBoundaryTest` |
| 2.2 format, cakupan `type`/`id`, pengecualian `secret_values` hanya untuk `Envelope`, base64 kanonik | `ServiceSignatureVectorsTest` (suite Contract) |
| 2.3 badan wajib objek, gagal tertutup tanpa kunci, hanya kunci aktif tenant yang menandatangani, batas 1 MiB, bentuk bingkai | `ServiceSignerTest` |
| 2.3 langkah 5 (tertulis ⇒ terverifikasi) | Tinjauan kode. Cabang gagalnya tak terjangkau tanpa regresi atau galat perangkat, jadi tidak ada tes yang memicunya (mutan "hapus verifikasi sendiri" tercatat hidup di ledger slice) |

## 6. Riwayat
- 2026-10-01: diusulkan bersama slice F-02a Kunci layanan (M1) dan kontrak 0.4.0 (`../kontrak/KONTRAK.md` §3).
- 2026-10-01: direvisi setelah review adversarial (0 kritis, 0 tinggi, 5 sedang, 5 rendah). Perubahannya: seluruh badan, termasuk `secret_values`, wajib I-JSON, dan badan tingkat atas selalu objek (§2.3 langkah 1). ID bingkai wajib ULID huruf kecil (KONTRAK §8, vektor dihasilkan ulang). KONTRAK §3 kini mewajibkan versi dokumen kepercayaan naik, pemeriksaan penerima, dan sidik jari enrolment yang mencakup `service_pubkey` dan `audit_pubkey`. Konsekuensi pada komitmen `secret_values` dicatat. Isi yang ditandatangani (§2.2) tidak berubah.
- 2026-10-02: **diterima** pemilik produk bersama kontrak 0.4.0. Mulai saat ini, setiap perubahan pada bagian 2 dan KONTRAK §3 (tanda tangan kunci layanan) wajib lewat gerbang manusia (docs/22).
