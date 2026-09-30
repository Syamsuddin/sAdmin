# ADR 0002 — Pustaka WebAuthn: web-auth/webauthn-lib

| | |
|---|---|
| Status | **Diterima** — dipilih pemilik produk |
| Tanggal | 2026-09-30 |
| Pemutus | Pemilik produk (konflik docs/09 lawan docs/07, aturan emas INDEX #3) |
| Lingkup | Verifikasi WebAuthn di core (login, pendaftaran, dan kelak persetujuan L2/L3 pra-agen) |
| Rujukan | docs/07 §authenticators · docs/09 · docs/21 §Autentikasi · `../kontrak/KONTRAK.md` §4 |

## 1. Konteks
docs/09 menyebut `laragear/webauthn` dengan tanda `[VERIFIKASI]`. Verifikasi atas v5.0.2 menemukan pustaka itu mengunci penyimpanannya sendiri:
- tabel `webauthn_credentials` dengan primary key berupa ID kredensial;
- pipa assertion yang memanggil `WebAuthnCredential::whereKey()` langsung;
- relasi polimorfik dengan UUID sebagai user handle;
- kunci publik disimpan sebagai PEM yang dienkripsi `APP_KEY` (cast `encrypted`).

Hal-hal itu bertentangan dengan tabel `authenticators` di docs/07 (ULID, `tenant_id`, `credential_id` bytea, `public_key_cose` bytea, `alg`, `sign_count`, `label`, `status`). Selain itu kunci COSE dibutuhkan apa adanya untuk roster yang diverifikasi agen, dan `APP_KEY` bukan kunci brankas, sehingga passkey tak boleh bergantung padanya saat pemulihan (docs/10).

Opsi yang ditimbang:

| Opsi | Paket baru | docs/07 | Catatan |
|---|---|---|---|
| laragear/webauthn | 2 | diganti | kunci publik bergantung `APP_KEY`; roster harus mendekripsi PEM |
| **web-auth/webauthn-lib** | 16 | utuh | pustaka PHP rujukan, penyimpanan bebas |
| implementasi internal | 0 | utuh | ±400 baris kode verifikasi keamanan kritis |

## 2. Keputusan (normatif)
1. **Pustaka:** `web-auth/webauthn-lib` ^5.3 (MIT).
2. **Satu pintu:** kode di luar `app/Infrastructure/WebAuthn` dilarang memakai namespace `Webauthn\` atau `Cose\` langsung. Aturannya meniru prinsip "satu-satunya jalur" pada Dispatch.
3. **Parameter ceremony** berlaku tetap:
   - `userVerification: required`;
   - attestation conveyance `none`;
   - algoritme hanya ES256 (-7) dan EdDSA (-8);
   - `residentKey: required` (passkey dapat ditemukan), sehingga halaman masuk tidak menanyakan nama.
4. **RP ID dan origin:**
   - RP ID = `institutions.console_hostname`.
   - Origin yang diharapkan = `https://` + hostname, kecuali `SADMIN_ORIGIN` diisi. Isian itu hanya untuk dev, misalnya bila ada port.
   - `SADMIN_RP_ID` hanya menjadi nilai bawaan `sadmin:institution-init`.
5. **Penyimpanan:** tetap docs/07 tanpa perubahan. `public_key_cose` menyimpan kunci COSE mentah dari authenticator data, dan `alg` diambil dari kunci itu.

## 3. Alternatif yang dipertimbangkan
Lihat tabel opsi di bagian 1: `laragear/webauthn` (mengganti docs/07, kunci publik bergantung `APP_KEY`) dan implementasi internal (±400 baris kode verifikasi keamanan kritis).

## 4. Konsekuensi
- Enam belas paket Composer baru, di antaranya `symfony/serializer`, `symfony/property-*`, `spomky-labs/cbor-php`, `spomky-labs/pki-framework`, `web-auth/cose-lib`, dan `phpdocumentor/*`. Semuanya ikut `composer audit` di CI (docs/21).
- Roster untuk agen bisa langsung memuat `public_key_cose`, tanpa `APP_KEY` dan tanpa konversi.
- Mengganti pustaka kelak cukup menyentuh adaptor.
- Passkey yang tidak bisa menjadi *resident key* (discoverable) tidak dapat didaftarkan. Yang terdampak adalah kunci keamanan lama tanpa slot resident.

## 5. Penegakan
| Klausul | Dijaga oleh |
|---|---|
| Satu pintu (hanya adaptor memakai `Webauthn\`, `Cose\`, `CBOR\`) | `WebAuthnBoundaryTest` |
| Parameter ceremony, origin eksplisit, tipe clientData, crossOrigin, anti-klon | `PasskeyLoginTest`, `PasskeyRegistrationTest` (autentikator virtual, tanpa bypass) |
| Penyimpanan docs/07 (COSE mentah, bytea) | `PasskeyRegistrationTest`, `ByteaColumnTest` |

## 6. Riwayat
- 2026-09-30: diterima (pilihan pemilik produk). Setelah audit keamanan ditambah: tipe clientData wajib sesuai ceremony dan ceremony lintas origin ditolak.
