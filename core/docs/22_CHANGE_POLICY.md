# 22 — Change Policy (berlaku kedua paket & rumah bersama)

Pemilik kebijakan git, perubahan, dan irreversibilitas untuk seluruh monorepo. Friksi sebanding irreversibilitas.

## Git
- Satu monorepo; branch per fitur `feat/<ringkas>`, perbaikan `fix/<ringkas>`; PR ke `main`; tidak ada commit langsung ke `main`.
- Versi produk: satu nomor SemVer untuk seluruh monorepo (`kontrak/` punya SemVer sendiri), tag beranotasi `vX.Y.Z` di `main`. Selama MVP `0.x`: tonggak M1–M4 = `0.1.0`–`0.4.0`; slice yang digabung di tengah tonggak = pra-rilis `vX.Y.0-alpha.N`; tag kandidat langkah 1 docs/25_RELEASE_CHECKLIST.md = `-rc.N`; `1.0.0` = rilis pertama ke instansi. Hanya tag tanpa akhiran pra-rilis yang boleh dipasang di instansi.
- Setiap tag punya entri di `../CHANGELOG.md` (format Keep a Changelog, termasuk catatan migrasi dengan tanda ⚠️ untuk yang destruktif).
- CI wajib hijau: tes paket yang disentuh, `make catalog-validate contract-test`, harness aksi/kapsul yang disentuh, `sadmin:forbidden-scan`, `validate.sh` kedua paket bila `docs/` disentuh.
- Review adversarial oleh subagen dengan context segar (membandingkan diff dengan dokumen pemilik) sebelum merge; merge oleh pemilik produk atau pemelihara yang ditunjuk.
- Proyek MIT sumber terbuka: kontribusi eksternal lewat PR yang sama; tanpa rahasia/nama instansi nyata di commit.

## Operasi irreversibel — gerbang manusia (berhenti & minta konfirmasi eksplisit)
| Operasi | Kenapa |
|---|---|
| Migrasi skema core yang destruktif (drop/rename kolom/tabel, ubah tipe) | kehilangan data |
| Perubahan format amplop, rencana, atau kanonisasi (`../kontrak` major) | memutus verifikasi tanda tangan di semua agen |
| Perubahan format rantai audit atau checkpoint | memutus verifikasi riwayat |
| Perubahan level risiko default, jeda L3, atau syarat tanda tangan | melemahkan P9 |
| Penghapusan aksi katalog (hanya boleh `deprecated`) | run lama & kebijakan agen merujuknya |
| Rotasi CA internal, kunci layanan, atau kunci audit | semua agen harus menerima kunci baru |
| Mengganti RP ID / hostname console | semua passkey harus didaftar ulang |
| Menambah platform terkelola | harus lulus harness penuh dulu |
| Rilis ke instansi | ikut docs/25_RELEASE_CHECKLIST.md |

Keputusan arsitektural atau keamanan baru dicatat sebagai ADR di `docs/adr/NNNN-judul.md` (paket core) sebelum implementasi.

## Rollback
- Core: rilis sebelumnya disimpan; `sadmin.backup` otomatis sebelum setiap pembaruan; migrasi destruktif hanya setelah backup terverifikasi.
- Agen: versi lama kembali otomatis bila sinyal hidup (Heartbeat) tak datang dalam 2 menit setelah `agent.update`.
- Rilis yang mengubah `../kontrak` major tidak boleh di-rollback sebagian: core dan semua agen harus satu major.
