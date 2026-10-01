# ADR — Catatan Keputusan Arsitektur (paket core)

Keputusan arsitektural atau keamanan baru dicatat di sini **sebelum** diimplementasikan (docs/22_CHANGE_POLICY.md). Berkas bernama `NNNN-judul-singkat.md` dan tidak pernah dihapus. ADR yang diganti diberi status *Digantikan oleh NNNN*.

## Indeks
| No | Judul | Status |
|---|---|---|
| [0001](0001-format-rantai-audit.md) | Format hash rantai audit | Diterima |
| [0002](0002-pustaka-webauthn.md) | Pustaka WebAuthn: web-auth/webauthn-lib | Diterima |
| [0003](0003-format-brankas.md) | Format brankas: enkripsi envelope dan kunci induk | Diterima |
| [0004](0004-checkpoint-audit.md) | Checkpoint audit bertanda tangan | Diterima |
| [0005](0005-peringatan-integritas.md) | Peringatan integritas dan kanal notifikasi core | Diterima |
| [0006](0006-tanda-tangan-layanan.md) | Tanda tangan kunci layanan pada bingkai core→agen | Diterima |
| [0007](0007-ca-internal.md) | CA internal: kunci, pin, dan sertifikat klien agen | Diterima |
| [0008](0008-penukaran-enrolment.md) | Penukaran enrolment: `Enroll`→`EnrollAccept`, roster/kebijakan awal, sidik jari | **Diusulkan** |

## Templat
```markdown
# ADR NNNN — <judul>

| | |
|---|---|
| Status | Diusulkan / Diterima / Ditolak / Digantikan oleh NNNN |
| Tanggal | YYYY-MM-DD |
| Pemutus | siapa yang berhak memutuskan (+ gerbang docs/22 bila ada) |
| Lingkup | apa yang diatur · Di luar lingkup: apa yang tidak |
| Rujukan | dokumen pemilik fakta yang terkait |

## 1. Konteks
Masalah dan kenapa perlu diputuskan sekarang.

## 2. Keputusan (normatif)
Aturan yang wajib diikuti implementasi, cukup rinci untuk diimplementasikan ulang tanpa membaca kode.

## 3. Alternatif yang dipertimbangkan
| Alternatif | Ditolak karena |

## 4. Konsekuensi
Yang menjadi mungkin/tidak mungkin, yang tertunda, dan biaya mengubah keputusan ini kelak.

## 5. Penegakan
| Klausul | Dijaga oleh (tes, pemindai, constraint) |

## 6. Riwayat
- YYYY-MM-DD: diusulkan / diterima / direvisi (apa yang berubah).
```
