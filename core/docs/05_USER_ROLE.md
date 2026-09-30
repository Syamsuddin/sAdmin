# 05 — User Role

Pemilik peran & matriks akses untuk kedua paket. Penegakan kriptografis di agen: `../edge/docs/21_SECURITY_RULES.md`; di console: `docs/21_SECURITY_RULES.md`.

## Peran MVP
| Peran | Jenis | Keterangan |
|---|---|---|
| Admin | manusia | ≥ 1 orang pemegang passkey (keputusan pemilik), wajib ≥ 2 autentikator; pemilik semua hak di MVP |
| Saksi | manusia | kontak (pimpinan/kontak darurat); bukan akun console `[ASUMSI]` |
| Pemegang root lokal | manusia | siapa pun dengan root SSH di server; hanya untuk mode darurat lokal & pemulihan |
| Asisten AI | sistem opsional | membaca data L0 sesuai kebijakan aliran data |
| Runner | sistem | memajukan run yang sudah disetujui |
| Agen | sistem | mengeksekusi amplop sah |
| Gateway | sistem | meneruskan pesan; tanpa hak apa pun atas data |

## Matriks akses
| Kemampuan | Admin | Saksi | Root lokal | Asisten AI | Runner/Agen |
|---|---|---|---|---|---|
| Lihat inventaris, metrik, log tersamarkan, audit | ✓ | ✗ | ✓ (lokal) | ✓ L0 sesuai kebijakan | ✓ |
| Jalankan aksi/kapsul L0–L1 | ✓ | ✗ | ✓ darurat | ✗ | ✓ atas perintah sah |
| Setujui L2/L3 (passkey) | ✓ | ✗ | ✗ | ✗ | ✗ |
| Batalkan L3 selama jeda | ✓ (console/bot) | ✓ (balasan bot/tautan) | ✓ (`sadmin-agent`) | ✗ | ✗ |
| Lompati jeda L3 | ✗ | ✗ | ✓ hanya mode darurat lokal | ✗ | ✗ |
| Ubah roster/kebijakan | ✓ L3 + jeda 24 jam | notifikasi + batal | ✓ terbitkan roster baru lokal dengan kunci pemulihan | ✗ | ✗ |
| Kelola memori | ✓ | ✗ | ✗ | ✗ (usulan pasca-MVP) | ✓ tulis memori kejadian terstruktur |
| Baca rahasia di brankas | hanya tampil-sekali saat dibuat (`db_credentials_once`) | ✗ | ✗ | ✗ | agen menerima nilai via `secret_values` |
| Ubah kebijakan aliran data AI & anggaran | ✓ (diaudit) | ✗ | ✗ | ✗ | ✗ |
| Hapus profil admin sendiri (UU PDP) | ✓ | — | — | — | — |

Peran pasca-MVP: Pengembang aplikasi (deploy terbatas ke aplikasinya), Operator unit/OPD (tenant), Admin kedua (mengaktifkan L3 dua tanda tangan).
