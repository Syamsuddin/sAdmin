# 00 — Executive Summary

## Masalah
Admin server di instansi pemerintah daerah umumnya bekerja sendirian lewat SSH dengan langkah manual yang panjang dan tak tercatat. Akibatnya pemasangan situs lambat dan tak seragam, kesalahan konfigurasi sulit dilacak, tidak ada bukti siapa melakukan apa, pengetahuan hilang saat admin berganti, dan panel komersial berlisensi per akun tidak dirancang untuk kedaulatan data dan UU PDP.

## Solusi
sAdmin adalah panel administrasi root sumber terbuka (MIT) untuk Ubuntu Server yang mengelola satu sampai beberapa server milik instansi. Setiap operasi adalah aksi bertipe dari satu katalog; aksi berbahaya hanya dieksekusi bila membawa tanda tangan passkey admin yang diverifikasi agen di server; pekerjaan rumit dibungkus kapsul yang bertanya sedikit lalu mengerjakan semuanya dan bisa dibatalkan bersih; setiap aksi terbukti di audit berjangkar; pengetahuan tentang server tersimpan di memori institusi. AI opsional: membantu menjelaskan, tidak pernah bisa menyetujui.

## Target MVP
Satu admin bisa menyiapkan server Ubuntu baru, memasang situs Laravel dari GitHub sampai HTTPS dengan satu sentuhan passkey, membatalkannya dengan bersih, dan membuktikan setiap aksi yang pernah terjadi.

## Metrik sukses
| Metrik | Target MVP | Cara ukur |
|---|---|---|
| Waktu `site.create` (repo Laravel → HTTPS 200) | median ≤ 5 menit, tanpa tunggu DNS | `capsule_runs.approved_at` → `succeeded_at` |
| Server setengah jadi di uji injeksi gangguan | 0 | harness (`edge/docs/13_TESTING.md`) |
| Aksi L2/L3 tereksekusi tanpa tanda tangan terverifikasi agen | 0 | rekonsiliasi audit dua sisi |

## Pengguna sasaran & pemangku kepentingan
Admin teknis tunggal di instansi yang mengelola sedikit server **baru**. Pemilik produk: Pak Syams. Pimpinan unit: penerima laporan dan penyimpan kit pemulihan `[ASUMSI]`.

## Positioning
Panel server berdaulat untuk instansi — bukan "panel paling banyak fitur" dan bukan "panel ber-AI" (arena yang sudah dimenangi panel lama).
