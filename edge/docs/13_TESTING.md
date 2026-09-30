# 13 — Testing (agen, gateway, harness)

Pemilik strategi tes paket edge **dan harness** (`../harness/`). Tes core: `../core/docs/13_TESTING.md`. Perintah: `docs/11_COMMANDS.md` & `../README.md`.

| Lapisan | Cakupan | Target |
|---|---|---|
| Unit | trust (Ed25519, WebAuthn, nonce, komitmen rahasia, roster/kebijakan), executor (pipa E1–E4, jurnal, timer, jeda), JCS, adaptor dengan `platform/fake` | ≥ 85% baris `internal/trust` & `internal/executor` |
| Kontrak | pesan Go lolos skema `../kontrak/schemas`; vektor JCS identik dengan PHP | wajib hijau |
| Integrasi harness | setiap aksi di VM LXD Ubuntu 24.04 sekali pakai | lihat siklus wajib |
| Injeksi gangguan | skenario di bawah | 0 server setengah jadi |
| Keamanan | skenario di bawah | semua ditolak |
| Skenario sistem | `install`, `restore`, `core-offline` | AC core & edge |
| Matriks harian | Ubuntu 24.04 + pembaruan terbaru; PHP & MariaDB yang didukung | hijau; merah = regresi upstream |
| Pengawas upstream | mingguan terhadap paket terbaru repositori | laporan |
| Evaluasi AI | skenario diagnosis dengan jawaban acuan (`harness/ai-eval/`) | ≥ ambang |

## Siklus wajib setiap aksi
`snapshot` → `apply` → `verify` → `apply` lagi (harus `skipped`) → `compensate` → **jejak nol**: diff snapshot (berkas di `/etc`, `/home`, `/var/lib` terpilih, unit systemd, paket, user, DB, aturan nftables) kosong. Aksi L0: `apply` dua kali tanpa perubahan snapshot.

## Injeksi gangguan (`FAULT=`)
| Skenario | Status akhir yang benar |
|---|---|
| `kill-agent-at-step:N` | agen restart → `interrupted` → `check` → run lanjut atau berkompensasi; tanpa eksekusi ganda |
| `drop-net-after-dispatch:N` | core `StatusQuery` setelah tersambung; tanpa amplop kedua |
| `fail-step:N` | kompensasi langkah 1..N-1 terbalik → `compensated`, jejak nol |
| `restart-core-while-waiting` | run tetap `waiting`, lanjut setelah core hidup |
| `fail-compensation:N` | `needs_attention`, kunci sumber daya tetap dipegang, peringatan terkirim |

## Uji keamanan (`make harness-security`)
Amplop tanpa `sig`; `sig` rusak; parameter diubah satu karakter setelah persetujuan; `plan.steps` ditambah; nonce diulang; amplop & rencana kedaluwarsa; assertion dari kredensial di luar roster; flag UV mati; origin/RP ID lain; roster palsu dari core tanpa jeda; L3 dikirim dengan `delay_seconds=0`; risiko diturunkan di amplop; komitmen rahasia ditukar; rantai audit lokal diubah; aksi dengan `platform_id` tak didukung. Semua wajib `rejected` dengan kode yang tepat dan tercatat di audit lokal.

## Aturan
- Kunci uji hanya dari `../harness/keys/`; dilarang flag/mode "skip verify" di kode produksi.
- Tes flakey diperbaiki atau dikarantina dengan isu terbuka, tidak dilonggarkan.
