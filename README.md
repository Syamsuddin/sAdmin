# sAdmin — monorepo

Panel server berdaulat untuk instansi: setiap aksi berbahaya disetujui dengan passkey dan terbukti di audit, pekerjaan rumit terbungkus kapsul yang bisa dibatalkan bersih, dan pengetahuan tentang server tidak ikut pergi saat admin berganti. Lisensi MIT (lihat `LICENSE`).

## Peta monorepo
| Path | Isi | Rumah fakta |
|---|---|---|
| `core/` | Laravel: console, core, brankas, runner kapsul | Paket VCBD `core` — juga **paket induk produk** (visi, fitur, scope, roadmap, istilah, peran, kebijakan git, DoD, rilis) |
| `edge/` | Go: `cmd/agent`, `cmd/gateway`, `internal/…` | Paket VCBD `edge` |
| `kontrak/` | Protokol pesan core↔gateway↔agen | `kontrak/KONTRAK.md` (+ `schemas/*.json`, `vectors/` saat M1) |
| `catalog/` | Definisi aksi (YAML) + definisi level risiko | `catalog/CATALOG.md` (+ `*.yaml` saat M1) |
| `capsules/` | Resep kapsul (YAML) | `capsules/CAPSULES.md` (+ `*.yaml` saat M2) |
| `harness/` | Uji VM LXD, injeksi gangguan, uji keamanan, evaluasi AI | Strategi: `edge/docs/13_TESTING.md` |
| `deploy/` | `install.sh`, unit systemd, template Nginx | Struktur: `core/docs/12_PROJECT_STRUCTURE.md` |
| `CHANGELOG.md` | Riwayat perubahan per versi (Keep a Changelog) | Skema versi: `core/docs/22_CHANGE_POLICY.md` §Git |

Semua path di dokumen paket ditulis relatif terhadap **root paket** (`core/` atau `edge/`), mis. `../catalog/CATALOG.md`; path di berkas rumah bersama (`README.md`, `kontrak/`, `catalog/`, `capsules/`) relatif terhadap root monorepo.

Presedensi rumah bersama: berkas mesin (`kontrak/schemas/*.json`, `catalog/*.yaml`, `capsules/*.yaml`) **menang** atas prosa `.md` di foldernya begitu berkas itu ada. Selisih → berhenti, laporkan, gerbang manusia (`core/docs/22_CHANGE_POLICY.md`).

## Paket mana untuk task apa
| Task | Buka sesi Claude Code di | Juga baca |
|---|---|---|
| Console, UI, core, brankas, runner, audit sisi core, memori, AI | `core/` | — |
| Implementasi aksi, agen, gateway, adaptor platform, harness | `edge/` | `catalog/CATALOG.md` |
| Aksi baru | `edge/` (implementasi) lalu `core/` (bila formulir/tampilan) | `catalog/CATALOG.md` |
| Kapsul baru | `core/` | `capsules/CAPSULES.md`, `catalog/CATALOG.md` |
| Ubah pesan protokol | ⚠️ gerbang manusia — `kontrak/KONTRAK.md` dulu, lalu kedua paket | `core/docs/22_CHANGE_POLICY.md` |

Prompt pertama tiap sesi: `Baca CLAUDE.md lalu INDEX.md. Untuk task X, muat hanya dokumen yang ditunjuk INDEX. Kerjakan, lalu jalankan blok verifikasi.`

## Perintah lintas-paket (dijalankan dari root)
Perintah khusus paket: `core/docs/11_COMMANDS.md`, `edge/docs/11_COMMANDS.md`.

| Tujuan | Perintah | Lulus bila |
|---|---|---|
| Validasi katalog & resep | `make catalog-validate` | exit 0; gagal bila ada aksi tanpa `platforms`, aksi non-L0 tanpa `compensate`, atau resep merujuk aksi/versi tak dikenal |
| Uji kontrak silang PHP↔Go | `make contract-test` | pesan buatan PHP lolos validator Go dan sebaliknya; semua vektor JCS identik byte-per-byte |
| Lingkungan dev | `make dev` | core lokal + 1 VM LXD berisi agen terhubung |
| Harness penuh | `make harness` | semua aksi & kapsul lulus siklus wajib |
| Harness satu aksi / kapsul | `make harness ACTION=db.create_with_user` · `make harness CAPSULE=site.create` (opsional `RUNS=5 REPORT=timing`) | hijau; `REPORT=timing` mencetak `median_s` |
| Skenario sistem | `make harness SCENARIO=<install\|enroll\|restore\|core-offline\|emergency-local\|unsupported-platform>` | hijau (AC-01, 02, 11, 12, 13, 16) |
| Injeksi gangguan | `make harness CAPSULE=site.create FAULT=kill-agent-at-step:5` | status akhir benar, jejak nol |
| Uji keamanan | `make harness-security` | semua amplop cacat ditolak agen |
| Evaluasi AI | `make harness-ai-eval` | skor ≥ ambang di `harness/ai-eval/threshold` |
| Validasi dokumen blueprint | `(cd core && bash scripts/validate.sh) && (cd edge && bash scripts/validate.sh)` | tanpa `[FAIL]` |

## Gerbang lintas-paket
Mode split VCBD tidak dipakai (terkunci ke OpenAPI BE/FE; protokol sAdmin adalah pesan WebSocket). Penggantinya: `make catalog-validate contract-test` wajib hijau di CI untuk setiap PR yang menyentuh `kontrak/`, `catalog/`, `capsules/`, atau kode yang memproduksi/mengonsumsi pesan.
