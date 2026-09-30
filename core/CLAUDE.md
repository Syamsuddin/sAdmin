# CLAUDE.md — sAdmin paket core

File ini selalu aktif. Untuk hal di luar ini → buka INDEX.md.

## Proyek
sAdmin core — control plane Laravel (console, runner kapsul, brankas, audit, memori) panel server berdaulat; paket induk produk. Detail: docs/00_EXECUTIVE_SUMMARY.md. Scope: docs/02_SCOPE.md. Peta monorepo: ../README.md.

## Prinsip kerja agen (non-negotiable)
1. Friksi sebanding irreversibilitas.
2. Lapisan deterministik (validasi, constraint, tes) di bawah penalaran.
3. Human-in-the-loop untuk high-stakes (migrasi DB, hapus data, keamanan, rilis).
4. Jangan refactor keputusan yang disengaja diam-diam.
5. Hormati scope (docs/02). Out-of-scope → berhenti & tanya.

## Stack  (sumber: docs/09)
PHP 8.3 · Laravel + Livewire · Tabler · PostgreSQL 16 · Reverb — Terlarang: eksekusi shell/SSH dari core, SPA React/Vue, Redis, CDN aset, dependency tanpa alasan.

## Struktur & konvensi  (sumber: docs/12)
Logika di `app/Domain/<Modul>/Actions|Services`; Livewire tipis. Amplop ke agen HANYA via `app/Domain/Execution/Dispatch`. Nama field protokol dari ../kontrak, aksi dari ../catalog, resep dari ../capsules — tidak ditulis ulang di PHP.

## Perintah penting  (sumber: docs/11)
test: `php artisan test` · kontrak: `make contract-test` (root) · migrasi ⚠️: `php artisan migrate` · runner: `php artisan sadmin:runner`

## Guardrail inti  (penuh: docs/20, 21, 22)
Jangan eksekusi OS/SSH dari core · jangan longgarkan/mock verifikasi tanda tangan · rahasia hanya di brankas (tak di log/audit/memori/prompt) · jangan ubah audit, approvals, rencana tersetujui · jangan turunkan risiko tanpa ADR · AI tak pernah menandatangani/mengeksekusi.

## Antarmuka  (sumber: docs/26_UI_CONVENTIONS.md)
Tabler + token light/dark di `resources/css/tokens.css`. Nilai di luar token terlarang · empat state wajib · lencana risiko selalu bertuliskan teks.

## Alur per-task  (penuh: docs/17, 19)
Baca INDEX.md → muat dokumen relevan → konfirmasi scope → vertical slice → tes (docs/13) → DoD (docs/24).

## Definisi selesai (ringkas; penuh: docs/24)
AC terkait hijau · tes & harness yang disentuh hijau · kontrak/katalog valid · tanpa pelonggaran · ada entri audit · tanpa rahasia bocor.

## Untuk apa pun di luar ini → INDEX.md
