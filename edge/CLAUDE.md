# CLAUDE.md — sAdmin paket edge

File ini selalu aktif. Untuk hal di luar ini → buka INDEX.md.

## Proyek
sAdmin edge — agen (tiap server) dan gateway (publik, bodoh) dalam Go: satu-satunya pengeksekusi aksi katalog dan pemverifikasi passkey. Produk & scope dimiliki paket core: ../core/docs/00_EXECUTIVE_SUMMARY.md, ../core/docs/02_SCOPE.md. Peta monorepo: ../README.md.

## Prinsip kerja agen (non-negotiable)
1. Friksi sebanding irreversibilitas.
2. Lapisan deterministik (validasi, constraint, tes) di bawah penalaran.
3. Human-in-the-loop untuk high-stakes (kontrak, kripto, keamanan, rilis).
4. Jangan refactor keputusan yang disengaja diam-diam.
5. Hormati scope (../core/docs/02). Out-of-scope → berhenti & tanya.

## Stack  (sumber: docs/09)
Go statis (CGO_ENABLED=0), bbolt, JSONL audit, stdlib net/http & crypto — Terlarang: cgo, `sh -c`, os/exec di luar internal/sysexec, aksi perintah bebas, profil distro selain ubuntu2404.

## Struktur & konvensi  (sumber: docs/12)
Satu paket per aksi di `internal/actions/<kelompok>/<aksi>` (Check/Apply/Verify/Compensate). Fakta distro hanya di `internal/platform/ubuntu2404`. Pesan dari ../kontrak (codegen), definisi aksi dari ../catalog.

## Perintah penting  (sumber: docs/11)
test: `go test ./...` · lint: `go vet ./... && staticcheck ./...` · harness: `make harness ACTION=<key>` (root) · kontrak: `make contract-test` (root)

## Guardrail inti  (penuh: docs/20, 21, ../core/docs/22)
Jangan lewati verifikasi (juga di tes) · risiko & jeda hanya dari kebijakan tersemat · aksi baru wajib YAML katalog + compensate + harness · jangan ulang buta, pakai jurnal/StatusQuery · jangan buka port di agen · rahasia tak pernah ke log/audit · jangan sentuh `chattr +a`.

## Alur per-task  (penuh: docs/17, 19)
Baca INDEX.md → muat dokumen relevan → konfirmasi scope → vertical slice → tes (docs/13) → DoD (../core/docs/24).

## Definisi selesai (ringkas; penuh: ../core/docs/24)
AC terkait hijau · siklus wajib harness & jejak nol · kontrak/katalog valid · tanpa pelonggaran · entri audit ada · tanpa rahasia bocor.

## Untuk apa pun di luar ini → INDEX.md
