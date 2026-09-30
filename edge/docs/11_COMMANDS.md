# 11 — Commands (agen & gateway)

Pemilik perintah paket edge; jalankan dari `edge/` kecuali disebut lain. Perintah lintas-paket & harness (`make …` dari root): `../README.md`. Core: `../core/docs/11_COMMANDS.md`.

| Tujuan | Perintah | Catatan |
|---|---|---|
| Build | `CGO_ENABLED=0 go build -trimpath -o bin/ ./cmd/agent ./cmd/gateway` | |
| Tes unit | `go test ./...` | |
| Tes dengan race detector | `go test -race ./internal/...` | wajib untuk `executor`, `transport` |
| Tes kontrak sisi Go | `go test ./internal/protocol/... -run Contract` | vektor `../kontrak/vectors/` |
| Lint | `go vet ./... && staticcheck ./...` | |
| Kerentanan | `govulncheck ./...` | CI |
| Codegen tipe pesan | `go generate ./internal/protocol` | dari `../kontrak/schemas/*.json`; dilarang edit hasil manual |
| Pindai larangan exec | `make -C .. edge-exec-scan` | gagal bila `os/exec` dipakai di luar `internal/sysexec` atau ada `sh -c` |
| Build rilis bertanda tangan | `make -C .. release-edge VERSION=x.y.z` | butuh kunci rilis offline |
| Enrol (di server) | `sudo sadmin-agent enroll --gateway <host>:8443 --ca-sha256 <fp> --token <token>` | |
| Konfirmasi timer (di server) | `sadmin-agent confirm <kode>` | dari sesi SSH baru |
| Batalkan jeda L3 (di server) | `sudo sadmin-agent cancel <kode>` | |
| Mode darurat lokal | `sudo sadmin-agent local run <aksi> --param k=v` | tercatat `emergency_local` |
| Reset roster dengan kit pemulihan | `sudo sadmin-agent local roster-reset --recovery-key <berkas>` | |
| Status agen | `sudo sadmin-agent status` | koneksi, versi, jeda/timer tertunda, kepala audit |
| Verifikasi audit lokal | `sudo sadmin-agent audit verify` | exit 0 = rantai utuh |
