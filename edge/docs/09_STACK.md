# 09 — Stack (agen & gateway)

Pemilik teknologi paket edge. Stack core: `../core/docs/09_STACK.md`.

| Lapisan | Teknologi | Versi |
|---|---|---|
| Bahasa | Go, `CGO_ENABLED=0`, target `linux/amd64` & `linux/arm64` | rilis stabil terbaru `[VERIFIKASI]` |
| WebSocket | `github.com/coder/websocket` | `[VERIFIKASI]` |
| WebAuthn (verifikasi assertion) | `github.com/go-webauthn/webauthn` (paket `protocol`) | `[VERIFIKASI]` |
| Penyimpanan lokal | `go.etcd.io/bbolt` | `[VERIFIKASI]` |
| JSON Schema | `github.com/santhosh-tekuri/jsonschema` v6 | `[VERIFIKASI]` |
| JCS | `github.com/gowebpki/jcs` + vektor bersama `../kontrak/vectors/` | `[VERIFIKASI]` |
| YAML (katalog) | `go.yaml.in/yaml/v3` | `[VERIFIKASI]` |
| Kripto | stdlib `crypto/ed25519`, `crypto/ecdsa`, `crypto/tls`, `crypto/x509` | stdlib |
| Log | stdlib `log/slog` (JSON) | stdlib |
| Lint | `go vet`, `staticcheck`, `govulncheck` | `[VERIFIKASI]` |
| Harness | LXD VM (Multipass alternatif), Make, tes Go `harness/` | paket Ubuntu/snap |

## Perangkat lunak yang dikelola di server (dipasang aksi, dari repositori resmi)
Ubuntu 24.04: Nginx, PHP-FPM (8.3 bawaan; versi lain dari sumber `[VERIFIKASI]`), MariaDB 10.11, certbot + `python3-certbot-dns-cloudflare`, restic, CrowdSec, nftables, WireGuard (host), unattended-upgrades, systemd timer. sAdmin tidak membangun/merawat paket sendiri.

## Teknologi terlarang
| Larangan | Alasan |
|---|---|
| cgo, SQLite berbasis cgo | biner statis |
| `sh -c`/`bash -c` dengan interpolasi parameter, `os/exec` di luar `internal/sysexec` | injeksi perintah |
| Aksi atau mode "jalankan perintah bebas", terminal jarak jauh | melanggar P1 |
| Profil platform selain `ubuntu2404`; kode "if distro == …" di dalam aksi | `../core/docs/02_SCOPE.md`; fakta distro hanya di adaptor |
| Framework web (gin, echo, dsb.) untuk gateway | stdlib `net/http` cukup; dependency = permukaan serangan |
| Modul Go baru tanpa alasan tertulis di PR | biner berhak root |
