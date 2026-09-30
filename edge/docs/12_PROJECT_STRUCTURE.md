# 12 — Project Structure (agen & gateway)

Pemilik struktur & penamaan paket edge.

```
edge/
├── cmd/agent/main.go             # subperintah: run (default), enroll, confirm, cancel, status, local, audit
├── cmd/gateway/main.go
├── internal/
│   ├── protocol/                 # tipe hasil codegen dari ../kontrak/schemas + jcs/ + validasi
│   ├── transport/                # wss mTLS, backoff, outbox
│   ├── trust/                    # roster, policy, sig, webauthn, nonce, secretcommit
│   ├── executor/                 # pipa E1–E4, jurnal, kunci, delays, timers
│   ├── actions/<kelompok>/<aksi>/# mis. actions/db/createwithuser/ — satu paket per aksi
│   ├── actions/registry.go       # peta key+version → implementasi (dicek terhadap ../catalog)
│   ├── platform/                 # antarmuka adaptor
│   ├── platform/ubuntu2404/      # SATU-SATUNYA implementasi MVP
│   ├── sysexec/                  # SATU-SATUNYA pemakai os/exec
│   ├── audit/  notify/  metrics/  store/ (bbolt)
│   └── gateway/                  # server mTLS, enroll, blob, relay UDS
└── docs/
../harness/                       # milik paket edge: vm/, faults/, security/, ai-eval/, keys/
../catalog/  ../kontrak/          # rumah bersama (lihat ../README.md)
```

## Konvensi
| Hal | Konvensi | Contoh |
|---|---|---|
| Paket aksi | `actions/<kelompok>/<nama tanpa titik/garis bawah>` | `db.create_with_user` → `actions/db/createwithuser` |
| Tipe aksi | `type Action struct{ P platform.Set }` dengan metode `Check`, `Apply`, `Verify`, `Compensate(ctx, Params) (Result, error)` | |
| Galat | `errs.Transient(code, err)` / `errs.Permanent(code, err)` | kode dari `../catalog` |
| Tes aksi | unit dengan platform palsu `platform/fake` + skenario harness | |
| Berkas yang ditulis ke server | milik sAdmin selalu di path ber-`sadmin` (`/etc/nginx/sadmin.d/`, `/etc/systemd/system/sadmin-*.timer`) | |

Aturan: aksi tidak memanggil `os/exec`, tidak membaca `/etc/os-release`, dan tidak menulis path distro secara langsung — semuanya lewat `platform.Set`.
