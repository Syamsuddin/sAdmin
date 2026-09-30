# 10 — Dev Env (agen & gateway)

Pemilik setup pengembangan edge. Perintah: `docs/11_COMMANDS.md`. Core lokal: `../core/docs/10_DEV_ENV.md`.

## Prasyarat
Go (versi di docs/09_STACK.md), LXD (`sudo snap install lxd && lxd init --auto`) atau Multipass, `make`, `staticcheck`, `govulncheck`, core lokal berjalan (untuk `make dev`).

## Langkah
1. `cd edge && go mod download`.
2. Dari root: `make dev` — membangun kedua biner, menjalankan gateway di `127.0.0.1:8443` dengan CA dev, meluncurkan VM LXD `sadmin-dev-1` (Ubuntu 24.04), menyalin agen, dan meng-enrol ke core lokal.
3. Kunci uji: `harness/keys/` berisi kunci layanan, audit, rilis, dan passkey virtual **khusus uji** (tak pernah dipakai di luar harness; agen build rilis menolak kunci yang ber-flag `test`).

## Konfigurasi dev (nama saja)
| Variabel / berkas | Fungsi |
|---|---|
| `SADMIN_GATEWAY_LISTEN` | alamat dengar gateway (dev `127.0.0.1:8443`) |
| `SADMIN_CORE_INBOX_SOCKET`, `SADMIN_GATEWAY_SOCKET` | Unix socket ke/dari core |
| `SADMIN_GATEWAY_HMAC_CRED` | nama kredensial `systemd-creds` (dev: berkas lokal) |
| `/etc/sadmin/agent.yaml` di VM | ditulis oleh `sadmin-agent enroll` |
