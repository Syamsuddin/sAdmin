# 08 — Architecture

Pemilik pola arsitektur paket core dan gambaran sistem. Arsitektur agen/gateway: `../edge/docs/08_ARCHITECTURE.md`. Teknologi: `docs/09_STACK.md`. Protokol: `../kontrak/KONTRAK.md`.

## Komponen & zona (Mode Tunggal)
```
Internet ──443──▶ Nginx ──▶ situs-situs terkelola
Internet ──8443─▶ sadmin-gateway (Go, mTLS)  ◀──wss── sadmin-agent di server lain
                     │ UDS HTTP + HMAC (dua arah)
Admin ──WireGuard wg0──▶ Nginx (vhost console, listen 10.77.0.1:443)
                     ▼
               core (Laravel: console Livewire, API internal, runner, brankas, audit, memori, AI)
                     │ 127.0.0.1
                PostgreSQL 16 · Reverb (127.0.0.1:8080, di-proxy Nginx wg0)
               sadmin-agent lokal (host ini juga server terkelola)
```

| Komponen | Zona | Tanggung jawab |
|---|---|---|
| Console | privat (wg0) | UI admin, login passkey, peninjauan rencana, formulir kapsul |
| Core | privat | katalog (cermin), penyusun rencana, runner, Dispatch, audit & jangkar, memori, lapisan AI, penjadwal |
| Brankas | privat (modul core) | enkripsi envelope; kunci induk via `systemd-creds` |
| Gateway, agen | lihat `../edge/docs/08_ARCHITECTURE.md` | |

## Lapisan core
| Lapisan | Rumah | Aturan |
|---|---|---|
| UI | komponen Livewire `app/Livewire/**` | tipis: validasi bentuk + panggil Action; tanpa query rumit, tanpa logika domain |
| Action/Service | `app/Domain/<Modul>/Actions`, `…/Services` | semua logika domain; satu Action = satu kasus penggunaan |
| Dispatch | `app/Domain/Execution/Dispatch` | **satu-satunya** jalur ke agen: susun amplop, JCS, tanda tangan layanan, kirim via socket gateway |
| Persistensi | Eloquent model `app/Models` | tanpa logika bisnis selain relasi & cast |
| Infrastruktur | `app/Infrastructure/{Gateway,Vault,Jcs,Notify,Ai}` | adaptor ke luar |

Modul domain: `Identity`, `Fleet`, `Sites`, `Catalog`, `Execution` (rencana, runner, kunci), `Audit`, `Vault`, `Backup`, `Alerts`, `Memory`, `Ai`, `Onboarding`.

## Integrasi eksternal MVP
| Integrasi | Dipakai oleh | Catatan |
|---|---|---|
| Cloudflare API | aksi `dns.*` (dieksekusi agen; token dikirim sebagai rahasia amplop) | opsional per domain |
| GitHub | `source.fetch_git` via deploy key SSH read-only | kunci privat di brankas |
| Offsite S3 + object lock | restic (`sadmin.backup`, backup situs) & jangkar audit | |
| Telegram Bot API, SMTP instansi | notifikasi dari agen & core | |
| Penyedia AI | `app/Infrastructure/Ai` | opsional; default mati |
| Let's Encrypt | sertifikat console (DNS-01) & situs | |

## Keputusan arsitektural kunci
| # | Keputusan | Alasan |
|---|---|---|
| A1 | Core tak pernah mengeksekusi perintah OS atau SSH | P1: satu katalog; agen verifikasi independen |
| A2 | Agen memverifikasi passkey terhadap roster tersemat | P2: core yang dibobol tak bisa menjalankan L2/L3 |
| A3 | Pekerjaan rutin sebagai systemd timer di server | P3: core mati ≠ server mati |
| A4 | Hanya gateway publik; console di wg0 | P4 |
| A5 | Dua paket VCBD mode tunggal + `kontrak/` `catalog/` `capsules/` bersama | mode split VCBD terkunci OpenAPI |
| A6 | Gateway↔core via Unix socket + HMAC, gateway tanpa kredensial DB | gateway dibobol ≠ DB dibobol |
| A7 | Antrean, cache, sesi Laravel pakai driver `database`; tanpa Redis | satu layanan data lebih sedikit untuk dirawat & diamankan |
| A8 | Semua L2/L3 lewat `Plan`, termasuk aksi tunggal | satu jalur verifikasi di agen |
| A9 | Rahasia di amplop diikat komitmen hash di rencana | passkey mengikat rahasia tanpa mengekspos nilai |
| A10 | Console hostname = RP ID permanen, sertifikat via DNS-01 | WebAuthn menolak IP; console tak publik |
| A11 | Mode Tunggal di MVP | skala target ≤ 3 server; risikonya diterima sadar |
