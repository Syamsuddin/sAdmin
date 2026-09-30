# 03 — Roadmap

Pemilik urutan fase untuk kedua paket. Tiap tonggak = vertical slice yang bisa didemokan; durasi tidak ditetapkan (bergantung alokasi waktu pemilik produk). M1 dan M2 paling berat dan paling menentukan.

## MVP
| Tonggak | Demo (lulus bila terlihat) | Fitur (`docs/01_PRD.md`) | Kerja core | Kerja edge |
|---|---|---|---|---|
| M1 Kerangka | Agen di VM terhubung, inventaris tampil di console via WireGuard, `sadmin audit verify` hijau | F-01…F-05, F-17 | install.sh, login passkey, inventaris, audit berantai, tema | agen+gateway, enrolment, aksi L0, jangkar audit lokal, harness dasar |
| M2 Aksi tulis & persetujuan | Rencana disetujui passkey; L3 menunggu jeda + notifikasi; `ssh.harden` kembali sendiri tanpa konfirmasi | F-06…F-09 | rencana, persetujuan, runner, kunci sumber daya, pembatalan | ±30 aksi, kebijakan & roster, jeda, pembatalan bertimer, `Notifier` |
| M3 Kapsul inti | Server kosong → situs Laravel HTTPS → diarsipkan dengan jejak nol | F-10…F-12 | 4 kapsul, formulir, linimasa, peringatan | aksi web/DB/SSL/DNS, backup restic, timer lokal, metrik |
| M4 Ketahanan | Control plane dihapus lalu dipulihkan dari backup + kit pemulihan; aksi darurat lokal tanpa core | F-13…F-16 | backup/restore core, memori, AI read-only | mode darurat lokal, sangga & sinkron |

## Pasca-MVP
| Fase | Isi |
|---|---|
| Fase 2 | sAdmin Deploy lengkap (GitHub App, webhook via gateway ber-HMAC, `sadmin.yml`, GitHub Deployments API); email mode relay; kapsul `site.clone_staging`, `site.change_domain`, `site.upgrade_php`, `site.add_worker`, `access.vendor_temporary`, `app.create_container`; kotak masuk usulan memori AI; dokter deliverability; AI tinjauan rilis |
| Fase 3 | Mode Armada; AI plan-and-execute dengan persetujuan; server MCP (L0–L1 + pengusulan); deteksi drift; brownfield (mode penemuan, `site.adopt`); mail server penuh; verifikasi memori otomatis & pencarian pgvector; preview per PR; `site.incident_response`; platform `ubuntu-26.04` `[VERIFIKASI]` |
| Fase 4 | Prakiraan kapasitas; laporan kepatuhan; model lokal; artefak GitHub Actions; kapsul buatan pengguna; ekspor serah terima memori; Shamir; multi-tenant OPD; aplikasi konfirmasi ponsel; migrasi dari cPanel; Debian 12/13 lalu AlmaLinux/Rocky hanya bila data menunjukkan kebutuhan; notifikasi self-hosted (mis. ntfy) |

Keputusan pasca-MVP yang sudah ditutup: deploy produksi selalu L2, webhook hanya auto-deploy staging (L1); memori admin kedua lingkup institusi butuh persetujuan admin lain; server email Postfix+Dovecot+Rspamd (Stalwart dievaluasi Fase 3).
