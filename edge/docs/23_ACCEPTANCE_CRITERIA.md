# 23 — Acceptance Criteria (paket edge)

Kriteria terima milik edge (fitur: `../core/docs/01_PRD.md`). AC core: `../core/docs/23_ACCEPTANCE_CRITERIA.md`. DoD: `../core/docs/24_DEFINITION_OF_DONE.md`. Fitur diterima dipindah ke `docs/_archive/23-<fitur>.md`. Semua perintah dari root monorepo.

## AC-02 Agen & gateway (F-02)
- Given VM Ubuntu 24.04 baru dan token enrolment, When perintah enrolment dijalankan, Then agen `connected` ≤ 30 detik dan sidik jari roster di terminal = di console.
- Given `ss -tlnp` dicatat sebelum pemasangan agen, When dicatat lagi sesudahnya, Then tidak ada port dengar baru.
```bash
make harness SCENARIO=enroll   # connect_s <= 30, new_listen_ports=0
```

## AC-04 Tanda tangan (F-07)
- Given skenario keamanan docs/13_TESTING.md, When dikirim ke agen, Then semuanya `rejected` dengan kode yang tepat dan tercatat di audit lokal.
```bash
make harness-security   # rejected=all, executed=0
```

## AC-05 Jeda L3 (F-07)
- Given rencana L3 disetujui, Then notifikasi dari agen tiba di Telegram & SMTP uji ≤ 60 detik dan memuat ringkasan dari amplop.
- Given pembatalan (console, balasan bot, atau `sadmin-agent cancel`) selama jeda, Then aksi tidak dieksekusi.
- Given tanpa pembatalan, Then aksi berjalan setelah jeda (harness memakai jeda 60 dtk lewat kebijakan uji).
```bash
make harness CAPSULE=l3-sample   # notify_s <= 60, cancel_prevents=ok, runs_after_delay=ok
```

## AC-06 Pembatalan bertimer (F-09)
- Given `ssh.harden` diterapkan tanpa `sadmin-agent confirm`, Then konfigurasi SSH kembali seperti semula ≤ 330 detik dan `Event timer.rolled_back` terkirim.
- Given agen di-restart di tengah timer, Then rollback tetap terjadi tepat waktu.
```bash
make harness ACTION=ssh.harden FAULT=no-confirm        # restored_s <= 330
make harness ACTION=firewall.apply FAULT=restart-agent  # restored=ok
```

## AC-07 Aksi katalog (F-06)
- Given setiap aksi MVP di `../catalog/CATALOG.md`, Then lulus siklus wajib dengan jejak nol.
```bash
make harness   # actions: N/N passed, zero_trace: N/N
```

## AC-09 Ketahanan kapsul (F-08)
- Given setiap skenario injeksi gangguan docs/13_TESTING.md pada `site.create`, Then status akhir sesuai tabel dan 0 server setengah jadi.
```bash
for f in kill-agent-at-step:5 drop-net-after-dispatch:7 fail-step:9 restart-core-while-waiting fail-compensation:6; do make harness CAPSULE=site.create FAULT=$f || exit 1; done
```

## AC-12 Independensi server (F-11)
- Given core dimatikan 24 jam (waktu disimulasikan), Then timer backup restic dan pembaruan SSL (staging LE) tetap berjalan, dan notifikasi darurat "agen tak terhubung" terkirim dari agen.
```bash
make harness SCENARIO=core-offline   # backup=ok, cert_renew=ok, emergency_notify=ok
```

## AC-13 Mode darurat lokal (F-14)
- Given core mati, When `sudo sadmin-agent local run release.rollback --param site=<domain>`, Then situs kembali ke rilis sebelumnya, audit lokal `emergency_local=true`, dan entri tersinkron ke core setelah core hidup.
```bash
make harness SCENARIO=emergency-local   # rollback=ok, synced=ok
```

## AC-16 Dukungan platform
- Given VM Debian 12 atau Ubuntu 22.04, When enrolment/`server.onboard`, Then ditolak dengan `E_PLATFORM` tanpa perubahan apa pun di server (snapshot sama).
- Given aksi di `../catalog` tanpa field `platforms`, Then `make catalog-validate` gagal.
```bash
make harness SCENARIO=unsupported-platform   # rejected=ok, changes=0
make catalog-validate
```
