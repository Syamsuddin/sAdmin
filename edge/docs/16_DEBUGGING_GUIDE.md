# 16 — Debugging Guide (agen & gateway)

Log: docs/15_OBSERVABILITY.md. Perintah: docs/11_COMMANDS.md. Galat: docs/14_ERROR_HANDLING.md. Sisi core: `../core/docs/16_DEBUGGING_GUIDE.md`.

| Gejala | Langkah |
|---|---|
| Agen tak terhubung | `sudo sadmin-agent status`; `journalctl -u sadmin-agent -n 100`; cek egress ke `<host>:8443`; cek umur sertifikat klien |
| Semua amplop `E_SIG_SERVICE` | `service_pubkey` di `trust/keys.json` ≠ kunci layanan core (pemulihan dengan kunci baru?) |
| `E_SIG_PASSKEY` padahal passkey benar | `roster_version` agen vs core; RP ID/origin di roster vs hostname console; flag UV |
| `E_PLAN_MISMATCH` | jalankan `go test ./internal/protocol/... -run Contract`; bandingkan JCS PHP vs Go untuk `plan.body` yang ditolak (ada di audit lokal) |
| Aksi terulang dua kali | periksa bucket `journal` untuk `idempotency_key`; pastikan hasil ditulis ke jurnal sebelum `Result` |
| Timer rollback tak jalan setelah reboot | bucket `timers` dimuat saat start? cek log `timer restored` |

## Jebakan proyek
- **Jangan ulang buta.** Hasil tak diketahui → `StatusQuery`/`check`; mengulang `apply` non-idempoten merusak server.
- **Audit `+a`.** Logrotate biasa gagal pada berkas `chattr +a`; rotasi = buka berkas baru. Jangan pernah `chattr -a` di kode.
- **Firewall memutus diri sendiri.** Aturan dasar `firewall.apply` wajib selalu mengizinkan keluar ke gateway 8443, DNS, NTP, repositori paket, dan (di host sAdmin) masuk 8443 + UDP WireGuard.
- **Timer harus tahan restart.** Timer & jeda hidup di bbolt, bukan hanya di goroutine.
- **Risiko dari kebijakan.** Jangan pernah membaca `risk` dari amplop untuk mengambil keputusan.
- **Distro di satu tempat.** Kalau tergoda menulis path `/etc/php/8.3/...` di dalam aksi, pindahkan ke `platform/ubuntu2404`.
- **Kebijakan baru butuh 24 jam.** Aksi baru di rilis agen belum bisa dipakai sampai `PolicyBundle` berlaku.
