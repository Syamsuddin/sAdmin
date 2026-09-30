# CATALOG — Katalog aksi & level risiko

Rumah tunggal definisi aksi (identitas, skema parameter, risiko, sumber daya, platform) dan makna level risiko, untuk core (menyusun rencana, formulir) dan agen (kebijakan, verifikasi). Mulai M1, satu berkas per aksi: `catalog/<kelompok>/<key>.yaml`; berkas YAML menang atas tabel di sini. Implementasi `check/apply/verify/compensate` hidup di `edge/internal/actions/` (lihat `edge/docs/12_PROJECT_STRUCTURE.md`).

## 1. Level risiko
| Level | Syarat di agen | Contoh |
|---|---|---|
| L0 | Tanda tangan layanan core | baca inventaris, metrik, log tersamarkan, status |
| L1 | Tanda tangan layanan; batas laju agen 30 aksi/menit | restart layanan, jalankan backup, `nginx.reload` |
| L2 | + 1 tanda tangan passkey admin atas `Plan` | ubah konfigurasi, SSH/firewall bertimer, buat/arsipkan situs, deploy produksi |
| L3 | + 1 tanda tangan passkey + jeda (default 1800 dtk, rentang 900–7200) + notifikasi **dari agen** ke admin & saksi; roster/kebijakan: jeda 86400 dtk | hapus database, restore menimpa, migrasi destruktif, perubahan roster/kebijakan |

Aturan: risiko kapsul = risiko langkah tertinggi. Control plane tidak dapat menurunkan risiko; kebijakan tersemat di agen yang menentukan. Kebijakan dapat menaikkan L3 menjadi dua tanda tangan bila ada admin kedua. Menurunkan level default = operasi bergerbang manusia + ADR.

## 2. Format definisi aksi (YAML)
| Kunci | Wajib | Isi |
|---|---|---|
| `key` | ya | `kelompok.nama`, mis. `db.create_with_user` |
| `version` | ya | integer; naik saat perilaku berubah; versi lama boleh deprecate, tak boleh dihapus |
| `risk` | ya | `L0`–`L3`; boleh `risk_rules` untuk eskalasi (mis. `app.migrate` → L3 bila destruktif) |
| `platforms` | ya | daftar `platform_id` yang lulus harness penuh; MVP hanya `[ubuntu-24.04]` |
| `params` | ya | JSON Schema; field rahasia ditandai `x-secret: true` |
| `resources` | ya | pola kunci sumber daya untuk kunci, mis. `site:{domain}`, `server:{server}/nginx` |
| `compensate` | ya kecuali L0 | nama aksi pembalik atau `self` (aksi punya `Compensate` sendiri) |
| `timed_confirm_s` | opsional | pembatalan bertimer (mis. 300); wajib untuk `ssh.harden`, `firewall.apply` |
| `errors` | ya | daftar kode galat aksi + kelas `transient`/`permanent` |
| `output` | opsional | JSON Schema keluaran; field rahasia `x-secret` |

`make catalog-validate` (README root) menolak: kunci wajib hilang, `platforms` kosong, aksi non-L0 tanpa `compensate`, `version` turun, kunci ganda.

## 3. Aksi MVP
Pola sumber daya: `srv` = `server:{server}`.

| Aksi | Risiko | Pembalik | Sumber daya | Catatan |
|---|---|---|---|---|
| `server.inventory`, `server.metrics`, `service.status`, `log.tail_redacted`, `site.status`, `db.list`, `cert.status`, `firewall.status`, `backup.list` | L0 | — | — | baca saja |
| `os.set_timezone` | L2 | self | `srv/timezone` | |
| `user.create_admin` | L2 | self | `srv/user:{name}` | |
| `ssh.harden` | L2 | self | `srv/ssh` | `timed_confirm_s: 300` |
| `firewall.apply` | L2 | self | `srv/firewall` | `timed_confirm_s: 300`; aturan dasar selalu mengizinkan keluar ke gateway 8443 |
| `crowdsec.install` | L2 | self | `srv/crowdsec` | |
| `swap.ensure` | L2 | self | `srv/swap` | |
| `apt.configure_unattended` | L2 | self | `srv/apt` | |
| `apt.upgrade_security` | L1 | — (tak dapat dibalik; tidak dipakai di kapsul ber-kompensasi) | `srv/apt` | pengecualian terdokumentasi: L1 tanpa compensate |
| `timer.install` | L2 | self | `srv/timer:{name}` | |
| `php.install_version` | L2 | self (hanya bila dipasang oleh run ini) | `srv/php:{version}` | dilewati bila sudah ada |
| `phpfpm.pool_create` / `phpfpm.pool_remove` | L2 | saling | `srv/phpfpm:{version}/{pool}` | |
| `linux.site_user_create` / `linux.site_user_remove` | L2 | saling | `srv/user:{user}` | |
| `nginx.server_block_create` / `nginx.server_block_remove` | L2 | saling | `srv/nginx:{domain}` | berkas di `/etc/nginx/sadmin.d/` |
| `nginx.reload` | L1 | — | `srv/nginx` | berurutan per server; `nginx -t` wajib hijau dulu |
| `service.restart` | L1 | — | `srv/service:{name}` | |
| `dns.record_ensure` / `dns.record_remove` | L2 | saling | `dns:{fqdn}` | Cloudflare API; dilewati bila DNS tak dikelola |
| `ssl.issue` / `ssl.revoke` | L2 | saling | `srv/cert:{domain}` | certbot; `wait_for: dns.points_to_server` |
| `db.create_with_user` | L2 | `db.drop_with_user` | `srv/db:{name}` | password dibangkitkan core sebagai rahasia |
| `db.drop_with_user` | L3 | — | `srv/db:{name}` | dump otomatis sebelum hapus |
| `db.dump` | L1 | — | `srv/db:{name}` | |
| `source.fetch_git` / `source.extract_zip` | L1 | self (hapus direktori rilis) | `site:{domain}/release:{id}` | ZIP: tolak path traversal, symlink keluar, > `max_mb` |
| `app.write_env` | L2 | self (pulihkan `.env` sebelumnya) | `site:{domain}/env` | |
| `app.build` | L1 | self | `site:{domain}/release:{id}` | jalan sebagai user situs via `systemd-run` dengan batas CPU/memori/waktu |
| `app.migrate` | L2 (L3 bila terdeteksi destruktif) | self bila migrasi punya `down`, selain itu dump sebelum | `site:{domain}/db` | |
| `release.switch` / `release.rollback` | L2 | saling | `site:{domain}/current` | simpan 5 rilis |
| `release.prune` | L1 | — | `site:{domain}/releases` | |
| `backup.configure` | L2 | self | `srv/backup:{target}` | restic + timer |
| `backup.run` | L1 | — | `srv/backup:{target}` | |
| `backup.restore` | L3 | — | target restore | dump/snapshot kondisi sekarang dulu |
| `agent.update` | L2 | self (biner lama kembali bila sinyal hidup gagal) | `srv/agent` | biner harus bertanda tangan rilis |
| `sadmin.backup_run` | L1 | — | `sadmin/backup` | |
