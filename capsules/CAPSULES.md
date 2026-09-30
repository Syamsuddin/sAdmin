# CAPSULES — Resep kapsul

Rumah tunggal resep kapsul (pertanyaan, pemeriksaan awal, langkah, pembalik). Mulai M2, satu berkas per kapsul: `capsules/<key>.yaml`; YAML menang atas berkas ini. Mesin yang menjalankannya: `core/docs/06_BUSINESS_PROCESS.md` (status & aturan eksekusi). Aksi yang dirujuk: `catalog/CATALOG.md`.

## 1. Format resep
| Kunci | Isi |
|---|---|
| `capsule`, `version` | kunci + integer versi (run mematok versi saat mulai) |
| `risk` | dihitung = maksimum risiko langkah; `make catalog-validate` menolak bila nilai tertulis lebih rendah |
| `platforms` | irisan `platforms` semua aksinya |
| `inputs` | pertanyaan minimum: `type` (`domain`, `enum`, `string`, `upload`, `server_ref`), `required`, `default`, `when` |
| `detect` | deteksi otomatis sebelum rencana (mis. `framework`, `php_version`, `needs_database`, `env_keys`) |
| `preflight` | pemeriksaan read-only sebelum rencana; gagal = tidak ada rencana, tidak ada perubahan |
| `steps` | urutan aksi; per langkah opsional `when`, `undo`, `wait_for` |
| `report` | isi laporan akhir; `db_credentials_once` = tampil sekali lalu hanya di brankas |
| `inverse` | kapsul pembalik yang ditawarkan tombol di laporan akhir |

Kondisi tunggu (`wait_for`) MVP: `dns.points_to_server`, `agent.connected`, `ssh.confirmed`. Batas default 48 jam.

## 2. Kapsul MVP
| Kapsul | Pertanyaan | Risiko | Pembalik |
|---|---|---|---|
| `server.onboard` | nama server, IP/hostname (akses awal = admin sendiri menjalankan perintah enrolment sebagai root) | L2 | `server.retire` (pasca-MVP) |
| `site.create` | domain, sumber (github/zip), branch, server | L2 | `site.archive` |
| `site.redeploy` | situs, branch/commit (default terbaru) | L2 | `release.rollback` |
| `site.archive` | situs | L2; penghapusan sumber daya setelah masa tunggu 7 hari = L3 | — |
| `sadmin.backup` | — (terjadwal harian, aktif sejak instalasi) | L1 | — |
| `sadmin.restore` | lokasi backup, kunci pemulihan | dijalankan lokal oleh pemegang root, di luar runner | — |

## 3. `site.create` v1
```yaml
capsule: site.create
version: 1
risk: L2
platforms: [ubuntu-24.04]
inputs:
  domain:  { type: domain, required: true }
  source:  { type: enum, options: [github, zip] }
  repo:    { type: string, when: "source == 'github'" }
  branch:  { type: string, default: main, when: "source == 'github'" }
  archive: { type: upload, when: "source == 'zip'", max_mb: 200 }
  server:  { type: server_ref, default: primary }
detect: [framework, php_version, needs_database, env_keys]
preflight: [platform.supported, domain.not_in_use, disk.free_min_gb:2, php.version_available, zip.safe]
steps:
  - dns.record_ensure          # undo: dns.record_remove; dilewati bila DNS tak dikelola -> waiting
  - linux.site_user_create     # undo: linux.site_user_remove
  - php.install_version        # dilewati bila sudah ada
  - phpfpm.pool_create         # undo: phpfpm.pool_remove
  - source.fetch_git | source.extract_zip
  - db.create_with_user        # when: needs_database; undo: db.drop_with_user
  - app.write_env
  - app.build
  - app.migrate
  - release.switch
  - nginx.server_block_create  # undo: nginx.server_block_remove
  - nginx.reload
  - ssl.issue                  # wait_for: dns.points_to_server
  - backup.configure
report: [url, db_credentials_once]
inverse: site.archive
```
Tata letak situs: `/home/<user-situs>/apps/<app>/{releases/<ts>-<sha7>, shared/, current -> releases/…}`; vhost menunjuk `current/public`; `release.prune` menyisakan 5 rilis. Preset MVP: Laravel dan PHP native.

## 4. `server.onboard` v1 (urutan langkah)
Core **tidak pernah** ber-SSH (P1). Akses awal = admin sendiri:
1. Console membuat run dan token enrolment sekali pakai (berlaku 15 menit), lalu menampilkan tiga perintah: unduh biner agen rilis bertanda tangan, cek `sha256sum -c` terhadap hash yang tampil, lalu `sudo sadmin-agent enroll --gateway <host>:8443 --ca-sha256 <sidik-jari-CA> --token <token>`.
2. Langkah pertama run: `wait_for: agent.connected` (batas 30 menit, bukan 48 jam). Agen mengirim CSR, menerima sertifikat, roster, dan kebijakan; sidik jari roster tampil di terminal dan di console — admin mencocokkannya lalu menyetujui rencana dengan passkey.
3. Langkah berikutnya: `os.set_timezone` → `user.create_admin` → `ssh.harden` (bertimer; `PermitRootLogin no`, `PasswordAuthentication no` — ini sekaligus mencabut akses awal) → `firewall.apply` (bertimer) → `crowdsec.install` → `swap.ensure` → `apt.configure_unattended` → `timer.install` (certbot, restic, logrotate, patch) → `backup.configure`.

Konfirmasi bertimer: admin membuka sesi SSH **baru** sebagai user admin lalu menjalankan `sadmin-agent confirm <kode>` (kode tampil di console). Host sAdmin sendiri di-enrol lokal oleh `deploy/install.sh`.
