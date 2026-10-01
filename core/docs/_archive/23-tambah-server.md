# Arsip AC-17 Tambah server & inventaris (F-02, sisi core) — diterima 2026-10-02

Kriteria ini sudah terpenuhi dan tesnya hijau, sehingga dipindah dari `docs/23_ACCEPTANCE_CRITERIA.md` (aturan emas #6 INDEX). Penegakannya kini ada di suite tes; mengubah perilaku di bawah ini berarti mengubah tes penegaknya lewat docs/22.

Diterima lewat slice M1 F-02c (tambah server & token enrolment), setelah review adversarial (docs/22). Penukaran token lewat `Enroll`→`EnrollAccept`, detail server (`Servers\Show`), dan data inventaris dari agen bukan bagian kriteria ini. Bagian-bagian itu menyusul di slice enrolment dan inventaris berikutnya, sedangkan AC-02 (agen `connected` ≤ 30 detik) tetap milik edge.

## AC-17 Tambah server & inventaris (F-02, sisi core)
- Given CA internal dan `SADMIN_GATEWAY_HOST` tersedia, When admin menyimpan formulir *Tambah server* (nama, hostname, alamat IP yang sah), Then server `enrolling` tercipta dan console menampilkan sekali perintah `sudo sadmin-agent enroll --gateway <host>:8443 --ca-sha256 <pin> --token <token>`; token 256 bit berlaku 15 menit, basis data hanya menyimpan SHA-256-nya, dan audit mencatat `server.register` + `server.enroll_token_issue` tanpa token.
- Given server masih `enrolling`, When admin menerbitkan token baru, Then token lama langsung tak berlaku; server berstatus lain atau milik tenant lain ditolak tanpa perubahan.
- Given masukan tak sah (nama bukan label DNS huruf kecil, hostname bukan nama host DNS, alamat IP loopback/tak spesifik/link-local/multicast) atau nama yang pernah dipakai, When disimpan, Then pesan setiap field yang salah tampil sekaligus dan tidak ada server maupun audit tertulis.
- Given tiga server belum dipensiunkan (Mode Tunggal, docs/02), When admin menambah server keempat, Then ditolak; tanpa CA, gateway, atau brankas (atau saat batas tercapai), formulir tak tampil dan state Gagal menjelaskan tindakannya; *Coba lagi* memeriksa ulang prasyarat.
- Given daftar server, When halaman dibuka, Then empat state docs/26 terpenuhi dan setiap status tampil sebagai teks.
```bash
php artisan test --filter='RegisterServer|IssueEnrollmentToken|ServerSchema|ServersPage|EnrollServerPage'   # Tests: … passed
php artisan test --group=redaction   # token tak muncul di audit/log
```
