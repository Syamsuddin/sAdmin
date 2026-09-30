# 26 — UI Conventions (console)

Rumah tunggal seluruh fakta antarmuka. Nilai di luar tabel token **TERLARANG** — di kode, nilai token hanya hidup di `resources/css/tokens.css` (docs/12_PROJECT_STRUCTURE.md) yang menimpa variabel Tabler.

## Jangkar desain
Tabler 1.x (Bootstrap 5, MIT) sebagai pustaka komponen & ikon, dengan token di bawah menimpa bawaannya. Dua mode: **light** dan **dark** memakai mekanisme Tabler `data-bs-theme` pada `<html>`; default `system` mengikuti `prefers-color-scheme`, override per admin di `admins.theme`.

## Token
| Kategori | Token | Light | Dark |
|---|---|---|---|
| Primer | `--color-primary` / `--color-primary-hover` | `#1D4ED8` / `#1E40AF` | `#2563EB` / `#1D4ED8` |
| Tautan | `--color-link` | `#1D4ED8` | `#60A5FA` |
| Latar | `--color-bg` | `#F8FAFC` | `#0F172A` |
| Permukaan | `--color-surface` | `#FFFFFF` | `#1E293B` |
| Garis | `--color-border` | `#E2E8F0` | `#334155` |
| Teks | `--color-text` / `--color-text-muted` | `#0F172A` / `#475569` | `#F1F5F9` / `#94A3B8` |
| Sukses | `--color-success` | `#15803D` | `#22C55E` |
| Peringatan | `--color-warning` | `#B45309` | `#F59E0B` |
| Bahaya | `--color-danger` | `#B91C1C` | `#EF4444` |
| Info | `--color-info` | `#0369A1` | `#38BDF8` |
| Lencana risiko L0 / L1 / L2 / L3 (latar) | `--risk-l0…l3` | `#475569` / `#0369A1` / `#B45309` / `#B91C1C` | `#94A3B8` / `#38BDF8` / `#F59E0B` / `#EF4444` |
| Teks di atas lencana & tombol berwarna | `--color-on-accent` | `#FFFFFF` | `#0F172A` untuk lencana; `#FFFFFF` untuk tombol primer |
| Huruf UI | `--font-ui` | Inter, fallback `system-ui, sans-serif` | sama |
| Huruf kode & log | `--font-mono` | JetBrains Mono, fallback `ui-monospace, monospace` | sama |
| Skala huruf | `--fs-sm` / `--fs-base` / `--fs-lg` / `--fs-xl` | 12 / 14 / 16 / 20 px | sama |
| Tinggi baris | `--lh` | 1.5 | sama |
| Spasi | `--sp-1…--sp-6` | 4 / 8 / 12 / 16 / 24 / 32 px | sama |
| Kepadatan | tinggi baris tabel / padding kartu | 36 px / 16 px | sama |
| Radius | `--radius-control` / `--radius-card` | 6 / 8 px | sama |
| Bayangan | `--shadow-float` | `0 4px 12px rgba(15,23,42,.12)` — hanya kartu mengambang & modal | `0 4px 12px rgba(0,0,0,.5)` |
| Breakpoint | desktop-first | ≥ 1200 penuh · 768–1199 sidebar ringkas · 375–767 sidebar jadi laci | sama |

Kontras: pasangan teks/latar di atas memenuhi WCAG AA (≥ 4.5:1 teks normal). Font dibundel lokal (tanpa Google Fonts).

## Inventaris komponen
| Komponen | Varian | Rumah file |
|---|---|---|
| Tabel data | biasa, dapat dipilih, dengan filter | `resources/views/components/ui/table.blade.php` |
| Field formulir | teks, pilih, unggah, domain, rujukan server, toggle | `components/ui/field/*.blade.php` |
| Tombol | primer, sekunder, bahaya, ikon | `components/ui/button.blade.php` |
| Tombol passkey | "Setujui dengan passkey" (memicu WebAuthn) | `components/ui/passkey-button.blade.php` |
| Modal konfirmasi | biasa, bahaya (ketik nama sumber daya) | `components/ui/modal.blade.php` |
| Toast | sukses, galat, info | `components/ui/toast.blade.php` |
| Lencana status | per status run/langkah/server/situs | `components/ui/status-badge.blade.php` |
| Lencana risiko | L0–L3, selalu dengan teks "L0"–"L3" | `components/ui/risk-badge.blade.php` |
| Linimasa langkah | untuk run kapsul | `components/ui/timeline.blade.php` |
| Blok log | monospace, rahasia disamarkan, gulir sendiri | `components/ui/log-block.blade.php` |
| Kartu metrik | angka + tren | `components/ui/metric-card.blade.php` |
| Banner peringatan global | kit pemulihan belum dikonfirmasi, audit merah | `components/ui/banner.blade.php` |
| Panel asisten AI | tersembunyi bila AI nonaktif | `app/Livewire/Ai/Panel.php` |
| Empty state | ikon + kalimat + satu ajakan | `components/ui/empty.blade.php` |
| Pengalih tema | system / light / dark | `components/ui/theme-switch.blade.php` |
| Ikon | Tabler Icons outline, SVG disalin apa adanya ke `resources/icons/tabler/` (dijaga tes asal-usul), dirender inline dengan `aria-hidden` | `components/ui/icon.blade.php` |

## Halaman → pola
Navigasi: sidebar kiri + topbar (pemilih server, lonceng peringatan, pengalih tema, akun).

| Halaman | Pola | Livewire |
|---|---|---|
| Masuk (passkey) | autentikasi | `Auth\Login` |
| Instalasi & wawancara awal | formulir (wizard bertahap) | `Onboarding\Wizard` |
| Dasbor armada | dasbor | `Dashboard\Fleet` |
| Server: daftar / detail | daftar+filter / detail | `Servers\Index`, `Servers\Show` |
| Tambah server (token enrolment) | formulir | `Servers\Enroll` |
| Situs: daftar / detail | daftar+filter / detail | `Sites\Index`, `Sites\Show` |
| Katalog kapsul | daftar+filter | `Capsules\Index` |
| Formulir kapsul | formulir | `Capsules\Form` |
| Rencana & persetujuan | detail (langkah, risiko tertinggi, "Memori yang dipertimbangkan", tombol passkey) | `Plans\Review` |
| Eksekusi kapsul | detail (linimasa, status, log ringkas, Batalkan eksekusi) | `Runs\Show` |
| Audit | daftar+filter | `Audit\Index` |
| Peringatan | daftar+filter | `Alerts\Index` |
| Backup & pemulihan | daftar+filter | `Backups\Index` |
| Memori: daftar / sunting | daftar+filter / formulir | `Memory\Index`, `Memory\Edit` |
| Pengaturan (passkey, WireGuard, saksi, kanal, kebijakan AI, anggaran, tema) | formulir | `Settings\*` |

## Empat state wajib (setiap halaman/komponen ber-data)
| State | Aturan |
|---|---|
| Kosong | ikon Tabler + satu kalimat + satu ajakan. Contoh daftar situs: "Belum ada website. Jalankan kapsul *Tambah website*." |
| Memuat | skeleton sesuai bentuk (baris tabel/kartu), bukan spinner layar penuh; `wire:loading` |
| Gagal | kotak `--color-danger` dengan penyebab + tindakan + ID korelasi (format docs/14_ERROR_HANDLING.md) + tombol Coba lagi |
| Sukses | data tampil; aksi berhasil → toast sukses |

## Mikroteks
Bahasa Indonesia formal-netral; istilah teknis lazim tetap Inggris (server block, deploy, rollback, passkey, release). Kata kerja tombol baku: **Simpan, Batal, Jalankan, Setujui dengan passkey, Batalkan eksekusi, Pulihkan, Coba lagi**. Tanggal: `29 Sep 2026, 14.05 WITA` (singkatan dari zona waktu instansi). Angka: pemisah ribuan titik, desimal koma.

## Larangan UI
- Nilai warna/ukuran/font di luar tabel token (dicek `php artisan sadmin:ui-token-scan`).
- Pustaka UI atau set ikon selain Tabler tanpa ADR.
- Gradien, glassmorphism, emoji di antarmuka, animasi dekoratif tanpa fungsi.
- Warna sebagai satu-satunya pembawa makna (lencana risiko & status selalu bertuliskan teks).
- Teks placeholder tersisa ("Lorem", "TODO").
- Komponen yang hanya diuji di satu mode tema.
