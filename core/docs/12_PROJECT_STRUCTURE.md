# 12 — Project Structure (paket core)

Pemilik struktur folder & penamaan paket core. Tata letak monorepo: `../README.md`.

## Pohon penting
```
core/
├── app/
│   ├── Domain/<Modul>/            # Identity, Fleet, Sites, Catalog, Execution, Audit, Vault, Backup, Alerts, Memory, Ai, Onboarding
│   │   ├── Actions/               # satu kasus penggunaan per kelas: CreatePlan, ApprovePlan, ...
│   │   ├── Services/              # logika bersama modul
│   │   └── Data/                  # DTO bertipe (readonly class)
│   ├── Domain/Execution/Dispatch/ # SATU-SATUNYA pengirim amplop
│   ├── Domain/Execution/Runner/   # loop runner, state machine run/langkah
│   ├── Infrastructure/{Gateway,Vault,Jcs,Notify,Ai,WebAuthn}/
│   ├── Livewire/<Halaman>/        # komponen halaman (lihat docs/26_UI_CONVENTIONS.md)
│   ├── Models/                    # Eloquent
│   └── Console/Commands/          # sadmin:* artisan
├── resources/views/components/ui/ # komponen Blade UI (inventaris: docs/26)
├── resources/css/tokens.css       # SATU-SATUNYA rumah nilai token di kode
├── database/migrations/
├── routes/{web.php,internal.php}  # internal.php = endpoint Unix socket dari gateway
├── tests/{Unit,Feature,Contract}/
└── docs/                          # paket VCBD ini
../deploy/                         # install.sh, unit systemd, template Nginx (milik paket core)
```

## Konvensi penamaan
| Hal | Konvensi | Contoh |
|---|---|---|
| Action | Kata kerja + objek, PascalCase | `ApprovePlan`, `DispatchStep` |
| Model | Tunggal PascalCase; tabel jamak snake_case | `CapsuleRun` → `capsule_runs` |
| Perintah artisan | prefix `sadmin:` kebab-case | `sadmin:audit-verify` |
| Komponen Livewire | `<Halaman>\<Bagian>` | `Runs\Timeline` |
| Kunci aksi/kapsul | persis seperti di `../catalog` / `../capsules` | `site.create` |
| Tes | `<Hal>Test`; grup `redaction`, `contract` | `ApprovePlanTest` |

## Lokasi jenis kode
Logika domain di `Actions/Services`, bukan di komponen Livewire, controller, atau model. Akses agen hanya lewat `Dispatch`. Nilai rahasia hanya lewat `Infrastructure/Vault`. Nama field protokol hanya dari `../kontrak`; nama/skema aksi hanya dari tabel cermin katalog — dilarang ditulis ulang sebagai konstanta PHP.
