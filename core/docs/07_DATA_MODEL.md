# 07 — Data Model (PostgreSQL 16)

Sumber kebenaran skema core. Dokumen lain merujuk, tidak menyalin. State lokal agen: `../edge/docs/07_DATA_MODEL.md`. Istilah: `docs/04_DOMAIN_MODEL.md`. Aturan data sensitif: `docs/21_SECURITY_RULES.md`.

## Konvensi (berlaku semua tabel)
- `id char(26)` ULID, PK (Laravel `HasUlids`). FK ke ULID juga `char(26)`.
- `tenant_id char(26) NOT NULL` FK→`tenants.id` pada semua tabel kecuali `tenants`, `catalog_actions`, `capsule_definitions`. MVP berisi satu tenant.
- `created_at`, `updated_at timestamptz NOT NULL`. Semua waktu disimpan UTC.
- Tanpa hard-delete untuk entitas yang diaudit: pakai `status` / `archived_at`. Pengecualian eksplisit: `memories` (hapus diizinkan, tercatat di audit), `admin_profiles` (hak hapus UU PDP), partisi `metric_samples` (retensi).
- Enum = `text` + `CHECK (… IN (…))`, bukan tipe enum PostgreSQL (migrasi lebih mudah).
- Kolom `jsonb` yang bisa memuat parameter aksi selalu **sudah disamarkan**; nilai rahasia hanya di `secrets`.

## Identitas & akses
### tenants
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id | char(26) | PK | |
| name | text | NOT NULL | |
| created_at / updated_at | timestamptz | NOT NULL | |

### institutions
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK, UNIQUE | satu per tenant |
| name | text | NOT NULL | |
| timezone | text | NOT NULL, default 'Asia/Makassar' | IANA; label tampilan WIB/WITA/WIT diturunkan |
| maintenance_window | jsonb | NOT NULL | `{"days":[…],"start":"22:00","end":"04:00"}` |
| backup_retention | jsonb | NOT NULL | `{"daily":7,"weekly":4,"monthly":6}` |
| recovery_kit_location | text | NULL | NULL = belum dikonfirmasi → banner peringatan |
| recovery_kit_confirmed_at | timestamptz | NULL | |
| console_hostname | text | NOT NULL | RP ID WebAuthn; tak dapat diubah lewat UI (landmine: docs/16_DEBUGGING_GUIDE.md) |
| deployment_mode | text | CHECK IN ('single','fleet'), default 'single' | |
| created_at / updated_at | timestamptz | | |

### admins
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| display_name | text | NOT NULL | nama panggilan |
| email | text | NULL, UNIQUE(tenant_id,email) | hanya untuk notifikasi; bukan login |
| status | text | CHECK IN ('active','disabled') | |
| theme | text | CHECK IN ('system','light','dark'), default 'system' | mode tema console |
| last_login_at | timestamptz | NULL | |
| created_at / updated_at | timestamptz | | |

### authenticators
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| admin_id | char(26) | FK→admins.id, NOT NULL | ≥ 2 aktif per admin (divalidasi di Service) |
| credential_id | bytea | NOT NULL, UNIQUE | |
| public_key_cose | bytea | NOT NULL | hanya kunci publik |
| alg | integer | NOT NULL | -7 (ES256) / -8 (EdDSA) |
| sign_count | bigint | NOT NULL, default 0 | |
| label | text | NOT NULL | mis. "YubiKey kantor" |
| status | text | CHECK IN ('active','revoked') | pencabutan = perubahan roster L3 |
| created_at / updated_at | timestamptz | | |

### wireguard_peers
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| admin_id | char(26) | FK→admins.id | |
| public_key | text | NOT NULL, UNIQUE | kunci privat TIDAK disimpan (QR tampil sekali) |
| address | inet | NOT NULL, UNIQUE | 10.77.0.0/24 |
| label | text | NOT NULL | perangkat |
| status | text | CHECK IN ('active','revoked') | |
| created_at / updated_at | timestamptz | | |

### contacts
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| kind | text | CHECK IN ('witness','emergency') | saksi / kontak darurat |
| name | text | NOT NULL | |
| telegram_chat_id | text | NULL | |
| email | text | NULL | CHECK: minimal satu kanal terisi |
| status | text | CHECK IN ('active','inactive') | perubahan saksi = perubahan kebijakan (L3) |
| created_at / updated_at | timestamptz | | |

### rosters
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| version | integer | NOT NULL, UNIQUE(tenant_id,version) | naik monoton |
| document | jsonb | NOT NULL | format: `../kontrak/KONTRAK.md` |
| document_hash | char(64) | NOT NULL | |
| status | text | CHECK IN ('pending','active','superseded','cancelled') | pending selama jeda 24 jam |
| effective_at | timestamptz | NULL | |
| created_at / updated_at | timestamptz | | |

### policy_bundles
Sama dengan `rosters` (id, tenant_id, version, document, document_hash, status, effective_at, timestamps); `document` = kebijakan agen.

## Armada
### servers
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| name | text | NOT NULL, UNIQUE(tenant_id,name) | |
| hostname | text | NOT NULL | |
| ip | inet | NOT NULL | |
| platform_id | text | NULL | dari agen; MVP hanya 'ubuntu-24.04' diterima |
| os_release | jsonb | NULL | isi `/etc/os-release` |
| ownership | text | CHECK IN ('managed','observed','ignored'), default 'managed' | |
| is_control_plane_host | boolean | NOT NULL, default false | Mode Tunggal |
| status | text | CHECK IN ('enrolling','online','offline','needs_attention','retired') | |
| enroll_token_hash | char(64) | NULL | token sekali pakai 15 menit |
| enroll_token_expires_at | timestamptz | NULL | |
| onboarded_at | timestamptz | NULL | |
| created_at / updated_at | timestamptz | | |

### agents
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| server_id | char(26) | FK→servers.id, UNIQUE | 1:1 |
| agent_version | text | NOT NULL | |
| cert_serial | text | NOT NULL | |
| cert_expires_at | timestamptz | NOT NULL | 7 hari |
| roster_version / policy_version | integer | NOT NULL | yang dilaporkan agen |
| last_seen_at | timestamptz | NULL | dari Heartbeat |
| connection | text | CHECK IN ('connected','disconnected') | |
| audit_head_seq | bigint | NULL | |
| audit_head_hash | char(64) | NULL | |
| created_at / updated_at | timestamptz | | |

### server_inventory_snapshots
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| server_id | char(26) | FK→servers.id | |
| data | jsonb | NOT NULL | keluaran `server.inventory` (fakta hidup untuk tampilan cepat, bukan memori) |
| captured_at | timestamptz | NOT NULL | simpan 30 terakhir per server |

### metric_samples (PARTITION BY RANGE (sampled_at), harian)
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| server_id | char(26) | NOT NULL | tanpa FK (performa partisi) |
| tenant_id | char(26) | NOT NULL | |
| sampled_at | timestamptz | NOT NULL | per menit |
| metric | text | NOT NULL | cpu_pct, mem_pct, disk_pct:<mount>, load1, … |
| value | double precision | NOT NULL | |
PK (server_id, metric, sampled_at). Retensi 30 hari = `DROP` partisi lama oleh `sadmin:metrics-prune`.

## Situs
### sites
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| server_id | char(26) | FK→servers.id | |
| domain | text | NOT NULL, UNIQUE(tenant_id,domain) WHERE status<>'removed' | |
| runtime | text | CHECK IN ('laravel','php') | |
| php_version | text | NOT NULL | '8.3' |
| linux_user | text | NOT NULL | |
| path | text | NOT NULL | `/home/<user>/apps/<app>` |
| dns_managed | boolean | NOT NULL | Cloudflare API atau manual |
| ownership | text | CHECK IN ('managed','observed','ignored') | |
| status | text | CHECK IN ('creating','active','failed','archived','removed') | |
| archived_at | timestamptz | NULL | mulai masa tunggu 7 hari |
| created_at / updated_at | timestamptz | | |

### site_sources
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| site_id | char(26) | FK→sites.id, UNIQUE | |
| kind | text | CHECK IN ('github','zip') | |
| repo | text | NULL | `owner/name`; wajib bila github |
| branch | text | NULL | |
| deploy_key_secret_id | char(26) | FK→secrets.id, NULL | kunci privat di brankas |
| created_at / updated_at | timestamptz | | |

### releases
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| site_id | char(26) | FK→sites.id | |
| ref | text | NOT NULL | commit sha / sha256 ZIP |
| dir_name | text | NOT NULL | `<ts>-<sha7>` |
| status | text | CHECK IN ('building','ready','current','previous','pruned','failed') | ≤ 5 non-pruned |
| run_id | char(26) | FK→capsule_runs.id | |
| created_at / updated_at | timestamptz | | |

### app_databases
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| site_id | char(26) | FK→sites.id, UNIQUE | |
| engine | text | CHECK IN ('mariadb') | |
| db_name / db_user | text | NOT NULL | |
| password_secret_id | char(26) | FK→secrets.id | |
| status | text | CHECK IN ('active','archived','dropped') | |
| created_at / updated_at | timestamptz | | |

### certificates
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| site_id | char(26) | FK→sites.id | |
| domains | text[] | NOT NULL | |
| issuer | text | NOT NULL | letsencrypt |
| expires_at | timestamptz | NOT NULL | peringatan < 14 hari |
| status | text | CHECK IN ('active','revoked','expired') | |
| created_at / updated_at | timestamptz | | |

### env_sets
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| site_id | char(26) | FK→sites.id | |
| keys | text[] | NOT NULL | nama kunci saja |
| secret_id | char(26) | FK→secrets.id | isi `.env` utuh terenkripsi |
| version | integer | NOT NULL | |
| created_at / updated_at | timestamptz | | |

## Eksekusi
### catalog_actions (cermin baca-saja dari `../catalog/*.yaml`)
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| key | text | PK(key,version) | |
| version | integer | | |
| definition | jsonb | NOT NULL | |
| definition_hash | char(64) | NOT NULL | |
| deprecated | boolean | NOT NULL, default false | |
| synced_at | timestamptz | NOT NULL | oleh `sadmin:catalog-sync`; YAML menang |

### capsule_definitions
Sama pola dengan `catalog_actions` (PK capsule_key+version, definition, definition_hash, deprecated, synced_at), sumber `../capsules/*.yaml`.

### plans
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | = `plan_id` di kontrak |
| body | jsonb | NOT NULL | `Plan.body` (placeholder rahasia, tanpa nilai) |
| plan_hash | char(64) | NOT NULL, UNIQUE | SHA-256 JCS(body) = tantangan WebAuthn |
| risk_max | text | CHECK IN ('L0','L1','L2','L3') | |
| expires_at | timestamptz | NOT NULL | ≤ 24 jam |
| created_at | timestamptz | NOT NULL | immutable setelah insert (trigger tolak UPDATE body/plan_hash) |

### capsule_runs
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| capsule_key | text | NOT NULL | |
| capsule_version | integer | NOT NULL | dipatok |
| inputs | jsonb | NOT NULL | disamarkan |
| plan_id | char(26) | FK→plans.id, NULL | NULL sebelum rencana dibuat |
| risk | text | CHECK IN ('L0','L1','L2','L3') | |
| status | text | CHECK IN ('planned','awaiting_approval','delayed','running','waiting','succeeded','compensating','compensated','needs_attention','cancelled') | transisi: docs/06_BUSINESS_PROCESS.md |
| created_by | char(26) | FK→admins.id | |
| approved_at | timestamptz | NULL | |
| delay_until | timestamptz | NULL | L3 |
| wait_condition | text | NULL | |
| next_check_at | timestamptz | NULL | indeks untuk runner |
| wait_deadline | timestamptz | NULL | |
| succeeded_at / finished_at | timestamptz | NULL | metrik 00 |
| created_at / updated_at | timestamptz | | |
Indeks: (status, next_check_at) untuk `SKIP LOCKED`.

### step_runs
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| run_id | char(26) | FK→capsule_runs.id | |
| index | smallint | NOT NULL, UNIQUE(run_id,index) | |
| action_key / action_version | text / integer | NOT NULL | dipatok |
| target_server_id | char(26) | FK→servers.id | |
| params | jsonb | NOT NULL | disamarkan |
| idempotency_key | text | NOT NULL, UNIQUE | `{run_id}:{index}:{phase}` fase apply |
| status | text | CHECK IN ('pending','dispatched','succeeded','skipped','failed','compensating','compensated','compensation_failed') | |
| attempt | smallint | NOT NULL, default 0 | ≤ 5 |
| result | jsonb | NULL | `Result` disamarkan |
| compensation_status | text | NULL | |
| created_at / updated_at | timestamptz | | |

### action_envelopes
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | = `envelope_id` |
| step_run_id | char(26) | FK→step_runs.id, NULL | NULL untuk aksi L0/L1 langsung |
| phase | text | CHECK IN ('apply','compensate') | |
| action_key / action_version | text / integer | NOT NULL | |
| target_server_id | char(26) | FK→servers.id | |
| params_hash | char(64) | NOT NULL | |
| risk | text | CHECK IN ('L0','L1','L2','L3') | |
| nonce | text | NOT NULL, UNIQUE | |
| expires_at | timestamptz | NOT NULL | ≤ 10 menit |
| plan_hash | char(64) | NULL | |
| step_index | smallint | NULL | |
| sent_at | timestamptz | NULL | |
| created_at | timestamptz | NOT NULL | |

### approvals
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| plan_id | char(26) | FK→plans.id, NULL | persetujuan rencana |
| roster_id / policy_bundle_id | char(26) | FK, NULL | persetujuan roster/kebijakan; tepat satu dari tiga terisi (CHECK) |
| admin_id | char(26) | FK→admins.id | |
| authenticator_id | char(26) | FK→authenticators.id | |
| webauthn_assertion | jsonb | NOT NULL | authenticator_data, client_data_json, signature |
| signed_hash | char(64) | NOT NULL | |
| created_at | timestamptz | NOT NULL | append-only |

### resource_locks
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| resource_key | text | PK | pola: `../catalog/CATALOG.md` |
| tenant_id | char(26) | NOT NULL | |
| run_id | char(26) | FK→capsule_runs.id | |
| step_index | smallint | NOT NULL | |
| acquired_at | timestamptz | NOT NULL | |

### cancellations
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| run_id | char(26) | FK→capsule_runs.id, NULL | |
| roster_id / policy_bundle_id | char(26) | FK, NULL | |
| by_kind | text | CHECK IN ('admin','witness','local_root') | |
| by_ref | char(26) | NULL | admin_id / contact_id |
| channel | text | CHECK IN ('console','telegram','email_link','agent_cli') | |
| created_at | timestamptz | NOT NULL | |

## Audit
### audit_entries (append-only)
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| seq | bigint | PK | satu rantai global (MVP satu tenant); ditulis di dalam transaksi ber-`pg_advisory_xact_lock` agar tanpa celah & tanpa cabang |
| tenant_id | char(26) | NOT NULL | |
| prev_hash | char(64) | NOT NULL | genesis = 64 nol |
| hash | char(64) | NOT NULL, UNIQUE | SHA-256(prev_hash ∥ JCS(entri tanpa hash)) |
| occurred_at | timestamptz | NOT NULL | |
| actor_type | text | CHECK IN ('admin','witness','runner','agent','system','ai','local_root') | |
| actor_id | text | NULL | |
| action_key | text | NOT NULL | juga `console.login`, `memory.update`, `ai.policy_change`, … |
| target | text | NULL | resource key |
| params_redacted | jsonb | NULL | |
| outcome | text | CHECK IN ('ok','rejected','failed','cancelled') | |
| envelope_ref | char(26) | NULL | |
| emergency_local | boolean | NOT NULL, default false | |
Trigger menolak `UPDATE` dan `DELETE`. Hak `UPDATE/DELETE/TRUNCATE` dicabut dari role aplikasi.

### audit_checkpoints
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| seq | bigint | PK, CHECK ≥ 1 | seq entri terakhir yang dicakup; tanpa FK (ADR 0004 §2.3) |
| tenant_id | char(26) | NOT NULL | |
| hash | char(64) | NOT NULL, CHECK hex huruf kecil | `hash` entri ber-`seq` itu |
| signature | text | NOT NULL, CHECK base64 88 karakter | Ed25519 kunci audit; isi yang ditandatangani: `../kontrak/KONTRAK.md` §3 |
| anchored_to | text[] | NOT NULL, CHECK subset | subset {'agents','offsite','digest'}; `{}` saat dibuat |
| created_at | timestamptz(6) | NOT NULL | ikut ditandatangani; tiap 15 menit atau 100 entri |
Trigger menolak `DELETE`/`TRUNCATE` dan `UPDATE` selain penambahan `anchored_to` (ADR 0004).

### agent_audit_receipts
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| server_id | char(26) | FK→servers.id | |
| agent_seq | bigint | NOT NULL, UNIQUE(server_id,agent_seq) | |
| entry_hash | char(64) | NOT NULL | |
| envelope_ref | char(26) | NULL | |
| emergency_local | boolean | NOT NULL | |
| reconciled | boolean | NOT NULL, default false | |
| created_at | timestamptz | NOT NULL | |

## Rahasia
### secrets
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| purpose | text | CHECK IN ('db_password','env','deploy_key','api_token','telegram_token','smtp','upload','service_key','audit_key','ca_key','gateway_hmac','ai_api_key') | |
| ciphertext | bytea | NOT NULL | XChaCha20-Poly1305 (sodium) dengan kunci data |
| nonce | bytea | NOT NULL | |
| key_wrap_id | char(26) | FK→key_wraps.id, UNIQUE | satu kunci data per rahasia (1:1, ADR 0003) |
| status | text | CHECK IN ('active','rotated','destroyed') | destroyed = ciphertext ditimpa nol, baris tetap |
| created_at / updated_at | timestamptz | | |
Indeks unik parsial `secrets_one_active_audit_key (tenant_id) WHERE purpose='audit_key' AND status='active'`: tepat satu kunci audit aktif per tenant (ADR 0004).

### key_wraps
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| wrapped_dek | bytea | NOT NULL | kunci data dibungkus kunci induk: nonce 24 B ∥ ciphertext (72 B; format & AAD: ADR 0003) |
| master_key_version | integer | NOT NULL | |
| created_at | timestamptz | NOT NULL | |

## Backup
| Tabel | Kolom kunci | Catatan |
|---|---|---|
| backup_policies | id, tenant_id, scope CHECK IN ('site','server','sadmin'), scope_ref, repository_url, repository_secret_id FK→secrets, schedule (text, OnCalendar systemd), retention jsonb, status | |
| backup_snapshots | id, tenant_id, policy_id FK, snapshot_id (restic), size_bytes bigint, taken_at, status CHECK IN ('ok','failed') | dilaporkan agen |
| restore_tests | id, tenant_id, snapshot_id FK, result CHECK IN ('ok','failed'), detail jsonb, tested_at | |

## Notifikasi
| Tabel | Kolom kunci | Catatan |
|---|---|---|
| notification_channels | id, tenant_id, kind CHECK IN ('telegram','smtp'), config jsonb objek (tanpa rahasia; isi per jenis: docs/adr/0005 §2.5), secret_id FK→secrets (purpose `telegram_token`/`smtp`), status CHECK IN ('active','inactive'), timestamps | dikirim juga ke agen sebagai bagian kebijakan (M2) |
| alert_rules | id, tenant_id, kind CHECK IN (disk_low, mem_high, service_down, cert_expiring, backup_failed, agent_disconnected, audit_mismatch), threshold jsonb objek, enabled bool, timestamps; UNIQUE(tenant_id,kind); CHECK `kind <> 'audit_mismatch' OR enabled` | integritas tak bisa dinonaktifkan |
| alerts | id, tenant_id, rule_id FK NULL, server_id NULL (FK→servers ditambahkan bersama tabel `servers`), severity CHECK IN ('info','warning','critical'), title, detail jsonb objek, status CHECK IN ('open','acknowledged','resolved'), dedup_key text NULL, opened_at, notified_at NULL, resolved_at NULL (terisi ⇔ `resolved`), timestamps | indeks unik parsial `alerts_unresolved_dedup` (tenant_id, dedup_key) selama belum `resolved`; `notified_at` = kanal pertama yang berhasil (docs/adr/0005 §2.2–2.3) |

## Memori
### memories
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| id, tenant_id | char(26) | PK; FK | |
| scope | text | CHECK IN ('institution','server','site') | |
| scope_ref | char(26) | NULL | server_id/site_id |
| type | text | CHECK IN ('fact','decision','incident','preference','constraint') | |
| content | text | NOT NULL | dilarang berisi rahasia (validasi pola) |
| reason | text | NULL | |
| source | text | CHECK IN ('admin_stated','observed','ai_proposed_confirmed') | |
| review_at | date | NULL | |
| verify_rule | jsonb | NULL | dipakai Fase 3 |
| status | text | CHECK IN ('active','inactive') | |
| created_by | text | NOT NULL | admin_id / 'system' |
| created_at / updated_at | timestamptz | | hapus diizinkan; setiap ubah/hapus menulis audit |

### memory_links
id, tenant_id, memory_id FK→memories ON DELETE CASCADE, link_type CHECK IN ('server','site','run','audit','memory'), link_ref text, created_at.

### admin_profiles
| Kolom | Tipe | Constraint | Catatan |
|---|---|---|---|
| admin_id | char(26) | PK, FK→admins.id | |
| tenant_id | char(26) | NOT NULL | |
| nickname | text | NULL | |
| role_title | text | NULL | |
| linux_skill | text | CHECK IN ('beginner','intermediate','expert') NULL | |
| language_style | text | NULL | |
| notify_channels | text[] | NULL | |
| quiet_hours | jsonb | NULL | |
| created_at / updated_at | timestamptz | | tanpa NIK/tanggal lahir/alamat; dapat dihapus pemilik |

## AI
| Tabel | Kolom kunci | Catatan |
|---|---|---|
| ai_provider_configs | id, tenant_id, provider CHECK IN ('none','cloud','ollama'), model text, endpoint text, api_key_secret_id FK→secrets NULL, enabled bool | default `none` |
| data_flow_policies | id, tenant_id, data_class CHECK IN ('logs','config','metadata','memory'), mode CHECK IN ('cloud','local_only','never'), UNIQUE(tenant_id,data_class) | perubahan diaudit |
| ai_usage_ledger | id, tenant_id, feature text, month date, tokens_in bigint, tokens_out bigint, quota bigint | peringatan 80%; berhenti di 100% |
