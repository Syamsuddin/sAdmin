# Arsip AC-03 Audit (F-04) — diterima 2026-10-01

Kriteria ini sudah terpenuhi dan tesnya hijau, sehingga dipindah dari `docs/23_ACCEPTANCE_CRITERIA.md` (aturan emas #6 INDEX). Penegakannya kini ada di suite tes; mengubah perilaku di bawah ini berarti mengubah tes penegaknya lewat docs/22.

Diterima lewat tiga slice M1: F-04 rantai audit (ADR 0001), F-04b checkpoint audit bertanda tangan (ADR 0004), dan F-04c alert `audit_mismatch` (ADR 0005). Jangkar audit ke agen, offsite, dan digest harian (bagian F-04 sisi edge) tidak termasuk kriteria core ini dan menunggu paket edge.

## AC-03 Audit (F-04)
- Given rantai audit berisi ≥ 200 entri, When `sadmin audit verify`, Then exit 0.
- Given satu `audit_entries.params_redacted` diubah via SQL superuser, When verify, Then exit ≠ 0 dan alert `audit_mismatch` critical terkirim ≤ 60 detik.
- Given checkpoint bertanda tangan kunci audit sudah ada (F-04b Checkpoint audit), When ujung rantai dipotong atau rantai ditulis ulang dari suatu titik dengan hash dihitung ulang lewat SQL superuser, Then verify exit ≠ 0 dengan `audit_mismatch` yang menyebut checkpoint yang dilanggar, dan checkpoint baru tak pernah ditandatangani di atas rantai yang rusak (ADR 0004).
```bash
php artisan test --filter=AuditChainTamperTest   # Tests: … passed
php artisan test --filter='AuditCheckpointTamperTest|CreateAuditCheckpointTest|InitializeAuditKeyTest'   # Tests: … passed
php artisan test --testsuite=Contract            # termasuk vektor ../kontrak/vectors/checkpoint
php artisan test --filter='AuditMismatchAlertTest|RaiseIntegrityAlertTest|NotifierTest|NotificationChannelCommandsTest|NotifyRedactionTest|AlertSchemaTest'   # butir 2: alert ≤ 60 detik (ADR 0005)
```

## Bukti penerimaan (2026-10-01)
| Perintah | Hasil |
|---|---|
| `php artisan test --filter=AuditChainTamperTest` | 18 passed |
| `php artisan test --filter='AuditCheckpointTamperTest\|CreateAuditCheckpointTest\|InitializeAuditKeyTest'` | 73 passed |
| `php artisan test --filter='AuditMismatchAlertTest\|…\|AlertSchemaTest'` | 56 passed |
| `php artisan test --testsuite=Contract` | 53 passed |
| `php artisan test` (suite penuh) | 449 passed |
