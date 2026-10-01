<?php

namespace App\Domain\Alerts\Actions;

use App\Domain\Alerts\Data\AlertKind;
use App\Domain\Alerts\Data\AlertSeverity;
use App\Domain\Alerts\Data\AlertStatus;
use App\Domain\Alerts\Data\DeliveryReport;
use App\Domain\Alerts\Data\IntegrityAlert;
use App\Domain\Alerts\Data\RaisedAlert;
use App\Domain\Alerts\Services\AlertDispatcher;
use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Infrastructure\Notify\NotificationMessage;
use App\Models\Alert;
use App\Models\Institution;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use Throwable;

/**
 * Membuka alert `audit_mismatch` critical lalu mengirimnya langsung ke semua kanal (ADR 0005 §2.2–2.3).
 * Satu kejadian = satu alert belum selesai; yang sudah terkirim tidak dikirim ulang sebelum 24 jam, lalu dikirim
 * sebagai pengingat selama kerusakannya masih terdeteksi. Penyimpanan yang gagal tak pernah menghentikan
 * pengiriman, dan tak ada galat yang lolos ke pendeteksi: exit code verify tak boleh berubah.
 */
final class RaiseIntegrityAlert
{
    /** Kunci advisory dua bagian (kelas, hashtext(dedup_key)): satu pengirim per kejadian di semua proses. */
    public const LOCK_CLASS = 7301005;

    /** Kunci yang dipegang proses lain ditunggu paling lama ±5 detik; sesudahnya kirim tanpa kunci (ganda > senyap). */
    public const LOCK_ATTEMPTS = 10;

    public const LOCK_POLL_MILLISECONDS = 500;

    public const REMIND_AFTER_HOURS = 24;

    public function __construct(
        private readonly AppendAuditEntry $audit,
        private readonly AlertDispatcher $dispatcher,
    ) {}

    public function handle(IntegrityAlert $data): RaisedAlert
    {
        $alertId = strtolower((string) Str::ulid());

        try {
            $institution = Institution::query()->first(['tenant_id', 'console_hostname']);
        } catch (Throwable $e) {
            return $this->undeliverable($alertId, $data, 'instansi tak terbaca: '.class_basename($e).': '.$e->getMessage());
        }
        if ($institution === null) {
            return $this->undeliverable($alertId, $data, 'instansi belum diinisialisasi, sehingga kanal tak diketahui');
        }
        $tenantId = (string) $institution->tenant_id;

        $locked = false;
        try {
            $stored = null;
            try {
                $locked = $this->lock($data);
                $stored = $this->store($tenantId, $alertId, $data);
                $alertId = $stored['id'];
            } catch (Throwable $e) {
                Log::critical('alert_store_failed', [
                    'alert_id' => $alertId,
                    'dedup_key' => $data->dedupKey(),
                    'error' => class_basename($e).': '.$e->getMessage(),
                ]);
            }

            if ($stored !== null && $stored['notified'] && ! $stored['remind']) {
                return new RaisedAlert($alertId, true, false, true, null);
            }
            $reminder = $stored['remind'] ?? false;

            try {
                $report = $this->dispatcher->deliver($tenantId, $this->message($data, $alertId, (string) $institution->console_hostname), $alertId);
            } catch (Throwable $e) {
                return $this->undeliverable($alertId, $data, 'kanal tak terbaca: '.class_basename($e).': '.$e->getMessage(), $stored !== null, $stored['created'] ?? false);
            }

            if (! $report->anyDelivered()) {
                Log::critical('alert_undelivered', [
                    'alert_id' => $alertId,
                    'dedup_key' => $data->dedupKey(),
                    'channels_failed' => count($report->failed),
                ]);
            } elseif ($stored !== null) {
                $this->markNotified($tenantId, $alertId, $report, $reminder);
            }

            return new RaisedAlert($alertId, $stored !== null, $stored['created'] ?? false, false, $report, $reminder);
        } finally {
            if ($locked) {
                $this->unlock($data);
            }
        }
    }

    /**
     * Kunci advisory sesi dengan batas tunggu: `pg_advisory_lock` menunggu selamanya, sehingga pemegang kunci yang
     * macet (SMTP yang menetes) atau sesi lain yang sengaja memegangnya akan menggantung pendeteksi.
     */
    private function lock(IntegrityAlert $data): bool
    {
        for ($attempt = 1; $attempt <= self::LOCK_ATTEMPTS; $attempt++) {
            if (DB::scalar('SELECT pg_try_advisory_lock(?, hashtext(?))', [self::LOCK_CLASS, $data->dedupKey()]) === true) {
                return true;
            }
            if ($attempt < self::LOCK_ATTEMPTS) {
                Sleep::for(self::LOCK_POLL_MILLISECONDS)->milliseconds();
            }
        }

        Log::warning('alert_lock_busy', ['dedup_key' => $data->dedupKey()]);

        return false;
    }

    /** @return array{id: string, created: bool, notified: bool, remind: bool} */
    private function store(string $tenantId, string $alertId, IntegrityAlert $data): array
    {
        return DB::transaction(function () use ($tenantId, $alertId, $data): array {
            $now = CarbonImmutable::now();

            DB::table('alert_rules')->insertOrIgnore([
                'id' => strtolower((string) Str::ulid()),
                'tenant_id' => $tenantId,
                'kind' => AlertKind::AuditMismatch->value,
                'threshold' => '{}',
                'enabled' => true,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
            $ruleId = DB::table('alert_rules')
                ->where('tenant_id', $tenantId)
                ->where('kind', AlertKind::AuditMismatch->value)
                ->value('id');

            $inserted = DB::table('alerts')->insertOrIgnore([
                'id' => $alertId,
                'tenant_id' => $tenantId,
                'rule_id' => $ruleId,
                'server_id' => null,
                'severity' => AlertSeverity::Critical->value,
                'title' => self::text('alerts.audit_mismatch.title'),
                'detail' => json_encode($data->detail(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
                'status' => AlertStatus::Open->value,
                'dedup_key' => $data->dedupKey(),
                'opened_at' => $now,
                'notified_at' => null,
                'resolved_at' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ]);

            if ($inserted === 1) {
                $this->audit->handle(new AuditEntryData(
                    tenantId: $tenantId,
                    actorType: ActorType::System,
                    actorId: null,
                    actionKey: 'alert.open',
                    outcome: AuditOutcome::Ok,
                    target: "alert:{$alertId}",
                    paramsRedacted: [
                        'kind' => AlertKind::AuditMismatch->value,
                        'severity' => AlertSeverity::Critical->value,
                        'seq' => $data->seq,
                    ],
                ));

                return ['id' => $alertId, 'created' => true, 'notified' => false, 'remind' => false];
            }

            $existing = Alert::query()
                ->where('tenant_id', $tenantId)
                ->where('dedup_key', $data->dedupKey())
                ->where('status', '<>', AlertStatus::Resolved->value)
                ->firstOrFail();

            $notified = $existing->notified_at !== null;

            return [
                'id' => $existing->id,
                'created' => false,
                'notified' => $notified,
                'remind' => $notified && $existing->notified_at->lessThanOrEqualTo($this->remindBefore()),
            ];
        });
    }

    private function remindBefore(): CarbonImmutable
    {
        return CarbonImmutable::now()->subHours(self::REMIND_AFTER_HOURS);
    }

    /**
     * Hanya keberhasilan yang diaudit, agar percobaan ulang tak menumbuhkan audit tanpa batas (ADR 0005 §2.3);
     * pengingat menambah paling banyak satu entri per hari.
     */
    private function markNotified(string $tenantId, string $alertId, DeliveryReport $report, bool $reminder): void
    {
        try {
            DB::transaction(function () use ($tenantId, $alertId, $report, $reminder): void {
                $updated = Alert::query()
                    ->whereKey($alertId)
                    ->where(fn ($query) => $query->whereNull('notified_at')->orWhere('notified_at', '<=', $this->remindBefore()))
                    ->update(['notified_at' => CarbonImmutable::now()]);

                if ($updated === 1) {
                    $this->audit->handle(new AuditEntryData(
                        tenantId: $tenantId,
                        actorType: ActorType::System,
                        actorId: null,
                        actionKey: 'alert.notify',
                        outcome: AuditOutcome::Ok,
                        target: "alert:{$alertId}",
                        paramsRedacted: ['delivered' => count($report->delivered), 'failed' => count($report->failed), 'reminder' => $reminder],
                    ));
                }
            });
        } catch (Throwable $e) {
            Log::critical('alert_store_failed', [
                'alert_id' => $alertId,
                'stage' => 'notified_at',
                'error' => class_basename($e).': '.$e->getMessage(),
            ]);
        }
    }

    private function unlock(IntegrityAlert $data): void
    {
        try {
            DB::select('SELECT pg_advisory_unlock(?, hashtext(?))', [self::LOCK_CLASS, $data->dedupKey()]);
        } catch (Throwable $e) {
            // Kunci sesi lepas sendiri saat koneksi ditutup; cukup dicatat.
            Log::error('alert_unlock_failed', ['dedup_key' => $data->dedupKey(), 'error' => class_basename($e)]);
        }
    }

    private function undeliverable(string $alertId, IntegrityAlert $data, string $reason, bool $stored = false, bool $created = false): RaisedAlert
    {
        Log::critical('alert_undelivered', ['alert_id' => $alertId, 'dedup_key' => $data->dedupKey(), 'reason' => $reason]);

        return new RaisedAlert($alertId, $stored, $created, false, null);
    }

    private function message(IntegrityAlert $data, string $alertId, string $hostname): NotificationMessage
    {
        $title = self::text('alerts.audit_mismatch.title');
        $cause = $data->seq === null
            ? self::text('alerts.audit_mismatch.penyebab', ['reason' => $data->reason])
            : self::text('alerts.audit_mismatch.penyebab_seq', ['seq' => (string) $data->seq, 'reason' => $data->reason]);

        return new NotificationMessage(
            self::text('alerts.subject', ['severity' => 'CRITICAL', 'title' => $title, 'host' => $hostname]),
            self::text('alerts.body', [
                'severity' => 'CRITICAL',
                'host' => $hostname,
                'title' => $title,
                'langkah' => self::text("alerts.audit_mismatch.langkah.{$data->check}"),
                'penyebab' => $cause,
                'tindakan' => self::text('alerts.audit_mismatch.tindakan'),
                'id' => $alertId,
            ]),
        );
    }

    /**
     * Notifikasi selalu Bahasa Indonesia (docs/14), juga dari CLI yang locale-nya bawaan.
     *
     * @param  array<string, string>  $replace
     */
    private static function text(string $key, array $replace = []): string
    {
        $line = __($key, $replace, 'id');

        return is_string($line) ? $line : $key;
    }
}
