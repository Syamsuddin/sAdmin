<?php

namespace App\Models;

use App\Domain\Alerts\Data\AlertSeverity;
use App\Domain\Alerts\Data\AlertStatus;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Satu kejadian peringatan (docs/07). Dibuka lewat App\Domain\Alerts\Actions; `detail` tak pernah memuat rahasia.
 *
 * @property AlertSeverity $severity
 * @property AlertStatus $status
 * @property array<string, mixed> $detail
 * @property CarbonImmutable $opened_at
 * @property CarbonImmutable|null $notified_at
 * @property CarbonImmutable|null $resolved_at
 */
class Alert extends Model
{
    use HasUlids;

    protected $fillable = ['id', 'tenant_id', 'rule_id', 'server_id', 'severity', 'title', 'detail', 'status', 'dedup_key', 'opened_at', 'notified_at', 'resolved_at'];

    protected function casts(): array
    {
        return [
            'severity' => AlertSeverity::class,
            'status' => AlertStatus::class,
            'detail' => 'array',
            'opened_at' => 'immutable_datetime',
            'notified_at' => 'immutable_datetime',
            'resolved_at' => 'immutable_datetime',
        ];
    }

    /** @return BelongsTo<AlertRule, $this> */
    public function rule(): BelongsTo
    {
        return $this->belongsTo(AlertRule::class);
    }
}
