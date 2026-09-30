<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use LogicException;

/**
 * Model baca-saja. Penulisan hanya lewat App\Domain\Audit\Actions\AppendAuditEntry,
 * yang memegang kunci advisory rantai dan menghitung hash.
 */
class AuditEntry extends Model
{
    public $incrementing = false;

    public $timestamps = false;

    protected $primaryKey = 'seq';

    protected $keyType = 'int';

    protected static function booted(): void
    {
        $tolak = static function (): never {
            throw new LogicException('audit_entries hanya ditulis lewat AppendAuditEntry dan tak pernah diubah.');
        };

        static::creating($tolak);
        static::updating($tolak);
        static::deleting($tolak);
    }

    protected function casts(): array
    {
        return [
            'occurred_at' => 'immutable_datetime',
            'params_redacted' => 'array',
            'emergency_local' => 'boolean',
        ];
    }

    /** @return BelongsTo<Tenant, $this> */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(Tenant::class);
    }
}
