<?php

namespace App\Models;

use App\Domain\Alerts\Data\AlertKind;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Satu aturan peringatan per jenis per tenant (docs/07, ambang bawaan docs/15). `threshold` selalu objek JSON,
 * sehingga dicast `object` agar ambang kosong tersimpan `{}`, bukan `[]`.
 *
 * @property AlertKind $kind
 * @property bool $enabled
 */
class AlertRule extends Model
{
    use HasUlids;

    protected $fillable = ['id', 'tenant_id', 'kind', 'threshold', 'enabled'];

    protected function casts(): array
    {
        return [
            'kind' => AlertKind::class,
            'threshold' => 'object',
            'enabled' => 'boolean',
        ];
    }
}
