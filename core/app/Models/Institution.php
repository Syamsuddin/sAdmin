<?php

namespace App\Models;

use Database\Factories\InstitutionFactory;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Institution extends Model
{
    /** @use HasFactory<InstitutionFactory> */
    use HasFactory, HasUlids;

    protected $fillable = ['tenant_id', 'name', 'timezone', 'maintenance_window', 'backup_retention', 'console_hostname', 'deployment_mode'];

    protected function casts(): array
    {
        return [
            'maintenance_window' => 'array',
            'backup_retention' => 'array',
            'recovery_kit_confirmed_at' => 'immutable_datetime',
        ];
    }

    /** @return BelongsTo<Tenant, $this> */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(Tenant::class);
    }
}
