<?php

namespace App\Models;

use App\Models\Casts\Bytea;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Kunci data satu rahasia, dibungkus kunci induk (ADR 0003 §2.2). Ditulis hanya lewat
 * App\Domain\Vault\Actions; dibuka hanya oleh App\Infrastructure\Vault\Vault.
 */
class KeyWrap extends Model
{
    use HasUlids;

    /** docs/07: key_wraps hanya punya created_at. */
    public const UPDATED_AT = null;

    protected $fillable = ['id', 'tenant_id', 'wrapped_dek', 'master_key_version'];

    protected $hidden = ['wrapped_dek'];

    protected function casts(): array
    {
        return [
            'wrapped_dek' => Bytea::class,
            'master_key_version' => 'integer',
        ];
    }
}
