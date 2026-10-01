<?php

namespace App\Models;

use App\Domain\Vault\Data\SecretPurpose;
use App\Domain\Vault\Data\SecretStatus;
use App\Models\Casts\Bytea;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Satu rahasia terenkripsi envelope (docs/07, ADR 0003). Ditulis hanya lewat App\Domain\Vault\Actions;
 * nilainya dibuka hanya lewat App\Infrastructure\Vault\Vault::reveal().
 *
 * @property SecretPurpose $purpose
 * @property SecretStatus $status
 */
class Secret extends Model
{
    use HasUlids;

    protected $fillable = ['id', 'tenant_id', 'purpose', 'ciphertext', 'nonce', 'key_wrap_id', 'status'];

    protected $hidden = ['ciphertext', 'nonce'];

    protected function casts(): array
    {
        return [
            'purpose' => SecretPurpose::class,
            'status' => SecretStatus::class,
            'ciphertext' => Bytea::class,
            'nonce' => Bytea::class,
        ];
    }

    /** @return BelongsTo<KeyWrap, $this> */
    public function keyWrap(): BelongsTo
    {
        return $this->belongsTo(KeyWrap::class);
    }
}
