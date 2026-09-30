<?php

namespace App\Models;

use App\Models\Casts\Bytea;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/** Satu passkey admin: hanya ID kredensial & kunci publik COSE (docs/07, docs/21). */
class Authenticator extends Model
{
    use HasUlids;

    protected $fillable = ['tenant_id', 'admin_id', 'credential_id', 'public_key_cose', 'alg', 'sign_count', 'label', 'status'];

    protected function casts(): array
    {
        return [
            'credential_id' => Bytea::class,
            'public_key_cose' => Bytea::class,
            'alg' => 'integer',
            'sign_count' => 'integer',
        ];
    }

    /** @return BelongsTo<Admin, $this> */
    public function admin(): BelongsTo
    {
        return $this->belongsTo(Admin::class);
    }
}
