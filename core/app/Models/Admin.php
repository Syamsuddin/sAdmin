<?php

namespace App\Models;

use App\Domain\Identity\Data\ThemePreference;
use Database\Factories\AdminFactory;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * Admin console: masuk hanya dengan passkey, tanpa password (docs/21).
 *
 * @property ThemePreference $theme
 */
class Admin extends Authenticatable
{
    /** @use HasFactory<AdminFactory> */
    use HasFactory, HasUlids;

    protected $fillable = ['tenant_id', 'display_name', 'email', 'status', 'theme'];

    /** Sama dengan default kolom (docs/07) agar instance yang baru dibuat tak membawa tema null. */
    protected $attributes = ['theme' => 'system'];

    protected function casts(): array
    {
        return [
            'last_login_at' => 'immutable_datetime',
            'theme' => ThemePreference::class,
        ];
    }

    /** Tanpa "ingat saya": sesi berakhir paling lambat 12 jam (docs/21). */
    public function getRememberTokenName(): string
    {
        return '';
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /** @return BelongsTo<Tenant, $this> */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(Tenant::class);
    }

    /** @return HasMany<Authenticator, $this> */
    public function authenticators(): HasMany
    {
        return $this->hasMany(Authenticator::class);
    }

    /** @return HasMany<Authenticator, $this> */
    public function activeAuthenticators(): HasMany
    {
        return $this->authenticators()->where('status', 'active');
    }
}
