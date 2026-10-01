<?php

namespace App\Models;

use App\Domain\Fleet\Data\ServerStatus;
use Carbon\CarbonImmutable;
use Database\Factories\ServerFactory;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne;

/**
 * Server terkelola (docs/07 §Armada). Dibuat dan diubah lewat App\Domain\Fleet\Actions; token enrolment hanya
 * tersimpan sebagai hash.
 *
 * @property ServerStatus $status
 * @property array<string, mixed>|null $os_release
 * @property bool $is_control_plane_host
 * @property CarbonImmutable|null $enroll_token_expires_at
 * @property CarbonImmutable|null $onboarded_at
 */
class Server extends Model
{
    /** @use HasFactory<ServerFactory> */
    use HasFactory, HasUlids;

    protected $fillable = ['tenant_id', 'name', 'hostname', 'ip', 'status', 'enroll_token_hash', 'enroll_token_expires_at'];

    protected $hidden = ['enroll_token_hash'];

    protected function casts(): array
    {
        return [
            'status' => ServerStatus::class,
            'os_release' => 'array',
            'is_control_plane_host' => 'boolean',
            'enroll_token_expires_at' => 'immutable_datetime',
            'onboarded_at' => 'immutable_datetime',
        ];
    }

    /** @return HasOne<Agent, $this> */
    public function agent(): HasOne
    {
        return $this->hasOne(Agent::class);
    }
}
