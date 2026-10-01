<?php

namespace App\Models;

use App\Domain\Fleet\Data\AgentConnection;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Agen satu server (1:1, docs/07 §Armada): sertifikat klien dan keadaan yang dilaporkan agen.
 *
 * @property AgentConnection $connection
 * @property CarbonImmutable $cert_expires_at
 * @property CarbonImmutable|null $last_seen_at
 */
class Agent extends Model
{
    use HasUlids;

    protected $fillable = [
        'tenant_id', 'server_id', 'agent_version', 'cert_serial', 'cert_expires_at', 'roster_version', 'policy_version',
        'last_seen_at', 'connection', 'audit_head_seq', 'audit_head_hash',
    ];

    protected function casts(): array
    {
        return [
            'connection' => AgentConnection::class,
            'cert_expires_at' => 'immutable_datetime',
            'last_seen_at' => 'immutable_datetime',
        ];
    }

    /** @return BelongsTo<Server, $this> */
    public function server(): BelongsTo
    {
        return $this->belongsTo(Server::class);
    }
}
