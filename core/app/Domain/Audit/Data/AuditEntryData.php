<?php

namespace App\Domain\Audit\Data;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use InvalidArgumentException;
use stdClass;

/**
 * Masukan satu entri audit. `paramsRedacted` WAJIB sudah disamarkan oleh pemanggil —
 * nilai rahasia tak pernah masuk audit (docs/21_SECURITY_RULES.md).
 */
final readonly class AuditEntryData
{
    /**
     * @param  array<array-key, mixed>|stdClass|null  $paramsRedacted
     */
    public function __construct(
        public string $tenantId,
        public ActorType $actorType,
        public ?string $actorId,
        public string $actionKey,
        public AuditOutcome $outcome,
        public ?string $target = null,
        public array|stdClass|null $paramsRedacted = null,
        public ?string $envelopeRef = null,
        public bool $emergencyLocal = false,
        public ?CarbonImmutable $occurredAt = null,
    ) {
        if (! Str::isUlid($tenantId)) {
            throw new InvalidArgumentException('tenant_id harus ULID.');
        }
        if ($envelopeRef !== null && ! Str::isUlid($envelopeRef)) {
            throw new InvalidArgumentException('envelope_ref harus ULID.');
        }
        if (trim($actionKey) === '') {
            throw new InvalidArgumentException('action_key wajib diisi.');
        }
    }
}
