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
        foreach (['actor_id' => $actorId, 'action_key' => $actionKey, 'target' => $target] as $field => $value) {
            if ($value !== null && str_contains($value, "\0")) {
                throw new InvalidArgumentException("{$field} tak boleh memuat byte NUL.");
            }
        }
        self::assertNoNul($paramsRedacted);
    }

    /** PostgreSQL memotong text di NUL dan menolak \u0000 di jsonb; entri seperti itu tak akan terverifikasi. */
    private static function assertNoNul(mixed $value): void
    {
        if (is_string($value) && str_contains($value, "\0")) {
            throw new InvalidArgumentException('params_redacted tak boleh memuat byte NUL.');
        }

        if ($value instanceof stdClass) {
            $value = get_object_vars($value);
        }

        if (is_array($value)) {
            foreach ($value as $key => $item) {
                self::assertNoNul((string) $key);
                self::assertNoNul($item);
            }
        }
    }
}
