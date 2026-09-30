<?php

namespace App\Domain\Audit\Services;

use App\Infrastructure\Jcs\Jcs;
use Carbon\CarbonImmutable;
use InvalidArgumentException;
use stdClass;

/**
 * hash = SHA-256(prev_hash ∥ JCS(entri tanpa hash)) — docs/07_DATA_MODEL.md;
 * rincian bentuk tiap field: docs/adr/0001-format-rantai-audit.md. Mengubahnya = gerbang manusia (docs/22).
 */
final class AuditHasher
{
    /**
     * Satu-satunya tempat daftar field yang di-hash; dipakai saat menulis dan saat memverifikasi.
     *
     * @param  array<array-key, mixed>|stdClass|null  $paramsRedacted
     * @return array<string, mixed>
     */
    public function body(
        int $seq,
        string $tenantId,
        string $prevHash,
        CarbonImmutable $occurredAt,
        string $actorType,
        ?string $actorId,
        string $actionKey,
        ?string $target,
        array|stdClass|null $paramsRedacted,
        string $outcome,
        ?string $envelopeRef,
        bool $emergencyLocal,
    ): array {
        return [
            'seq' => $seq,
            'tenant_id' => $tenantId,
            'prev_hash' => $prevHash,
            'occurred_at' => self::formatTime($occurredAt),
            'actor_type' => $actorType,
            'actor_id' => $actorId,
            'action_key' => $actionKey,
            'target' => $target,
            'params_redacted' => $paramsRedacted,
            'outcome' => $outcome,
            'envelope_ref' => $envelopeRef,
            'emergency_local' => $emergencyLocal,
        ];
    }

    /**
     * Bentuk ulang isi entri dari baris DB lewat pengurai ketat (KONTRAK §3); objek tetap objek agar `{}` tetap `{}`.
     *
     * @return array<string, mixed>
     */
    public function bodyFromRow(stdClass $row): array
    {
        $params = $row->params_redacted === null ? null : Jcs::decode($row->params_redacted);

        if (! ($params === null || is_array($params) || $params instanceof stdClass)) {
            throw new InvalidArgumentException('JCS: params_redacted harus objek atau larik JSON.');
        }

        return $this->body(
            seq: (int) $row->seq,
            tenantId: $row->tenant_id,
            prevHash: $row->prev_hash,
            occurredAt: CarbonImmutable::parse($row->occurred_at),
            actorType: $row->actor_type,
            actorId: $row->actor_id,
            actionKey: $row->action_key,
            target: $row->target,
            paramsRedacted: $params,
            outcome: $row->outcome,
            envelopeRef: $row->envelope_ref,
            emergencyLocal: (bool) $row->emergency_local,
        );
    }

    /** @param array<string, mixed> $body */
    public function hash(array $body): string
    {
        return hash('sha256', $body['prev_hash'].Jcs::canonicalize($body));
    }

    /** RFC 3339 UTC berakhiran Z, presisi mikrodetik tetap 6 digit (sama dengan timestamptz(6)). */
    public static function formatTime(CarbonImmutable $time): string
    {
        return $time->utc()->format('Y-m-d\TH:i:s.u\Z');
    }
}
