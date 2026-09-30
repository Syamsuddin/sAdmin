<?php

namespace App\Domain\Audit\Actions;

use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Services\AuditHasher;
use App\Infrastructure\Jcs\Jcs;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;

/**
 * Menambah satu entri ke rantai audit. Panggil di dalam transaksi Action pemilik perubahan state
 * agar entri dan perubahannya jadi atau batal bersama (docs/21_SECURITY_RULES.md).
 */
final class AppendAuditEntry
{
    /** Kunci advisory rantai global: seq tanpa celah dan tanpa cabang meski ditulis paralel. */
    public const CHAIN_LOCK_KEY = 7301001;

    public function __construct(private readonly AuditHasher $hasher) {}

    public function handle(AuditEntryData $data): AuditHead
    {
        return DB::transaction(function () use ($data): AuditHead {
            DB::select('SELECT pg_advisory_xact_lock(?)', [self::CHAIN_LOCK_KEY]);

            $last = DB::table('audit_entries')->orderByDesc('seq')->first(['seq', 'hash']);
            $prev = $last === null ? AuditHead::genesis() : new AuditHead((int) $last->seq, $last->hash);

            $body = $this->hasher->body(
                seq: $prev->seq + 1,
                tenantId: $data->tenantId,
                prevHash: $prev->hash,
                occurredAt: $data->occurredAt ?? CarbonImmutable::now(),
                actorType: $data->actorType->value,
                actorId: $data->actorId,
                actionKey: $data->actionKey,
                target: $data->target,
                paramsRedacted: $data->paramsRedacted,
                outcome: $data->outcome->value,
                envelopeRef: $data->envelopeRef,
                emergencyLocal: $data->emergencyLocal,
            );
            $hash = $this->hasher->hash($body);

            DB::table('audit_entries')->insert([
                ...$body,
                'hash' => $hash,
                'params_redacted' => $body['params_redacted'] === null ? null : Jcs::canonicalize($body['params_redacted']),
            ]);

            return new AuditHead($body['seq'], $hash);
        });
    }
}
