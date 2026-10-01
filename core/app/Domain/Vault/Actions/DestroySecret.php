<?php

namespace App\Domain\Vault\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Vault\Data\SecretStatus;
use App\Models\KeyWrap;
use App\Models\Secret;
use Illuminate\Support\Facades\DB;

/**
 * Menghancurkan satu rahasia (docs/07, ADR 0003 §2.4): ciphertext dan kunci data ditimpa nol, baris tetap.
 * Rahasia yang sudah hancur = no-op tanpa audit.
 */
final class DestroySecret
{
    public function __construct(private readonly AppendAuditEntry $audit) {}

    public function handle(string $secretId, ActorType $actorType, ?string $actorId): Secret
    {
        return DB::transaction(function () use ($secretId, $actorType, $actorId): Secret {
            $secret = Secret::query()->lockForUpdate()->findOrFail($secretId);
            if ($secret->status === SecretStatus::Destroyed) {
                return $secret;
            }

            $wrap = KeyWrap::query()->lockForUpdate()->findOrFail($secret->key_wrap_id);
            $wrap->wrapped_dek = str_repeat("\0", strlen($wrap->wrapped_dek));
            $wrap->save();

            $secret->ciphertext = str_repeat("\0", strlen($secret->ciphertext));
            $secret->status = SecretStatus::Destroyed;
            $secret->save();

            $this->audit->handle(new AuditEntryData(
                tenantId: $secret->tenant_id,
                actorType: $actorType,
                actorId: $actorId,
                actionKey: 'secret.destroy',
                outcome: AuditOutcome::Ok,
                target: 'secret:'.$secret->id,
                paramsRedacted: ['purpose' => $secret->purpose->value],
            ));

            return $secret;
        });
    }
}
