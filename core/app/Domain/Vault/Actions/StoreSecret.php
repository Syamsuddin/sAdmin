<?php

namespace App\Domain\Vault\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Vault\Data\SecretPurpose;
use App\Domain\Vault\Data\SecretStatus;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\Vault;
use App\Models\KeyWrap;
use App\Models\Secret;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SensitiveParameter;
use UnexpectedValueException;

/**
 * Menyimpan satu rahasia baru di brankas (ADR 0003 §2.4): kunci data sendiri, key_wraps + secrets + audit dalam
 * satu transaksi, lalu dibaca ulang dan dibuka sebelum transaksi selesai. Audit hanya mencatat purpose.
 */
final class StoreSecret
{
    public function __construct(
        private readonly Vault $vault,
        private readonly AppendAuditEntry $audit,
    ) {}

    public function handle(string $tenantId, SecretPurpose $purpose, #[SensitiveParameter] SecretValue $value, ActorType $actorType, ?string $actorId): Secret
    {
        $secretId = strtolower((string) Str::ulid());
        $keyWrapId = strtolower((string) Str::ulid());
        $sealed = $this->vault->seal($tenantId, $secretId, $keyWrapId, $purpose, $value);

        return DB::transaction(function () use ($tenantId, $purpose, $value, $actorType, $actorId, $secretId, $keyWrapId, $sealed): Secret {
            KeyWrap::query()->create([
                'id' => $keyWrapId,
                'tenant_id' => $tenantId,
                'wrapped_dek' => $sealed->wrappedDek,
                'master_key_version' => $sealed->masterKeyVersion,
            ]);
            Secret::query()->create([
                'id' => $secretId,
                'tenant_id' => $tenantId,
                'purpose' => $purpose,
                'ciphertext' => $sealed->ciphertext,
                'nonce' => $sealed->nonce,
                'key_wrap_id' => $keyWrapId,
                'status' => SecretStatus::Active,
            ]);

            // Invarian "tertulis ⇒ terbuka": rahasia yang tersimpan tapi tak terbuka hilang tanpa jejak. Batalkan di sini.
            $stored = Secret::query()->with('keyWrap')->findOrFail($secretId);
            if (! $this->vault->reveal($stored)->equals($value)) {
                throw new UnexpectedValueException('Rahasia tak terbaca ulang identik; penyimpanan dibatalkan.');
            }

            $this->audit->handle(new AuditEntryData(
                tenantId: $tenantId,
                actorType: $actorType,
                actorId: $actorId,
                actionKey: 'secret.store',
                outcome: AuditOutcome::Ok,
                target: 'secret:'.$secretId,
                paramsRedacted: ['purpose' => $purpose->value],
            ));

            return $stored;
        });
    }
}
