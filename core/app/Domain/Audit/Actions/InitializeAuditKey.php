<?php

namespace App\Domain\Audit\Actions;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Audit\Services\CheckpointSigner;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\Ed25519;
use App\Models\Institution;
use DomainException;
use Illuminate\Support\Facades\DB;

/**
 * Membuat kunci audit Ed25519 instansi sekali (ADR 0004 §2.1): seed hanya di brankas, kunci publik tercatat di audit
 * dan dikembalikan untuk kit pemulihan. Mengganti kunci aktif = rotasi, yang butuh gerbang manusia (docs/22).
 */
final class InitializeAuditKey
{
    public const LOCK_KEY = 7301003;

    public function __construct(
        private readonly StoreSecret $store,
        private readonly AppendAuditEntry $audit,
        private readonly CheckpointSigner $signer,
    ) {}

    /** @return array{secretId: string, publicKey: string} kunci publik base64 standar (../kontrak/KONTRAK.md §3) */
    public function handle(): array
    {
        $tenantId = Institution::query()->value('tenant_id');
        if (! is_string($tenantId)) {
            throw new DomainException('Instansi belum diinisialisasi; jalankan sadmin:institution-init lebih dulu.');
        }

        return DB::transaction(function () use ($tenantId): array {
            DB::select('SELECT pg_advisory_xact_lock(?)', [self::LOCK_KEY]);

            if ($this->signer->activeKeyId($tenantId) !== null) {
                throw new DomainException('Kunci audit aktif sudah ada. Menggantinya adalah rotasi kunci audit: butuh gerbang manusia (docs/22) dan ADR baru.');
            }

            $secret = $this->store->handle($tenantId, SecretPurpose::AuditKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
            $publicKey = Ed25519::encode($this->signer->publicKey($secret->id, $tenantId));

            $this->audit->handle(new AuditEntryData(
                tenantId: $tenantId,
                actorType: ActorType::LocalRoot,
                actorId: null,
                actionKey: 'audit.key_initialize',
                outcome: AuditOutcome::Ok,
                target: "secret:{$secret->id}",
                paramsRedacted: ['public_key' => $publicKey],
            ));

            return ['secretId' => $secret->id, 'publicKey' => $publicKey];
        });
    }
}
