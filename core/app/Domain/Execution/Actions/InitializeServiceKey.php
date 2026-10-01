<?php

namespace App\Domain\Execution\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Execution\Dispatch\ServiceSigner;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\Ed25519;
use App\Models\Institution;
use App\Models\Secret;
use DomainException;
use Illuminate\Support\Facades\DB;

/**
 * Membuat kunci layanan Ed25519 instansi sekali seumur instalasi (ADR 0006 §2.1): seed hanya di brankas, kunci publik
 * tercatat di audit. Kunci baru sesudahnya = rotasi: agen yang sudah tersemat menolak semua bingkai (docs/22).
 */
final class InitializeServiceKey
{
    public const LOCK_KEY = 7301004;

    public function __construct(
        private readonly StoreSecret $store,
        private readonly AppendAuditEntry $audit,
        private readonly ServiceSigner $signer,
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

            // Kunci yang pernah ada (status apa pun) berarti kunci baru = rotasi de facto: agen yang sudah menyematkan
            // service_pubkey lama menolak semua bingkai. Rotasi butuh gerbang manusia (docs/22) dan ADR baru.
            $everCreated = Secret::query()
                ->where('tenant_id', $tenantId)
                ->where('purpose', SecretPurpose::ServiceKey->value)
                ->exists();
            if ($everCreated) {
                throw new DomainException('Kunci layanan sudah pernah dibuat. Membuat kunci baru adalah rotasi kunci layanan: agen yang sudah tersemat akan menolak semua bingkai, jadi butuh gerbang manusia (docs/22) dan ADR baru.');
            }

            $secret = $this->store->handle($tenantId, SecretPurpose::ServiceKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
            $publicKey = Ed25519::encode($this->signer->publicKey($secret->id, $tenantId));

            $this->audit->handle(new AuditEntryData(
                tenantId: $tenantId,
                actorType: ActorType::LocalRoot,
                actorId: null,
                actionKey: 'service.key_initialize',
                outcome: AuditOutcome::Ok,
                target: "secret:{$secret->id}",
                paramsRedacted: ['public_key' => $publicKey],
            ));

            return ['secretId' => $secret->id, 'publicKey' => $publicKey];
        });
    }
}
