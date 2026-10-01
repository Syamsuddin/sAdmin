<?php

namespace App\Domain\Fleet\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Fleet\Services\AgentCertificateProfile;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\Vault;
use App\Infrastructure\Vault\X509Authority;
use App\Models\Institution;
use App\Models\Secret;
use DomainException;
use Illuminate\Support\Facades\DB;

/**
 * Membuat CA internal instansi sekali seumur instalasi (ADR 0007 §2.1): kunci privat dan sertifikat CA hanya di
 * brankas, pin tercatat di audit. CA baru sesudahnya = rotasi: agen yang sudah tersemat menolak gateway (docs/22).
 */
final class InitializeCertificateAuthority
{
    public const LOCK_KEY = 7301006;

    public function __construct(
        private readonly StoreSecret $store,
        private readonly AppendAuditEntry $audit,
        private readonly Vault $vault,
    ) {}

    /** @return array{secretId: string, caSha256: string, notAfter: string} pin 64 hex & notAfter RFC 3339 UTC */
    public function handle(): array
    {
        $tenantId = Institution::query()->value('tenant_id');
        if (! is_string($tenantId)) {
            throw new DomainException('Instansi belum diinisialisasi; jalankan sadmin:institution-init lebih dulu.');
        }

        return DB::transaction(function () use ($tenantId): array {
            DB::select('SELECT pg_advisory_xact_lock(?)', [self::LOCK_KEY]);

            // CA yang pernah ada (status apa pun) berarti CA baru = rotasi de facto: agen yang sudah menyematkan pin
            // lama menolak gateway. Rotasi butuh gerbang manusia (docs/22) dan ADR baru.
            $everCreated = Secret::query()
                ->where('tenant_id', $tenantId)
                ->where('purpose', SecretPurpose::CaKey->value)
                ->exists();
            if ($everCreated) {
                throw new DomainException('CA internal sudah pernah dibuat. Membuat CA baru adalah rotasi CA: agen yang sudah tersemat akan menolak gateway, jadi butuh gerbang manusia (docs/22) dan ADR baru.');
            }

            $bundle = X509Authority::generate(
                AgentCertificateProfile::CA_COMMON_NAME,
                AgentCertificateProfile::authorityExtensions(),
                AgentCertificateProfile::CA_DAYS,
                random_int(1, PHP_INT_MAX),
            );
            $secret = $this->store->handle($tenantId, SecretPurpose::CaKey, $bundle, ActorType::LocalRoot, null);

            // Pin dari sertifikat yang dibuka ulang dari brankas, bukan dari nilai di memori (ADR 0007 §2.1 langkah 4).
            $caPem = $this->vault->caCertificate($secret->id, $tenantId);
            $caSha256 = AgentCertificateProfile::fingerprint($caPem);
            $notAfter = gmdate('Y-m-d\TH:i:s\Z', (int) (openssl_x509_parse($caPem)['validTo_time_t'] ?? 0));

            $this->audit->handle(new AuditEntryData(
                tenantId: $tenantId,
                actorType: ActorType::LocalRoot,
                actorId: null,
                actionKey: 'ca.initialize',
                outcome: AuditOutcome::Ok,
                target: "secret:{$secret->id}",
                paramsRedacted: ['ca_sha256' => $caSha256, 'not_after' => $notAfter],
            ));

            return ['secretId' => $secret->id, 'caSha256' => $caSha256, 'notAfter' => $notAfter];
        });
    }
}
