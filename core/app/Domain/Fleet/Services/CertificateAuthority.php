<?php

namespace App\Domain\Fleet\Services;

use App\Domain\Fleet\Data\IssuedCertificate;
use App\Domain\Vault\Data\SecretPurpose;
use App\Domain\Vault\Data\SecretStatus;
use App\Infrastructure\Vault\Vault;
use App\Models\Secret;
use DomainException;
use InvalidArgumentException;
use LogicException;

/**
 * CA internal tenant (ADR 0007): sertifikat dan pin CA selalu dibuka dari brankas, dan satu-satunya penerbit
 * sertifikat klien agen. Penerbitan tak menulis audit karena tak mengubah state; Action pemanggil (enrolment,
 * CertRenew) yang mencatat serialnya.
 */
final class CertificateAuthority
{
    public function __construct(private readonly Vault $vault) {}

    /** ID rahasia CA aktif tenant, atau null bila belum dibuat (tak pernah dibuat implisit, ADR 0007 §2.1). */
    public function activeKeyId(string $tenantId): ?string
    {
        $id = Secret::query()
            ->where('tenant_id', $tenantId)
            ->where('purpose', SecretPurpose::CaKey->value)
            ->where('status', SecretStatus::Active->value)
            ->value('id');

        return is_string($id) ? $id : null;
    }

    /** Sertifikat CA (PEM) dari brankas, bukan dari kolom DB atau audit (ADR 0007 §2.2). */
    public function certificatePem(string $tenantId): string
    {
        return $this->vault->caCertificate($this->requireKeyId($tenantId), $tenantId);
    }

    /** Pin `--ca-sha256` tenant (KONTRAK §2), dihitung dari sertifikat CA di brankas saat ini. */
    public function fingerprint(string $tenantId): string
    {
        return AgentCertificateProfile::fingerprint($this->certificatePem($tenantId));
    }

    /**
     * Menerbitkan sertifikat klien agen 7 hari untuk $serverId dari CSR agen (ADR 0007 §2.3). CSR yang melanggar
     * KONTRAK §2 dilempar sebagai CertificateRequestRejected; sertifikat hanya dikembalikan bila lolos aturan
     * penerimaan gateway dan profil penerbitan.
     */
    public function issueAgentCertificate(string $tenantId, string $serverId, string $csrPem): IssuedCertificate
    {
        if (! AgentCertificateProfile::isServerId($serverId)) {
            throw new InvalidArgumentException('server_id harus ULID huruf kecil (KONTRAK §8).');
        }
        $request = AgentCertificateProfile::checkRequest($csrPem);
        $keyId = $this->requireKeyId($tenantId);

        $serial = random_int(1, PHP_INT_MAX);
        $certPem = $this->vault->signCertificateRequest(
            $keyId, $tenantId, $request['csr'], AgentCertificateProfile::agentExtensions($serverId), AgentCertificateProfile::AGENT_CERT_DAYS, $serial,
        );

        // Tertulis ⇒ terverifikasi (ADR 0007 §2.3 langkah 5): core tak pernah mengembalikan sertifikat yang ditolak gateway.
        return AgentCertificateProfile::conformingIssued($certPem, $this->vault->caCertificate($keyId, $tenantId), $serverId, $request['publicKey'], $serial)
            ?? throw new LogicException('Sertifikat klien terbitan tak lolos aturan penerimaan atau profil penerbitan KONTRAK §2; tidak dikembalikan.');
    }

    private function requireKeyId(string $tenantId): string
    {
        return $this->activeKeyId($tenantId)
            ?? throw new DomainException('Tidak ada CA internal aktif. Bila belum pernah dibuat, jalankan sadmin:ca-init; bila pernah ada lalu dihancurkan, CA baru adalah rotasi CA yang butuh gerbang manusia (docs/22, ADR 0007 §2.1).');
    }
}
