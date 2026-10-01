<?php

namespace App\Domain\Fleet\Services;

use App\Domain\Fleet\Actions\RegisterServer;
use App\Domain\Fleet\Data\EnrollmentTarget;
use App\Domain\Fleet\Data\ServerRegistrationRejected;
use App\Infrastructure\Vault\VaultUnavailable;
use DomainException;

/**
 * Prasyarat perintah enrolment: alamat gateway dan pin CA. Diperiksa sebelum server atau token dibuat, sehingga
 * console tak pernah menyerahkan token yang tak bisa dipakai.
 */
final class EnrollmentInstructions
{
    /** Port gateway publik, hanya di host sAdmin (keputusan D-06). */
    public const GATEWAY_PORT = 8443;

    public function __construct(private readonly CertificateAuthority $ca) {}

    public function target(string $tenantId): EnrollmentTarget
    {
        $host = config('sadmin.gateway_host');
        if (! is_string($host) || ! self::isGatewayHost($host)) {
            throw new ServerRegistrationRejected('gateway_unset');
        }
        if ($this->ca->activeKeyId($tenantId) === null) {
            throw new ServerRegistrationRejected('ca_missing');
        }

        try {
            $pin = $this->ca->fingerprint($tenantId);
        } catch (VaultUnavailable $e) {
            throw new ServerRegistrationRejected('vault_unavailable', $e);
        } catch (DomainException $e) {
            // CA dihancurkan di antara dua kueri di atas.
            throw new ServerRegistrationRejected('ca_missing', $e);
        }

        return new EnrollmentTarget($host.':'.self::GATEWAY_PORT, $pin);
    }

    /**
     * Nama host DNS huruf kecil atau IPv4 yang bisa dimiliki satu mesin (bukan loopback, siaran, atau multicast);
     * nama ini wajib ada di SAN sertifikat server gateway (KONTRAK §2).
     */
    public static function isGatewayHost(string $host): bool
    {
        return RegisterServer::isHostname($host)
            || (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && RegisterServer::serverAddress($host) === $host);
    }
}
