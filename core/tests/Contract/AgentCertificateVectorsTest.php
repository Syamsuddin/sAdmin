<?php

namespace Tests\Contract;

use App\Domain\Fleet\Data\CertificateRequestRejected;
use App\Domain\Fleet\Data\CertificateVerification;
use App\Domain\Fleet\Services\AgentCertificateProfile;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Vektor bersama PHP↔Go untuk CSR agen dan sertifikat klien agen: ../kontrak/vectors/agent-csr dan agent-cert
 * (../kontrak/KONTRAK.md §2), dihasilkan oracle independen (ADR 0007). Merah di sini = aturan berubah = gerbang
 * manusia, bukan tes yang disesuaikan.
 */
#[Group('contract')]
class AgentCertificateVectorsTest extends TestCase
{
    private static function vectorDir(string $set): string
    {
        return dirname(__DIR__, 3).'/kontrak/vectors/'.$set;
    }

    /** @return array<string, mixed> */
    private static function load(string $path): array
    {
        return json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
    }

    /** @return iterable<string, array{string}> */
    public static function csrVectors(): iterable
    {
        foreach (glob(self::vectorDir('agent-csr').'/*.json') ?: [] as $path) {
            yield basename($path) => [$path];
        }
    }

    /** @return iterable<string, array{string}> */
    public static function certificateVectors(): iterable
    {
        foreach (glob(self::vectorDir('agent-cert').'/*.json') ?: [] as $path) {
            yield basename($path) => [$path];
        }
    }

    public function test_vector_sets_cover_acceptance_and_every_rejection_reason(): void
    {
        $csr = array_map(fn (array $args): array => self::load($args[0]), iterator_to_array(self::csrVectors()));
        $certificates = array_map(fn (array $args): array => self::load($args[0]), iterator_to_array(self::certificateVectors()));

        $this->assertContains(true, array_column($csr, 'valid'), 'Vektor CSR sah tak ditemukan di '.self::vectorDir('agent-csr'));
        $this->assertContains(true, array_column($certificates, 'valid'), 'Vektor sertifikat sah tak ditemukan di '.self::vectorDir('agent-cert'));
        $this->assertEqualsCanonicalizing(CertificateRequestRejected::REASONS, array_values(array_unique(array_filter(array_column($csr, 'reason')))));
        $this->assertEqualsCanonicalizing(CertificateVerification::REASONS, array_values(array_unique(array_filter(array_column($certificates, 'reason')))));
    }

    #[DataProvider('csrVectors')]
    public function test_php_matches_shared_csr_vector(string $path): void
    {
        $vector = self::load($path);

        try {
            $request = AgentCertificateProfile::checkRequest($vector['csr_pem']);
            $reason = null;
        } catch (CertificateRequestRejected $e) {
            $reason = $e->reason;
        }

        $this->assertSame($vector['reason'], $reason);
        $this->assertSame($vector['valid'], $reason === null);
        if (isset($request)) {
            // CSR yang diteruskan ke OpenSSL dibangun ulang dari DER: blok yang sama, selalu diakhiri tepat satu LF.
            $this->assertSame(rtrim($vector['csr_pem'], "\n")."\n", $request['csr']);
            $this->assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $request['publicKey']);
        }
    }

    #[DataProvider('certificateVectors')]
    public function test_php_matches_shared_certificate_vector(string $path): void
    {
        $vector = self::load($path);
        $now = (new DateTimeImmutable($vector['now']))->getTimestamp();

        $result = AgentCertificateProfile::verify($vector['cert_pem'], $vector['ca_pem'], $now);

        $this->assertSame($vector['reason'], $result->reason);
        $this->assertSame($vector['server_id'], $result->serverId);
        $this->assertSame($vector['valid'], $result->valid());
        $this->assertSame($vector['ca_sha256'], AgentCertificateProfile::fingerprint($vector['ca_pem']));
        $this->assertSame(hash('sha256', (string) base64_decode(preg_replace('/-----[^-]+-----|\s/', '', $vector['ca_pem']) ?? '', true)), $vector['ca_sha256']);
    }

    /** Sertifikat sah buatan oracle = profil penerbitan core: keduanya ditulis dari teks KONTRAK §2 yang sama. */
    public function test_oracle_valid_certificate_conforms_to_the_issuance_profile(): void
    {
        $vector = self::load(self::vectorDir('agent-cert').'/01-valid.json');
        $info = openssl_x509_parse($vector['cert_pem']);
        $this->assertIsArray($info);
        $publicKey = openssl_pkey_get_details(openssl_pkey_get_public($vector['cert_pem']));
        $this->assertIsArray($publicKey);

        $issued = AgentCertificateProfile::conformingIssued($vector['cert_pem'], $vector['ca_pem'], $vector['server_id'], $publicKey['key'], (int) $info['serialNumber']);

        $this->assertNotNull($issued, 'Sertifikat sah oracle tak lolos profil penerbitan core.');
        $this->assertSame($vector['cert_pem'], $issued->certificatePem);
        $this->assertSame('5ad0000000000001', $issued->serial);
        $this->assertSame('2026-10-01T00:00:00+00:00', $issued->notBefore->format(DATE_ATOM));
        $this->assertSame('2026-10-08T00:00:00+00:00', $issued->notAfter->format(DATE_ATOM));

        // Serial lain atau server_id lain = bukan sertifikat yang diminta.
        $this->assertNull(AgentCertificateProfile::conformingIssued($vector['cert_pem'], $vector['ca_pem'], $vector['server_id'], $publicKey['key'], (int) $info['serialNumber'] + 1));
        $this->assertNull(AgentCertificateProfile::conformingIssued($vector['cert_pem'], $vector['ca_pem'], '01k6f3h9m2q7r4s8t0v5w1x3y7', $publicKey['key'], (int) $info['serialNumber']));
    }
}
