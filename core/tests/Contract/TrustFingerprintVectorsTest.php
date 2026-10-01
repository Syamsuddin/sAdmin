<?php

namespace Tests\Contract;

use App\Domain\Fleet\Services\TrustDocuments;
use App\Domain\Fleet\Services\TrustFingerprint;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Vektor bersama PHP↔Go untuk sidik jari kepercayaan enrolment: ../kontrak/vectors/trust-fingerprint (KONTRAK §3),
 * dihitung oracle independen (ADR 0008 §2.6). Merah di sini = format berubah = gerbang manusia, bukan tes yang disesuaikan.
 */
#[Group('contract')]
class TrustFingerprintVectorsTest extends TestCase
{
    private static function vectorDir(): string
    {
        return dirname(__DIR__, 3).'/kontrak/vectors/trust-fingerprint';
    }

    /** @return iterable<string, array{string}> */
    public static function vectors(): iterable
    {
        foreach (glob(self::vectorDir().'/*.json') ?: [] as $path) {
            yield basename($path) => [$path];
        }
    }

    public function test_vector_set_covers_valid_and_rejected_inputs(): void
    {
        $valid = array_map(fn (array $a): bool => json_decode((string) file_get_contents($a[0]), true, 512, JSON_THROW_ON_ERROR)['valid'], iterator_to_array(self::vectors()));

        $this->assertContains(true, $valid, 'Vektor sidik jari sah tak ditemukan di '.self::vectorDir());
        $this->assertContains(false, $valid, 'Vektor sidik jari tolak tak ditemukan di '.self::vectorDir());
    }

    #[DataProvider('vectors')]
    public function test_php_matches_shared_trust_fingerprint_vector(string $path): void
    {
        $vector = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

        if (! $vector['valid']) {
            $this->expectException(InvalidArgumentException::class);
            TrustFingerprint::message($vector['input']);

            return;
        }

        $this->assertSame($vector['message'], TrustFingerprint::message($vector['input']));
        $this->assertSame($vector['fingerprint'], TrustFingerprint::compute($vector['input']));
        $this->assertSame($vector['display'], TrustFingerprint::display($vector['fingerprint']));
    }

    public function test_document_hashes_in_the_baseline_vector_come_from_jcs_of_the_documents(): void
    {
        $vector = json_decode((string) file_get_contents(self::vectorDir().'/01-baseline.json'), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame($vector['input']['roster_hash'], TrustDocuments::hash($vector['roster_document']));
        $this->assertSame($vector['input']['policy_hash'], TrustDocuments::hash($vector['policy_document']));
    }

    public function test_contract_constant_matches_the_contract_version_file(): void
    {
        $version = trim((string) file_get_contents(dirname(__DIR__, 3).'/kontrak/VERSION'));

        $this->assertSame(implode('.', array_slice(explode('.', $version), 0, 2)), TrustDocuments::CONTRACT, 'Naikkan TrustDocuments::CONTRACT bersama kontrak/VERSION (kontrak major/minor 0.x memutus).');
    }
}
