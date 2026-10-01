<?php

namespace Tests\Contract;

use App\Domain\Audit\Services\CheckpointSigner;
use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\SecretValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Vektor bersama PHP↔Go untuk tanda tangan kunci audit: ../kontrak/vectors/checkpoint (../kontrak/KONTRAK.md §3),
 * dihitung oracle independen (ADR 0004 §2.2). Merah di sini = format berubah = gerbang manusia, bukan tes yang disesuaikan.
 */
#[Group('contract')]
class CheckpointSignatureVectorsTest extends TestCase
{
    private static function vectorDir(): string
    {
        return dirname(__DIR__, 3).'/kontrak/vectors/checkpoint';
    }

    /** @return iterable<string, array{string}> */
    public static function vectors(): iterable
    {
        foreach (glob(self::vectorDir().'/*.json') ?: [] as $path) {
            yield basename($path) => [$path];
        }
    }

    public function test_vector_set_has_valid_and_invalid_cases(): void
    {
        $verdicts = array_map(
            fn (array $args): bool => json_decode((string) file_get_contents($args[0]), false, 512, JSON_THROW_ON_ERROR)->valid,
            iterator_to_array(self::vectors()),
        );

        $this->assertContains(true, $verdicts, 'Vektor checkpoint sah tak ditemukan di '.self::vectorDir());
        $this->assertContains(false, $verdicts, 'Vektor checkpoint tolak tak ditemukan di '.self::vectorDir());
    }

    #[DataProvider('vectors')]
    public function test_php_matches_shared_checkpoint_vector(string $path): void
    {
        $vector = json_decode((string) file_get_contents($path), false, 512, JSON_THROW_ON_ERROR);
        $seed = new SecretValue((string) hex2bin($vector->seed_hex));
        $checkpoint = $vector->checkpoint;

        $publicKey = Ed25519::publicKey($seed);
        $this->assertSame($vector->public_key, Ed25519::encode($publicKey));

        $message = CheckpointSigner::message($checkpoint->seq, $checkpoint->hash, $checkpoint->created_at);
        $this->assertSame($vector->message, $message);

        if ($vector->valid) {
            $this->assertSame($vector->signature, Ed25519::encode(Ed25519::sign($seed, $message)), 'Ed25519 deterministik: tanda tangan wajib identik.');
        }
        $this->assertSame($vector->valid, CheckpointSigner::verify($publicKey, $checkpoint->seq, $checkpoint->hash, $checkpoint->created_at, $vector->signature));
    }
}
