<?php

namespace Tests\Contract;

use App\Infrastructure\Jcs\Jcs;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/** Vektor tolak bersama PHP↔Go: ../kontrak/vectors/jcs-reject (../kontrak/KONTRAK.md §3, E_CANONICAL). */
#[Group('contract')]
class JcsRejectVectorsTest extends TestCase
{
    private static function vectorDir(): string
    {
        return dirname(__DIR__, 3).'/kontrak/vectors/jcs-reject';
    }

    /** @return iterable<string, array{string}> */
    public static function vectors(): iterable
    {
        foreach (glob(self::vectorDir().'/*.json') ?: [] as $path) {
            yield basename($path) => [$path];
        }
    }

    public function test_reject_vector_set_is_present(): void
    {
        $this->assertNotEmpty(iterator_to_array(self::vectors()), 'Vektor tolak tak ditemukan di '.self::vectorDir());
    }

    #[DataProvider('vectors')]
    public function test_php_rejects_non_ijson_input(string $path): void
    {
        $vector = json_decode((string) file_get_contents($path), false, 512, JSON_THROW_ON_ERROR);
        $raw = base64_decode($vector->input_base64, true);
        $this->assertIsString($raw);

        try {
            Jcs::decode($raw);
            $this->fail("Masukan seharusnya ditolak ({$vector->reason}): {$vector->description}");
        } catch (InvalidArgumentException $e) {
            $this->assertStringStartsWith('JCS:', $e->getMessage());
        }
    }
}
