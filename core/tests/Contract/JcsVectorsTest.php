<?php

namespace Tests\Contract;

use App\Infrastructure\Jcs\Jcs;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/** Vektor bersama PHP↔Go: ../kontrak/vectors/jcs (../kontrak/KONTRAK.md §3). */
#[Group('contract')]
class JcsVectorsTest extends TestCase
{
    private static function vectorDir(): string
    {
        return dirname(__DIR__, 3).'/kontrak/vectors/jcs';
    }

    /** @return iterable<string, array{string}> */
    public static function vectors(): iterable
    {
        foreach (glob(self::vectorDir().'/*.json') ?: [] as $path) {
            yield basename($path) => [$path];
        }
    }

    public function test_vector_set_is_present(): void
    {
        $this->assertNotEmpty(iterator_to_array(self::vectors()), 'Vektor JCS tak ditemukan di '.self::vectorDir());
    }

    #[DataProvider('vectors')]
    public function test_php_canonical_form_matches_shared_vector(string $path): void
    {
        $vector = json_decode((string) file_get_contents($path), false, 512, JSON_THROW_ON_ERROR);

        $canonical = Jcs::canonicalize($vector->input);

        $this->assertSame($vector->canonical, $canonical);
        $this->assertSame($vector->sha256, hash('sha256', $vector->canonical));
        $this->assertSame($vector->sha256, Jcs::hash($vector->input));
    }

    #[DataProvider('vectors')]
    public function test_strict_decoder_accepts_vector_text_and_round_trips(string $path): void
    {
        $vector = json_decode((string) file_get_contents($path), false, 512, JSON_THROW_ON_ERROR);
        $text = json_encode($vector->input, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $this->assertSame($vector->canonical, Jcs::canonicalize(Jcs::decode($text)));
    }
}
