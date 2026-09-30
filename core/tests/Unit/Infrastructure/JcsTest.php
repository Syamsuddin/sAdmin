<?php

namespace Tests\Unit\Infrastructure;

use App\Infrastructure\Jcs\Jcs;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

class JcsTest extends TestCase
{
    /** @return iterable<string, array{mixed}> */
    public static function forbiddenValues(): iterable
    {
        yield 'pecahan' => [1.5];
        yield 'pecahan bernilai bulat' => [1.0];
        yield 'pecahan bersarang' => [['a' => ['b' => 0.1]]];
        yield 'integer di atas 2^53-1' => [Jcs::MAX_SAFE_INTEGER + 1];
        yield 'integer di bawah -(2^53-1)' => [-Jcs::MAX_SAFE_INTEGER - 1];
        yield 'string bukan UTF-8' => ["\xff\xfe"];
        yield 'kunci bukan UTF-8' => [["\xff" => 1]];
        yield 'objek tak didukung' => [new DateTimeImmutable];
    }

    #[DataProvider('forbiddenValues')]
    public function test_rejects_values_that_would_diverge_between_php_and_go(mixed $value): void
    {
        $this->expectException(InvalidArgumentException::class);

        Jcs::canonicalize($value);
    }

    public function test_accepts_safe_integer_bounds(): void
    {
        $this->assertSame('[9007199254740991,-9007199254740991]', Jcs::canonicalize([Jcs::MAX_SAFE_INTEGER, -Jcs::MAX_SAFE_INTEGER]));
    }

    public function test_enforces_maximum_nesting_depth(): void
    {
        $nested = [];
        for ($i = 1; $i < Jcs::MAX_DEPTH; $i++) {
            $nested = [$nested];
        }
        $this->assertSame(str_repeat('[', Jcs::MAX_DEPTH).str_repeat(']', Jcs::MAX_DEPTH), Jcs::canonicalize($nested));

        $this->expectException(InvalidArgumentException::class);
        Jcs::canonicalize([$nested]);
    }

    /** @return iterable<string, array{string}> */
    public static function duplicateKeys(): iterable
    {
        yield 'langsung' => ['{"a":1,"a":2}'];
        yield 'dengan spasi' => ['{ "a" : 1 , "a" : 2 }'];
        yield 'setelah escape' => ['{"a":1,"a":2}'];
        yield 'bersarang di larik' => ['[{"k":{"x":1,"x":2}}]'];
    }

    #[DataProvider('duplicateKeys')]
    public function test_strict_decoder_rejects_duplicate_member_names(string $json): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('JCS: nama anggota ganda');

        Jcs::decode($json);
    }

    /** @return iterable<string, array{string}> */
    public static function lookalikesOfDuplicates(): iterable
    {
        yield 'kunci sama di objek berbeda' => ['[{"a":1},{"a":2}]'];
        yield 'titik dua di dalam string' => ['{"a":"x\":y","b":"a"}'];
        yield 'string berakhir backslash' => ['{"a":"\\\\","b":1}'];
        yield 'kunci beda kapital' => ['{"a":1,"A":2}'];
    }

    #[DataProvider('lookalikesOfDuplicates')]
    public function test_strict_decoder_accepts_lookalikes_of_duplicates(string $json): void
    {
        $this->assertSame(Jcs::canonicalize(json_decode($json)), Jcs::canonicalize(Jcs::decode($json)));
    }

    public function test_strict_decoder_keeps_objects_as_objects(): void
    {
        $this->assertSame('{"a":{},"b":[]}', Jcs::canonicalize(Jcs::decode('{"b":[],"a":{}}')));
    }

    public function test_empty_php_array_is_array_and_empty_stdclass_is_object(): void
    {
        $this->assertSame('[]', Jcs::canonicalize([]));
        $this->assertSame('{}', Jcs::canonicalize(new stdClass));
    }

    public function test_non_list_array_becomes_object_with_keys_sorted_as_strings(): void
    {
        $this->assertSame('{"10":"a","2":"b"}', Jcs::canonicalize([2 => 'b', 10 => 'a']));
    }

    public function test_numeric_stdclass_properties_keep_string_keys(): void
    {
        $this->assertSame('{"1":true}', Jcs::canonicalize(json_decode('{"1":true}')));
    }

    public function test_hash_is_lowercase_sha256_of_canonical_form(): void
    {
        $this->assertSame(hash('sha256', '{"a":1,"b":[]}'), Jcs::hash(['b' => [], 'a' => 1]));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', Jcs::hash(null));
    }
}
