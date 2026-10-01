<?php

namespace Tests\Unit\Infrastructure;

use App\Infrastructure\Vault\SecretValue;
use Error;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;

/** ADR 0003 §2.4: nilai rahasia hanya keluar lewat expose(), tak lewat dump, serialisasi, atau klon. */
class SecretValueTest extends TestCase
{
    private const CANARY = 'CANARY-secretvalue-7f3a9c';

    public function test_exposes_the_value_and_compares_in_constant_time(): void
    {
        $value = new SecretValue(self::CANARY);

        $this->assertSame(self::CANARY, $value->expose());
        $this->assertTrue($value->equals(new SecretValue(self::CANARY)));
        $this->assertFalse($value->equals(new SecretValue(self::CANARY.'x')));
    }

    public function test_binary_values_survive(): void
    {
        $binary = "\x00\xff\x00".random_bytes(29);

        $this->assertSame($binary, (new SecretValue($binary))->expose());
    }

    public function test_empty_value_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new SecretValue('');
    }

    public function test_dumps_and_casts_never_print_the_value(): void
    {
        $value = new SecretValue(self::CANARY);

        ob_start();
        var_dump($value);
        $dumped = (string) ob_get_clean();

        foreach ([
            'var_dump' => $dumped,
            'print_r' => print_r($value, true),
            'print_r (array)' => print_r((array) $value, true),
            'var_export' => var_export($value, true),
            'json_encode' => (string) json_encode($value),
            'get_object_vars' => print_r(get_object_vars($value), true),
        ] as $how => $output) {
            $this->assertStringNotContainsString(self::CANARY, $output, $how);
        }
        $this->assertStringContainsString('[disamarkan]', print_r($value, true));
    }

    public function test_cannot_be_serialized_or_cloned(): void
    {
        $value = new SecretValue(self::CANARY);

        try {
            serialize($value);
            $this->fail('serialize() harus ditolak.');
        } catch (LogicException $e) {
            $this->assertStringNotContainsString(self::CANARY, $e->getMessage());
        }

        try {
            clone $value;
            $this->fail('clone harus ditolak.');
        } catch (Error $e) {
            $this->assertStringContainsString('__clone', $e->getMessage());
        }
    }
}
