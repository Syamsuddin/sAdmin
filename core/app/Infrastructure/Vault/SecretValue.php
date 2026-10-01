<?php

namespace App\Infrastructure\Vault;

use InvalidArgumentException;
use LogicException;
use SensitiveParameter;
use WeakMap;

/**
 * Pembawa nilai rahasia polos (ADR 0003 §2.4). Nilainya disimpan di luar objek (WeakMap privat), sehingga
 * var_dump, print_r, var_export, json_encode, dan cast (array) tak pernah mencetaknya, dan objek tak dapat
 * diserialisasi atau diklon. Nilai hanya keluar lewat expose(), tepat di titik pemakaiannya.
 */
final class SecretValue
{
    /** @var WeakMap<self, string>|null */
    private static ?WeakMap $values = null;

    public function __construct(#[SensitiveParameter] string $value)
    {
        if ($value === '') {
            throw new InvalidArgumentException('Nilai rahasia tak boleh kosong.');
        }

        self::$values ??= new WeakMap;
        self::$values[$this] = $value;
    }

    public function expose(): string
    {
        return self::$values[$this] ?? throw new LogicException('SecretValue tanpa nilai.');
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->expose(), $other->expose());
    }

    /** @return array{value: string} */
    public function __debugInfo(): array
    {
        return ['value' => '[disamarkan]'];
    }

    /** @return array<never> */
    public function __serialize(): array
    {
        throw new LogicException('SecretValue tak boleh diserialisasi (ADR 0003 §2.4).');
    }

    /** @param  array<array-key, mixed>  $data */
    public function __unserialize(array $data): void
    {
        throw new LogicException('SecretValue tak boleh diserialisasi (ADR 0003 §2.4).');
    }

    private function __clone() {}
}
