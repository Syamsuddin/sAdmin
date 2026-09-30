<?php

namespace App\Models\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * Kolom PostgreSQL bytea. PDO pgsql mengirim parameter sebagai teks, sehingga biner mentah terpotong
 * DIAM-DIAM di byte NUL pertama; karena itu nilai selalu ditulis dalam format hex `\x…`.
 * Saat dibaca, PDO mengembalikan stream.
 *
 * @implements CastsAttributes<string|null, mixed>
 */
final class Bytea implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }
        if (is_resource($value)) {
            rewind($value);

            return (string) stream_get_contents($value);
        }
        if (is_string($value) && str_starts_with($value, '\\x')) {
            return (string) hex2bin(substr($value, 2));
        }

        throw new InvalidArgumentException("Kolom bytea [{$key}] tak dikenali formatnya.");
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw new InvalidArgumentException("Kolom bytea [{$key}] harus string biner.");
        }

        return self::literal($value);
    }

    /** Bentuk parameter kueri untuk membandingkan kolom bytea, mis. where('credential_id', Bytea::literal($id)). */
    public static function literal(string $binary): string
    {
        return '\\x'.bin2hex($binary);
    }
}
