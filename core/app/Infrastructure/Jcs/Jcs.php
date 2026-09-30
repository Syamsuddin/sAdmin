<?php

namespace App\Infrastructure\Jcs;

use InvalidArgumentException;
use JsonException;
use stdClass;

/**
 * Kanonisasi RFC 8785 (JCS) — aturan: ../kontrak/KONTRAK.md §3, vektor: ../kontrak/vectors/jcs.
 *
 * Angka pecahan ditolak dan integer dibatasi ke rentang yang persis terwakili double IEEE-754,
 * karena kontrak mewajibkan integer atau string di badan kanonik agar PHP dan Go identik byte-per-byte.
 */
final class Jcs
{
    public const MAX_SAFE_INTEGER = 9007199254740991;

    /** Batas sarang objek/larik: apa pun yang lolos kanonisasi juga lolos json_decode saat verifikasi. */
    public const MAX_DEPTH = 64;

    public static function canonicalize(mixed $value): string
    {
        return self::value($value, 0);
    }

    private static function value(mixed $value, int $depth): string
    {
        if ((is_array($value) || $value instanceof stdClass) && $depth >= self::MAX_DEPTH) {
            throw new InvalidArgumentException('JCS: struktur bersarang melebihi '.self::MAX_DEPTH.' tingkat.');
        }

        return match (true) {
            $value === null => 'null',
            $value === true => 'true',
            $value === false => 'false',
            is_int($value) => self::integer($value),
            is_string($value) => self::string($value),
            is_float($value) => throw new InvalidArgumentException('JCS: angka pecahan dilarang di badan kanonik; pakai integer atau string.'),
            $value instanceof stdClass => self::object(get_object_vars($value), $depth + 1),
            is_array($value) => array_is_list($value) ? self::list($value, $depth + 1) : self::object($value, $depth + 1),
            default => throw new InvalidArgumentException('JCS: tipe '.get_debug_type($value).' tak didukung.'),
        };
    }

    /**
     * Pengurai ketat untuk teks JSON dari luar (KONTRAK §3, E_CANONICAL): menolak, tidak memperbaiki,
     * masukan yang bukan I-JSON. Objek tetap stdClass agar `{}` dan `[]` terbedakan saat dikanonisasi ulang.
     */
    public static function decode(string $json): mixed
    {
        if (str_starts_with($json, "\xEF\xBB\xBF")) {
            throw new InvalidArgumentException('JCS: teks diawali BOM.');
        }
        if (! mb_check_encoding($json, 'UTF-8')) {
            throw new InvalidArgumentException('JCS: teks bukan UTF-8 yang sah.');
        }
        if (! json_validate($json)) {
            throw new InvalidArgumentException('JCS: bukan JSON yang sah ('.json_last_error_msg().').');
        }

        // Sebelum json_decode ke objek: PHP menolak nama properti berawalan NUL dengan pesan yang menyesatkan.
        self::assertValidMemberNames($json);

        try {
            $value = json_decode($json, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('JCS: bukan JSON yang sah ('.$e->getMessage().').', previous: $e);
        }

        self::canonicalize($value);

        return $value;
    }

    /** SHA-256 hex huruf kecil atas bentuk kanonik. */
    public static function hash(mixed $value): string
    {
        return hash('sha256', self::canonicalize($value));
    }

    private static function integer(int $value): string
    {
        if ($value > self::MAX_SAFE_INTEGER || $value < -self::MAX_SAFE_INTEGER) {
            // Nilai sengaja tak disebut: pesan ini bisa berakhir di log integritas (docs/21).
            throw new InvalidArgumentException('JCS: integer di luar ±2^53-1; kirim sebagai string.');
        }

        return (string) $value;
    }

    private static function string(string $value): string
    {
        if (! mb_check_encoding($value, 'UTF-8')) {
            throw new InvalidArgumentException('JCS: string bukan UTF-8 yang sah.');
        }

        // Tanpa flag /u: byte 0x00–0x1F, '"', dan '\' tak pernah muncul di dalam urutan multibyte UTF-8.
        $escaped = preg_replace_callback('/[\x00-\x1f"\\\\]/', static fn (array $m): string => match ($m[0]) {
            '"' => '\\"',
            '\\' => '\\\\',
            "\x08" => '\\b',
            "\t" => '\\t',
            "\n" => '\\n',
            "\x0c" => '\\f',
            "\r" => '\\r',
            default => sprintf('\\u%04x', ord($m[0])),
        }, $value) ?? throw new InvalidArgumentException('JCS: gagal meng-escape string.');

        return '"'.$escaped.'"';
    }

    /** @param list<mixed> $items */
    private static function list(array $items, int $depth): string
    {
        return '['.implode(',', array_map(static fn (mixed $item): string => self::value($item, $depth), $items)).']';
    }

    /** @param array<array-key, mixed> $members */
    private static function object(array $members, int $depth): string
    {
        $pairs = [];
        foreach ($members as $key => $member) {
            $key = (string) $key;
            self::assertNoNulInName($key);
            $pairs[] = [self::utf16SortKey($key), $key, $member];
        }

        usort($pairs, static fn (array $a, array $b): int => strcmp($a[0], $b[0]));

        $parts = array_map(
            static fn (array $pair): string => self::string($pair[1]).':'.self::value($pair[2], $depth),
            $pairs,
        );

        return '{'.implode(',', $parts).'}';
    }

    /**
     * Nama anggota unik per objek (json_decode diam-diam memakai nilai terakhir) dan tanpa U+0000 (KONTRAK §3).
     * Dipanggil setelah json_validate berhasil, jadi teks dijamin JSON yang sah (string selalu tertutup).
     */
    private static function assertValidMemberNames(string $json): void
    {
        /** @var list<array<array-key, true>> $scopes satu set nama per objek/larik yang sedang terbuka */
        $scopes = [];
        $length = strlen($json);

        for ($i = 0; $i < $length; $i++) {
            $char = $json[$i];

            if ($char === '{' || $char === '[') {
                $scopes[] = [];
            } elseif ($char === '}' || $char === ']') {
                array_pop($scopes);
            } elseif ($char === '"') {
                $start = $i;
                for ($i++; $json[$i] !== '"'; $i++) {
                    if ($json[$i] === '\\') {
                        $i++;
                    }
                }

                $after = $i + 1 + strspn($json, " \t\n\r", $i + 1);
                if (($json[$after] ?? '') !== ':') {
                    continue;
                }

                $name = (string) json_decode(substr($json, $start, $i - $start + 1), false, 512, JSON_THROW_ON_ERROR);
                self::assertNoNulInName($name);
                $top = array_key_last($scopes);
                if (isset($scopes[$top][$name])) {
                    throw new InvalidArgumentException('JCS: nama anggota ganda dalam satu objek.');
                }
                $scopes[$top][$name] = true;
            }
        }
    }

    private static function assertNoNulInName(string $name): void
    {
        if (str_contains($name, "\0")) {
            throw new InvalidArgumentException('JCS: nama anggota memuat U+0000.');
        }
    }

    /** RFC 8785 §3.2.3: kunci diurutkan per unit kode UTF-16; UTF-16BE membuat strcmp setara. */
    private static function utf16SortKey(string $key): string
    {
        if (! mb_check_encoding($key, 'UTF-8')) {
            throw new InvalidArgumentException('JCS: kunci objek bukan UTF-8 yang sah.');
        }

        return mb_convert_encoding($key, 'UTF-16BE', 'UTF-8');
    }
}
