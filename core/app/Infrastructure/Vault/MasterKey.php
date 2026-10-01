<?php

namespace App\Infrastructure\Vault;

use InvalidArgumentException;

/** Kunci induk brankas yang sudah dibuka systemd (ADR 0003 §2.1). `source` hanya label tampilan, bukan rahasia. */
final readonly class MasterKey
{
    /** Satu-satunya versi yang didukung; versi lain = rotasi kunci induk (butuh ADR baru). */
    public const CURRENT_VERSION = 1;

    public const BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    public function __construct(
        public int $version,
        private SecretValue $key,
        public string $source,
    ) {
        if (strlen($key->expose()) !== self::BYTES) {
            throw new InvalidArgumentException('Kunci induk harus tepat '.self::BYTES.' byte.');
        }
    }

    public function bytes(): string
    {
        return $this->key->expose();
    }
}
