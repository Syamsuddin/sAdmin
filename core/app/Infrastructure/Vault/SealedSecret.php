<?php

namespace App\Infrastructure\Vault;

/** Hasil enkripsi envelope satu rahasia, siap ditulis ke key_wraps & secrets (ADR 0003 §2.2–2.3). Tanpa nilai polos. */
final readonly class SealedSecret
{
    public function __construct(
        public string $wrappedDek,
        public int $masterKeyVersion,
        public string $nonce,
        public string $ciphertext,
    ) {}
}
