<?php

namespace App\Infrastructure\WebAuthn;

/** Hasil pendaftaran yang sudah diverifikasi; semua biner mentah (bukan base64). */
final readonly class RegisteredCredential
{
    public function __construct(
        public string $credentialId,
        public string $publicKeyCose,
        public int $alg,
        public int $signCount,
    ) {}
}
