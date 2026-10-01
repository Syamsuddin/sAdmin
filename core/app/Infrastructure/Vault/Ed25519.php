<?php

namespace App\Infrastructure\Vault;

use SensitiveParameter;

/**
 * Ed25519 murni (RFC 8032) untuk kunci penanda tangan yang seed-nya tersimpan di brankas. Satu-satunya pemanggil
 * sodium_crypto_sign_* (ADR 0004 §2.1). Kunci publik dan tanda tangan dikodekan base64 standar berpadding
 * (../kontrak/KONTRAK.md §3); pengodean yang tak kanonik dianggap tak sah.
 */
final class Ed25519
{
    public const SEED_BYTES = SODIUM_CRYPTO_SIGN_SEEDBYTES;

    public const PUBLIC_KEY_BYTES = SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;

    public const SIGNATURE_BYTES = SODIUM_CRYPTO_SIGN_BYTES;

    public static function generateSeed(): SecretValue
    {
        return new SecretValue(random_bytes(self::SEED_BYTES));
    }

    /** Kunci publik 32 byte mentah. */
    public static function publicKey(#[SensitiveParameter] SecretValue $seed): string
    {
        $keypair = self::keypair($seed);
        try {
            return sodium_crypto_sign_publickey($keypair);
        } finally {
            sodium_memzero($keypair);
        }
    }

    /** Tanda tangan 64 byte mentah. */
    public static function sign(#[SensitiveParameter] SecretValue $seed, string $message): string
    {
        $keypair = self::keypair($seed);
        $secretKey = sodium_crypto_sign_secretkey($keypair);
        sodium_memzero($keypair);
        try {
            return sodium_crypto_sign_detached($message, $secretKey);
        } finally {
            sodium_memzero($secretKey);
        }
    }

    public static function verify(string $publicKey, string $message, string $signature): bool
    {
        if (strlen($publicKey) !== self::PUBLIC_KEY_BYTES || strlen($signature) !== self::SIGNATURE_BYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
    }

    public static function encode(string $bytes): string
    {
        return base64_encode($bytes);
    }

    /** Dekode base64 standar berpadding secara ketat; null bila tak sah atau tak kanonik. */
    public static function decode(string $text): ?string
    {
        $bytes = base64_decode($text, true);

        return $bytes !== false && base64_encode($bytes) === $text ? $bytes : null;
    }

    private static function keypair(SecretValue $seed): string
    {
        if (strlen($seed->expose()) !== self::SEED_BYTES) {
            throw new VaultIntegrityError('Seed Ed25519 di brankas harus tepat 32 byte.');
        }

        return sodium_crypto_sign_seed_keypair($seed->expose());
    }
}
