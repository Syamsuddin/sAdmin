<?php

namespace App\Domain\Fleet\Services;

use App\Infrastructure\Jcs\Jcs;
use App\Infrastructure\Vault\Ed25519;
use InvalidArgumentException;

/**
 * Sidik jari kepercayaan enrolment (ADR 0008 §2.6). Byte yang di-hash dimiliki ../kontrak/KONTRAK.md §3;
 * mengubahnya = kontrak major + gerbang manusia (docs/22), karena sudah tersemat di agen.
 */
final class TrustFingerprint
{
    public const MESSAGE_PREFIX = "sadmin-trust/1\n";

    private const MEMBERS = ['audit_pubkey', 'policy_hash', 'roster_hash', 'server_id', 'service_pubkey'];

    /**
     * @param  array<string, mixed>  $input
     */
    public static function message(array $input): string
    {
        $members = array_keys($input);
        sort($members);
        if ($members !== self::MEMBERS) {
            throw new InvalidArgumentException('Sidik jari butuh tepat lima anggota (KONTRAK §3).');
        }
        foreach (['roster_hash', 'policy_hash'] as $key) {
            if (! is_string($input[$key]) || preg_match('/\A[0-9a-f]{64}\z/', $input[$key]) !== 1) {
                throw new InvalidArgumentException("{$key} harus 64 hex huruf kecil.");
            }
        }
        foreach (['service_pubkey', 'audit_pubkey'] as $key) {
            if (! is_string($input[$key]) || ! self::isCanonicalPublicKey($input[$key])) {
                throw new InvalidArgumentException("{$key} harus base64 baku berpadding kanonik dari 32 byte.");
            }
        }
        if (! is_string($input['server_id']) || preg_match('/\A[0-7][0-9a-hjkmnp-tv-z]{25}\z/', $input['server_id']) !== 1) {
            throw new InvalidArgumentException('server_id harus ULID huruf kecil (KONTRAK §8).');
        }

        return self::MESSAGE_PREFIX.Jcs::canonicalize($input);
    }

    /** @param  array<string, mixed>  $input */
    public static function compute(array $input): string
    {
        return hash('sha256', self::message($input));
    }

    /** 16 kelompok 4 karakter, 8 per baris, dua baris dipisah satu LF (KONTRAK §3). */
    public static function display(string $fingerprint): string
    {
        if (preg_match('/\A[0-9a-f]{64}\z/', $fingerprint) !== 1) {
            throw new InvalidArgumentException('Sidik jari harus 64 hex huruf kecil.');
        }
        $groups = str_split($fingerprint, 4);

        return implode(' ', array_slice($groups, 0, 8))."\n".implode(' ', array_slice($groups, 8));
    }

    private static function isCanonicalPublicKey(string $text): bool
    {
        if (strlen($text) !== 44 || preg_match('/\A[A-Za-z0-9+\/]{43}=\z/', $text) !== 1) {
            return false;
        }
        $raw = base64_decode($text, true);

        return $raw !== false && strlen($raw) === 32 && Ed25519::encode($raw) === $text;
    }
}
