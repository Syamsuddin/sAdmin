<?php

namespace App\Domain\Identity\Data;

use RuntimeException;

/**
 * Penolakan ceremony passkey. `reason` memetakan ke lang/id/errors.php (langkah, penyebab, tindakan) dan
 * tak pernah memuat isi dari klien; detail teknis hanya ke log bersama ID korelasi (docs/14).
 */
final class PasskeyRejected extends RuntimeException
{
    public const REASONS = [
        'challenge_missing', 'unknown_credential', 'verification_failed', 'admin_inactive',
        'registration_complete', 'credential_exists', 'invalid_label', 'invite_expired', 'rate_limited',
        'cancelled', 'unsupported', 'origin_mismatch',
    ];

    public function __construct(public readonly string $reason)
    {
        parent::__construct("Passkey ditolak: {$reason}");
    }
}
