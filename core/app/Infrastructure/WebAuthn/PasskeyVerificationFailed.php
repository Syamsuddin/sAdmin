<?php

namespace App\Infrastructure\WebAuthn;

use RuntimeException;
use Throwable;

/**
 * Verifikasi WebAuthn gagal. `getMessage()` berisi detail teknis untuk log saja (docs/14);
 * yang tampil ke admin adalah pesan dari lang/id/errors.php.
 */
final class PasskeyVerificationFailed extends RuntimeException
{
    public static function because(string $detail, ?Throwable $previous = null): self
    {
        return new self($detail, 0, $previous);
    }
}
