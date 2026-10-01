<?php

namespace App\Domain\Fleet\Data;

use Illuminate\Support\Str;
use RuntimeException;
use Throwable;

/**
 * Penolakan tambah server atau terbit token enrolment. `reason` memetakan ke lang/id/errors.php `server.*` (langkah,
 * penyebab, tindakan) dan tak pernah memuat masukan admin maupun token; detail teknis hanya ke log (docs/14).
 */
final class ServerRegistrationRejected extends RuntimeException
{
    /** Penolakan masukan formulir: tampil per field, tanpa log galat (docs/14 §Klasifikasi). */
    public const FIELDS = ['invalid_name' => 'name', 'name_taken' => 'name', 'invalid_hostname' => 'hostname', 'invalid_ip' => 'ip'];

    public const REASONS = [
        'invalid_name', 'name_taken', 'invalid_hostname', 'invalid_ip',
        'server_limit', 'not_enrolling', 'gateway_unset', 'ca_missing', 'vault_unavailable',
    ];

    public readonly string $correlationId;

    public function __construct(public readonly string $reason, ?Throwable $previous = null)
    {
        $this->correlationId = (string) Str::ulid();
        parent::__construct("Tambah server ditolak: {$reason}", 0, $previous);
    }

    public function field(): ?string
    {
        return self::FIELDS[$this->reason] ?? null;
    }
}
