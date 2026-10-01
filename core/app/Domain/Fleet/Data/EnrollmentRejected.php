<?php

namespace App\Domain\Fleet\Data;

use RuntimeException;

/**
 * Penukaran enrolment ditolak (ADR 0008 §2.2). `errorCode` = kode galat ../kontrak/KONTRAK.md §7 yang dijawab gateway.
 * `reason` hanya untuk metrik dan tes, tak pernah dikirim ke agen: E_ENROLL_TOKEN sengaja tak membedakan sebabnya.
 */
final class EnrollmentRejected extends RuntimeException
{
    public const CODES = ['E_SCHEMA', 'E_KONTRAK_VERSION', 'E_ENROLL_TOKEN', 'E_PLATFORM', 'E_CSR', 'E_CORE_UNAVAILABLE'];

    public function __construct(public readonly string $errorCode, public readonly string $reason)
    {
        parent::__construct("Enrolment ditolak: {$errorCode} ({$reason}).");
    }
}
