<?php

namespace App\Domain\Fleet\Data;

use RuntimeException;

/**
 * CSR agen yang melanggar aturan CSR ../kontrak/KONTRAK.md §2; `reason` = aturan pertama yang dilanggar, dipetakan ke
 * `E_CSR` oleh enrolment. Pesannya tak pernah memuat isi CSR (data tak tepercaya dari agen).
 */
final class CertificateRequestRejected extends RuntimeException
{
    public const REASONS = ['size', 'pem', 'structure', 'key', 'subject', 'signature'];

    public function __construct(public readonly string $reason)
    {
        parent::__construct("CSR agen ditolak: {$reason} (KONTRAK §2, E_CSR).");
    }
}
