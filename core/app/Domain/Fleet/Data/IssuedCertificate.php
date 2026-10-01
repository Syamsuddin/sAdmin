<?php

namespace App\Domain\Fleet\Data;

use DateTimeImmutable;

/** Sertifikat klien agen yang sudah lolos verifikasi sendiri (ADR 0007 §2.3); serial = hex huruf kecil tanpa nol di depan. */
final readonly class IssuedCertificate
{
    public function __construct(
        public string $certificatePem,
        public string $serial,
        public DateTimeImmutable $notBefore,
        public DateTimeImmutable $notAfter,
        public string $serverId,
    ) {}
}
