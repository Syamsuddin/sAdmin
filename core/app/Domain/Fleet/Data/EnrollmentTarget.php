<?php

namespace App\Domain\Fleet\Data;

/** Tujuan enrolment agen: `--gateway <host>:8443` dan pin `--ca-sha256` (KONTRAK §2). */
final readonly class EnrollmentTarget
{
    public function __construct(public string $gateway, public string $caSha256) {}
}
