<?php

namespace App\Domain\Fleet\Data;

use SensitiveParameter;

/** Hasil penukaran enrolment: bingkai `EnrollAccept` siap kirim (memuat sertifikat, bukan rahasia) dan sidik jarinya. */
final readonly class AcceptedEnrollment
{
    public function __construct(
        public string $serverId,
        #[SensitiveParameter] public string $frame,
        public string $trustFingerprint,
    ) {}
}
