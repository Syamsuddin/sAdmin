<?php

namespace App\Infrastructure\WebAuthn;

/** RP WebAuthn: id = institutions.console_hostname (permanen), origin = yang wajib tercantum di clientDataJSON. */
final readonly class RelyingParty
{
    public function __construct(
        public string $id,
        public string $name,
        public string $origin,
    ) {}
}
