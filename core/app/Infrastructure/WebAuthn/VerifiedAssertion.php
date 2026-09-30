<?php

namespace App\Infrastructure\WebAuthn;

final readonly class VerifiedAssertion
{
    public function __construct(
        public string $credentialId,
        public string $userHandle,
        public int $signCount,
    ) {}
}
