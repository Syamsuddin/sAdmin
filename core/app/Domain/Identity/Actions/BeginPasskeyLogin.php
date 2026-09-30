<?php

namespace App\Domain\Identity\Actions;

use App\Domain\Identity\Services\PasskeyChallengeStore;
use App\Domain\Identity\Services\RelyingPartyResolver;
use App\Infrastructure\WebAuthn\WebAuthnServer;

/** Login tanpa nama pengguna: passkey dapat-ditemukan memilih akunnya sendiri (ADR 0002). */
final class BeginPasskeyLogin
{
    public function __construct(
        private readonly WebAuthnServer $webAuthn,
        private readonly RelyingPartyResolver $relyingParty,
        private readonly PasskeyChallengeStore $challenges,
    ) {}

    public function handle(): string
    {
        $options = $this->webAuthn->requestOptions($this->relyingParty->resolve());
        $this->challenges->put('login', $options);

        return $options;
    }
}
