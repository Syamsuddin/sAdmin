<?php

namespace App\Domain\Identity\Actions;

use App\Domain\Identity\Data\PasskeyRejected;
use App\Domain\Identity\Services\PasskeyChallengeStore;
use App\Domain\Identity\Services\RelyingPartyResolver;
use App\Infrastructure\WebAuthn\WebAuthnServer;
use App\Models\Admin;

final class BeginPasskeyRegistration
{
    /** Setiap admin wajib ≥ 2 autentikator; penambahan sesudahnya = perubahan roster L3 (docs/21). */
    public const REQUIRED_AUTHENTICATORS = 2;

    public function __construct(
        private readonly WebAuthnServer $webAuthn,
        private readonly RelyingPartyResolver $relyingParty,
        private readonly PasskeyChallengeStore $challenges,
    ) {}

    public function handle(Admin $admin): string
    {
        if (! $admin->isActive()) {
            throw new PasskeyRejected('admin_inactive');
        }
        if ($admin->activeAuthenticators()->count() >= self::REQUIRED_AUTHENTICATORS) {
            throw new PasskeyRejected('registration_complete');
        }

        $options = $this->webAuthn->creationOptions(
            $this->relyingParty->resolve(),
            $admin->id,
            $admin->display_name,
            $admin->display_name,
            $admin->authenticators()->get()->map(fn ($authenticator): string => (string) $authenticator->credential_id)->values()->all(),
        );
        $this->challenges->put('register:'.$admin->id, $options);

        return $options;
    }
}
