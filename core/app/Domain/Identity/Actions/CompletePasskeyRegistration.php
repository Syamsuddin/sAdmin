<?php

namespace App\Domain\Identity\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Identity\Data\PasskeyRejected;
use App\Domain\Identity\Services\PasskeyChallengeStore;
use App\Domain\Identity\Services\RelyingPartyResolver;
use App\Infrastructure\WebAuthn\PasskeyVerificationFailed;
use App\Infrastructure\WebAuthn\WebAuthnServer;
use App\Models\Admin;
use App\Models\Authenticator;
use App\Models\Casts\Bytea;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

final class CompletePasskeyRegistration
{
    public function __construct(
        private readonly WebAuthnServer $webAuthn,
        private readonly RelyingPartyResolver $relyingParty,
        private readonly PasskeyChallengeStore $challenges,
        private readonly AppendAuditEntry $audit,
    ) {}

    public function handle(Admin $admin, string $credentialJson, string $label): Authenticator
    {
        $label = trim($label);
        if ($label === '' || mb_strlen($label) > 60 || preg_match('/\p{Cc}/u', $label) === 1) {
            throw new PasskeyRejected('invalid_label');
        }

        $options = $this->challenges->pull('register:'.$admin->id) ?? throw new PasskeyRejected('challenge_missing');

        try {
            $credential = $this->webAuthn->verifyRegistration($credentialJson, $options, $this->relyingParty->resolve());
        } catch (PasskeyVerificationFailed $e) {
            $rejection = new PasskeyRejected('verification_failed');
            Log::warning('passkey_registration_rejected', ['correlation_id' => $rejection->correlationId, 'admin_id' => $admin->id, 'detail' => $e->getMessage()]);

            throw $rejection;
        }

        return DB::transaction(function () use ($admin, $credential, $label): Authenticator {
            // Kunci baris admin: dua pendaftaran paralel tak boleh melewati batas 2.
            $locked = Admin::query()->lockForUpdate()->findOrFail($admin->id);
            if (! $locked->isActive()) {
                throw new PasskeyRejected('admin_inactive');
            }
            if ($locked->activeAuthenticators()->count() >= BeginPasskeyRegistration::REQUIRED_AUTHENTICATORS) {
                throw new PasskeyRejected('registration_complete');
            }
            if (Authenticator::query()->where('credential_id', Bytea::literal($credential->credentialId))->exists()) {
                throw new PasskeyRejected('credential_exists');
            }

            $authenticator = Authenticator::query()->create([
                'id' => (string) Str::ulid(),
                'tenant_id' => $locked->tenant_id,
                'admin_id' => $locked->id,
                'credential_id' => $credential->credentialId,
                'public_key_cose' => $credential->publicKeyCose,
                'alg' => $credential->alg,
                'sign_count' => $credential->signCount,
                'label' => $label,
                'status' => 'active',
            ]);

            $this->audit->handle(new AuditEntryData(
                tenantId: $locked->tenant_id,
                actorType: ActorType::Admin,
                actorId: $locked->id,
                actionKey: 'authenticator.register',
                outcome: AuditOutcome::Ok,
                target: 'authenticator:'.$authenticator->id,
                paramsRedacted: ['label' => $label, 'alg' => $credential->alg],
            ));

            return $authenticator;
        });
    }
}
