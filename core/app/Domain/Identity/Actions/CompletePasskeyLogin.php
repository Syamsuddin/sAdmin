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
use App\Infrastructure\WebAuthn\StoredCredential;
use App\Infrastructure\WebAuthn\WebAuthnServer;
use App\Models\Admin;
use App\Models\Authenticator;
use App\Models\Casts\Bytea;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Memverifikasi assertion lalu mengembalikan admin; sesi dibuat oleh lapisan HTTP. Setiap penolakan tetap
 * tercatat di audit (outcome rejected) — di luar transaksi agar tak ikut batal.
 */
final class CompletePasskeyLogin
{
    public function __construct(
        private readonly WebAuthnServer $webAuthn,
        private readonly RelyingPartyResolver $relyingParty,
        private readonly PasskeyChallengeStore $challenges,
        private readonly AppendAuditEntry $audit,
    ) {}

    public function handle(string $credentialJson, ?string $ip): Admin
    {
        $admin = null;

        try {
            $options = $this->challenges->pull('login') ?? throw new PasskeyRejected('challenge_missing');

            try {
                $credentialId = $this->webAuthn->assertedCredentialId($credentialJson);
            } catch (PasskeyVerificationFailed $e) {
                throw $this->rejected('verification_failed', $e, null);
            }

            $authenticator = Authenticator::query()
                ->where('credential_id', Bytea::literal($credentialId))
                ->where('status', 'active')
                ->with('admin')
                ->first() ?? throw new PasskeyRejected('unknown_credential');
            $admin = $authenticator->admin;
            if (! $admin->isActive()) {
                throw new PasskeyRejected('admin_inactive');
            }

            try {
                $verified = $this->webAuthn->verifyAssertion($credentialJson, $options, $this->relyingParty->resolve(), new StoredCredential(
                    (string) $authenticator->credential_id,
                    (string) $authenticator->public_key_cose,
                    $admin->id,
                    $authenticator->sign_count,
                ));
            } catch (PasskeyVerificationFailed $e) {
                throw $this->rejected('verification_failed', $e, $admin->id);
            }

            return DB::transaction(function () use ($authenticator, $admin, $verified, $ip): Admin {
                $authenticator->forceFill(['sign_count' => $verified->signCount])->save();
                $admin->forceFill(['last_login_at' => now()])->save();
                $this->record($admin->tenant_id, $admin->id, AuditOutcome::Ok, ['authenticator' => $authenticator->id, 'ip' => $ip]);

                return $admin;
            });
        } catch (PasskeyRejected $e) {
            $this->record(
                $admin instanceof Admin ? $admin->tenant_id : $this->relyingParty->institution()->tenant_id,
                $admin?->id,
                AuditOutcome::Rejected,
                ['reason' => $e->reason, 'ip' => $ip, 'correlation_id' => $e->correlationId],
            );

            throw $e;
        }
    }

    /** Detail teknis hanya ke log, dengan ID korelasi yang sama dengan yang tampil ke admin (docs/14). */
    private function rejected(string $reason, PasskeyVerificationFailed $e, ?string $adminId): PasskeyRejected
    {
        $rejection = new PasskeyRejected($reason);
        Log::warning('passkey_login_rejected', ['correlation_id' => $rejection->correlationId, 'admin_id' => $adminId, 'detail' => $e->getMessage()]);

        return $rejection;
    }

    /** @param  array<string, string|null>  $params */
    private function record(string $tenantId, ?string $adminId, AuditOutcome $outcome, array $params): void
    {
        $this->audit->handle(new AuditEntryData(
            tenantId: $tenantId,
            actorType: ActorType::Admin,
            actorId: $adminId,
            actionKey: 'console.login',
            outcome: $outcome,
            target: $adminId !== null ? 'admin:'.$adminId : null,
            paramsRedacted: $params,
        ));
    }
}
