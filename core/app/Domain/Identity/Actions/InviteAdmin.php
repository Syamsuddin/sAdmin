<?php

namespace App\Domain\Identity\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Identity\Services\RelyingPartyResolver;
use App\Models\Admin;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\URL;
use InvalidArgumentException;

/**
 * Langkah 4 P1: admin baru + tautan bertanda tangan untuk mendaftarkan tepat 2 passkey (docs/21).
 * Tanda tangan relatif, dan origin diambil dari RP, agar tautan selalu menuju hostname console.
 */
final class InviteAdmin
{
    public function __construct(
        private readonly AppendAuditEntry $audit,
        private readonly RelyingPartyResolver $relyingParty,
    ) {}

    /** @return array{0: Admin, 1: string} admin dan tautan pendaftaran */
    public function handle(string $displayName): array
    {
        $displayName = trim($displayName);
        if ($displayName === '' || mb_strlen($displayName) > 60 || preg_match('/\p{Cc}/u', $displayName) === 1) {
            throw new InvalidArgumentException('Nama panggilan wajib diisi (maks. 60 karakter, tanpa karakter kontrol).');
        }

        $institution = $this->relyingParty->institution();
        $origin = $this->relyingParty->resolve()->origin;

        $admin = DB::transaction(function () use ($institution, $displayName): Admin {
            $admin = Admin::query()->create([
                'tenant_id' => $institution->tenant_id,
                'display_name' => $displayName,
                'status' => 'active',
            ]);

            $this->audit->handle(new AuditEntryData(
                tenantId: $institution->tenant_id,
                actorType: ActorType::LocalRoot,
                actorId: null,
                actionKey: 'admin.invite',
                outcome: AuditOutcome::Ok,
                target: 'admin:'.$admin->id,
                paramsRedacted: ['display_name' => $displayName],
            ));

            return $admin;
        });

        $path = URL::temporarySignedRoute(
            'passkeys.register',
            now()->addMinutes((int) config('sadmin.invite_ttl_minutes')),
            ['admin' => $admin->id],
            absolute: false,
        );

        return [$admin, $origin.$path];
    }
}
