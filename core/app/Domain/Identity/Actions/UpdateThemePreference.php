<?php

namespace App\Domain\Identity\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Identity\Data\ThemePreference;
use App\Models\Admin;
use Illuminate\Support\Facades\DB;

/** F-17: mode tema console per admin (docs/26). Memilih ulang tema yang sama bukan perubahan state: tanpa audit. */
final class UpdateThemePreference
{
    public function __construct(private readonly AppendAuditEntry $audit) {}

    public function handle(Admin $admin, ThemePreference $theme): void
    {
        DB::transaction(function () use ($admin, $theme): void {
            // Baris dikunci: `from` di audit adalah nilai tersimpan, bukan salinan basi dari tab lain.
            $stored = Admin::query()->lockForUpdate()->findOrFail($admin->id);
            $from = $stored->theme;
            if ($from === $theme) {
                return;
            }

            $stored->update(['theme' => $theme]);

            $this->audit->handle(new AuditEntryData(
                tenantId: $stored->tenant_id,
                actorType: ActorType::Admin,
                actorId: $stored->id,
                actionKey: 'admin.theme_change',
                outcome: AuditOutcome::Ok,
                target: 'admin:'.$stored->id,
                paramsRedacted: ['from' => $from->value, 'to' => $theme->value],
            ));
        });

        $admin->theme = $theme;
        $admin->syncOriginalAttribute('theme');
    }
}
