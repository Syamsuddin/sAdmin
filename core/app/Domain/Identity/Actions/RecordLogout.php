<?php

namespace App\Domain\Identity\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Models\Admin;

final class RecordLogout
{
    public function __construct(private readonly AppendAuditEntry $audit) {}

    /** @param  string  $reason  `manual`, `absolute_timeout` (batas mutlak 12 jam, docs/21), atau `admin_disabled` */
    public function handle(Admin $admin, string $reason): void
    {
        $this->audit->handle(new AuditEntryData(
            tenantId: $admin->tenant_id,
            actorType: ActorType::Admin,
            actorId: $admin->id,
            actionKey: 'console.logout',
            outcome: AuditOutcome::Ok,
            target: 'admin:'.$admin->id,
            paramsRedacted: ['reason' => $reason],
        ));
    }
}
