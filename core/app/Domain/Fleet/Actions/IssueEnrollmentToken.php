<?php

namespace App\Domain\Fleet\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Fleet\Data\EnrollmentTarget;
use App\Domain\Fleet\Data\EnrollmentToken;
use App\Domain\Fleet\Data\ServerRegistrationRejected;
use App\Domain\Fleet\Data\ServerStatus;
use App\Domain\Fleet\Services\EnrollmentInstructions;
use App\Models\Admin;
use App\Models\Server;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;

/**
 * Menerbitkan token enrolment sekali pakai untuk server yang masih menunggu enrolment (KONTRAK §5 `Enroll`).
 * Token baru langsung menggantikan token lama. Core hanya menyimpan hash-nya, dan audit hanya mencatat batas
 * waktunya, tak pernah tokennya.
 */
final class IssueEnrollmentToken
{
    /** Masa berlaku token (KONTRAK §5). */
    public const TTL_MINUTES = 15;

    public function __construct(
        private readonly EnrollmentInstructions $instructions,
        private readonly AppendAuditEntry $audit,
    ) {}

    public function handle(Admin $admin, string $serverId): EnrollmentToken
    {
        return $this->issue($admin, $serverId, $this->instructions->target($admin->tenant_id));
    }

    /** Dipakai RegisterServer di dalam transaksinya, setelah prasyarat enrolment diperiksa. */
    public function issue(Admin $admin, string $serverId, EnrollmentTarget $target): EnrollmentToken
    {
        return DB::transaction(function () use ($admin, $serverId, $target): EnrollmentToken {
            $server = Server::query()->where('tenant_id', $admin->tenant_id)->lockForUpdate()->find($serverId);
            if ($server === null || $server->status !== ServerStatus::Enrolling) {
                throw new ServerRegistrationRejected('not_enrolling');
            }

            // 256 bit acak dalam hex: aman disalin ke shell dan tak pernah diawali "-" yang terbaca sebagai flag.
            $token = bin2hex(random_bytes(32));
            // Dibulatkan ke bawah ke detik: token tak pernah berlaku lebih dari 15 menit.
            $expiresAt = CarbonImmutable::now()->startOfSecond()->addMinutes(self::TTL_MINUTES);

            $server->update(['enroll_token_hash' => hash('sha256', $token), 'enroll_token_expires_at' => $expiresAt]);

            $this->audit->handle(new AuditEntryData(
                tenantId: $server->tenant_id,
                actorType: ActorType::Admin,
                actorId: $admin->id,
                actionKey: 'server.enroll_token_issue',
                outcome: AuditOutcome::Ok,
                target: "server:{$server->id}",
                paramsRedacted: ['expires_at' => $expiresAt->utc()->format('Y-m-d\TH:i:s\Z')],
            ));

            return new EnrollmentToken($server->id, $server->name, $token, $expiresAt, $target);
        });
    }
}
