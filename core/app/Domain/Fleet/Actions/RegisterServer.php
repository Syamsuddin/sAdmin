<?php

namespace App\Domain\Fleet\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Fleet\Data\EnrollmentToken;
use App\Domain\Fleet\Data\ServerRegistrationRejected;
use App\Domain\Fleet\Data\ServerStatus;
use App\Domain\Fleet\Services\EnrollmentInstructions;
use App\Models\Admin;
use App\Models\Server;
use Illuminate\Support\Facades\DB;

/**
 * Admin menambah server terkelola: server berstatus `enrolling` plus token enrolment pertamanya (docs/04 Enrolment).
 * Agen di server itu kelak menukar token dengan sertifikat klien lewat `Enroll` (KONTRAK §5).
 */
final class RegisterServer
{
    public const LOCK_KEY = 7301007;

    /** Mode Tunggal: paling banyak tiga server terkelola yang belum dipensiunkan (docs/02_SCOPE.md). */
    public const MAX_SERVERS = 3;

    private const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';

    public function __construct(
        private readonly EnrollmentInstructions $instructions,
        private readonly IssueEnrollmentToken $tokens,
        private readonly AppendAuditEntry $audit,
    ) {}

    public function handle(Admin $admin, string $name, string $hostname, string $ip): EnrollmentToken
    {
        $name = trim($name);
        $hostname = strtolower(trim($hostname));
        $ip = trim($ip);

        if (preg_match('/^'.self::LABEL.'\z/', $name) !== 1) {
            throw new ServerRegistrationRejected('invalid_name');
        }
        if (! self::isHostname($hostname)) {
            throw new ServerRegistrationRejected('invalid_hostname');
        }
        // Alamat yang tak bisa menjadi server: loopback, tak spesifik, link-local, dan rentang cadangan lain.
        $packed = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE) === false ? false : inet_pton($ip);
        if ($packed === false) {
            throw new ServerRegistrationRejected('invalid_ip');
        }
        $ip = (string) inet_ntop($packed);

        // Prasyarat diperiksa sebelum menulis apa pun: server tak pernah dibuat tanpa perintah enrolment yang sah.
        $target = $this->instructions->target($admin->tenant_id);

        return DB::transaction(function () use ($admin, $name, $hostname, $ip, $target): EnrollmentToken {
            DB::select('SELECT pg_advisory_xact_lock(?)', [self::LOCK_KEY]);

            $servers = Server::query()->where('tenant_id', $admin->tenant_id);
            if ((clone $servers)->where('status', '<>', ServerStatus::Retired->value)->count() >= self::MAX_SERVERS) {
                throw new ServerRegistrationRejected('server_limit');
            }
            // Nama server yang sudah dipensiunkan pun tetap terpakai: UNIQUE(tenant_id, name) di docs/07.
            if ((clone $servers)->where('name', $name)->exists()) {
                throw new ServerRegistrationRejected('name_taken');
            }

            $server = Server::query()->create([
                'tenant_id' => $admin->tenant_id,
                'name' => $name,
                'hostname' => $hostname,
                'ip' => $ip,
                'status' => ServerStatus::Enrolling,
            ]);

            $this->audit->handle(new AuditEntryData(
                tenantId: $admin->tenant_id,
                actorType: ActorType::Admin,
                actorId: $admin->id,
                actionKey: 'server.register',
                outcome: AuditOutcome::Ok,
                target: "server:{$server->id}",
                paramsRedacted: ['name' => $name, 'hostname' => $hostname, 'ip' => $ip],
            ));

            return $this->tokens->issue($admin, $server->id, $target);
        });
    }

    /** Nama host DNS huruf kecil (RFC 1123), label teratas bukan angka semua agar alamat IP tak lolos sebagai nama. */
    public static function isHostname(string $host): bool
    {
        return strlen($host) <= 253
            && preg_match('/^'.self::LABEL.'(?:\.'.self::LABEL.')*\z/', $host) === 1
            && preg_match('/(?:^|\.)[0-9]+\z/', $host) !== 1;
    }
}
