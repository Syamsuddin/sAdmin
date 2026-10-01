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
        $address = self::serverAddress(trim($ip));

        $invalid = array_keys(array_filter([
            'invalid_name' => preg_match('/^'.self::LABEL.'\z/', $name) !== 1,
            'invalid_hostname' => ! self::isHostname($hostname),
            'invalid_ip' => $address === null,
        ]));
        if ($invalid !== []) {
            throw ServerRegistrationRejected::fields(...$invalid);
        }
        $ip = (string) $address;

        // Prasyarat diperiksa sebelum menulis apa pun: server tak pernah dibuat tanpa perintah enrolment yang sah.
        $target = $this->instructions->target($admin->tenant_id);

        return DB::transaction(function () use ($admin, $name, $hostname, $ip, $target): EnrollmentToken {
            DB::select('SELECT pg_advisory_xact_lock(?)', [self::LOCK_KEY]);

            if (! $this->hasCapacity($admin->tenant_id)) {
                throw new ServerRegistrationRejected('server_limit');
            }
            // Nama server yang sudah dipensiunkan pun tetap terpakai: UNIQUE(tenant_id, name) di docs/07.
            if (Server::query()->where('tenant_id', $admin->tenant_id)->where('name', $name)->exists()) {
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

    /** Mode Tunggal masih menerima server baru untuk tenant ini (docs/02_SCOPE.md). */
    public function hasCapacity(string $tenantId): bool
    {
        return Server::query()->where('tenant_id', $tenantId)->where('status', '<>', ServerStatus::Retired->value)->count()
            < self::MAX_SERVERS;
    }

    /**
     * Nama host DNS huruf kecil (RFC 1123). Label teratas tak boleh angka semua atau heksadesimal `0x…`, karena
     * pengurai URL dan inet_aton membaca nama seperti itu sebagai alamat IPv4.
     */
    public static function isHostname(string $host): bool
    {
        return strlen($host) <= 253
            && preg_match('/^'.self::LABEL.'(?:\.'.self::LABEL.')*\z/', $host) === 1
            && preg_match('/(?:^|\.)(?:[0-9]+|0x[0-9a-f]*)\z/', $host) !== 1;
    }

    /**
     * Bentuk kanonik alamat IP yang bisa dimiliki satu mesin, atau null. Ditolak: rentang cadangan (loopback, tak
     * spesifik, link-local, siaran, IPv4-mapped) dan multicast (224.0.0.0/4, ff00::/8) yang tak dicakup filter PHP.
     */
    public static function serverAddress(string $ip): ?string
    {
        $packed = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE) === false ? false : inet_pton($ip);
        if ($packed === false) {
            return null;
        }
        $first = ord($packed[0]);
        if (strlen($packed) === 4 ? ($first & 0xF0) === 0xE0 : $first === 0xFF) {
            return null;
        }

        return inet_ntop($packed) ?: null;
    }
}
