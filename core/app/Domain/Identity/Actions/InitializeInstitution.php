<?php

namespace App\Domain\Identity\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Models\Institution;
use App\Models\Tenant;
use DomainException;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;

/**
 * Langkah 3 P1 (docs/06): hostname console = RP ID WebAuthn permanen. Mengganti RP ID mendaftar ulang semua
 * passkey (gerbang manusia docs/22), jadi inisialisasi kedua ditolak.
 */
final class InitializeInstitution
{
    private const HOSTNAME = '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/';

    public function __construct(private readonly AppendAuditEntry $audit) {}

    public function handle(string $hostname, string $name): Institution
    {
        $hostname = strtolower(trim($hostname));
        if (filter_var($hostname, FILTER_VALIDATE_IP) !== false || preg_match(self::HOSTNAME, $hostname) !== 1) {
            throw new InvalidArgumentException('Hostname console harus FQDN (mis. sadmin.instansi.go.id), bukan alamat IP, tanpa skema atau port.');
        }
        $name = trim($name);
        if ($name === '' || mb_strlen($name) > 120 || preg_match('/\p{Cc}/u', $name) === 1) {
            throw new InvalidArgumentException('Nama instansi wajib diisi (maks. 120 karakter, tanpa karakter kontrol).');
        }

        return DB::transaction(function () use ($hostname, $name): Institution {
            if (Institution::query()->lockForUpdate()->exists()) {
                throw new DomainException('Instansi sudah diinisialisasi; hostname console (RP ID) tak dapat diubah.');
            }

            $tenant = Tenant::query()->first() ?? Tenant::query()->create(['name' => $name]);
            $institution = Institution::query()->create([
                'tenant_id' => $tenant->id,
                'name' => $name,
                'maintenance_window' => ['days' => [], 'start' => '22:00', 'end' => '04:00'],
                'backup_retention' => ['daily' => 7, 'weekly' => 4, 'monthly' => 6],
                'console_hostname' => $hostname,
            ]);

            $this->audit->handle(new AuditEntryData(
                tenantId: $tenant->id,
                actorType: ActorType::LocalRoot,
                actorId: null,
                actionKey: 'institution.initialize',
                outcome: AuditOutcome::Ok,
                target: 'institution:'.$institution->id,
                paramsRedacted: ['console_hostname' => $hostname, 'name' => $name],
            ));

            return $institution;
        });
    }
}
