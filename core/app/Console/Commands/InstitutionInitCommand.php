<?php

namespace App\Console\Commands;

use App\Domain\Identity\Actions\InitializeInstitution;
use DomainException;
use Illuminate\Console\Command;
use InvalidArgumentException;

class InstitutionInitCommand extends Command
{
    protected $signature = 'sadmin:institution-init {hostname? : Hostname console = RP ID WebAuthn permanen (bawaan SADMIN_RP_ID)} {--name= : Nama instansi}';

    protected $description = 'Inisialisasi instansi sekali; hostname console tak dapat diubah kemudian';

    public function handle(InitializeInstitution $initialize): int
    {
        $hostname = (string) ($this->argument('hostname') ?: config('sadmin.webauthn.default_rp_id'));
        $name = (string) ($this->option('name') ?: 'Instansi');

        try {
            $institution = $initialize->handle($hostname, $name);
        } catch (InvalidArgumentException|DomainException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info("Instansi \"{$institution->name}\" siap. Hostname console (RP ID): {$institution->console_hostname}");
        $this->line('Hostname ini permanen: mengubahnya mendaftar ulang semua passkey (docs/22).');

        return self::SUCCESS;
    }
}
