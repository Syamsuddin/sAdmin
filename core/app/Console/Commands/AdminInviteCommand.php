<?php

namespace App\Console\Commands;

use App\Domain\Identity\Actions\InviteAdmin;
use DomainException;
use Illuminate\Console\Command;
use InvalidArgumentException;

class AdminInviteCommand extends Command
{
    protected $signature = 'sadmin:admin-invite {name : Nama panggilan admin}';

    protected $description = 'Buat admin dan tautan sekali-daftar untuk 2 passkey (berlaku 15 menit)';

    public function handle(InviteAdmin $invite): int
    {
        try {
            [$admin, $url] = $invite->handle((string) $this->argument('name'));
        } catch (InvalidArgumentException|DomainException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info("Admin \"{$admin->display_name}\" dibuat.");
        $this->line('Buka tautan ini dari perangkat admin (lewat WireGuard) dalam '.config('sadmin.invite_ttl_minutes').' menit untuk mendaftarkan 2 passkey:');
        $this->line($url);

        return self::SUCCESS;
    }
}
