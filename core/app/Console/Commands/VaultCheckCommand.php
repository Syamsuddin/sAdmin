<?php

namespace App\Console\Commands;

use App\Domain\Vault\Data\SecretStatus;
use App\Infrastructure\Vault\Vault;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use App\Models\KeyWrap;
use App\Models\Secret;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class VaultCheckCommand extends Command
{
    protected $signature = 'sadmin:vault-check';

    protected $description = 'Periksa kunci induk brankas: uji bungkus-buka dan buka setiap kunci data aktif tanpa membuka nilai (exit 0 = sehat)';

    public function handle(Vault $vault): int
    {
        try {
            $kek = $vault->selfTest();
        } catch (VaultUnavailable|VaultIntegrityError $e) {
            $this->error('Brankas tak tersedia: '.$e->getMessage());
            $this->line('Tindakan: periksa unit systemd core memuat kredensial kunci induk (docs/10, ADR 0003 §2.1).');

            return self::FAILURE;
        }
        $this->info("Kunci induk versi {$kek->version} termuat dari {$kek->source}; uji bungkus-buka lulus.");

        $checked = 0;
        $failed = [];
        $wraps = KeyWrap::query()
            ->whereIn('id', Secret::query()->where('status', '!=', SecretStatus::Destroyed->value)->select('key_wrap_id'))
            ->orderBy('id')
            ->lazy();
        foreach ($wraps as $wrap) {
            $checked++;
            try {
                $vault->checkKeyWrap($wrap, $kek);
            } catch (VaultUnavailable|VaultIntegrityError $e) {
                $failed[] = $wrap->id;
            }
        }

        if ($failed === []) {
            $this->info("{$checked} kunci data rahasia aktif terbuka dengan kunci induk ini.");

            return self::SUCCESS;
        }

        Log::critical('vault_key_mismatch', ['failed_key_wraps' => $failed, 'checked' => $checked]);
        $this->error(count($failed)." dari {$checked} kunci data gagal dibuka: ".implode(', ', array_slice($failed, 0, 5)).(count($failed) > 5 ? ', …' : '').'.');
        $this->line('Tindakan: pastikan kunci induk yang dimuat systemd adalah kunci instalasi ini (kit pemulihan); jangan ubah baris secrets/key_wraps.');

        return self::FAILURE;
    }
}
