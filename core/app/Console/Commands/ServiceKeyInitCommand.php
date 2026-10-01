<?php

namespace App\Console\Commands;

use App\Domain\Execution\Actions\InitializeServiceKey;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use DomainException;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class ServiceKeyInitCommand extends Command
{
    protected $signature = 'sadmin:service-key-init';

    protected $description = 'Buat kunci layanan Ed25519 instansi sekali (seed di brankas) dan cetak kunci publiknya';

    public function handle(InitializeServiceKey $initialize): int
    {
        try {
            $key = $initialize->handle();
        } catch (DomainException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        } catch (VaultUnavailable $e) {
            Log::error('service_key_init_failed', ['reason' => 'brankas tak tersedia: '.$e->getMessage()]);
            $this->error('Brankas tak tersedia: '.$e->getMessage());
            $this->line('Tindakan: jalankan sadmin:vault-check dan pastikan kunci induk termuat (ADR 0003 §2.1).');

            return self::FAILURE;
        } catch (VaultIntegrityError $e) {
            Log::critical('service_key_init_failed', ['reason' => 'brankas gagal membuka kunci yang baru disimpan: '.$e->getMessage()]);
            $this->error('Brankas gagal membuka kunci layanan yang baru disimpan: '.$e->getMessage());
            $this->line('Tindakan: perlakukan sebagai insiden integritas; jalankan sadmin:vault-check dan jangan ubah baris secrets/key_wraps.');

            return self::FAILURE;
        }

        $this->info('Kunci layanan dibuat; seed-nya hanya tersimpan di brankas.');
        $this->line("Kunci publik layanan (base64): {$key['publicKey']}");
        $this->line('Agen menyematkan kunci publik ini saat enrolment dan memverifikasi setiap bingkai core dengannya (ADR 0006).');

        return self::SUCCESS;
    }
}
