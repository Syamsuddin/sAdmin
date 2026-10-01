<?php

namespace App\Console\Commands;

use App\Domain\Audit\Actions\InitializeAuditKey;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use DomainException;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class AuditKeyInitCommand extends Command
{
    protected $signature = 'sadmin:audit-key-init';

    protected $description = 'Buat kunci audit Ed25519 instansi sekali (seed di brankas) dan cetak kunci publiknya';

    public function handle(InitializeAuditKey $initialize): int
    {
        try {
            $key = $initialize->handle();
        } catch (DomainException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        } catch (VaultUnavailable $e) {
            Log::error('audit_key_init_failed', ['reason' => 'brankas tak tersedia: '.$e->getMessage()]);
            $this->error('Brankas tak tersedia: '.$e->getMessage());
            $this->line('Tindakan: jalankan sadmin:vault-check dan pastikan kunci induk termuat (ADR 0003 §2.1).');

            return self::FAILURE;
        } catch (VaultIntegrityError $e) {
            Log::critical('audit_key_init_failed', ['reason' => 'brankas gagal membuka kunci yang baru disimpan: '.$e->getMessage()]);
            $this->error('Brankas gagal membuka kunci audit yang baru disimpan: '.$e->getMessage());
            $this->line('Tindakan: perlakukan sebagai insiden integritas; jalankan sadmin:vault-check dan jangan ubah baris secrets/key_wraps.');

            return self::FAILURE;
        }

        $this->info('Kunci audit dibuat; seed-nya hanya tersimpan di brankas.');
        $this->line("Kunci publik audit (base64): {$key['publicKey']}");
        $this->line('Catat kunci publik ini di kit pemulihan dan serahkan kepada auditor: checkpoint audit diverifikasi dengannya (ADR 0004).');

        return self::SUCCESS;
    }
}
