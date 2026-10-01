<?php

namespace App\Console\Commands;

use App\Domain\Fleet\Actions\InitializeCertificateAuthority;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use DomainException;
use Illuminate\Console\Command;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Log;
use RuntimeException;

class CaInitCommand extends Command
{
    protected $signature = 'sadmin:ca-init';

    protected $description = 'Buat CA internal instansi sekali (kunci dan sertifikat di brankas) dan cetak pin --ca-sha256';

    public function handle(InitializeCertificateAuthority $initialize): int
    {
        try {
            $ca = $initialize->handle();
        } catch (DomainException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        } catch (VaultUnavailable $e) {
            Log::error('ca_init_failed', ['reason' => 'brankas tak tersedia: '.$e->getMessage()]);
            $this->error('Brankas tak tersedia: '.$e->getMessage());
            $this->line('Tindakan: jalankan sadmin:vault-check dan pastikan kunci induk termuat (ADR 0003 §2.1).');

            return self::FAILURE;
        } catch (VaultIntegrityError $e) {
            Log::critical('ca_init_failed', ['reason' => 'brankas gagal membuka CA yang baru disimpan: '.$e->getMessage()]);
            $this->error('Brankas gagal membuka CA yang baru disimpan: '.$e->getMessage());
            $this->line('Tindakan: perlakukan sebagai insiden integritas; jalankan sadmin:vault-check dan jangan ubah baris secrets/key_wraps.');

            return self::FAILURE;
        } catch (QueryException|RuntimeException $e) {
            // docs/14: tanpa stack trace atau SQL ke admin; rinciannya hanya ke log. Tak ada yang tersimpan (transaksi batal).
            Log::error('ca_init_failed', ['reason' => $e::class.': '.$e->getMessage()]);
            $this->error('CA internal gagal dibuat; tidak ada yang tersimpan. Rincian ada di log (ca_init_failed).');

            return self::FAILURE;
        }

        $this->info('CA internal dibuat; kunci privat dan sertifikatnya hanya tersimpan di brankas.');
        $this->line("Sidik jari CA (--ca-sha256): {$ca['caSha256']}");
        $this->line("Berlaku sampai: {$ca['notAfter']}");
        $this->line('Agen menyematkan sidik jari ini saat enrolment dan hanya menerima gateway bersertifikat dari CA ini (ADR 0007).');

        return self::SUCCESS;
    }
}
