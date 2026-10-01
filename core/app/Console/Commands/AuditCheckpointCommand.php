<?php

namespace App\Console\Commands;

use App\Domain\Audit\Actions\CreateAuditCheckpoint;
use App\Domain\Audit\Data\CheckpointResult;
use App\Domain\Audit\Data\CheckpointStatus;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use UnexpectedValueException;

class AuditCheckpointCommand extends Command
{
    protected $signature = 'sadmin:audit-checkpoint {--if-due : Hanya bila jatuh tempo (15 menit atau 100 entri); dipakai penjadwal}';

    protected $description = 'Tandatangani ujung rantai audit dengan kunci audit (checkpoint, ADR 0004)';

    public function handle(CreateAuditCheckpoint $create): int
    {
        try {
            $result = $create->handle((bool) $this->option('if-due'));
        } catch (VaultUnavailable $e) {
            return $this->failed('brankas tak tersedia: '.$e->getMessage(), critical: false);
        } catch (VaultIntegrityError $e) {
            return $this->failed('kunci audit di brankas gagal dibuka: '.$e->getMessage(), critical: true);
        } catch (UnexpectedValueException $e) {
            // Tertulis ⇒ terverifikasi gagal (ADR 0004 §2.4 no. 7): kelas Integritas docs/14.
            return $this->failed($e->getMessage(), critical: true);
        }

        return match ($result->status) {
            CheckpointStatus::Created => $this->succeeded("Checkpoint seq {$result->seq} dibuat (hash {$result->hash}, {$result->createdAt})."),
            CheckpointStatus::NothingNew => $this->succeeded($result->seq === null
                ? 'Rantai audit masih kosong; tak ada yang ditandatangani.'
                : "Tak ada entri baru sejak checkpoint seq {$result->seq}."),
            CheckpointStatus::NotDue => $this->succeeded("Belum jatuh tempo: checkpoint terakhir seq {$result->seq}."),
            CheckpointStatus::Unavailable => $this->failed((string) $result->reason, critical: false),
            CheckpointStatus::Refused => $this->refused($result),
        };
    }

    private function succeeded(string $message): int
    {
        $this->info($message);

        return self::SUCCESS;
    }

    private function refused(CheckpointResult $result): int
    {
        Log::critical('audit_mismatch', [
            'broken_at_seq' => $result->brokenAtSeq,
            'reason' => $result->reason,
            'last_checkpoint_seq' => $result->seq,
        ]);

        $this->error("Checkpoint tidak dibuat: rantai audit rusak pada seq {$result->brokenAtSeq}: {$result->reason}.");
        $this->line('Tindakan: jangan ubah data apa pun; perlakukan sebagai insiden keamanan dan jalankan sadmin:audit-verify.');

        return self::FAILURE;
    }

    private function failed(string $reason, bool $critical): int
    {
        if ($critical) {
            Log::critical('audit_checkpoint_failed', ['reason' => $reason]);
        } else {
            Log::error('audit_checkpoint_failed', ['reason' => $reason]);
        }

        $this->error("Checkpoint tidak dibuat: {$reason}.");
        $this->line('Tindakan: jalankan sadmin:vault-check, pastikan kunci audit ada (sadmin:audit-key-init), lalu ulangi.');

        return self::FAILURE;
    }
}
