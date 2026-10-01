<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\RaisesIntegrityAlerts;
use App\Domain\Alerts\Actions\RaiseIntegrityAlert;
use App\Domain\Alerts\Data\IntegrityAlert;
use App\Domain\Audit\Data\ChainVerification;
use App\Domain\Audit\Services\AuditChainVerifier;
use App\Domain\Audit\Services\AuditCheckpointVerifier;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class AuditVerifyCommand extends Command
{
    use RaisesIntegrityAlerts;

    /** Rantai utuh tetapi checkpoint tak dapat diperiksa karena brankas tak tersedia (ADR 0004 §2.5). */
    public const INCOMPLETE = 2;

    protected $signature = 'sadmin:audit-verify';

    protected $description = 'Verifikasi rantai hash audit_entries dan checkpoint bertanda tangan (exit 0 = utuh)';

    public function handle(AuditChainVerifier $verifier, AuditCheckpointVerifier $checkpoints, RaiseIntegrityAlert $alerts): int
    {
        // Batas checkpoint dibaca sebelum rantai ditelusuri (ADR 0004 §2.5): checkpoint yang lahir di tengah
        // verifikasi tak boleh terbaca sebagai rantai terpotong.
        $upToSeq = $checkpoints->latestSeq();
        $chain = $verifier->verify();

        if (! $chain->intact) {
            return $this->chainBroken($chain, $alerts);
        }

        $this->info("Rantai audit utuh: {$chain->checked} entri, head seq {$chain->head->seq} hash {$chain->head->hash}.");

        $result = $checkpoints->verify($chain->head, $upToSeq);

        if ($result->intact) {
            if ($result->lastValidSeq === null) {
                $this->line('Checkpoint: belum ada, sehingga pemotongan ujung rantai belum dapat dideteksi (ADR 0004).');
            } else {
                $uncovered = $chain->head->seq - $result->lastValidSeq;
                $this->info("Checkpoint utuh: {$result->checked} checkpoint sah, terakhir seq {$result->lastValidSeq}; {$uncovered} entri sesudahnya belum tercakup checkpoint.");
            }

            return self::SUCCESS;
        }

        if (! $result->verifiable) {
            Log::error('audit_verify_incomplete', ['reason' => $result->reason, 'checked_checkpoints' => $result->checked]);

            $this->error("Checkpoint tak dapat diperiksa: {$result->reason}.");
            $this->line('Tindakan: jalankan sadmin:vault-check dan pastikan unit memuat kredensial kunci induk (ADR 0003 §2.1), lalu ulangi.');

            return self::INCOMPLETE;
        }

        Log::critical('audit_mismatch', [
            'checkpoint_seq' => $result->brokenAtSeq,
            'reason' => $result->reason,
            'last_intact_seq' => $result->lastValidSeq ?? 0,
        ]);

        $this->error("Verifikasi checkpoint gagal pada seq {$result->brokenAtSeq}: {$result->reason}.");
        $this->line('Checkpoint sah terakhir: '.($result->lastValidSeq === null ? 'tidak ada' : "seq {$result->lastValidSeq}")." ({$result->checked} checkpoint lolos).");
        $this->line('Tindakan: jangan ubah data apa pun; perlakukan sebagai insiden keamanan dan bandingkan dengan jangkar audit di agen/offsite.');
        $this->raiseIntegrityAlert($alerts, IntegrityAlert::checkpointBroken((int) $result->brokenAtSeq, (string) $result->reason));

        return self::FAILURE;
    }

    private function chainBroken(ChainVerification $result, RaiseIntegrityAlert $alerts): int
    {
        Log::critical('audit_mismatch', [
            'broken_at_seq' => $result->brokenAtSeq,
            'reason' => $result->reason,
            'last_intact_seq' => $result->head->seq,
        ]);

        $this->error("Verifikasi audit gagal pada seq {$result->brokenAtSeq}: {$result->reason}.");
        $this->line("Entri utuh terakhir: seq {$result->head->seq} ({$result->checked} entri lolos).");
        $this->line('Tindakan: jangan ubah data apa pun; perlakukan sebagai insiden keamanan dan bandingkan dengan jangkar audit di agen/offsite.');
        $this->raiseIntegrityAlert($alerts, IntegrityAlert::chainBroken((int) $result->brokenAtSeq, (string) $result->reason));

        return self::FAILURE;
    }
}
