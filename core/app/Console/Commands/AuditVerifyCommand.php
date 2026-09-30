<?php

namespace App\Console\Commands;

use App\Domain\Audit\Services\AuditChainVerifier;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class AuditVerifyCommand extends Command
{
    protected $signature = 'sadmin:audit-verify';

    protected $description = 'Verifikasi rantai hash audit_entries (exit 0 = utuh)';

    public function handle(AuditChainVerifier $verifier): int
    {
        $result = $verifier->verify();

        if ($result->intact) {
            $this->info("Rantai audit utuh: {$result->checked} entri, head seq {$result->head->seq} hash {$result->head->hash}.");

            return self::SUCCESS;
        }

        Log::critical('audit_mismatch', [
            'broken_at_seq' => $result->brokenAtSeq,
            'reason' => $result->reason,
            'last_intact_seq' => $result->head->seq,
        ]);

        $this->error("Verifikasi audit gagal pada seq {$result->brokenAtSeq}: {$result->reason}.");
        $this->line("Entri utuh terakhir: seq {$result->head->seq} ({$result->checked} entri lolos).");
        $this->line('Tindakan: jangan ubah data apa pun; perlakukan sebagai insiden keamanan dan bandingkan dengan jangkar audit di agen/offsite.');

        return self::FAILURE;
    }
}
