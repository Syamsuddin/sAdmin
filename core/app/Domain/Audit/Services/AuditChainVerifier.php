<?php

namespace App\Domain\Audit\Services;

use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Data\ChainVerification;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use JsonException;

/**
 * Menelusuri rantai dari genesis: seq berurutan tanpa celah, prev_hash menyambung, hash cocok dengan isi.
 * Penghapusan entri paling ujung hanya terdeteksi lewat checkpoint berjangkar (docs/adr/0001).
 */
final class AuditChainVerifier
{
    public function __construct(private readonly AuditHasher $hasher) {}

    public function verify(): ChainVerification
    {
        $head = AuditHead::genesis();
        $checked = 0;

        foreach (DB::table('audit_entries')->lazyById(500, 'seq') as $row) {
            $seq = (int) $row->seq;
            $expectedSeq = $head->seq + 1;

            if ($seq !== $expectedSeq) {
                return ChainVerification::broken($checked, $head, $expectedSeq, "entri seq {$expectedSeq} hilang (rantai bercelah)");
            }

            if (! hash_equals($head->hash, $row->prev_hash)) {
                return ChainVerification::broken($checked, $head, $seq, 'prev_hash tak sama dengan hash entri sebelumnya');
            }

            try {
                $recomputed = $this->hasher->hash($this->hasher->bodyFromRow($row));
            } catch (InvalidArgumentException|JsonException $e) {
                return ChainVerification::broken($checked, $head, $seq, 'isi entri tak dapat dikanonisasi: '.$e->getMessage());
            }

            if (! hash_equals($row->hash, $recomputed)) {
                return ChainVerification::broken($checked, $head, $seq, 'hash tak cocok dengan isi entri (isi berubah setelah ditulis)');
            }

            $head = new AuditHead($seq, $row->hash);
            $checked++;
        }

        return ChainVerification::intact($checked, $head);
    }
}
