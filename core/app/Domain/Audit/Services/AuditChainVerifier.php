<?php

namespace App\Domain\Audit\Services;

use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Data\ChainVerification;
use Illuminate\Support\Facades\DB;
use JsonException;
use Throwable;

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
            } catch (Throwable $e) {
                // Baris hasil manipulasi apa pun wajib berakhir sebagai audit_mismatch, bukan crash.
                return ChainVerification::broken($checked, $head, $seq, 'isi entri tak dapat dikanonisasi: '.self::describe($e));
            }

            if (! hash_equals($row->hash, $recomputed)) {
                return ChainVerification::broken($checked, $head, $seq, 'hash tak cocok dengan isi entri (isi berubah setelah ditulis)');
            }

            $head = new AuditHead($seq, $row->hash);
            $checked++;
        }

        return ChainVerification::intact($checked, $head);
    }

    /** Hanya pesan yang pasti bebas isi entri (JCS & JSON) yang diteruskan; selebihnya nama kelas saja. */
    private static function describe(Throwable $e): string
    {
        return $e instanceof JsonException || str_starts_with($e->getMessage(), 'JCS:')
            ? $e->getMessage()
            : class_basename($e);
    }
}
