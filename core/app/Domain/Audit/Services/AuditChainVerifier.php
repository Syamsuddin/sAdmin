<?php

namespace App\Domain\Audit\Services;

use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Data\ChainVerification;
use Illuminate\Support\Facades\DB;
use JsonException;
use stdClass;
use Throwable;

/**
 * Menelusuri rantai: seq berurutan tanpa celah, prev_hash menyambung, hash cocok dengan isi (docs/adr/0001 §2.7).
 * Pemotongan ujung dan penulisan ulang dari suatu titik hanya terdeteksi lewat checkpoint (docs/adr/0004).
 */
final class AuditChainVerifier
{
    public function __construct(private readonly AuditHasher $hasher) {}

    public function verify(): ChainVerification
    {
        return $this->verifyAfter(AuditHead::genesis());
    }

    /**
     * Menelusuri entri sesudah $start sampai ujung rantai. $start wajib sudah tepercaya: genesis, atau entri yang
     * dicakup checkpoint bertanda tangan sah dan sudah dibuktikan utuh (ADR 0004 §2.4).
     */
    public function verifyAfter(AuditHead $start): ChainVerification
    {
        $head = $start;
        $checked = 0;

        foreach (DB::table('audit_entries')->where('seq', '>', $start->seq)->lazyById(500, 'seq') as $row) {
            $seq = (int) $row->seq;
            $expectedSeq = $head->seq + 1;

            if ($seq !== $expectedSeq) {
                return ChainVerification::broken($checked, $head, $expectedSeq, "entri seq {$expectedSeq} hilang (rantai bercelah)");
            }

            if (! hash_equals($head->hash, $row->prev_hash)) {
                return ChainVerification::broken($checked, $head, $seq, 'prev_hash tak sama dengan hash entri sebelumnya');
            }

            $reason = $this->contentMismatch($row);
            if ($reason !== null) {
                return ChainVerification::broken($checked, $head, $seq, $reason);
            }

            $head = new AuditHead($seq, $row->hash);
            $checked++;
        }

        return ChainVerification::intact($checked, $head);
    }

    /** Null bila kolom hash cocok dengan hash hasil hitung ulang dari isi baris; selain itu alasannya (§2.7 no. 3–4). */
    public function contentMismatch(stdClass $row): ?string
    {
        try {
            $recomputed = $this->hasher->hash($this->hasher->bodyFromRow($row));
        } catch (Throwable $e) {
            // Baris hasil manipulasi apa pun wajib berakhir sebagai audit_mismatch, bukan crash.
            return 'isi entri tak dapat dikanonisasi: '.self::describe($e);
        }

        return hash_equals($row->hash, $recomputed) ? null : 'hash tak cocok dengan isi entri (isi berubah setelah ditulis)';
    }

    /** Hanya pesan yang pasti bebas isi entri (JCS & JSON) yang diteruskan; selebihnya nama kelas saja. */
    private static function describe(Throwable $e): string
    {
        return $e instanceof JsonException || str_starts_with($e->getMessage(), 'JCS:')
            ? $e->getMessage()
            : class_basename($e);
    }
}
