<?php

namespace App\Domain\Audit\Services;

use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Data\CheckpointVerification;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use Illuminate\Support\Facades\DB;

/**
 * Memeriksa semua checkpoint terhadap rantai yang sudah lolos AuditChainVerifier (ADR 0004 §2.5): kunci audit ada,
 * tanda tangan sah, rantai tidak berakhir sebelum checkpoint, dan hash entri sama dengan hash checkpoint.
 */
final class AuditCheckpointVerifier
{
    public function __construct(private readonly CheckpointSigner $signer) {}

    /** $chainHead = ujung rantai yang sudah terbukti utuh. Brankas hanya dimuat bila ada checkpoint. */
    public function verify(AuditHead $chainHead): CheckpointVerification
    {
        /** @var array<string, string> $publicKeys tenant_id => kunci publik mentah */
        $publicKeys = [];
        $checked = 0;
        $lastValid = null;

        $rows = DB::table('audit_checkpoints as c')
            ->leftJoin('audit_entries as e', 'e.seq', '=', 'c.seq')
            ->select(['c.seq', 'c.tenant_id', 'c.hash', 'c.signature', 'c.created_at', 'e.hash as entry_hash'])
            ->lazyById(500, 'c.seq', 'seq');

        foreach ($rows as $row) {
            $seq = (int) $row->seq;

            if (! isset($publicKeys[$row->tenant_id])) {
                $keyId = $this->signer->activeKeyId($row->tenant_id);
                if ($keyId === null) {
                    return CheckpointVerification::broken($checked, $lastValid, $seq, 'kunci audit aktif tenant tidak ada padahal checkpoint ada');
                }
                try {
                    $publicKeys[$row->tenant_id] = $this->signer->publicKey($keyId, $row->tenant_id);
                } catch (VaultUnavailable $e) {
                    return CheckpointVerification::unverifiable($checked, $lastValid, 'brankas tak tersedia: '.$e->getMessage());
                } catch (VaultIntegrityError $e) {
                    return CheckpointVerification::broken($checked, $lastValid, $seq, 'kunci audit di brankas gagal dibuka: '.$e->getMessage());
                }
            }

            if (! CheckpointSigner::verifyRow($publicKeys[$row->tenant_id], $row)) {
                return CheckpointVerification::broken($checked, $lastValid, $seq, 'tanda tangan checkpoint tidak sah');
            }
            if ($seq > $chainHead->seq) {
                return CheckpointVerification::broken($checked, $lastValid, $seq, "rantai berakhir di seq {$chainHead->seq} sebelum checkpoint (ujung rantai terpotong)");
            }
            if ($row->entry_hash === null || ! hash_equals($row->hash, $row->entry_hash)) {
                return CheckpointVerification::broken($checked, $lastValid, $seq, 'hash entri berbeda dengan checkpoint (rantai ditulis ulang)');
            }

            $lastValid = $seq;
            $checked++;
        }

        return CheckpointVerification::intact($checked, $lastValid);
    }
}
