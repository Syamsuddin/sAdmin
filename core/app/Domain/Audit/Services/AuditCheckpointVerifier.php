<?php

namespace App\Domain\Audit\Services;

use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Data\CheckpointVerification;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use Illuminate\Support\Facades\DB;

/**
 * Memeriksa checkpoint terhadap rantai yang sudah lolos AuditChainVerifier (ADR 0004 §2.5): kunci audit ada,
 * tanda tangan sah, rantai tidak berakhir sebelum checkpoint, dan hash entri sama dengan hash checkpoint.
 */
final class AuditCheckpointVerifier
{
    public function __construct(private readonly CheckpointSigner $signer) {}

    /**
     * Seq checkpoint terbesar saat ini. Dibaca SEBELUM rantai ditelusuri: checkpoint yang lahir di tengah verifikasi
     * boleh melampaui ujung rantai yang dipegang verifikator tanpa rantai terpotong.
     */
    public function latestSeq(): int
    {
        return (int) DB::table('audit_checkpoints')->max('seq');
    }

    /** $chainHead = ujung rantai yang sudah terbukti utuh; $upToSeq = latestSeq() sebelum rantai ditelusuri. */
    public function verify(AuditHead $chainHead, int $upToSeq): CheckpointVerification
    {
        /** @var array<string, string> $publicKeys tenant_id => kunci publik mentah */
        $publicKeys = [];
        $unavailable = null;
        $checked = 0;
        $lastValid = null;

        $rows = DB::table('audit_checkpoints as c')
            ->leftJoin('audit_entries as e', 'e.seq', '=', 'c.seq')
            ->where('c.seq', '<=', $upToSeq)
            ->select(['c.seq', 'c.tenant_id', 'c.hash', 'c.signature', 'c.created_at', 'e.hash as entry_hash'])
            ->lazyById(500, 'c.seq', 'seq');

        foreach ($rows as $row) {
            $seq = (int) $row->seq;
            if (! is_string($row->tenant_id) || ! is_string($row->hash)) {
                return CheckpointVerification::broken($checked, $lastValid, $seq, 'baris checkpoint tak lengkap (tenant_id atau hash kosong)');
            }

            if ($unavailable === null && ! isset($publicKeys[$row->tenant_id])) {
                $keyId = $this->signer->activeKeyId($row->tenant_id);
                if ($keyId === null) {
                    return CheckpointVerification::broken($checked, $lastValid, $seq, 'kunci audit aktif tenant tidak ada padahal checkpoint ada');
                }
                try {
                    $publicKeys[$row->tenant_id] = $this->signer->publicKey($keyId, $row->tenant_id);
                } catch (VaultUnavailable $e) {
                    // Pemeriksaan no. 3–4 tak butuh kunci dan tetap dijalankan, supaya brankas yang sengaja dibuat
                    // tak tersedia tak bisa menyamarkan rantai terpotong atau ditulis ulang menjadi exit 2.
                    $unavailable = 'brankas tak tersedia: '.$e->getMessage();
                } catch (VaultIntegrityError $e) {
                    return CheckpointVerification::broken($checked, $lastValid, $seq, 'kunci audit di brankas gagal dibuka: '.$e->getMessage());
                }
            }

            if ($unavailable === null) {
                $reason = CheckpointSigner::rowMismatch($publicKeys[$row->tenant_id], $row);
                if ($reason !== null) {
                    return CheckpointVerification::broken($checked, $lastValid, $seq, $reason);
                }
            }
            if ($seq > $chainHead->seq) {
                return CheckpointVerification::broken($checked, $lastValid, $seq, "rantai berakhir di seq {$chainHead->seq} sebelum checkpoint (ujung rantai terpotong)");
            }
            if ($row->entry_hash === null || ! hash_equals($row->hash, $row->entry_hash)) {
                return CheckpointVerification::broken($checked, $lastValid, $seq, 'hash entri berbeda dengan checkpoint (rantai ditulis ulang)');
            }

            if ($unavailable === null) {
                $lastValid = $seq;
                $checked++;
            }
        }

        return $unavailable === null
            ? CheckpointVerification::intact($checked, $lastValid)
            : CheckpointVerification::unverifiable($checked, $lastValid, $unavailable);
    }
}
