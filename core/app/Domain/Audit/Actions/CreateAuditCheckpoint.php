<?php

namespace App\Domain\Audit\Actions;

use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Data\CheckpointResult;
use App\Domain\Audit\Data\CheckpointStatus;
use App\Domain\Audit\Services\AuditChainVerifier;
use App\Domain\Audit\Services\AuditHasher;
use App\Domain\Audit\Services\CheckpointSigner;
use App\Models\Institution;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use stdClass;
use UnexpectedValueException;

/**
 * Menandatangani ujung rantai audit dengan kunci audit (ADR 0004 §2.4). Segmen sejak checkpoint terakhir dibuktikan
 * lebih dulu, sehingga checkpoint tak pernah mengesahkan rantai yang sudah diubah. Tidak menulis entri audit karena
 * checkpoint adalah artefak audit itu sendiri. Galat brankas (VaultUnavailable, VaultIntegrityError) diteruskan.
 */
final class CreateAuditCheckpoint
{
    /** Menyerialkan pembuat checkpoint tanpa memblokir penulis audit (kunci rantai 7301001). */
    public const LOCK_KEY = 7301002;

    public const DUE_ENTRIES = 100;

    public const DUE_MINUTES = 15;

    public function __construct(
        private readonly AuditChainVerifier $verifier,
        private readonly CheckpointSigner $signer,
    ) {}

    /** $onlyIfDue: penjadwal — hanya bila belum ada checkpoint, ≥ 100 entri baru, atau ≥ 15 menit sejak terakhir. */
    public function handle(bool $onlyIfDue = false): CheckpointResult
    {
        return DB::transaction(function () use ($onlyIfDue): CheckpointResult {
            DB::select('SELECT pg_advisory_xact_lock(?)', [self::LOCK_KEY]);

            $last = DB::table('audit_checkpoints')->orderByDesc('seq')->first();
            $lastSeq = $last === null ? null : (int) $last->seq;
            $tip = DB::table('audit_entries')->orderByDesc('seq')->first(['seq', 'hash']);
            $tipSeq = $tip === null ? 0 : (int) $tip->seq;

            if ($lastSeq !== null && $tipSeq < $lastSeq) {
                return CheckpointResult::refused($lastSeq, $lastSeq, "rantai berakhir di seq {$tipSeq} sebelum checkpoint seq {$lastSeq} (ujung rantai terpotong)");
            }
            if ($tip === null || $tipSeq === $lastSeq) {
                if ($last !== null && $tip !== null && ! hash_equals((string) $last->hash, $tip->hash)) {
                    return CheckpointResult::refused($lastSeq, $tipSeq, "hash entri seq {$tipSeq} berbeda dengan checkpoint (rantai ditulis ulang)");
                }

                return CheckpointResult::skipped(CheckpointStatus::NothingNew, $lastSeq);
            }
            if ($onlyIfDue && ! $this->isDue($last, $tipSeq)) {
                return CheckpointResult::skipped(CheckpointStatus::NotDue, $lastSeq);
            }

            $tenantId = Institution::query()->value('tenant_id');
            if (! is_string($tenantId)) {
                return CheckpointResult::unavailable($lastSeq, 'instansi belum diinisialisasi (sadmin:institution-init)');
            }
            $keyId = $this->signer->activeKeyId($tenantId);
            if ($keyId === null) {
                return CheckpointResult::unavailable($lastSeq, 'kunci audit belum dibuat (sadmin:audit-key-init)');
            }
            $publicKey = $this->signer->publicKey($keyId, $tenantId);

            $start = AuditHead::genesis();
            if ($last !== null) {
                $reason = $this->anchorMismatch($last, $publicKey);
                if ($reason !== null) {
                    return CheckpointResult::refused($lastSeq, (int) $last->seq, $reason);
                }
                $start = new AuditHead((int) $last->seq, $last->hash);
            }

            // Berjalan sampai ujung terkini, yang boleh melewati $tip bila ada entri baru sejak dibaca.
            $chain = $this->verifier->verifyAfter($start);
            if (! $chain->intact) {
                return CheckpointResult::refused($lastSeq, (int) $chain->brokenAtSeq, (string) $chain->reason);
            }
            $head = $chain->head;

            $createdAt = AuditHasher::formatTime(CarbonImmutable::now());
            DB::table('audit_checkpoints')->insert([
                'seq' => $head->seq,
                'tenant_id' => $tenantId,
                'hash' => $head->hash,
                'signature' => $this->signer->sign($keyId, $tenantId, $head->seq, $head->hash, $createdAt),
                'created_at' => $createdAt,
                'anchored_to' => '{}',
            ]);

            // Invarian "tertulis ⇒ terverifikasi": checkpoint yang tak lolos verifikasi akan membuat verify merah
            // selamanya, dan barisnya tak bisa dihapus (trigger). Batalkan di sini.
            $stored = DB::table('audit_checkpoints')->where('seq', $head->seq)->first();
            if ($stored === null || ! hash_equals($head->hash, $stored->hash) || CheckpointSigner::rowMismatch($publicKey, $stored) !== null) {
                throw new UnexpectedValueException('Checkpoint tak terbaca ulang dengan tanda tangan sah; pembuatan dibatalkan.');
            }

            return CheckpointResult::created($head->seq, $head->hash, $createdAt);
        });
    }

    private function isDue(?stdClass $last, int $tipSeq): bool
    {
        return $last === null
            || $tipSeq - (int) $last->seq >= self::DUE_ENTRIES
            || CarbonImmutable::parse($last->created_at)->addMinutes(self::DUE_MINUTES) <= CarbonImmutable::now();
    }

    /** Null bila checkpoint terakhir sah dan entri yang dicakupnya masih utuh (§2.4 no. 5); selain itu alasannya. */
    private function anchorMismatch(stdClass $last, string $publicKey): ?string
    {
        $seq = (int) $last->seq;
        $reason = CheckpointSigner::rowMismatch($publicKey, $last);
        if ($reason !== null) {
            return "checkpoint seq {$seq}: {$reason}";
        }

        $entry = DB::table('audit_entries')->where('seq', $seq)->first();
        if ($entry === null) {
            return "entri seq {$seq} yang dicakup checkpoint hilang";
        }
        if (! hash_equals((string) $last->hash, $entry->hash)) {
            return "hash entri seq {$seq} berbeda dengan checkpoint (rantai ditulis ulang)";
        }

        return $this->verifier->contentMismatch($entry);
    }
}
