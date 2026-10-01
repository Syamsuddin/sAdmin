<?php

namespace App\Domain\Alerts\Data;

/**
 * Satu kejadian `audit_mismatch` dari pendeteksi (ADR 0005 §2.1). `reason` berasal dari verifier, tanpa rahasia,
 * dan dipotong agar muat di satu pesan Telegram.
 */
final readonly class IntegrityAlert
{
    public const CHECK_CHAIN = 'chain';

    public const CHECK_CHECKPOINT = 'checkpoint';

    public const CHECK_CHECKPOINT_CREATE = 'checkpoint_create';

    public const CHECK_CHECKPOINT_READBACK = 'checkpoint_readback';

    public const CHECK_AUDIT_KEY = 'audit_key';

    public const MAX_REASON = 500;

    public ?int $seq;

    public string $reason;

    /** seq < 1 bukan lokasi entri; diperlakukan sebagai tak diketahui, bukan galat, agar alert tetap terkirim. */
    private function __construct(
        public string $detector,
        public string $check,
        ?int $seq,
        string $reason,
    ) {
        $this->seq = $seq !== null && $seq >= 1 ? $seq : null;
        $this->reason = mb_strimwidth($reason, 0, self::MAX_REASON, '…');
    }

    public static function chainBroken(int $seq, string $reason): self
    {
        return new self('sadmin:audit-verify', self::CHECK_CHAIN, $seq, $reason);
    }

    public static function checkpointBroken(int $seq, string $reason): self
    {
        return new self('sadmin:audit-verify', self::CHECK_CHECKPOINT, $seq, $reason);
    }

    public static function checkpointRefused(int $seq, string $reason): self
    {
        return new self('sadmin:audit-checkpoint', self::CHECK_CHECKPOINT_CREATE, $seq, $reason);
    }

    public static function checkpointReadback(string $reason): self
    {
        return new self('sadmin:audit-checkpoint', self::CHECK_CHECKPOINT_READBACK, null, $reason);
    }

    /** Kunci audit di brankas gagal dibuka saat membuat checkpoint (kelas Integritas docs/14). */
    public static function auditKeyUnreadable(string $reason): self
    {
        return new self('sadmin:audit-checkpoint', self::CHECK_AUDIT_KEY, null, $reason);
    }

    /** Satu alert belum selesai per lokasi kerusakan (ADR 0005 §2.2). */
    public function dedupKey(): string
    {
        return $this->seq === null
            ? AlertKind::AuditMismatch->value.":{$this->check}"
            : AlertKind::AuditMismatch->value.":seq:{$this->seq}";
    }

    /** @return array{detector: string, check: string, seq: int|null, reason: string} */
    public function detail(): array
    {
        return ['detector' => $this->detector, 'check' => $this->check, 'seq' => $this->seq, 'reason' => $this->reason];
    }
}
