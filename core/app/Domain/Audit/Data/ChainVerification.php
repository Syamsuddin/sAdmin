<?php

namespace App\Domain\Audit\Data;

/** Hasil verifikasi rantai audit; `head` = entri utuh terakhir sebelum titik rusak. */
final readonly class ChainVerification
{
    private function __construct(
        public bool $intact,
        public int $checked,
        public AuditHead $head,
        public ?int $brokenAtSeq,
        public ?string $reason,
    ) {}

    public static function intact(int $checked, AuditHead $head): self
    {
        return new self(true, $checked, $head, null, null);
    }

    public static function broken(int $checked, AuditHead $head, int $brokenAtSeq, string $reason): self
    {
        return new self(false, $checked, $head, $brokenAtSeq, $reason);
    }
}
