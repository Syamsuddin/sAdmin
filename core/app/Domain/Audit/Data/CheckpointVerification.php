<?php

namespace App\Domain\Audit\Data;

/**
 * Hasil pemeriksaan checkpoint sesudah rantai utuh (ADR 0004 §2.5). `verifiable` = false bila brankas tak tersedia
 * sehingga tanda tangan tak dapat diperiksa (exit 2), berbeda dari checkpoint yang terbukti rusak (exit 1).
 */
final readonly class CheckpointVerification
{
    private function __construct(
        public bool $intact,
        public bool $verifiable,
        public int $checked,
        public ?int $lastValidSeq,
        public ?int $brokenAtSeq,
        public ?string $reason,
    ) {}

    public static function intact(int $checked, ?int $lastValidSeq): self
    {
        return new self(true, true, $checked, $lastValidSeq, null, null);
    }

    public static function broken(int $checked, ?int $lastValidSeq, int $brokenAtSeq, string $reason): self
    {
        return new self(false, true, $checked, $lastValidSeq, $brokenAtSeq, $reason);
    }

    public static function unverifiable(int $checked, ?int $lastValidSeq, string $reason): self
    {
        return new self(false, false, $checked, $lastValidSeq, null, $reason);
    }
}
