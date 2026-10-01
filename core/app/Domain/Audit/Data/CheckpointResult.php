<?php

namespace App\Domain\Audit\Data;

final readonly class CheckpointResult
{
    private function __construct(
        public CheckpointStatus $status,
        public ?int $seq,
        public ?string $hash = null,
        public ?string $createdAt = null,
        public ?int $brokenAtSeq = null,
        public ?string $reason = null,
    ) {}

    public static function created(int $seq, string $hash, string $createdAt): self
    {
        return new self(CheckpointStatus::Created, $seq, $hash, $createdAt);
    }

    /** $lastSeq = seq checkpoint terakhir yang sudah ada (null bila belum ada). */
    public static function skipped(CheckpointStatus $status, ?int $lastSeq): self
    {
        return new self($status, $lastSeq);
    }

    public static function refused(?int $lastSeq, int $brokenAtSeq, string $reason): self
    {
        return new self(CheckpointStatus::Refused, $lastSeq, brokenAtSeq: $brokenAtSeq, reason: $reason);
    }

    public static function unavailable(?int $lastSeq, string $reason): self
    {
        return new self(CheckpointStatus::Unavailable, $lastSeq, reason: $reason);
    }
}
