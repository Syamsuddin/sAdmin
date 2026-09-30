<?php

namespace App\Domain\Audit\Data;

/** Ujung rantai audit: `audit_head` {seq, hash} (../kontrak/KONTRAK.md §5). */
final readonly class AuditHead
{
    public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    public function __construct(
        public int $seq,
        public string $hash,
    ) {}

    public static function genesis(): self
    {
        return new self(0, self::GENESIS_HASH);
    }
}
