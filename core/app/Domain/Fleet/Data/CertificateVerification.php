<?php

namespace App\Domain\Fleet\Data;

/** Hasil aturan penerimaan sertifikat klien agen (../kontrak/KONTRAK.md §2): server_id, atau aturan pertama yang dilanggar. */
final readonly class CertificateVerification
{
    public const REASONS = ['pem', 'structure', 'issuer', 'signature', 'validity', 'key', 'basic_constraints', 'eku', 'san'];

    private function __construct(
        public ?string $serverId,
        public ?string $reason,
    ) {}

    public static function accepted(string $serverId): self
    {
        return new self($serverId, null);
    }

    public static function rejected(string $reason): self
    {
        return new self(null, $reason);
    }

    public function valid(): bool
    {
        return $this->serverId !== null;
    }
}
