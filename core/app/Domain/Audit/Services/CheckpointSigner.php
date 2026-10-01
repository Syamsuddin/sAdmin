<?php

namespace App\Domain\Audit\Services;

use App\Domain\Vault\Data\SecretPurpose;
use App\Domain\Vault\Data\SecretStatus;
use App\Infrastructure\Jcs\Jcs;
use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\Vault;
use App\Models\Secret;
use Carbon\CarbonImmutable;
use stdClass;
use Throwable;

/**
 * Tanda tangan checkpoint dengan kunci audit tenant (ADR 0004 §2.1–2.2). Byte yang ditandatangani dimiliki
 * ../kontrak/KONTRAK.md §3; mengubahnya = kontrak major + gerbang manusia (docs/22).
 */
final class CheckpointSigner
{
    public const MESSAGE_PREFIX = "sadmin-audit-checkpoint/1\n";

    public function __construct(private readonly Vault $vault) {}

    /** $createdAt sudah berformat AuditHasher::formatTime (RFC 3339 UTC, 6 digit mikrodetik). */
    public static function message(int $seq, string $hash, string $createdAt): string
    {
        return self::MESSAGE_PREFIX.Jcs::canonicalize(['seq' => $seq, 'hash' => $hash, 'created_at' => $createdAt]);
    }

    /** ID rahasia kunci audit aktif tenant, atau null bila belum dibuat (tak pernah dibuat implisit, §2.1). */
    public function activeKeyId(string $tenantId): ?string
    {
        $id = Secret::query()
            ->where('tenant_id', $tenantId)
            ->where('purpose', SecretPurpose::AuditKey->value)
            ->where('status', SecretStatus::Active->value)
            ->value('id');

        return is_string($id) ? $id : null;
    }

    /** Kunci publik 32 byte mentah, diturunkan dari seed di brankas: akar kepercayaan verifikasi di core (§2.1). */
    public function publicKey(string $keyId, string $tenantId): string
    {
        return $this->vault->ed25519PublicKey($keyId, SecretPurpose::AuditKey, $tenantId);
    }

    /** Tanda tangan base64 standar berpadding (88 karakter). */
    public function sign(string $keyId, string $tenantId, int $seq, string $hash, string $createdAt): string
    {
        return Ed25519::encode(
            $this->vault->signEd25519($keyId, SecretPurpose::AuditKey, $tenantId, self::message($seq, $hash, $createdAt)),
        );
    }

    public static function verify(string $publicKey, int $seq, string $hash, string $createdAt, string $signature): bool
    {
        $bytes = Ed25519::decode($signature);

        return $bytes !== null && Ed25519::verify($publicKey, self::message($seq, $hash, $createdAt), $bytes);
    }

    /**
     * Tanda tangan satu baris audit_checkpoints sah. Baris hasil manipulasi apa pun (waktu atau teks tak terurai)
     * berarti tak sah, bukan crash; pemanggil mencatatnya sebagai audit_mismatch.
     */
    public static function verifyRow(string $publicKey, stdClass $row): bool
    {
        try {
            $createdAt = AuditHasher::formatTime(CarbonImmutable::parse($row->created_at));

            return self::verify($publicKey, (int) $row->seq, (string) $row->hash, $createdAt, (string) $row->signature);
        } catch (Throwable) {
            return false;
        }
    }
}
