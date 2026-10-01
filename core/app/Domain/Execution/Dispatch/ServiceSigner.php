<?php

namespace App\Domain\Execution\Dispatch;

use App\Domain\Vault\Data\SecretPurpose;
use App\Domain\Vault\Data\SecretStatus;
use App\Infrastructure\Jcs\Jcs;
use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\Vault;
use App\Models\Secret;
use DomainException;
use Illuminate\Support\Str;
use InvalidArgumentException;
use LogicException;
use stdClass;

/**
 * Satu-satunya penyusun bingkai core→agen bertanda tangan kunci layanan (ADR 0006 §2.3). Byte yang ditandatangani
 * dimiliki ../kontrak/KONTRAK.md §3; mengubahnya = kontrak major + gerbang manusia (docs/22).
 */
final class ServiceSigner
{
    public const MESSAGE_PREFIX = "sadmin-service/1\n";

    /** Batas ukuran bingkai WebSocket (KONTRAK §2). */
    public const MAX_FRAME_BYTES = 1048576;

    /** Anggota bingkai core→agen, tepat empat (KONTRAK §3). */
    private const FRAME_MEMBERS = ['body', 'id', 'sig', 'type'];

    public function __construct(private readonly Vault $vault) {}

    /**
     * awalan ∥ JCS({type, id, body}). Khusus Envelope, secret_values dikeluarkan dari body: nilainya terikat lewat
     * komitmen placeholder di params, yang ikut ditandatangani (KONTRAK §3, §5).
     *
     * @param  array<array-key, mixed>|stdClass  $body
     */
    public static function message(string $type, string $id, array|stdClass $body): string
    {
        if (is_array($body) && array_is_list($body)) {
            // PHP mengodekan list (termasuk [] kosong) sebagai larik JSON; badan bingkai wajib objek (ADR 0006 §2.3).
            throw new InvalidArgumentException('Badan bingkai wajib objek JSON; pakai stdClass untuk objek kosong.');
        }

        // json_encode mengodekan larik non-list sebagai objek; badan tetap objek walau sisanya ber-kunci 0..n-1 atau
        // kosong setelah secret_values dikeluarkan.
        $body = is_array($body) ? (object) $body : clone $body;
        if ($type === 'Envelope') {
            unset($body->secret_values);
        }

        return self::MESSAGE_PREFIX.Jcs::canonicalize(['type' => $type, 'id' => $id, 'body' => $body]);
    }

    /** ID rahasia kunci layanan aktif tenant, atau null bila belum dibuat (tak pernah dibuat implisit, ADR 0006 §2.1). */
    public function activeKeyId(string $tenantId): ?string
    {
        $id = Secret::query()
            ->where('tenant_id', $tenantId)
            ->where('purpose', SecretPurpose::ServiceKey->value)
            ->where('status', SecretStatus::Active->value)
            ->value('id');

        return is_string($id) ? $id : null;
    }

    /** Kunci publik 32 byte mentah, diturunkan dari seed di brankas, bukan dari kolom DB (ADR 0006 §2.1). */
    public function publicKey(string $keyId, string $tenantId): string
    {
        return $this->vault->ed25519PublicKey($keyId, SecretPurpose::ServiceKey, $tenantId);
    }

    /**
     * Teks bingkai {type, id, body, sig} siap kirim, yang sudah lolos verifikasi sendiri seperti langkah E1-1 dan
     * E1-2 agen (ADR 0006 §2.3). Teks Envelope memuat secret_values: jangan pernah dicatat ke log atau tabel.
     *
     * @param  array<array-key, mixed>|stdClass  $body
     */
    public function frame(string $tenantId, string $type, string $id, array|stdClass $body): string
    {
        if ($type === '' || ! self::isUlid($id)) {
            throw new InvalidArgumentException('Bingkai butuh type tak kosong dan id berupa ULID huruf kecil (KONTRAK §2, §8).');
        }
        // Seluruh badan wajib I-JSON, termasuk secret_values yang tak ikut ditandatangani (KONTRAK §3).
        Jcs::canonicalize($body);
        $message = self::message($type, $id, $body);

        $keyId = $this->activeKeyId($tenantId)
            ?? throw new DomainException('Kunci layanan belum dibuat; jalankan sadmin:service-key-init lebih dulu.');
        $sig = Ed25519::encode($this->vault->signEd25519($keyId, SecretPurpose::ServiceKey, $tenantId, $message));

        $frame = json_encode(
            ['type' => $type, 'id' => $id, 'body' => $body, 'sig' => $sig],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );
        if (strlen($frame) > self::MAX_FRAME_BYTES) {
            throw new InvalidArgumentException('Bingkai melebihi 1 MiB (KONTRAK §2).');
        }

        if (! self::verifyFrame($this->publicKey($keyId, $tenantId), $frame)) {
            throw new LogicException('Bingkai core→agen gagal verifikasi sendiri (ADR 0006 §2.3); bingkai tidak dikirim.');
        }

        return $frame;
    }

    /**
     * Pemeriksaan agen yang menyangkut sig, dengan urutan yang sama: teks I-JSON, bentuk bingkai tepat empat anggota,
     * lalu sig kanonik yang sah atas pesan (KONTRAK §3). Keputusan akhir tetap milik agen.
     */
    public static function verifyFrame(string $publicKey, string $frame): bool
    {
        try {
            $decoded = Jcs::decode($frame);
        } catch (InvalidArgumentException) {
            return false;
        }

        if (! $decoded instanceof stdClass) {
            return false;
        }
        $members = array_keys(get_object_vars($decoded));
        sort($members);
        if ($members !== self::FRAME_MEMBERS
            || ! is_string($decoded->type) || $decoded->type === ''
            || ! is_string($decoded->id) || ! self::isUlid($decoded->id)
            || ! $decoded->body instanceof stdClass
            || ! is_string($decoded->sig)) {
            return false;
        }

        $signature = Ed25519::decode($decoded->sig);

        return $signature !== null
            && Ed25519::verify($publicKey, self::message($decoded->type, $decoded->id, $decoded->body), $signature);
    }

    /** ULID huruf kecil, dibandingkan apa adanya (KONTRAK §8): ID core selalu huruf kecil (ADR 0003 §2.2). */
    private static function isUlid(string $id): bool
    {
        return Str::isUlid($id) && $id === strtolower($id);
    }
}
