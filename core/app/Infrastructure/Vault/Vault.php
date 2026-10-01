<?php

namespace App\Infrastructure\Vault;

use App\Domain\Vault\Data\SecretPurpose;
use App\Domain\Vault\Data\SecretStatus;
use App\Models\KeyWrap;
use App\Models\Secret;
use DomainException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * Satu-satunya pintu kriptografi brankas (ADR 0003 §2.7): enkripsi envelope XChaCha20-Poly1305 dengan kunci data
 * per rahasia, dibungkus kunci induk. AAD mengikat ciphertext ke barisnya sehingga baris yang ditukar atau
 * dilabel ulang lewat SQL gagal dibuka, bukan menghasilkan nilai yang salah.
 */
final class Vault
{
    private const FORMAT = 'sadmin-vault/1';

    private const NONCE_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    private const TAG_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

    private const DEK_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    public const WRAPPED_DEK_BYTES = self::NONCE_BYTES + self::DEK_BYTES + self::TAG_BYTES;

    /** Seed kunci penanda tangan Ed25519 (ADR 0004 §2.1). */
    private const ED25519_PURPOSES = [SecretPurpose::AuditKey, SecretPurpose::ServiceKey];

    /** Kunci yang dipakai di dalam brankas saja, tak pernah dikembalikan reveal() (ADR 0004 §2.1, ADR 0007 §2.1). */
    private const INTERNAL_PURPOSES = [SecretPurpose::AuditKey, SecretPurpose::ServiceKey, SecretPurpose::CaKey];

    public function __construct(private readonly MasterKeyLoader $loader) {}

    /** Mengenkripsi satu nilai dengan kunci data baru; ID dibuat pemanggil karena ikut diikat ke AAD. */
    public function seal(string $tenantId, string $secretId, string $keyWrapId, SecretPurpose $purpose, #[SensitiveParameter] SecretValue $value): SealedSecret
    {
        foreach (['tenant_id' => $tenantId, 'secret_id' => $secretId, 'key_wrap_id' => $keyWrapId] as $field => $id) {
            if (! Str::isUlid($id) || $id !== strtolower($id)) {
                throw new InvalidArgumentException("{$field} harus ULID huruf kecil (ADR 0003 §2.2).");
            }
        }

        $kek = $this->loader->load();
        $dek = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
        $wrapNonce = random_bytes(self::NONCE_BYTES);
        $nonce = random_bytes(self::NONCE_BYTES);

        try {
            $wrapped = $wrapNonce.sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $dek, self::wrapAad($tenantId, $keyWrapId, $kek->version), $wrapNonce, $kek->bytes(),
            );
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $value->expose(), self::secretAad($tenantId, $secretId, $purpose, $keyWrapId), $nonce, $dek,
            );
        } finally {
            sodium_memzero($dek);
        }

        return new SealedSecret($wrapped, $kek->version, $nonce, $ciphertext);
    }

    /**
     * Membuka nilai satu rahasia (ADR 0003 §2.5). Pemanggil menyebut purpose & tenant yang ia harapkan, sehingga
     * penunjuk yang ditukar di tabel perujuk tak membuka rahasia lain. Baris dibaca ulang di bawah FOR SHARE agar
     * tak hancur di tengah jalan. Gagal tertutup: tak pernah mengembalikan nilai yang tak terverifikasi. Seed kunci
     * Ed25519 dan kunci CA ditolak: brankas memakainya di dalam saja (ADR 0004 §2.1, ADR 0007 §2.1).
     */
    public function reveal(string $secretId, SecretPurpose $expectedPurpose, string $tenantId): SecretValue
    {
        if (in_array($expectedPurpose, self::INTERNAL_PURPOSES, true)) {
            throw new InvalidArgumentException("Kunci {$expectedPurpose->value} tak pernah dibuka keluar brankas; pakai signEd25519()/ed25519PublicKey() atau caCertificate()/signCertificateRequest() (ADR 0004 §2.1, ADR 0007 §2.1).");
        }

        return $this->open($secretId, $expectedPurpose, $tenantId);
    }

    /** Membandingkan nilai tersimpan dengan $expected di dalam brankas tanpa mengembalikannya (baca ulang saat simpan, §2.4). */
    public function matches(string $secretId, SecretPurpose $expectedPurpose, string $tenantId, #[SensitiveParameter] SecretValue $expected): bool
    {
        return $this->open($secretId, $expectedPurpose, $tenantId)->equals($expected);
    }

    private function open(string $secretId, SecretPurpose $expectedPurpose, string $tenantId): SecretValue
    {
        return DB::transaction(function () use ($secretId, $expectedPurpose, $tenantId): SecretValue {
            $secret = Secret::query()->sharedLock()->findOrFail($secretId);
            if ($secret->status === SecretStatus::Destroyed) {
                throw new DomainException("Rahasia {$secret->id} sudah dihancurkan.");
            }
            if ($secret->purpose !== $expectedPurpose || $secret->tenant_id !== $tenantId) {
                throw new VaultIntegrityError("Rahasia {$secret->id} ber-purpose {$secret->purpose->value} milik tenant {$secret->tenant_id}; yang diminta {$expectedPurpose->value} untuk tenant {$tenantId}.");
            }
            $wrap = $secret->keyWrap ?? throw new VaultIntegrityError("Rahasia {$secret->id} tak punya kunci data.");

            $dek = $this->unwrap($wrap, $this->loader->load());
            try {
                $plain = strlen($secret->nonce) === self::NONCE_BYTES && strlen($secret->ciphertext) > self::TAG_BYTES
                    ? sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                        $secret->ciphertext,
                        self::secretAad($secret->tenant_id, $secret->id, $secret->purpose, $secret->key_wrap_id),
                        $secret->nonce,
                        $dek,
                    )
                    : false;
            } finally {
                sodium_memzero($dek);
            }

            if ($plain === false) {
                throw new VaultIntegrityError("Rahasia {$secret->id} gagal dibuka: ciphertext atau ikatannya (tenant, purpose, kunci data) tidak cocok.");
            }

            return new SecretValue($plain);
        });
    }

    /**
     * Menandatangani pesan dengan kunci Ed25519 yang seed-nya ada di brankas (ADR 0004 §2.1). Seed tak pernah keluar
     * dari Infrastructure/Vault; pemanggil hanya menerima tanda tangan 64 byte.
     */
    public function signEd25519(string $secretId, SecretPurpose $expectedPurpose, string $tenantId, string $message): string
    {
        return Ed25519::sign($this->open($secretId, self::signingPurpose($expectedPurpose), $tenantId), $message);
    }

    /** Kunci publik 32 byte dari seed Ed25519 di brankas (ADR 0004 §2.1). */
    public function ed25519PublicKey(string $secretId, SecretPurpose $expectedPurpose, string $tenantId): string
    {
        return Ed25519::publicKey($this->open($secretId, self::signingPurpose($expectedPurpose), $tenantId));
    }

    /** Sertifikat CA (PEM) dari rahasia `ca_key`; kunci privatnya tetap di brankas (ADR 0007 §2.1). */
    public function caCertificate(string $secretId, string $tenantId): string
    {
        return X509Authority::certificate($this->open($secretId, SecretPurpose::CaKey, $tenantId));
    }

    /**
     * Menandatangani CSR dengan kunci CA di brankas (ADR 0007 §2.3). Kunci privat tak pernah keluar dari
     * Infrastructure/Vault; pemanggil menyusun profil ekstensinya dan hanya menerima sertifikat PEM.
     *
     * @param  array<string, string>  $extensions
     */
    public function signCertificateRequest(string $secretId, string $tenantId, string $csrPem, array $extensions, int $days, int $serial): string
    {
        return X509Authority::sign($this->open($secretId, SecretPurpose::CaKey, $tenantId), $csrPem, $extensions, $days, $serial);
    }

    /** Membuktikan satu kunci data terbuka dengan kunci induk yang termuat, tanpa membuka nilai rahasianya (§2.6). */
    public function checkKeyWrap(KeyWrap $wrap, MasterKey $kek): void
    {
        $dek = $this->unwrap($wrap, $kek);
        sodium_memzero($dek);
    }

    /** Memuat kunci induk dan menguji bungkus-buka di memori; tak menyentuh DB (§2.6). */
    public function selfTest(): MasterKey
    {
        $kek = $this->loader->load();
        $dek = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
        $nonce = random_bytes(self::NONCE_BYTES);
        $aad = self::FORMAT.'/self-test';

        $wrapped = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($dek, $aad, $nonce, $kek->bytes());
        $opened = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($wrapped, $aad, $nonce, $kek->bytes());
        $ok = $opened !== false && hash_equals($dek, $opened);
        sodium_memzero($dek);
        if ($opened !== false) {
            sodium_memzero($opened);
        }
        if (! $ok) {
            throw new VaultIntegrityError('Uji bungkus-buka kunci induk gagal.');
        }

        return $kek;
    }

    private function unwrap(KeyWrap $wrap, MasterKey $kek): string
    {
        if ($wrap->master_key_version !== $kek->version) {
            throw new VaultUnavailable("Kunci data {$wrap->id} memakai kunci induk versi {$wrap->master_key_version}; yang termuat versi {$kek->version}.");
        }

        $dek = strlen($wrap->wrapped_dek) === self::WRAPPED_DEK_BYTES
            ? sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                substr($wrap->wrapped_dek, self::NONCE_BYTES),
                self::wrapAad($wrap->tenant_id, $wrap->id, $wrap->master_key_version),
                substr($wrap->wrapped_dek, 0, self::NONCE_BYTES),
                $kek->bytes(),
            )
            : false;

        if ($dek === false || strlen($dek) !== self::DEK_BYTES) {
            throw new VaultIntegrityError("Kunci data {$wrap->id} gagal dibuka: kunci induk salah atau baris key_wraps diubah.");
        }

        return $dek;
    }

    /** Hanya kunci yang di ../kontrak/KONTRAK.md §3 berjenis Ed25519; rahasia lain tak boleh dipakai menandatangani. */
    private static function signingPurpose(SecretPurpose $purpose): SecretPurpose
    {
        if (! in_array($purpose, self::ED25519_PURPOSES, true)) {
            throw new InvalidArgumentException("Rahasia ber-purpose {$purpose->value} bukan kunci Ed25519.");
        }

        return $purpose;
    }

    private static function wrapAad(string $tenantId, string $keyWrapId, int $masterKeyVersion): string
    {
        return self::FORMAT."/key_wrap/{$tenantId}/{$keyWrapId}/{$masterKeyVersion}";
    }

    private static function secretAad(string $tenantId, string $secretId, SecretPurpose $purpose, string $keyWrapId): string
    {
        return self::FORMAT."/secret/{$tenantId}/{$secretId}/{$purpose->value}/{$keyWrapId}";
    }
}
