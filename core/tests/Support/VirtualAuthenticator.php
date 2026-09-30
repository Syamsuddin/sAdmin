<?php

namespace Tests\Support;

use CBOR\ByteStringObject;
use CBOR\CBORObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * Autentikator WebAuthn virtual untuk tes (docs/13): membuat attestation & assertion sungguhan yang ditandatangani
 * kunci uji, sehingga verifikasi server dijalankan penuh, tak pernah di-bypass. EdDSA memakai kunci deterministik
 * dari SADMIN_TEST_PASSKEY_SEED; ES256 memakai kunci P-256 acak (openssl tak bisa diturunkan dari seed).
 * Setiap parameter yang bisa dipalsukan penyerang (origin, RP ID, flag, counter, challenge, user handle) bisa diubah.
 */
final class VirtualAuthenticator
{
    private const FLAG_UP = 0x01;

    private const FLAG_UV = 0x04;

    private const FLAG_AT = 0x40;

    public string $origin = 'https://sadmin.localhost';

    public string $rpId = 'sadmin.localhost';

    public int $signCount = 0;

    public bool $userVerified = true;

    public bool $userPresent = true;

    /** Menimpa `type` clientDataJSON (null = sesuai ceremony). */
    public ?string $clientDataType = null;

    public bool $crossOrigin = false;

    public readonly string $credentialId;

    private string $userHandle = '';

    private ?string $edSecretKey = null;

    private ?string $edPublicKey = null;

    private ?OpenSSLAsymmetricKey $ecKey = null;

    private function __construct(public readonly int $alg, string $label)
    {
        $seed = hex2bin((string) env('SADMIN_TEST_PASSKEY_SEED'));
        if ($seed === false || strlen($seed) !== 32) {
            throw new RuntimeException('SADMIN_TEST_PASSKEY_SEED wajib 64 karakter hex (phpunit.xml).');
        }
        $this->credentialId = hash('sha256', 'kredensial:'.$label.$seed, true);

        if ($alg === -8) {
            $pair = sodium_crypto_sign_seed_keypair(hash('sha256', 'ed25519:'.$label.$seed, true));
            $this->edSecretKey = sodium_crypto_sign_secretkey($pair);
            $this->edPublicKey = sodium_crypto_sign_publickey($pair);
        } else {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            if ($key === false) {
                throw new RuntimeException('Gagal membuat kunci P-256 uji.');
            }
            $this->ecKey = $key;
        }
    }

    public static function eddsa(string $label = 'utama'): self
    {
        return new self(-8, $label);
    }

    public static function es256(string $label = 'utama'): self
    {
        return new self(-7, $label);
    }

    /** Membalas opsi pendaftaran (JSON dari server) seperti navigator.credentials.create() + toJSON(). */
    public function register(string $creationOptionsJson): string
    {
        $options = json_decode($creationOptionsJson, true, 512, JSON_THROW_ON_ERROR);
        $this->userHandle = self::b64d($options['user']['id']);

        $clientData = $this->clientData('webauthn.create', $options['challenge']);
        $authData = $this->authData(self::FLAG_AT)
            .str_repeat("\0", 16)
            .pack('n', strlen($this->credentialId)).$this->credentialId
            .$this->coseKey();

        $attestation = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return $this->credentialJson([
            'clientDataJSON' => self::b64e($clientData),
            'attestationObject' => self::b64e((string) $attestation),
            'transports' => ['internal'],
        ]);
    }

    /** Membalas opsi masuk seperti navigator.credentials.get() + toJSON(). */
    public function assert(string $requestOptionsJson, ?string $userHandle = null): string
    {
        $options = json_decode($requestOptionsJson, true, 512, JSON_THROW_ON_ERROR);
        $clientData = $this->clientData('webauthn.get', $options['challenge']);
        $authData = $this->authData(0);

        return $this->credentialJson([
            'clientDataJSON' => self::b64e($clientData),
            'authenticatorData' => self::b64e($authData),
            'signature' => self::b64e($this->sign($authData.hash('sha256', $clientData, true))),
            'userHandle' => self::b64e($userHandle ?? $this->userHandle),
        ]);
    }

    /** Menjadikan autentikator ini "sudah terdaftar" untuk admin tertentu (tes yang tak melewati pendaftaran). */
    public function ownedBy(string $userHandle): self
    {
        $this->userHandle = $userHandle;

        return $this;
    }

    /** Kunci publik COSE mentah, sama dengan yang disimpan server setelah pendaftaran. */
    public function coseKey(): string
    {
        return (string) ($this->alg === -8
            ? self::map([1 => 1, 3 => -8, -1 => 6, -2 => $this->edPublicKey])
            : self::map([1 => 2, 3 => -7, -1 => 1, -2 => $this->ecCoordinate('x'), -3 => $this->ecCoordinate('y')]));
    }

    private function clientData(string $type, string $challenge): string
    {
        return json_encode([
            'type' => $this->clientDataType ?? $type,
            'challenge' => $challenge,
            'origin' => $this->origin,
            'crossOrigin' => $this->crossOrigin,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private function authData(int $extraFlags): string
    {
        $flags = ($this->userPresent ? self::FLAG_UP : 0) | ($this->userVerified ? self::FLAG_UV : 0) | $extraFlags;

        return hash('sha256', $this->rpId, true).chr($flags).pack('N', $this->signCount);
    }

    private function sign(string $data): string
    {
        if ($this->alg === -8) {
            return sodium_crypto_sign_detached($data, (string) $this->edSecretKey);
        }
        openssl_sign($data, $signature, $this->ecKey, OPENSSL_ALGO_SHA256);

        return $signature;
    }

    private function ecCoordinate(string $axis): string
    {
        $details = openssl_pkey_get_details($this->ecKey);

        return str_pad($details['ec'][$axis], 32, "\0", STR_PAD_LEFT);
    }

    /** @param  array<string, string>  $response */
    private function credentialJson(array $response): string
    {
        return json_encode([
            'id' => self::b64e($this->credentialId),
            'rawId' => self::b64e($this->credentialId),
            'type' => 'public-key',
            'response' => $response,
            'clientExtensionResults' => new \stdClass,
            'authenticatorAttachment' => 'platform',
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /** @param  array<int, int|string|null>  $entries */
    private static function map(array $entries): MapObject
    {
        $map = MapObject::create();
        foreach ($entries as $key => $value) {
            $map->add(self::int($key), is_int($value) ? self::int($value) : ByteStringObject::create((string) $value));
        }

        return $map;
    }

    private static function int(int $value): CBORObject
    {
        return $value < 0 ? NegativeIntegerObject::create($value) : UnsignedIntegerObject::create($value);
    }

    public static function b64e(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function b64d(string $data): string
    {
        return (string) base64_decode(strtr($data, '-_', '+/'), true);
    }
}
