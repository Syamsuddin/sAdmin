<?php

namespace App\Infrastructure\WebAuthn;

use CBOR\Decoder;
use CBOR\Normalizable;
use CBOR\StringStream;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\Ed25519;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CollectedClientData;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Satu-satunya pintu ke web-auth/webauthn-lib (ADR 0002). Parameter ceremony tetap: userVerification
 * required, attestation none, residentKey required, hanya ES256 (-7) & EdDSA (-8), origin eksplisit.
 * Opsi disimpan sebagai JSON yang sama persis dengan yang dikirim ke browser, lalu dipulihkan saat verifikasi.
 */
final class WebAuthnServer
{
    public const TIMEOUT_MS = 60000;

    public const ALGORITHMS = [ES256::ID, Ed25519::ID];

    private readonly SerializerInterface $serializer;

    public function __construct()
    {
        $this->serializer = (new WebauthnSerializerFactory(
            AttestationStatementSupportManager::create([NoneAttestationStatementSupport::create()]),
        ))->create();
    }

    /**
     * @param  list<string>  $excludeCredentialIds  kredensial biner yang sudah dimiliki admin
     */
    public function creationOptions(RelyingParty $rp, string $userHandle, string $userName, string $displayName, array $excludeCredentialIds): string
    {
        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($rp->name, $rp->id),
            user: PublicKeyCredentialUserEntity::create($userName, $userHandle, $displayName),
            challenge: random_bytes(32),
            pubKeyCredParams: array_map(PublicKeyCredentialParameters::createPk(...), self::ALGORITHMS),
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            ),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: array_map(
                static fn (string $id): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $id),
                $excludeCredentialIds,
            ),
            timeout: self::TIMEOUT_MS,
        );

        return $this->toJson($options);
    }

    public function requestOptions(RelyingParty $rp): string
    {
        return $this->toJson(PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: $rp->id,
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            timeout: self::TIMEOUT_MS,
        ));
    }

    public function verifyRegistration(string $credentialJson, string $optionsJson, RelyingParty $rp): RegisteredCredential
    {
        try {
            $response = $this->credential($credentialJson)->response;
            if (! $response instanceof AuthenticatorAttestationResponse) {
                throw PasskeyVerificationFailed::because('Respons bukan attestation.');
            }
            self::assertClientData($response->clientDataJSON, 'webauthn.create');
            $options = $this->serializer->deserialize($optionsJson, PublicKeyCredentialCreationOptions::class, 'json');

            $record = AuthenticatorAttestationResponseValidator::create($this->ceremonies($rp)->creationCeremony())
                ->check($response, $options, $rp->id);
        } catch (PasskeyVerificationFailed $e) {
            throw $e;
        } catch (Throwable $e) {
            throw PasskeyVerificationFailed::because('Attestation ditolak: '.$e->getMessage(), $e);
        }

        $alg = $this->algorithmOf($record->credentialPublicKey);

        return new RegisteredCredential($record->publicKeyCredentialId, $record->credentialPublicKey, $alg, $record->counter);
    }

    /** ID kredensial biner dari assertion, untuk mencari baris `authenticators` sebelum diverifikasi. */
    public function assertedCredentialId(string $credentialJson): string
    {
        try {
            return $this->credential($credentialJson)->rawId;
        } catch (Throwable $e) {
            throw PasskeyVerificationFailed::because('Assertion tak terbaca: '.$e->getMessage(), $e);
        }
    }

    public function verifyAssertion(string $credentialJson, string $optionsJson, RelyingParty $rp, StoredCredential $stored): VerifiedAssertion
    {
        try {
            $credential = $this->credential($credentialJson);
            $response = $credential->response;
            if (! $response instanceof AuthenticatorAssertionResponse) {
                throw PasskeyVerificationFailed::because('Respons bukan assertion.');
            }
            self::assertClientData($response->clientDataJSON, 'webauthn.get');
            if ($response->userHandle === null || ! hash_equals($stored->userHandle, $response->userHandle)) {
                throw PasskeyVerificationFailed::because('User handle tak cocok dengan pemilik kredensial.');
            }
            $options = $this->serializer->deserialize($optionsJson, PublicKeyCredentialRequestOptions::class, 'json');

            $record = CredentialRecord::create(
                publicKeyCredentialId: $stored->credentialId,
                type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                transports: [],
                attestationType: 'none',
                trustPath: EmptyTrustPath::create(),
                aaguid: Uuid::fromString('00000000-0000-0000-0000-000000000000'),
                credentialPublicKey: $stored->publicKeyCose,
                userHandle: $stored->userHandle,
                counter: $stored->signCount,
            );

            $updated = AuthenticatorAssertionResponseValidator::create($this->ceremonies($rp)->requestCeremony())
                ->check($record, $response, $options, $rp->id, $response->userHandle);
        } catch (PasskeyVerificationFailed $e) {
            throw $e;
        } catch (Throwable $e) {
            throw PasskeyVerificationFailed::because('Assertion ditolak: '.$e->getMessage(), $e);
        }

        return new VerifiedAssertion($updated->publicKeyCredentialId, $updated->userHandle, $updated->counter);
    }

    /**
     * Spesifikasi WebAuthn §7.1 langkah 7 / §7.2 langkah 11: tipe harus sesuai ceremony. Kolektor bawaan
     * web-auth 5.3 menerima kedua tipe untuk kedua ceremony, dan CheckTopOrigin lolos bila topOrigin kosong,
     * sehingga keduanya diperiksa di sini; console tak pernah dibuka dalam iframe lintas origin.
     */
    private static function assertClientData(CollectedClientData $clientData, string $expectedType): void
    {
        if ($clientData->type !== $expectedType) {
            throw PasskeyVerificationFailed::because("Tipe clientData {$clientData->type} bukan {$expectedType}.");
        }
        if ($clientData->crossOrigin) {
            throw PasskeyVerificationFailed::because('Ceremony lintas origin (iframe) ditolak.');
        }
    }

    private function ceremonies(RelyingParty $rp): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory;
        $factory->setAllowedOrigins([$rp->origin]);
        $factory->setAlgorithmManager(Manager::create()->add(ES256::create(), Ed25519::create()));

        return $factory;
    }

    private function credential(string $json): PublicKeyCredential
    {
        return $this->serializer->deserialize($json, PublicKeyCredential::class, 'json');
    }

    private function algorithmOf(string $coseKey): int
    {
        // cbor-php menormalkan integer menjadi string desimal ('-8'), jadi dicocokkan setelah diperiksa ketat.
        $decoded = Decoder::create()->decode(StringStream::create($coseKey));
        $map = $decoded instanceof Normalizable ? $decoded->normalize() : null;
        $raw = is_array($map) ? ($map[3] ?? null) : null;
        $alg = is_string($raw) && preg_match('/^-?\d+$/', $raw) === 1 ? (int) $raw : $raw;
        if (! in_array($alg, self::ALGORITHMS, true)) {
            throw PasskeyVerificationFailed::because('Algoritme kunci di luar ES256/EdDSA.');
        }

        return $alg;
    }

    private function toJson(object $options): string
    {
        return $this->serializer->serialize($options, 'json', [
            AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
            JsonEncode::OPTIONS => JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        ]);
    }
}
