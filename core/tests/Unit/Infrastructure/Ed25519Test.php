<?php

namespace Tests\Unit\Infrastructure;

use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\VaultIntegrityError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** ADR 0004 §2.1–2.2: Ed25519 murni RFC 8032 dan base64 standar kanonik (../kontrak/KONTRAK.md §3). */
class Ed25519Test extends TestCase
{
    /** @return iterable<string, array{string, string, string, string}> seed, kunci publik, pesan, tanda tangan (hex) */
    public static function rfc8032Vectors(): iterable
    {
        yield 'RFC 8032 §7.1 TEST 1' => [
            '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
            '',
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        ];
        yield 'RFC 8032 §7.1 TEST 2' => [
            '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
            '72',
            '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
        ];
    }

    #[DataProvider('rfc8032Vectors')]
    public function test_matches_rfc8032_vectors(string $seed, string $publicKey, string $message, string $signature): void
    {
        $seedValue = new SecretValue((string) hex2bin($seed));

        $this->assertSame($publicKey, bin2hex(Ed25519::publicKey($seedValue)));
        $this->assertSame($signature, bin2hex(Ed25519::sign($seedValue, (string) hex2bin($message))));
        $this->assertTrue(Ed25519::verify((string) hex2bin($publicKey), (string) hex2bin($message), (string) hex2bin($signature)));
    }

    public function test_verify_rejects_altered_message_signature_key_and_wrong_lengths(): void
    {
        $seed = Ed25519::generateSeed();
        $publicKey = Ed25519::publicKey($seed);
        $signature = Ed25519::sign($seed, 'pesan');

        $this->assertTrue(Ed25519::verify($publicKey, 'pesan', $signature));
        $this->assertFalse(Ed25519::verify($publicKey, 'pesaN', $signature));
        $this->assertFalse(Ed25519::verify($publicKey, 'pesan', $signature ^ str_pad("\x01", 64, "\0")));
        $this->assertFalse(Ed25519::verify(Ed25519::publicKey(Ed25519::generateSeed()), 'pesan', $signature));
        $this->assertFalse(Ed25519::verify(substr($publicKey, 1), 'pesan', $signature));
        $this->assertFalse(Ed25519::verify($publicKey, 'pesan', substr($signature, 1)));
        $this->assertFalse(Ed25519::verify($publicKey, 'pesan', $signature."\0"));
    }

    public function test_generated_seeds_are_32_random_bytes(): void
    {
        $a = Ed25519::generateSeed();
        $b = Ed25519::generateSeed();

        $this->assertSame(32, strlen($a->expose()));
        $this->assertFalse($a->equals($b));
    }

    /** @return iterable<string, array{string}> */
    public static function badSeeds(): iterable
    {
        yield '31 byte' => [str_repeat("\x01", 31)];
        yield '33 byte' => [str_repeat("\x01", 33)];
    }

    #[DataProvider('badSeeds')]
    public function test_refuses_seed_that_is_not_32_bytes(string $seed): void
    {
        $this->expectException(VaultIntegrityError::class);

        Ed25519::sign(new SecretValue($seed), 'pesan');
    }

    public function test_decode_accepts_only_canonical_padded_standard_base64(): void
    {
        $bytes = str_repeat("\xff", 63)."\x00";
        $canonical = Ed25519::encode($bytes);

        $this->assertSame(88, strlen($canonical));
        $this->assertSame($bytes, Ed25519::decode($canonical));

        $nonCanonical = substr($canonical, 0, 85).'B==';
        $this->assertSame($bytes, base64_decode($nonCanonical, true), 'Prasyarat: PHP sendiri menerima bit sisa.');
        $this->assertNull(Ed25519::decode($nonCanonical));
        $this->assertNull(Ed25519::decode(rtrim($canonical, '=')), 'tanpa padding');
        $this->assertNull(Ed25519::decode(strtr($canonical, '+/', '-_')), 'base64url');
        $this->assertNull(Ed25519::decode(' '.$canonical), 'spasi');
        $this->assertNull(Ed25519::decode('!!!!'));
    }
}
