<?php

namespace Tests\Feature;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Finder\Finder;

/**
 * ADR 0003 §2.7 & ADR 0004 §2.1: satu pintu kriptografi brankas (AEAD dan tanda tangan Ed25519 dari seed brankas);
 * enkripsi Laravel (APP_KEY) terlarang untuk rahasia (docs/09). ADR 0005 §2.6: nilai rahasia dibuka (`expose()`)
 * hanya di brankas dan adaptor pengirim Notify.
 */
class VaultBoundaryTest extends TestCase
{
    private const VAULT = 'Infrastructure/Vault/';

    private const NOTIFY = 'Infrastructure/Notify/';

    /** Fungsi OpenSSL yang memegang kunci privat, dan pintu X509Authority yang membuka isi rahasia CA. */
    private const OPENSSL_PRIVATE = '/\bopenssl_(?:pkey_new|pkey_export|pkey_export_to_file|pkey_get_private|get_privatekey|csr_new|csr_sign|sign|private_encrypt|private_decrypt|open|seal|pkcs12_export|pkcs12_export_to_file|pkcs7_sign|cms_sign)\s*\(|X509Authority::(?:sign|certificate)\s*\(/i';

    /** @return array<string, string> path relatif => isi */
    private function appSources(): array
    {
        $sources = [];
        foreach (Finder::create()->files()->in(dirname(__DIR__, 2).'/app')->name('*.php') as $file) {
            $sources[$file->getRelativePathname()] = (string) file_get_contents($file->getPathname());
        }

        return $sources;
    }

    public function test_only_the_vault_uses_the_aead_signing_and_reads_the_master_key(): void
    {
        $offenders = [];
        foreach ($this->appSources() as $path => $source) {
            if (str_starts_with($path, self::VAULT)) {
                continue;
            }
            // Ed25519::sign/publicKey membuka seed: hanya brankas yang boleh (ADR 0004 §2.1, docs/12).
            if (preg_match('/sodium_crypto_aead_|sodium_crypto_sign_|Ed25519::(?:sign|publicKey)\s*\(|CREDENTIALS_DIRECTORY|sadmin\.vault\./i', $source) === 1) {
                $offenders[] = $path;
            }
        }

        $this->assertSame([], $offenders, 'Pakai App\Infrastructure\Vault (Vault, Ed25519), bukan AEAD, tanda tangan, atau kunci induk langsung.');
    }

    /** ADR 0007 §2.1: kunci privat CA hanya dipakai di Infrastructure/Vault; domain cukup kunci publik dan sertifikat. */
    public function test_only_the_vault_uses_openssl_private_keys_and_the_ca_key(): void
    {
        $offenders = [];
        foreach ($this->appSources() as $path => $source) {
            if (str_starts_with($path, self::VAULT)) {
                continue;
            }
            if (preg_match(self::OPENSSL_PRIVATE, $source) === 1) {
                $offenders[] = $path;
            }
        }

        $this->assertSame([], $offenders, 'Pakai Vault::caCertificate()/signCertificateRequest(), bukan fungsi OpenSSL kunci privat atau X509Authority langsung.');
    }

    /** ADR 0007 §2.3: CertificateAuthority satu-satunya penerbit sertifikat; pemanggil lain brankas CA tak diizinkan. */
    public function test_only_the_certificate_authority_asks_the_vault_to_sign_certificates(): void
    {
        $callers = [];
        foreach ($this->appSources() as $path => $source) {
            if (! str_starts_with($path, self::VAULT) && preg_match('/->signCertificateRequest\s*\(/', $source) === 1) {
                $callers[] = $path;
            }
        }

        $this->assertSame(['Domain/Fleet/Services/CertificateAuthority.php'], $callers);
    }

    public function test_secret_values_are_exposed_only_in_the_vault_and_notify_adapters(): void
    {
        $offenders = [];
        foreach ($this->appSources() as $path => $source) {
            if (str_starts_with($path, self::VAULT) || str_starts_with($path, self::NOTIFY)) {
                continue;
            }
            if (preg_match('/->expose\s*\(/i', $source) === 1) {
                $offenders[] = $path;
            }
        }

        $this->assertSame([], $offenders, 'Nilai rahasia hanya dibuka di titik pakai: brankas atau adaptor Notify (ADR 0005 §2.6).');
    }

    public function test_notify_adapters_reveal_only_channel_secrets_and_never_touch_signing_keys(): void
    {
        $purposes = [];
        $offenders = [];
        foreach ($this->appSources() as $path => $source) {
            if (! str_starts_with($path, self::NOTIFY)) {
                continue;
            }
            preg_match_all('/->reveal\s*\([^;]*?SecretPurpose::(\w+)/s', $source, $found);
            array_push($purposes, ...$found[1]);
            // Notify membuka rahasia hanya lewat reveal(); tak pernah seed Ed25519 atau jalur brankas lain.
            if (preg_match('/Ed25519|signEd25519|ed25519PublicKey|AuditKey|ServiceKey|CaKey|X509Authority|caCertificate|signCertificateRequest|->open\s*\(|->matches\s*\(/', $source) === 1) {
                $offenders[] = $path;
            }
        }

        $this->assertSame([], $offenders);
        $this->assertNotSame([], $purposes, 'Adaptor Notify seharusnya membuka rahasianya lewat Vault::reveal().');
        $this->assertSame([], array_values(array_diff(array_unique($purposes), ['TelegramToken', 'Smtp'])));
    }

    public function test_laravel_encryption_is_not_used_anywhere_in_app(): void
    {
        $patterns = [
            'Crypt facade' => '/\bCrypt::|Facades\\\\Crypt\b/',
            'Encrypter' => '/Illuminate\\\\(Contracts\\\\)?Encryption\\\\/',
            'helper encrypt()/decrypt()' => '/(?<![\w>:$])(?<!function )(?:en|de)crypt\s*\(/i',
            'cast encrypted' => '/[\'"]encrypted(?::[\w\\\\]+)?[\'"]/',
            "layanan 'encrypter'" => '/[\'"]encrypter[\'"]/',
        ];

        $offenders = [];
        foreach ($this->appSources() as $path => $source) {
            foreach ($patterns as $what => $pattern) {
                if (preg_match($pattern, $source) === 1) {
                    $offenders[] = "{$path}: {$what}";
                }
            }
        }

        $this->assertSame([], $offenders, 'Rahasia hanya lewat brankas (docs/09, ADR 0003 §2.7).');
    }

    public function test_patterns_catch_what_they_forbid(): void
    {
        $this->assertSame(1, preg_match('/(?<![\w>:$])(?<!function )(?:en|de)crypt\s*\(/i', '$x = encrypt($v);'));
        $this->assertSame(1, preg_match('/(?<![\w>:$])(?<!function )(?:en|de)crypt\s*\(/i', 'return \\decrypt($v);'));
        $this->assertSame(0, preg_match('/(?<![\w>:$])(?<!function )(?:en|de)crypt\s*\(/i', '$cipher->decrypt($v);'));
        $this->assertSame(1, preg_match('/[\'"]encrypted(?::[\w\\\\]+)?[\'"]/', "'token' => 'encrypted:array',"));
        $this->assertSame(1, preg_match('/\bCrypt::|Facades\\\\Crypt\b/', 'use Illuminate\Support\Facades\Crypt;'));
        $this->assertSame(1, preg_match('/[\'"]encrypter[\'"]/', 'app(\'encrypter\')->encrypt($v);'));
        $this->assertSame(1, preg_match(self::OPENSSL_PRIVATE, '$cert = openssl_csr_sign($csr, $ca, $key, 7);'));
        $this->assertSame(1, preg_match(self::OPENSSL_PRIVATE, '$k = \\openssl_pkey_get_private($pem);'));
        $this->assertSame(1, preg_match(self::OPENSSL_PRIVATE, 'X509Authority::sign($bundle, $csr, [], 7, 1);'));
        $this->assertSame(0, preg_match(self::OPENSSL_PRIVATE, '$ok = openssl_verify($data, $sig, $pub, OPENSSL_ALGO_SHA256);'));
        $this->assertSame(0, preg_match(self::OPENSSL_PRIVATE, 'X509Authority::generate($cn, $ext, 3650, $serial);'));
    }
}
