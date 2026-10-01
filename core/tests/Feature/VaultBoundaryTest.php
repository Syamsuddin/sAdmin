<?php

namespace Tests\Feature;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Finder\Finder;

/**
 * ADR 0003 §2.7 & ADR 0004 §2.1: satu pintu kriptografi brankas (AEAD dan tanda tangan Ed25519 dari seed brankas);
 * enkripsi Laravel (APP_KEY) terlarang untuk rahasia (docs/09).
 */
class VaultBoundaryTest extends TestCase
{
    private const VAULT = 'Infrastructure/Vault/';

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
            // Ed25519::sign/publicKey dan expose() membuka nilai/seed: hanya brankas yang boleh (ADR 0004 §2.1, docs/12).
            if (preg_match('/sodium_crypto_aead_|sodium_crypto_sign_|Ed25519::(?:sign|publicKey)\s*\(|->expose\s*\(|CREDENTIALS_DIRECTORY|sadmin\.vault\./i', $source) === 1) {
                $offenders[] = $path;
            }
        }

        $this->assertSame([], $offenders, 'Pakai App\Infrastructure\Vault (Vault, Ed25519), bukan AEAD, tanda tangan, atau kunci induk langsung.');
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
    }
}
