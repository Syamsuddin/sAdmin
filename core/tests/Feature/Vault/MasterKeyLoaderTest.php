<?php

namespace Tests\Feature\Vault;

use App\Infrastructure\Vault\MasterKey;
use App\Infrastructure\Vault\MasterKeyLoader;
use App\Infrastructure\Vault\VaultUnavailable;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0003 §2.1: sumber, bentuk, dan izin kunci induk; selalu gagal tertutup. */
class MasterKeyLoaderTest extends TestCase
{
    use InteractsWithVault;

    private string $credentialsDir;

    protected function setUp(): void
    {
        parent::setUp();
        putenv('CREDENTIALS_DIRECTORY');
        $this->credentialsDir = sys_get_temp_dir().'/sadmin-creds-test-'.bin2hex(random_bytes(6));
        mkdir($this->credentialsDir, 0700);
    }

    protected function tearDown(): void
    {
        putenv('CREDENTIALS_DIRECTORY');
        foreach (glob($this->credentialsDir.'/{,*/}*', GLOB_BRACE) ?: [] as $file) {
            is_dir($file) ? null : unlink($file);
        }
        foreach (glob($this->credentialsDir.'/*', GLOB_ONLYDIR) ?: [] as $dir) {
            rmdir($dir);
        }
        rmdir($this->credentialsDir);
        parent::tearDown();
    }

    private function load(): MasterKey
    {
        return app(MasterKeyLoader::class)->load();
    }

    private function assertUnavailable(string $messagePart): void
    {
        try {
            $this->load();
            $this->fail('Kunci induk seharusnya ditolak.');
        } catch (VaultUnavailable $e) {
            $this->assertStringContainsString($messagePart, $e->getMessage());
        }
    }

    public function test_dev_key_file_is_loaded_as_version_one(): void
    {
        $key = random_bytes(32);
        $this->useVaultKey($key);

        $loaded = $this->load();

        $this->assertSame(1, $loaded->version);
        $this->assertSame($key, $loaded->bytes());
        $this->assertSame('berkas dev SADMIN_VAULT_DEV_KEY', $loaded->source);
    }

    /** @return array<string, array{int}> */
    public static function wrongLengths(): array
    {
        return ['kosong' => [0], '31 byte' => [31], '33 byte' => [33], '64 byte (hex)' => [64]];
    }

    #[DataProvider('wrongLengths')]
    public function test_key_must_be_exactly_32_raw_bytes(int $length): void
    {
        $this->useVaultKey(str_repeat('k', $length));

        $this->assertUnavailable("berisi {$length} byte");
    }

    public function test_trailing_newline_is_not_tolerated(): void
    {
        $this->useVaultKey(random_bytes(32)."\n");

        $this->assertUnavailable('berisi 33 byte');
    }

    /** @return array<string, array{int}> */
    public static function exposedModes(): array
    {
        return ['0640' => [0640], '0604' => [0604], '0660' => [0660]];
    }

    #[DataProvider('exposedModes')]
    public function test_dev_key_file_readable_by_others_is_refused(int $mode): void
    {
        $this->useVaultKey(null, $mode);

        $this->assertUnavailable('chmod 600');
    }

    public function test_missing_dev_key_file_is_refused(): void
    {
        config(['sadmin.vault.dev_key_file' => $this->credentialsDir.'/tidak-ada.key']);

        $this->assertUnavailable('tidak ada');
    }

    /** @return array<string, array{string}> */
    public static function nonDevelopmentEnvironments(): array
    {
        return ['production' => ['production'], 'huruf besar' => ['Production'], 'singkatan' => ['prod'], 'staging' => ['staging']];
    }

    /** Daftar izin local/testing: APP_ENV apa pun selain itu, termasuk salah ketik, menolak kunci dev. */
    #[DataProvider('nonDevelopmentEnvironments')]
    public function test_dev_key_is_refused_outside_local_and_testing(string $environment): void
    {
        $this->useVaultKey();
        $this->app['env'] = $environment;

        try {
            $this->assertUnavailable('hanya untuk APP_ENV local/testing');
        } finally {
            $this->app['env'] = 'testing';
        }
    }

    #[DataProvider('nonDevelopmentEnvironments')]
    public function test_outside_development_credentials_must_live_under_run_credentials(string $environment): void
    {
        $this->withoutVaultKey();
        config(['sadmin.vault.credential' => 'sadmin-vault-master']);
        file_put_contents($this->credentialsDir.'/sadmin-vault-master', random_bytes(32));
        putenv('CREDENTIALS_DIRECTORY='.$this->credentialsDir);
        $this->app['env'] = $environment;

        try {
            // .env yang diubah tak boleh mengarahkan kunci induk ke berkas polos sembarang.
            $this->assertUnavailable('di bawah /run/credentials/');
        } finally {
            $this->app['env'] = 'testing';
        }
    }

    #[DataProvider('nonDevelopmentEnvironments')]
    public function test_outside_development_a_systemd_credential_loads(string $environment): void
    {
        $this->withoutVaultKey();
        config(['sadmin.vault.credential' => 'sadmin-vault-master']);
        mkdir($this->credentialsDir.'/php8.3-fpm.service', 0700);
        $key = random_bytes(32);
        file_put_contents($this->credentialsDir.'/php8.3-fpm.service/sadmin-vault-master', $key);
        putenv('CREDENTIALS_DIRECTORY='.$this->credentialsDir.'/php8.3-fpm.service');
        $this->app['env'] = $environment;

        try {
            $loaded = (new MasterKeyLoader(systemdCredentialsRoot: (string) realpath($this->credentialsDir)))->load();
        } finally {
            $this->app['env'] = 'testing';
        }

        $this->assertSame($key, $loaded->bytes());
        $this->assertSame('kredensial systemd sadmin-vault-master', $loaded->source);
    }

    public function test_directory_instead_of_key_file_is_refused(): void
    {
        config(['sadmin.vault.dev_key_file' => $this->credentialsDir]);

        $this->expectException(VaultUnavailable::class);

        $this->load();
    }

    public function test_systemd_credential_is_loaded_at_runtime(): void
    {
        $this->withoutVaultKey();
        config(['sadmin.vault.credential' => 'sadmin-vault-master']);
        $key = random_bytes(32);
        file_put_contents($this->credentialsDir.'/sadmin-vault-master', $key);
        // systemd memberi akses lewat ACL; bit grup bisa menyala dan tetap sah.
        chmod($this->credentialsDir.'/sadmin-vault-master', 0440);
        putenv('CREDENTIALS_DIRECTORY='.$this->credentialsDir);

        $loaded = $this->load();

        $this->assertSame($key, $loaded->bytes());
        $this->assertSame('kredensial systemd sadmin-vault-master', $loaded->source);
    }

    public function test_dev_key_alongside_systemd_credential_is_ambiguous_and_refused(): void
    {
        file_put_contents($this->credentialsDir.'/sadmin-vault-master', random_bytes(32));
        putenv('CREDENTIALS_DIRECTORY='.$this->credentialsDir);
        $this->useVaultKey();

        $this->assertUnavailable('sama-sama terisi');
    }

    public function test_without_credentials_directory_the_vault_is_unavailable(): void
    {
        $this->withoutVaultKey();
        config(['sadmin.vault.credential' => 'sadmin-vault-master']);

        $this->assertUnavailable('CREDENTIALS_DIRECTORY kosong');
    }

    public function test_missing_credential_file_is_refused(): void
    {
        $this->withoutVaultKey();
        config(['sadmin.vault.credential' => 'sadmin-vault-master']);
        putenv('CREDENTIALS_DIRECTORY='.$this->credentialsDir);

        $this->assertUnavailable('tidak ada');
    }

    /** @return array<string, array{string}> */
    public static function invalidCredentialNames(): array
    {
        return [
            'kosong' => [''],
            'traversal' => ['../etc/shadow'],
            'garis miring' => ['a/b'],
            'diawali titik' => ['.hidden'],
            'spasi' => ['kunci induk'],
            '65 karakter' => [str_repeat('a', 65)],
            'baris baru di akhir' => ["sadmin-vault-master\n"],
        ];
    }

    #[DataProvider('invalidCredentialNames')]
    public function test_invalid_credential_names_are_refused(string $name): void
    {
        $this->withoutVaultKey();
        config(['sadmin.vault.credential' => $name]);
        putenv('CREDENTIALS_DIRECTORY='.$this->credentialsDir);

        $this->assertUnavailable('SADMIN_VAULT_CRED tak sah');
    }
}
