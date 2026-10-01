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
        foreach (glob($this->credentialsDir.'/*') ?: [] as $file) {
            unlink($file);
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

    public function test_dev_key_is_refused_in_production_even_when_valid(): void
    {
        $this->useVaultKey();
        $this->app['env'] = 'production';

        try {
            $this->assertUnavailable('dilarang di produksi');
        } finally {
            $this->app['env'] = 'testing';
        }
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

    public function test_dev_key_wins_over_systemd_credential_outside_production(): void
    {
        file_put_contents($this->credentialsDir.'/sadmin-vault-master', random_bytes(32));
        putenv('CREDENTIALS_DIRECTORY='.$this->credentialsDir);
        $devKey = random_bytes(32);
        $this->useVaultKey($devKey);

        $this->assertSame($devKey, $this->load()->bytes());
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
