<?php

namespace Tests\Feature\Fleet;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Fleet\Actions\InitializeCertificateAuthority;
use App\Domain\Fleet\Services\AgentCertificateProfile;
use App\Domain\Fleet\Services\CertificateAuthority;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\Vault;
use App\Infrastructure\Vault\X509Authority;
use App\Models\Institution;
use App\Models\Secret;
use App\Models\Tenant;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Group;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0007 §2.1–2.2: tepat satu CA aktif per tenant, dibuat eksplisit, kunci & sertifikat hanya di brankas. */
class InitializeCertificateAuthorityTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private string $tenantId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenantId = Institution::factory()->create()->tenant_id;
    }

    private function authorities(): int
    {
        return Secret::query()->where('purpose', SecretPurpose::CaKey->value)->count();
    }

    /** @return array{secretId: string, caSha256: string, notAfter: string} */
    private function initCa(): array
    {
        return app(InitializeCertificateAuthority::class)->handle();
    }

    /**
     * Isi rahasia CA aktif, dibuka mandiri dari teks ADR 0003 §2.2–2.3 dengan kunci induk uji. Brankas sendiri menolak
     * mengembalikannya (ADR 0007 §2.1), jadi tes butuh jalur di luarnya.
     */
    private function caBundle(): string
    {
        $secret = Secret::query()->with('keyWrap')->where('purpose', 'ca_key')->where('status', 'active')->sole();
        $wrapped = (string) $secret->keyWrap?->wrapped_dek;
        $kek = (string) file_get_contents((string) config('sadmin.vault.dev_key_file'));

        $dek = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($wrapped, 24), "sadmin-vault/1/key_wrap/{$secret->tenant_id}/{$secret->key_wrap_id}/1", substr($wrapped, 0, 24), $kek,
        );
        $this->assertIsString($dek, 'Kunci data CA tak terbuka dengan format ADR 0003.');
        $bundle = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $secret->ciphertext, "sadmin-vault/1/secret/{$secret->tenant_id}/{$secret->id}/ca_key/{$secret->key_wrap_id}", $secret->nonce, $dek,
        );
        $this->assertIsString($bundle, 'Isi rahasia CA tak terbuka dengan format ADR 0003.');

        return $bundle;
    }

    /** @return array{key: string, cert: string} */
    private function bundleParts(): array
    {
        $matched = preg_match('/\A(-----BEGIN ((?:EC )?PRIVATE KEY)-----\n.+?\n-----END \2-----\n)(-----BEGIN CERTIFICATE-----\n.+\n-----END CERTIFICATE-----\n)\z/s', $this->caBundle(), $parts);
        $this->assertSame(1, $matched, 'Isi rahasia CA wajib blok kunci privat disusul blok CERTIFICATE (ADR 0007 §2.1).');

        return ['key' => $parts[1], 'cert' => $parts[3]];
    }

    public function test_creates_one_active_authority_and_records_its_pin(): void
    {
        $this->artisan('sadmin:ca-init')
            ->expectsOutputToContain('Sidik jari CA (--ca-sha256): ')
            ->assertExitCode(0);

        $secret = Secret::query()->where('purpose', SecretPurpose::CaKey->value)->sole();
        $this->assertSame($this->tenantId, $secret->tenant_id);
        $this->assertSame('active', $secret->status->value);

        $entries = DB::table('audit_entries')->orderBy('seq')->get();
        $this->assertSame(['secret.store', 'ca.initialize'], $entries->pluck('action_key')->all());
        $this->assertSame('local_root', $entries[1]->actor_type);
        $this->assertNull($entries[1]->actor_id);
        $this->assertSame('ok', $entries[1]->outcome);
        $this->assertSame("secret:{$secret->id}", $entries[1]->target);

        $recorded = json_decode($entries[1]->params_redacted, true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(['ca_sha256', 'not_after'], array_keys($recorded));
        $der = base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $this->bundleParts()['cert']), true);
        $this->assertSame(hash('sha256', (string) $der), $recorded['ca_sha256']);
        $this->assertSame(app(CertificateAuthority::class)->fingerprint($this->tenantId), $recorded['ca_sha256']);
        $this->assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $recorded['ca_sha256']);
        $this->assertMatchesRegularExpression('/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\z/', $recorded['not_after']);
    }

    public function test_authority_certificate_follows_the_contract_profile(): void
    {
        $this->initCa();
        ['key' => $keyPem, 'cert' => $certPem] = $this->bundleParts();

        $info = openssl_x509_parse($certPem);
        $this->assertIsArray($info);
        $this->assertSame(['CN' => 'sAdmin internal CA'], $info['subject']);
        $this->assertSame($info['subject'], $info['issuer']);
        $this->assertTrue(AgentCertificateProfile::issuedValidityConforms($info['validTo_time_t'] - $info['validFrom_time_t'], 3650));
        $this->assertEqualsWithDelta(time(), $info['validFrom_time_t'], 60);
        $this->assertSame('ecdsa-with-SHA256', $info['signatureTypeSN']);
        $this->assertSame('CA:TRUE, pathlen:0', $info['extensions']['basicConstraints']);
        $this->assertSame('Certificate Sign, CRL Sign', $info['extensions']['keyUsage']);
        $this->assertGreaterThan(0, (int) $info['serialNumber']);

        $key = openssl_pkey_get_private($keyPem);
        $this->assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        $this->assertSame(OPENSSL_KEYTYPE_EC, $details['type']);
        $this->assertSame('prime256v1', $details['ec']['curve_name']);
        $this->assertTrue(openssl_x509_check_private_key($certPem, $key));
        $this->assertSame(1, openssl_x509_verify($certPem, openssl_pkey_get_public($certPem)));
        $this->assertSame($certPem, app(CertificateAuthority::class)->certificatePem($this->tenantId));
    }

    public function test_command_prints_the_same_pin_it_records(): void
    {
        $this->assertSame(0, Artisan::call('sadmin:ca-init'));
        $output = Artisan::output();
        preg_match('#Sidik jari CA \(--ca-sha256\): (\S+)#', $output, $printed);
        preg_match('#Berlaku sampai: (\S+)#', $output, $until);
        $recorded = json_decode((string) DB::table('audit_entries')->where('action_key', 'ca.initialize')->value('params_redacted'), true);

        $this->assertSame($recorded['ca_sha256'], $printed[1] ?? null);
        $this->assertSame($recorded['not_after'], $until[1] ?? null);
        $this->artisan('sadmin:audit-verify')->assertExitCode(0);
    }

    public function test_refuses_a_second_authority_because_replacing_it_is_rotation(): void
    {
        $this->initCa();

        $this->artisan('sadmin:ca-init')
            ->expectsOutputToContain('rotasi CA')
            ->assertExitCode(1);

        $this->assertSame(1, $this->authorities());
        $this->assertSame(2, DB::table('audit_entries')->count());
    }

    public function test_a_destroyed_authority_is_not_silently_replaced_because_that_is_rotation(): void
    {
        $this->initCa();
        $old = Secret::query()->where('purpose', SecretPurpose::CaKey->value)->sole();
        app(DestroySecret::class)->handle($old->id, ActorType::LocalRoot, null);

        $this->artisan('sadmin:ca-init')
            ->expectsOutputToContain('rotasi CA')
            ->assertExitCode(1);

        $this->assertSame(0, Secret::query()->where('purpose', SecretPurpose::CaKey->value)->where('status', 'active')->count());
    }

    public function test_service_and_audit_keys_do_not_block_the_authority(): void
    {
        $this->artisan('sadmin:audit-key-init')->assertExitCode(0);
        $this->artisan('sadmin:service-key-init')->assertExitCode(0);

        $this->initCa();

        $this->assertSame(1, $this->authorities());
        $this->assertSame(1, Secret::query()->where('purpose', SecretPurpose::ServiceKey->value)->count());
    }

    public function test_concurrent_initializations_are_serialized_by_the_advisory_lock(): void
    {
        config(['database.connections.pgsql_kunci' => config('database.connections.pgsql')]);
        $other = DB::connection('pgsql_kunci');
        $other->select('SELECT pg_advisory_lock(?)', [InitializeCertificateAuthority::LOCK_KEY]);
        DB::statement("SET lock_timeout = '200ms'");

        try {
            $this->initCa();
            $this->fail('Pembuatan CA seharusnya menunggu kunci advisory yang dipegang koneksi lain.');
        } catch (QueryException $e) {
            $this->assertStringContainsString('lock timeout', $e->getMessage());
        } finally {
            DB::statement('RESET lock_timeout');
            $other->select('SELECT pg_advisory_unlock(?)', [InitializeCertificateAuthority::LOCK_KEY]);
            $other->disconnect();
        }

        $this->assertSame(0, $this->authorities());
    }

    public function test_authority_of_another_tenant_neither_blocks_nor_serves_this_institution(): void
    {
        // ULID terkecil dan terbesar: kueri tanpa filter tenant mengambil CA asing apa pun urutan pindainya.
        $foreignPins = [];
        foreach (['0000000000000000000000000a', '7zzzzzzzzzzzzzzzzzzzzzzzzz'] as $id) {
            $foreign = Tenant::factory()->create(['id' => $id]);
            $bundle = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 7);
            $secret = app(StoreSecret::class)->handle($foreign->id, SecretPurpose::CaKey, $bundle, ActorType::LocalRoot, null);
            $foreignPins[] = AgentCertificateProfile::fingerprint(app(Vault::class)->caCertificate($secret->id, $foreign->id));
        }

        $pin = $this->initCa()['caSha256'];

        $this->assertSame($pin, app(CertificateAuthority::class)->fingerprint($this->tenantId));
        $this->assertNotContains($pin, $foreignPins);
        $this->assertSame(1, Secret::query()->where('purpose', 'ca_key')->where('tenant_id', $this->tenantId)->count());
    }

    public function test_vault_integrity_failure_while_storing_is_logged_critical(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION uji_rusak_rahasia() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN NEW.ciphertext := decode(repeat('00', length(NEW.ciphertext)), 'hex'); RETURN NEW; END
            $$;
            CREATE TRIGGER uji_rusak_rahasia BEFORE INSERT ON secrets FOR EACH ROW EXECUTE FUNCTION uji_rusak_rahasia();
            SQL);
        Log::shouldReceive('critical')->once()->withArgs(fn (string $message): bool => $message === 'ca_init_failed');

        $this->artisan('sadmin:ca-init')
            ->expectsOutputToContain('insiden integritas')
            ->assertExitCode(1);

        $this->assertSame(0, $this->authorities());
    }

    public function test_database_failure_is_reported_without_sql_or_stack_trace(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION uji_tolak_audit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF NEW.action_key = 'ca.initialize' THEN RAISE EXCEPTION 'uji: audit ditolak'; END IF; RETURN NEW; END
            $$;
            CREATE TRIGGER uji_tolak_audit BEFORE INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION uji_tolak_audit();
            SQL);
        Log::shouldReceive('error')->once()->withArgs(fn (string $message, array $context): bool => $message === 'ca_init_failed' && str_contains($context['reason'], 'QueryException'));

        $this->assertSame(1, Artisan::call('sadmin:ca-init'));
        $output = Artisan::output();

        $this->assertStringContainsString('tidak ada yang tersimpan', $output);
        $this->assertStringNotContainsString('SQLSTATE', $output);
        $this->assertStringNotContainsString('insert into', strtolower($output));
        $this->assertSame(0, $this->authorities());
        $this->assertSame(0, DB::table('audit_entries')->count());
    }

    public function test_refuses_before_the_institution_exists(): void
    {
        Institution::query()->delete();

        $this->artisan('sadmin:ca-init')
            ->expectsOutputToContain('sadmin:institution-init')
            ->assertExitCode(1);

        $this->assertSame(0, $this->authorities());
    }

    public function test_refuses_without_vault_and_writes_nothing(): void
    {
        $this->withoutVaultKey();
        Log::shouldReceive('error')->once()->withArgs(fn (string $message): bool => $message === 'ca_init_failed');

        $this->artisan('sadmin:ca-init')
            ->expectsOutputToContain('Brankas tak tersedia')
            ->assertExitCode(1);

        $this->assertSame(0, $this->authorities());
        $this->assertSame(0, DB::table('audit_entries')->count());
    }

    public function test_database_allows_only_one_active_authority_per_tenant(): void
    {
        $this->initCa();
        $bundle = fn () => X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 7);

        try {
            app(StoreSecret::class)->handle($this->tenantId, SecretPurpose::CaKey, $bundle(), ActorType::LocalRoot, null);
            $this->fail('CA aktif kedua seharusnya ditolak indeks unik.');
        } catch (QueryException $e) {
            $this->assertStringContainsString('secrets_one_active_ca_key', $e->getMessage());
        }

        // CA tenant lain tidak terhalang.
        $other = Institution::factory()->create(['console_hostname' => 'lain.localhost'])->tenant_id;
        app(StoreSecret::class)->handle($other, SecretPurpose::CaKey, $bundle(), ActorType::LocalRoot, null);

        $this->assertSame(2, $this->authorities());
    }

    public function test_reveal_refuses_the_authority_key(): void
    {
        $this->initCa();
        $secret = Secret::query()->where('purpose', SecretPurpose::CaKey->value)->sole();

        $this->expectException(InvalidArgumentException::class);

        app(Vault::class)->reveal($secret->id, SecretPurpose::CaKey, $this->tenantId);
    }

    #[Group('redaction')]
    public function test_private_key_never_leaks_to_console_log_audit_or_rows(): void
    {
        $logFile = (string) tempnam(sys_get_temp_dir(), 'sadmin-redaction-');
        config(['logging.default' => 'single', 'logging.channels.single.path' => $logFile, 'logging.channels.single.level' => 'debug']);

        $output = '';
        foreach ([0, 1] as $exit) {
            $this->assertSame($exit, Artisan::call('sadmin:ca-init'));
            $output .= Artisan::output();
        }
        $keyPem = $this->bundleParts()['key'];
        $keyBody = (string) preg_replace('/-----[^-]+-----|\s/', '', $keyPem);
        $keyDer = (string) base64_decode($keyBody, true);
        $private = openssl_pkey_get_private($keyPem);
        $this->assertNotFalse($private);
        $scalar = (string) openssl_pkey_get_details($private)['ec']['d'];
        $this->assertGreaterThanOrEqual(28, strlen($scalar), 'Skalar privat P-256 harus terbaca untuk dipindai.');
        Log::warning('uji_redaksi_ca', ['ca' => app(CertificateAuthority::class)->certificatePem($this->tenantId)]);

        $haystacks = [
            'keluaran konsol' => $output,
            'log' => (string) file_get_contents($logFile),
            'audit_entries' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM audit_entries t'), 'j')),
            'secrets' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM secrets t'), 'j')),
            'key_wraps' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM key_wraps t'), 'j')),
        ];
        @unlink($logFile);

        $this->assertStringContainsString('uji_redaksi_ca', $haystacks['log'], 'Log tes harus benar-benar tertulis.');
        $this->assertStringContainsString('Sidik jari CA', $haystacks['keluaran konsol'], 'Keluaran konsol harus benar-benar tertangkap.');
        $this->assertStringContainsString('rotasi CA', $haystacks['keluaran konsol'], 'Jalur penolakan juga harus ikut terpindai.');
        $needles = [
            'PEM' => 'PRIVATE KEY-----',
            // Baris kedua PEM PKCS#8 memuat skalar privat; awal baris pertama hanya header yang sama untuk semua kunci P-256.
            'baris PEM' => explode("\n", $keyPem)[2],
            'isi PEM' => $keyBody,
            'DER hex' => bin2hex($keyDer),
            'skalar hex' => bin2hex($scalar),
            'skalar base64' => base64_encode($scalar),
            'skalar base64url' => rtrim(strtr(base64_encode($scalar), '+/', '-_'), '='),
        ];
        foreach ($haystacks as $where => $text) {
            foreach ($needles as $form => $needle) {
                $this->assertStringNotContainsString($needle, $text, "Kunci privat CA ({$form}) bocor ke {$where}.");
            }
            $this->assertStringNotContainsString($scalar, $text, "Kunci privat CA (skalar mentah) bocor ke {$where}.");
        }
    }
}
