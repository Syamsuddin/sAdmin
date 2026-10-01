<?php

namespace Tests\Feature\Execution;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Execution\Actions\InitializeServiceKey;
use App\Domain\Execution\Dispatch\ServiceSigner;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\Vault;
use App\Models\Institution;
use App\Models\Secret;
use App\Models\Tenant;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use stdClass;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0006 §2.1: tepat satu kunci layanan aktif per tenant, dibuat eksplisit, seed hanya di brankas. */
class InitializeServiceKeyTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private string $tenantId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenantId = Institution::factory()->create()->tenant_id;
    }

    private function serviceKeys(): int
    {
        return Secret::query()->where('purpose', SecretPurpose::ServiceKey->value)->count();
    }

    private function initServiceKey(): string
    {
        return app(InitializeServiceKey::class)->handle()['publicKey'];
    }

    /**
     * Seed kunci layanan aktif, dibuka mandiri dari teks ADR 0003 §2.2–2.3 dengan kunci induk uji. Brankas sendiri
     * menolak mengembalikan seed (ADR 0006 §2.1), jadi tes butuh jalur di luarnya.
     */
    private function serviceSeed(): string
    {
        $secret = Secret::query()->with('keyWrap')->where('purpose', 'service_key')->where('status', 'active')->sole();
        $wrapped = (string) $secret->keyWrap?->wrapped_dek;
        $kek = (string) file_get_contents((string) config('sadmin.vault.dev_key_file'));

        $dek = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($wrapped, 24), "sadmin-vault/1/key_wrap/{$secret->tenant_id}/{$secret->key_wrap_id}/1", substr($wrapped, 0, 24), $kek,
        );
        $this->assertIsString($dek, 'Kunci data kunci layanan tak terbuka dengan format ADR 0003.');
        $seed = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $secret->ciphertext, "sadmin-vault/1/secret/{$secret->tenant_id}/{$secret->id}/service_key/{$secret->key_wrap_id}", $secret->nonce, $dek,
        );
        $this->assertIsString($seed, 'Seed kunci layanan tak terbuka dengan format ADR 0003.');

        return $seed;
    }

    public function test_creates_one_active_service_key_and_records_its_public_key(): void
    {
        $this->artisan('sadmin:service-key-init')
            ->expectsOutputToContain('Kunci publik layanan (base64): ')
            ->assertExitCode(0);

        $secret = Secret::query()->where('purpose', SecretPurpose::ServiceKey->value)->sole();
        $this->assertSame($this->tenantId, $secret->tenant_id);
        $this->assertSame('active', $secret->status->value);
        $this->assertSame(32, strlen($this->serviceSeed()));

        $entries = DB::table('audit_entries')->orderBy('seq')->get();
        $this->assertSame(['secret.store', 'service.key_initialize'], $entries->pluck('action_key')->all());
        $this->assertSame('local_root', $entries[1]->actor_type);
        $this->assertNull($entries[1]->actor_id);
        $this->assertSame('ok', $entries[1]->outcome);
        $this->assertSame("secret:{$secret->id}", $entries[1]->target);

        $recorded = json_decode($entries[1]->params_redacted, true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(['public_key'], array_keys($recorded));
        $derived = app(Vault::class)->ed25519PublicKey($secret->id, SecretPurpose::ServiceKey, $this->tenantId);
        $this->assertSame(Ed25519::encode($derived), $recorded['public_key']);
        $this->assertSame(Ed25519::encode(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($this->serviceSeed()))), $recorded['public_key']);
        $this->assertSame(44, strlen($recorded['public_key']));
    }

    public function test_command_prints_the_same_public_key_it_records(): void
    {
        $this->assertSame(0, Artisan::call('sadmin:service-key-init'));
        preg_match('#Kunci publik layanan \(base64\): (\S+)#', Artisan::output(), $printed);
        $recorded = json_decode((string) DB::table('audit_entries')->where('action_key', 'service.key_initialize')->value('params_redacted'), true)['public_key'];

        $this->assertSame($recorded, $printed[1] ?? null);
        $this->assertMatchesRegularExpression('#^[A-Za-z0-9+/]{43}=$#', $recorded);
        $this->artisan('sadmin:audit-verify')->assertExitCode(0);
    }

    public function test_printed_public_key_verifies_frames_signed_with_the_key(): void
    {
        Artisan::call('sadmin:service-key-init');
        preg_match('#Kunci publik layanan \(base64\): (\S+)#', Artisan::output(), $printed);
        $this->assertCount(2, $printed);

        $frame = app(ServiceSigner::class)->frame($this->tenantId, 'Ack', strtolower((string) Str::ulid()), (object) ['id' => (string) Str::ulid()]);

        $this->assertTrue(ServiceSigner::verifyFrame((string) Ed25519::decode($printed[1]), $frame));
    }

    public function test_refuses_a_second_key_because_replacing_it_is_rotation(): void
    {
        $this->initServiceKey();

        $this->artisan('sadmin:service-key-init')
            ->expectsOutputToContain('rotasi kunci layanan')
            ->assertExitCode(1);

        $this->assertSame(1, $this->serviceKeys());
        $this->assertSame(2, DB::table('audit_entries')->count());
    }

    public function test_a_destroyed_key_is_not_silently_replaced_because_that_is_rotation(): void
    {
        $this->initServiceKey();
        $old = Secret::query()->where('purpose', SecretPurpose::ServiceKey->value)->sole();
        app(DestroySecret::class)->handle($old->id, ActorType::LocalRoot, null);

        $this->artisan('sadmin:service-key-init')
            ->expectsOutputToContain('rotasi kunci layanan')
            ->assertExitCode(1);

        $this->assertSame(0, Secret::query()->where('purpose', SecretPurpose::ServiceKey->value)->where('status', 'active')->count());
    }

    public function test_an_audit_key_does_not_block_the_service_key_and_they_differ(): void
    {
        $this->artisan('sadmin:audit-key-init')->assertExitCode(0);
        $serviceKey = $this->initServiceKey();

        $auditKey = json_decode((string) DB::table('audit_entries')->where('action_key', 'audit.key_initialize')->value('params_redacted'), true)['public_key'];
        $this->assertNotSame($auditKey, $serviceKey);
        $this->assertSame(1, $this->serviceKeys());
    }

    public function test_concurrent_initializations_are_serialized_by_the_advisory_lock(): void
    {
        config(['database.connections.pgsql_kunci' => config('database.connections.pgsql')]);
        $other = DB::connection('pgsql_kunci');
        $other->select('SELECT pg_advisory_lock(?)', [InitializeServiceKey::LOCK_KEY]);
        DB::statement("SET lock_timeout = '200ms'");

        try {
            $this->initServiceKey();
            $this->fail('Pembuatan kunci seharusnya menunggu kunci advisory yang dipegang koneksi lain.');
        } catch (QueryException $e) {
            $this->assertStringContainsString('lock timeout', $e->getMessage());
        } finally {
            DB::statement('RESET lock_timeout');
            $other->select('SELECT pg_advisory_unlock(?)', [InitializeServiceKey::LOCK_KEY]);
            $other->disconnect();
        }

        $this->assertSame(0, $this->serviceKeys());
    }

    public function test_key_of_another_tenant_neither_blocks_nor_signs_for_this_institution(): void
    {
        // ULID terkecil dan terbesar: kueri tanpa filter tenant mengambil kunci asing apa pun urutan pindainya.
        foreach (['0000000000000000000000000a', '7zzzzzzzzzzzzzzzzzzzzzzzzz'] as $id) {
            $foreign = Tenant::factory()->create(['id' => $id]);
            app(StoreSecret::class)->handle($foreign->id, SecretPurpose::ServiceKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
        }

        $publicKey = $this->initServiceKey();
        $frame = app(ServiceSigner::class)->frame($this->tenantId, 'Ack', strtolower((string) Str::ulid()), (object) ['id' => (string) Str::ulid()]);

        $this->assertTrue(ServiceSigner::verifyFrame((string) Ed25519::decode($publicKey), $frame));
        $this->assertSame(1, Secret::query()->where('purpose', 'service_key')->where('tenant_id', $this->tenantId)->count());
    }

    public function test_vault_integrity_failure_while_storing_is_logged_critical(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE FUNCTION uji_rusak_rahasia() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN NEW.ciphertext := decode(repeat('00', length(NEW.ciphertext)), 'hex'); RETURN NEW; END
            $$;
            CREATE TRIGGER uji_rusak_rahasia BEFORE INSERT ON secrets FOR EACH ROW EXECUTE FUNCTION uji_rusak_rahasia();
            SQL);
        Log::shouldReceive('critical')->once()->withArgs(fn (string $message): bool => $message === 'service_key_init_failed');

        $this->artisan('sadmin:service-key-init')
            ->expectsOutputToContain('insiden integritas')
            ->assertExitCode(1);

        $this->assertSame(0, $this->serviceKeys());
    }

    public function test_refuses_before_the_institution_exists(): void
    {
        Institution::query()->delete();

        $this->artisan('sadmin:service-key-init')
            ->expectsOutputToContain('sadmin:institution-init')
            ->assertExitCode(1);

        $this->assertSame(0, $this->serviceKeys());
    }

    public function test_refuses_without_vault_and_writes_nothing(): void
    {
        $this->withoutVaultKey();
        Log::shouldReceive('error')->once()->withArgs(fn (string $message): bool => $message === 'service_key_init_failed');

        $this->artisan('sadmin:service-key-init')
            ->expectsOutputToContain('Brankas tak tersedia')
            ->assertExitCode(1);

        $this->assertSame(0, $this->serviceKeys());
        $this->assertSame(0, DB::table('audit_entries')->count());
    }

    public function test_database_allows_only_one_active_service_key_per_tenant(): void
    {
        $this->initServiceKey();

        try {
            app(StoreSecret::class)->handle($this->tenantId, SecretPurpose::ServiceKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
            $this->fail('Kunci layanan aktif kedua seharusnya ditolak indeks unik.');
        } catch (QueryException $e) {
            $this->assertStringContainsString('secrets_one_active_service_key', $e->getMessage());
        }

        // Kunci lain dan kunci layanan tenant lain tidak terhalang.
        app(StoreSecret::class)->handle($this->tenantId, SecretPurpose::AuditKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
        $other = Institution::factory()->create(['console_hostname' => 'lain.localhost'])->tenant_id;
        app(StoreSecret::class)->handle($other, SecretPurpose::ServiceKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);

        $this->assertSame(2, $this->serviceKeys());
    }

    public function test_reveal_refuses_the_service_key_seed(): void
    {
        $this->initServiceKey();
        $secret = Secret::query()->where('purpose', SecretPurpose::ServiceKey->value)->sole();

        $this->expectException(\InvalidArgumentException::class);

        app(Vault::class)->reveal($secret->id, SecretPurpose::ServiceKey, $this->tenantId);
    }

    #[Group('redaction')]
    public function test_seed_never_leaks_to_console_log_audit_rows_or_frames(): void
    {
        $logFile = (string) tempnam(sys_get_temp_dir(), 'sadmin-redaction-');
        config(['logging.default' => 'single', 'logging.channels.single.path' => $logFile, 'logging.channels.single.level' => 'debug']);

        $output = '';
        foreach ([0, 1] as $exit) {
            $this->assertSame($exit, Artisan::call('sadmin:service-key-init'));
            $output .= Artisan::output();
        }
        $seed = $this->serviceSeed();

        $signer = app(ServiceSigner::class);
        $frames = implode("\n", [
            $signer->frame($this->tenantId, 'Envelope', strtolower((string) Str::ulid()), (object) ['params' => new stdClass, 'nonce' => base64_encode(random_bytes(32))]),
            $signer->frame($this->tenantId, 'Cancel', strtolower((string) Str::ulid()), ['plan_hash' => str_repeat('a', 64)]),
        ]);
        Log::warning('uji_redaksi_kunci_layanan', ['frames' => $frames]);

        $haystacks = [
            'keluaran konsol' => $output,
            'log' => (string) file_get_contents($logFile),
            'bingkai' => $frames,
            'audit_entries' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM audit_entries t'), 'j')),
            'secrets' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM secrets t'), 'j')),
            'key_wraps' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM key_wraps t'), 'j')),
        ];
        @unlink($logFile);

        $this->assertStringContainsString('uji_redaksi_kunci_layanan', $haystacks['log'], 'Log tes harus benar-benar tertulis.');
        $this->assertStringContainsString('Kunci publik layanan', $haystacks['keluaran konsol'], 'Keluaran konsol harus benar-benar tertangkap.');
        $this->assertStringContainsString('rotasi kunci layanan', $haystacks['keluaran konsol'], 'Jalur penolakan juga harus ikut terpindai.');
        foreach ($haystacks as $where => $text) {
            foreach (['hex' => bin2hex($seed), 'base64' => base64_encode($seed), 'base64url' => rtrim(strtr(base64_encode($seed), '+/', '-_'), '=')] as $form => $needle) {
                $this->assertStringNotContainsString($needle, $text, "Seed kunci layanan ({$form}) bocor ke {$where}.");
            }
            $this->assertStringNotContainsString($seed, $text, "Seed kunci layanan (mentah) bocor ke {$where}.");
        }
    }
}
