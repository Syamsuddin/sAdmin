<?php

namespace Tests\Feature\Audit;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\Vault;
use App\Models\Institution;
use App\Models\Secret;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Group;
use Tests\Support\InteractsWithAuditChain;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0004 §2.1: tepat satu kunci audit aktif per tenant, dibuat eksplisit, seed hanya di brankas. */
class InitializeAuditKeyTest extends TestCase
{
    use InteractsWithAuditChain, InteractsWithVault, RefreshDatabase;

    private function auditKeys(): int
    {
        return Secret::query()->where('purpose', SecretPurpose::AuditKey->value)->count();
    }

    public function test_creates_one_active_audit_key_and_records_its_public_key(): void
    {
        $this->artisan('sadmin:audit-key-init')
            ->expectsOutputToContain('Kunci publik audit (base64): ')
            ->assertExitCode(0);

        $secret = Secret::query()->where('purpose', SecretPurpose::AuditKey->value)->sole();
        $this->assertSame($this->auditTenantId, $secret->tenant_id);
        $this->assertSame(32, strlen(app(Vault::class)->reveal($secret->id, SecretPurpose::AuditKey, $this->auditTenantId)->expose()));

        $entries = DB::table('audit_entries')->orderBy('seq')->get();
        $this->assertSame(['secret.store', 'audit.key_initialize'], $entries->pluck('action_key')->all());
        $this->assertSame('local_root', $entries[1]->actor_type);
        $this->assertSame("secret:{$secret->id}", $entries[1]->target);

        $recorded = json_decode($entries[1]->params_redacted, true, 512, JSON_THROW_ON_ERROR)['public_key'];
        $derived = app(Vault::class)->ed25519PublicKey($secret->id, SecretPurpose::AuditKey, $this->auditTenantId);
        $this->assertSame(Ed25519::encode($derived), $recorded);
        $this->assertSame(44, strlen($recorded));
    }

    public function test_command_prints_the_same_public_key_it_records(): void
    {
        $publicKey = $this->initAuditKey();

        $this->assertSame(
            $publicKey,
            json_decode((string) DB::table('audit_entries')->where('action_key', 'audit.key_initialize')->value('params_redacted'), true)['public_key'],
        );
    }

    public function test_refuses_a_second_key_because_replacing_it_is_rotation(): void
    {
        $this->initAuditKey();

        $this->artisan('sadmin:audit-key-init')
            ->expectsOutputToContain('rotasi kunci audit')
            ->assertExitCode(1);

        $this->assertSame(1, $this->auditKeys());
        $this->assertSame(2, DB::table('audit_entries')->count());
    }

    public function test_refuses_before_the_institution_exists(): void
    {
        Institution::query()->delete();

        $this->artisan('sadmin:audit-key-init')
            ->expectsOutputToContain('sadmin:institution-init')
            ->assertExitCode(1);

        $this->assertSame(0, $this->auditKeys());
    }

    public function test_refuses_without_vault_and_writes_nothing(): void
    {
        $this->withoutVaultKey();

        $this->artisan('sadmin:audit-key-init')
            ->expectsOutputToContain('Brankas tak tersedia')
            ->assertExitCode(1);

        $this->assertSame(0, $this->auditKeys());
        $this->assertSame(0, DB::table('audit_entries')->count());
    }

    public function test_database_allows_only_one_active_audit_key_per_tenant(): void
    {
        $this->initAuditKey();

        try {
            app(StoreSecret::class)->handle($this->auditTenantId, SecretPurpose::AuditKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
            $this->fail('Kunci audit aktif kedua seharusnya ditolak indeks unik.');
        } catch (QueryException $e) {
            $this->assertStringContainsString('secrets_one_active_audit_key', $e->getMessage());
        }

        // Kunci lain dan kunci audit tenant lain tidak terhalang.
        app(StoreSecret::class)->handle($this->auditTenantId, SecretPurpose::ServiceKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
        $other = Institution::factory()->create(['console_hostname' => 'lain.localhost'])->tenant_id;
        app(StoreSecret::class)->handle($other, SecretPurpose::AuditKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);

        $this->assertSame(2, $this->auditKeys());
    }

    public function test_a_destroyed_key_no_longer_counts_as_active(): void
    {
        $this->initAuditKey();
        $old = Secret::query()->where('purpose', SecretPurpose::AuditKey->value)->sole();
        app(DestroySecret::class)->handle($old->id, ActorType::LocalRoot, null);

        $this->artisan('sadmin:audit-key-init')->assertExitCode(0);

        $this->assertSame(1, Secret::query()->where('purpose', SecretPurpose::AuditKey->value)->where('status', 'active')->count());
    }

    public function test_vault_signs_only_with_ed25519_key_purposes(): void
    {
        $token = app(StoreSecret::class)->handle($this->auditTenantId, SecretPurpose::ApiToken, new SecretValue(str_repeat('k', 32)), ActorType::Admin, 'admin-uji');

        $this->expectException(InvalidArgumentException::class);

        app(Vault::class)->signEd25519($token->id, SecretPurpose::ApiToken, $this->auditTenantId, 'pesan');
    }

    #[Group('redaction')]
    public function test_seed_never_leaks_to_audit_log_output_or_rows(): void
    {
        $logFile = (string) tempnam(sys_get_temp_dir(), 'sadmin-redaction-');
        config(['logging.default' => 'single', 'logging.channels.single.path' => $logFile, 'logging.channels.single.level' => 'debug']);

        $this->artisan('sadmin:audit-key-init')->assertExitCode(0);
        $secret = Secret::query()->where('purpose', SecretPurpose::AuditKey->value)->sole();
        $seed = app(Vault::class)->reveal($secret->id, SecretPurpose::AuditKey, $this->auditTenantId)->expose();

        $this->appendEntries(3);
        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(0);
        $this->tamperCheckpoints(fn () => DB::table('audit_checkpoints')->update(['signature' => Ed25519::encode(str_repeat("\0", 64))]));
        $this->artisan('sadmin:audit-verify')->assertExitCode(1);
        $this->appendEntries(1);
        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);

        $haystacks = [
            'log' => (string) file_get_contents($logFile),
            'audit_entries' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM audit_entries t'), 'j')),
            'audit_checkpoints' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM audit_checkpoints t'), 'j')),
            'secrets' => implode("\n", array_column(DB::select('SELECT row_to_json(t)::text AS j FROM secrets t'), 'j')),
        ];
        @unlink($logFile);

        $this->assertStringContainsString('audit_mismatch', $haystacks['log'], 'Log tes harus benar-benar tertulis.');
        foreach ($haystacks as $where => $text) {
            foreach (['hex' => bin2hex($seed), 'base64' => base64_encode($seed), 'base64url' => rtrim(strtr(base64_encode($seed), '+/', '-_'), '=')] as $form => $needle) {
                $this->assertStringNotContainsString($needle, $text, "Seed kunci audit ({$form}) bocor ke {$where}.");
            }
            $this->assertStringNotContainsString($seed, $text, "Seed kunci audit (mentah) bocor ke {$where}.");
        }
    }
}
