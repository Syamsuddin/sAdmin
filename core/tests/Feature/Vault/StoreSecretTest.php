<?php

namespace Tests\Feature\Vault;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Domain\Vault\Data\SecretStatus;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\Vault;
use App\Infrastructure\Vault\VaultUnavailable;
use App\Models\AuditEntry;
use App\Models\Casts\Bytea;
use App\Models\KeyWrap;
use App\Models\Secret;
use App\Models\Tenant;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0003 §2.2–2.4: bentuk baris, satu kunci data per rahasia, transaksi + audit tanpa nilai. */
class StoreSecretTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private Tenant $tenant;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenant = Tenant::factory()->create();
    }

    private function store(string $value, SecretPurpose $purpose = SecretPurpose::ApiToken, ?string $tenantId = null): Secret
    {
        return app(StoreSecret::class)->handle($tenantId ?? $this->tenant->id, $purpose, new SecretValue($value), ActorType::Admin, 'admin-uji');
    }

    private function assertNothingWritten(): void
    {
        $this->assertSame(0, Secret::query()->count());
        $this->assertSame(0, KeyWrap::query()->count());
        $this->assertSame(0, AuditEntry::query()->count());
    }

    public function test_stores_an_envelope_encrypted_secret_that_reveals_intact(): void
    {
        $value = 'token-uji-'.bin2hex(random_bytes(8));

        $secret = $this->store($value, SecretPurpose::TelegramToken);

        $row = Secret::query()->with('keyWrap')->findOrFail($secret->id);
        $this->assertSame(SecretStatus::Active, $row->status);
        $this->assertSame(SecretPurpose::TelegramToken, $row->purpose);
        $this->assertSame($this->tenant->id, $row->tenant_id);
        $this->assertSame(24, strlen($row->nonce));
        $this->assertSame(strlen($value) + 16, strlen($row->ciphertext));
        $this->assertStringNotContainsString($value, $row->ciphertext);
        $this->assertNotNull($row->keyWrap);
        $this->assertSame(Vault::WRAPPED_DEK_BYTES, strlen($row->keyWrap->wrapped_dek));
        $this->assertSame(72, Vault::WRAPPED_DEK_BYTES);
        $this->assertSame(1, $row->keyWrap->master_key_version);
        $this->assertSame($this->tenant->id, $row->keyWrap->tenant_id);
        $this->assertTrue(Str::isUlid($row->id) && $row->id === strtolower($row->id));

        $this->assertSame($value, app(Vault::class)->reveal($row)->expose());
    }

    public function test_writes_one_audit_entry_with_purpose_only(): void
    {
        $value = 'rahasia-'.bin2hex(random_bytes(8));

        $secret = $this->store($value, SecretPurpose::Smtp);

        $entry = AuditEntry::query()->sole();
        $this->assertSame('secret.store', $entry->action_key);
        $this->assertSame('secret:'.$secret->id, $entry->target);
        $this->assertSame('admin', $entry->actor_type);
        $this->assertSame('admin-uji', $entry->actor_id);
        $this->assertSame('ok', $entry->outcome);
        $this->assertSame(['purpose' => 'smtp'], $entry->params_redacted);
        $this->artisan('sadmin:audit-verify')->assertExitCode(0);
    }

    public function test_binary_values_with_nul_bytes_round_trip(): void
    {
        $value = "\x00\x00\xff\x00".random_bytes(60)."\x00";

        $secret = $this->store($value, SecretPurpose::DeployKey);

        $this->assertSame($value, app(Vault::class)->reveal($secret->fresh() ?? $secret)->expose());
    }

    public function test_each_secret_gets_its_own_data_key_and_nonces(): void
    {
        $a = $this->store('nilai-sama')->fresh(['keyWrap']);
        $b = $this->store('nilai-sama')->fresh(['keyWrap']);

        $this->assertNotNull($a?->keyWrap);
        $this->assertNotNull($b?->keyWrap);
        $this->assertNotSame($a->key_wrap_id, $b->key_wrap_id);
        $this->assertNotSame($a->nonce, $b->nonce);
        $this->assertNotSame($a->ciphertext, $b->ciphertext);
        $this->assertNotSame(substr($a->keyWrap->wrapped_dek, 0, 24), substr($b->keyWrap->wrapped_dek, 0, 24));
        $this->assertNotSame($a->keyWrap->wrapped_dek, $b->keyWrap->wrapped_dek);
    }

    public function test_every_purpose_of_the_data_model_is_accepted(): void
    {
        foreach (SecretPurpose::cases() as $purpose) {
            $secret = $this->store('nilai-'.$purpose->value, $purpose);
            $this->assertSame('nilai-'.$purpose->value, app(Vault::class)->reveal($secret)->expose());
        }

        $this->assertSame(count(SecretPurpose::cases()), Secret::query()->count());
    }

    public function test_database_rejects_unknown_purpose_status_and_shared_key_wrap(): void
    {
        $secret = $this->store('nilai');
        $base = ['tenant_id' => $this->tenant->id, 'ciphertext' => Bytea::literal('x'), 'nonce' => Bytea::literal('n'),
            'created_at' => now(), 'updated_at' => now()];

        foreach ([
            'purpose' => ['purpose' => 'password_bebas', 'status' => 'active', 'key_wrap_id' => $this->freeKeyWrap()],
            'status' => ['purpose' => 'api_token', 'status' => 'dihapus', 'key_wrap_id' => $this->freeKeyWrap()],
            'key_wrap_id unik' => ['purpose' => 'api_token', 'status' => 'active', 'key_wrap_id' => $secret->key_wrap_id],
        ] as $case => $columns) {
            try {
                DB::transaction(fn () => DB::table('secrets')->insert(['id' => strtolower((string) Str::ulid()), ...$base, ...$columns]));
                $this->fail("Basis data seharusnya menolak {$case}.");
            } catch (QueryException $e) {
                $this->assertContains($e->getCode(), ['23514', '23505'], $case);
            }
        }
    }

    private function freeKeyWrap(): string
    {
        $id = strtolower((string) Str::ulid());
        DB::table('key_wraps')->insert(['id' => $id, 'tenant_id' => $this->tenant->id, 'wrapped_dek' => Bytea::literal(str_repeat("\1", 72)),
            'master_key_version' => 1, 'created_at' => now()]);

        return $id;
    }

    public function test_unavailable_vault_writes_nothing(): void
    {
        $this->withoutVaultKey();

        $this->expectException(VaultUnavailable::class);
        try {
            $this->store('nilai');
        } finally {
            $this->assertNothingWritten();
        }
    }

    public function test_unknown_tenant_rolls_back_everything(): void
    {
        try {
            $this->store('nilai', tenantId: strtolower((string) Str::ulid()));
            $this->fail('Tenant tak dikenal seharusnya ditolak FK.');
        } catch (QueryException) {
            $this->assertNothingWritten();
        }
    }

    public function test_non_ulid_tenant_is_rejected_before_any_write(): void
    {
        try {
            $this->store('nilai', tenantId: 'bukan-ulid');
            $this->fail('tenant_id bukan ULID seharusnya ditolak.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('ULID', $e->getMessage());
            $this->assertNothingWritten();
        }
    }
}
