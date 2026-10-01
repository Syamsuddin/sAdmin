<?php

namespace Tests\Feature\Vault;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Domain\Vault\Data\SecretStatus;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\Vault;
use App\Models\AuditEntry;
use App\Models\Secret;
use App\Models\Tenant;
use DomainException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** docs/07 + ADR 0003 §2.4: hancurkan = ciphertext & kunci data ditimpa nol, baris tetap, tercatat di audit. */
class DestroySecretTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private Tenant $tenant;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenant = Tenant::factory()->create();
    }

    private function store(string $value): Secret
    {
        return app(StoreSecret::class)->handle($this->tenant->id, SecretPurpose::DbPassword, new SecretValue($value), ActorType::System, null);
    }

    private function destroy(Secret $secret): Secret
    {
        return app(DestroySecret::class)->handle($secret->id, ActorType::Runner, 'run-uji');
    }

    public function test_destroy_zeroes_ciphertext_and_data_key_and_keeps_the_row(): void
    {
        $secret = $this->store('kata-sandi-db');
        $length = strlen($secret->ciphertext);

        $this->destroy($secret);

        $row = Secret::query()->with('keyWrap')->findOrFail($secret->id);
        $this->assertSame(SecretStatus::Destroyed, $row->status);
        $this->assertSame(str_repeat("\0", $length), $row->ciphertext);
        $this->assertSame(str_repeat("\0", Vault::WRAPPED_DEK_BYTES), $row->keyWrap?->wrapped_dek);

        $entry = AuditEntry::query()->where('action_key', 'secret.destroy')->sole();
        $this->assertSame('secret:'.$secret->id, $entry->target);
        $this->assertSame(['purpose' => 'db_password'], $entry->params_redacted);
        $this->assertSame('runner', $entry->actor_type);
        $this->artisan('sadmin:audit-verify')->assertExitCode(0);
    }

    public function test_destroyed_secret_cannot_be_revealed(): void
    {
        $secret = $this->store('kata-sandi-db');
        $this->destroy($secret);

        $this->expectException(DomainException::class);

        app(Vault::class)->reveal($secret->id, SecretPurpose::DbPassword, $this->tenant->id);
    }

    public function test_destroying_twice_is_a_no_op_without_audit(): void
    {
        $secret = $this->store('kata-sandi-db');
        $this->destroy($secret);
        $entries = AuditEntry::query()->count();

        $again = $this->destroy($secret);

        $this->assertSame(SecretStatus::Destroyed, $again->status);
        $this->assertSame($entries, AuditEntry::query()->count());
    }

    public function test_other_secrets_are_untouched(): void
    {
        $gone = $this->store('hilang');
        $kept = $this->store('tetap');

        $this->destroy($gone);

        $this->assertSame('tetap', app(Vault::class)->reveal($kept->id, SecretPurpose::DbPassword, $this->tenant->id)->expose());
    }

    public function test_destroy_locks_the_row_before_deciding(): void
    {
        $secret = $this->store('kata-sandi-db');
        DB::enableQueryLog();

        $this->destroy($secret);

        // Tanpa FOR UPDATE, dua penghancuran serentak sama-sama melihat `active` dan mencatat audit ganda.
        $locked = array_filter(DB::getQueryLog(), fn (array $q): bool => preg_match('/^select .* from "secrets" .* for update$/i', $q['query']) === 1);
        $this->assertNotEmpty($locked, 'DestroySecret wajib mengunci baris secrets (FOR UPDATE).');
    }

    public function test_unknown_secret_is_rejected(): void
    {
        $this->expectException(ModelNotFoundException::class);

        app(DestroySecret::class)->handle(strtolower((string) Str::ulid()), ActorType::System, null);
    }
}
