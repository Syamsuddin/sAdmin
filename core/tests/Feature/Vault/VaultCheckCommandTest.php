<?php

namespace Tests\Feature\Vault;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\SecretValue;
use App\Models\Casts\Bytea;
use App\Models\Secret;
use App\Models\Tenant;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Mockery;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0003 §2.6: `sadmin:vault-check` membuktikan kunci induk yang termuat adalah kunci instalasi ini. */
class VaultCheckCommandTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private const CANARY = 'CANARY-vaultcheck-41d2';

    private function store(string $value): Secret
    {
        $tenant = Tenant::query()->first() ?? Tenant::factory()->create();

        return app(StoreSecret::class)->handle($tenant->id, SecretPurpose::GatewayHmac, new SecretValue($value), ActorType::LocalRoot, null);
    }

    public function test_fails_when_the_master_key_is_unavailable(): void
    {
        $this->withoutVaultKey();

        $this->artisan('sadmin:vault-check')
            ->expectsOutputToContain('Brankas tak tersedia')
            ->assertExitCode(1);
    }

    public function test_healthy_without_secrets(): void
    {
        $this->artisan('sadmin:vault-check')
            ->expectsOutputToContain('versi 1 termuat dari berkas dev')
            ->expectsOutputToContain('0 kunci data rahasia aktif terbuka')
            ->assertExitCode(0);
    }

    public function test_opens_every_active_key_wrap_and_skips_destroyed_ones(): void
    {
        $this->store(self::CANARY.'-1');
        $this->store(self::CANARY.'-2');
        app(DestroySecret::class)->handle($this->store(self::CANARY.'-3')->id, ActorType::LocalRoot, null);

        $this->artisan('sadmin:vault-check')
            ->expectsOutputToContain('2 kunci data rahasia aktif terbuka')
            ->doesntExpectOutputToContain(self::CANARY)
            ->assertExitCode(0);
    }

    public function test_wrong_master_key_fails_and_names_the_key_wraps(): void
    {
        $a = $this->store(self::CANARY.'-a');
        $b = $this->store(self::CANARY.'-b');
        $this->useVaultKey();
        Log::spy();

        // Satu baris keluaran hanya memenuhi satu ekspektasi, jadi baris galat dicocokkan utuh (urut ID).
        $ids = [$a->key_wrap_id, $b->key_wrap_id];
        sort($ids);

        $this->artisan('sadmin:vault-check')
            ->expectsOutputToContain('2 dari 2 kunci data gagal dibuka: '.implode(', ', $ids).'.')
            ->doesntExpectOutputToContain(self::CANARY)
            ->assertExitCode(1);

        Log::shouldHaveReceived('critical')->with('vault_key_mismatch', Mockery::on(
            fn (array $context): bool => $context['checked'] === 2 && count($context['failed_key_wraps']) === 2,
        ));
    }

    public function test_one_corrupted_key_wrap_is_reported_alone(): void
    {
        $this->store(self::CANARY.'-ok');
        $bad = $this->store(self::CANARY.'-rusak');
        $wrapped = (string) $bad->keyWrap?->wrapped_dek;
        DB::table('key_wraps')->where('id', $bad->key_wrap_id)
            ->update(['wrapped_dek' => Bytea::literal(substr_replace($wrapped, chr(ord($wrapped[30]) ^ 0x80), 30, 1))]);

        $this->artisan('sadmin:vault-check')
            ->expectsOutputToContain('1 dari 2 kunci data gagal dibuka: '.$bad->key_wrap_id.'.')
            ->assertExitCode(1);
    }
}
