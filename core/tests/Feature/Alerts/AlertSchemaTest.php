<?php

namespace Tests\Feature\Alerts;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\SecretValue;
use App\Models\Tenant;
use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** Constraint tabel notifikasi docs/07 dan ADR 0005 §2.2/§2.5: dijaga basis data, bukan hanya kode. */
class AlertSchemaTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private string $tenantId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tenantId = Tenant::factory()->create()->id;
    }

    /** @param  array<string, mixed>  $overrides */
    private function insertRule(array $overrides = []): string
    {
        $id = strtolower((string) Str::ulid());
        DB::table('alert_rules')->insert(array_merge([
            'id' => $id,
            'tenant_id' => $this->tenantId,
            'kind' => 'audit_mismatch',
            'threshold' => '{}',
            'enabled' => true,
            'created_at' => CarbonImmutable::now(),
            'updated_at' => CarbonImmutable::now(),
        ], $overrides));

        return $id;
    }

    /** @param  array<string, mixed>  $overrides */
    private function insertAlert(array $overrides = []): string
    {
        $id = strtolower((string) Str::ulid());
        DB::table('alerts')->insert(array_merge([
            'id' => $id,
            'tenant_id' => $this->tenantId,
            'rule_id' => null,
            'server_id' => null,
            'severity' => 'critical',
            'title' => 'Audit tidak utuh',
            'detail' => '{"seq": 7}',
            'status' => 'open',
            'dedup_key' => 'audit_mismatch:seq:7',
            'opened_at' => CarbonImmutable::now(),
            'notified_at' => null,
            'resolved_at' => null,
            'created_at' => CarbonImmutable::now(),
            'updated_at' => CarbonImmutable::now(),
        ], $overrides));

        return $id;
    }

    private function assertRejected(string $constraint, callable $write): void
    {
        try {
            // Savepoint: pernyataan yang ditolak tak boleh membatalkan transaksi RefreshDatabase.
            DB::transaction(fn () => $write());
        } catch (QueryException $e) {
            $this->assertStringContainsString($constraint, $e->getMessage());

            return;
        }

        $this->fail("Basis data menerima baris yang seharusnya ditolak {$constraint}.");
    }

    public function test_audit_mismatch_rule_can_never_be_disabled(): void
    {
        $this->assertRejected('alert_rules_audit_mismatch_enabled_check', fn () => $this->insertRule(['enabled' => false]));

        $id = $this->insertRule();
        $this->assertRejected('alert_rules_audit_mismatch_enabled_check', fn () => DB::table('alert_rules')->where('id', $id)->update(['enabled' => false]));
    }

    public function test_other_rules_may_be_disabled(): void
    {
        $this->insertRule(['kind' => 'disk_low', 'threshold' => '{"warning": 85, "critical": 95}', 'enabled' => false]);

        $this->assertSame(1, DB::table('alert_rules')->where('kind', 'disk_low')->where('enabled', false)->count());
    }

    public function test_one_rule_per_kind_per_tenant(): void
    {
        $this->insertRule();

        $this->assertRejected('alert_rules_tenant_id_kind_unique', fn () => $this->insertRule());
    }

    /** @return iterable<string, array{string, string, array<string, mixed>}> */
    public static function invalidRows(): iterable
    {
        yield 'jenis aturan asing' => ['alert_rules', 'alert_rules_kind_check', ['kind' => 'vault_mismatch']];
        yield 'ambang bukan objek' => ['alert_rules', 'alert_rules_threshold_check', ['kind' => 'disk_low', 'threshold' => '[85]']];
        yield 'severity asing' => ['alerts', 'alerts_severity_check', ['severity' => 'fatal']];
        yield 'status asing' => ['alerts', 'alerts_status_check', ['status' => 'closed']];
        yield 'detail bukan objek' => ['alerts', 'alerts_detail_check', ['detail' => '"rusak"']];
        yield 'resolved tanpa waktu' => ['alerts', 'alerts_resolved_at_check', ['status' => 'resolved']];
        yield 'waktu selesai tanpa resolved' => ['alerts', 'alerts_resolved_at_check', ['resolved_at' => '2026-10-01 00:00:00+00']];
    }

    /** @param  array<string, mixed>  $overrides */
    #[DataProvider('invalidRows')]
    public function test_check_constraints_reject_invalid_rows(string $table, string $constraint, array $overrides): void
    {
        $this->assertRejected($constraint, fn () => $table === 'alerts' ? $this->insertAlert($overrides) : $this->insertRule($overrides));
    }

    public function test_at_most_one_unresolved_alert_per_dedup_key(): void
    {
        $first = $this->insertAlert();
        $this->assertRejected('alerts_unresolved_dedup', fn () => $this->insertAlert(['status' => 'acknowledged']));

        // Kunci yang sama di tenant lain, atau sesudah alert lama selesai, adalah kejadian baru.
        $this->insertAlert(['tenant_id' => Tenant::factory()->create()->id]);
        DB::table('alerts')->where('id', $first)->update(['status' => 'resolved', 'resolved_at' => CarbonImmutable::now()]);
        $this->insertAlert();
        $this->insertAlert(['dedup_key' => null]);
        $this->insertAlert(['dedup_key' => null]);

        $this->assertSame(2, DB::table('alerts')->where('tenant_id', $this->tenantId)->where('dedup_key', 'audit_mismatch:seq:7')->count());
    }

    /** @return iterable<string, array{string, array<string, mixed>}> */
    public static function invalidChannels(): iterable
    {
        yield 'jenis kanal asing' => ['notification_channels_kind_check', ['kind' => 'whatsapp']];
        yield 'status asing' => ['notification_channels_status_check', ['status' => 'paused']];
        yield 'config bukan objek' => ['notification_channels_config_check', ['config' => '["chat"]']];
        yield 'tanpa rahasia' => ['null value in column "secret_id"', ['secret_id' => null]];
    }

    /** @param  array<string, mixed>  $overrides */
    #[DataProvider('invalidChannels')]
    public function test_channel_constraints(string $constraint, array $overrides): void
    {
        $secretId = $this->storeTelegramSecret();

        $this->assertRejected($constraint, fn () => DB::table('notification_channels')->insert(array_merge([
            'id' => strtolower((string) Str::ulid()),
            'tenant_id' => $this->tenantId,
            'kind' => 'telegram',
            'config' => '{"chat_id": "-100123"}',
            'secret_id' => $secretId,
            'status' => 'active',
            'created_at' => CarbonImmutable::now(),
            'updated_at' => CarbonImmutable::now(),
        ], $overrides)));
    }

    private function storeTelegramSecret(): string
    {
        return app(StoreSecret::class)->handle(
            $this->tenantId,
            SecretPurpose::TelegramToken,
            new SecretValue('123456789:AAskemaujiskemaujiskemaujiskemauji'),
            ActorType::LocalRoot,
            null,
        )->id;
    }
}
