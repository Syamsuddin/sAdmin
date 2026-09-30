<?php

namespace Tests\Feature\Audit;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Audit\Services\AuditHasher;
use App\Models\Tenant;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

/** AC-03 (docs/23): verify hijau atas ≥ 200 entri; perubahan lewat SQL mentah terdeteksi. */
class AuditChainTamperTest extends TestCase
{
    use RefreshDatabase;

    private const ENTRIES = 210;

    protected function setUp(): void
    {
        parent::setUp();

        $tenant = Tenant::factory()->create();
        $append = app(AppendAuditEntry::class);
        $actors = ActorType::cases();
        $outcomes = AuditOutcome::cases();

        for ($i = 1; $i <= self::ENTRIES; $i++) {
            $append->handle(new AuditEntryData(
                tenantId: $tenant->id,
                actorType: $actors[$i % count($actors)],
                actorId: $i % 3 === 0 ? null : "aktor-{$i}",
                actionKey: $i % 2 === 0 ? 'site.create' : 'console.login',
                outcome: $outcomes[$i % count($outcomes)],
                target: $i % 5 === 0 ? null : "site:situs-{$i}",
                paramsRedacted: $i % 4 === 0 ? null : ['urutan' => $i, 'domain' => "situs-{$i}.example.test", 'rahasia' => '***'],
                envelopeRef: $i % 7 === 0 ? (string) Str::ulid() : null,
                emergencyLocal: $i % 11 === 0,
            ));
        }
    }

    /**
     * Mensimulasikan penyerang berhak pemilik tabel/superuser (docs/13): trigger dimatikan sesaat.
     */
    private function tamper(string $sql): void
    {
        DB::statement('ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_update_delete');
        DB::statement($sql);
        DB::statement('ALTER TABLE audit_entries ENABLE TRIGGER audit_entries_no_update_delete');
    }

    public function test_untampered_chain_of_at_least_200_entries_verifies(): void
    {
        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('Rantai audit utuh: '.self::ENTRIES.' entri')
            ->assertExitCode(0);
    }

    public function test_editing_params_redacted_via_raw_sql_fails_verification_and_logs_critical(): void
    {
        Log::shouldReceive('critical')->once()->withArgs(
            fn (string $message, array $context): bool => $message === 'audit_mismatch' && $context['broken_at_seq'] === 137,
        );

        $this->tamper("UPDATE audit_entries SET params_redacted = '{\"urutan\": 137, \"domain\": \"palsu.example.test\"}' WHERE seq = 137");

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('gagal pada seq 137')
            ->assertExitCode(1);
    }

    #[Group('redaction')]
    public function test_integrity_failure_never_echoes_entry_contents_to_output_or_log(): void
    {
        $canary = 'CANARY-'.Str::random(24);
        $logged = [];
        Log::shouldReceive('critical')->once()->andReturnUsing(function (string $message, array $context) use (&$logged): void {
            $logged = [$message, $context];
        });

        $this->tamper("UPDATE audit_entries SET params_redacted = '{\"bocor\": \"{$canary}\", \"angka\": 9007199254740993}' WHERE seq = 7");

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('tak dapat dikanonisasi')
            ->doesntExpectOutputToContain($canary)
            ->doesntExpectOutputToContain('9007199254740993')
            ->assertExitCode(1);

        $this->assertSame('audit_mismatch', $logged[0]);
        $this->assertStringNotContainsString($canary, (string) json_encode($logged));
        $this->assertStringNotContainsString('9007199254740993', (string) json_encode($logged));
    }

    /** @return iterable<string, array{string}> */
    public static function columnTampers(): iterable
    {
        yield 'tenant_id' => ['tenant_id = (SELECT id FROM tenants WHERE id <> audit_entries.tenant_id LIMIT 1)'];
        yield 'prev_hash' => ["prev_hash = repeat('b', 64)"];
        yield 'occurred_at +1µs' => ["occurred_at = occurred_at + interval '1 microsecond'"];
        yield 'actor_type' => ["actor_type = CASE WHEN actor_type = 'system' THEN 'admin' ELSE 'system' END"];
        yield 'actor_id NULL↔kosong' => ["actor_id = CASE WHEN actor_id IS NULL THEN '' ELSE NULL END"];
        yield 'action_key' => ["action_key = action_key || '.x'"];
        yield 'target' => ["target = COALESCE(target, '') || 'x'"];
        yield 'outcome' => ["outcome = CASE WHEN outcome = 'ok' THEN 'failed' ELSE 'ok' END"];
        yield 'envelope_ref' => ["envelope_ref = CASE WHEN envelope_ref IS NULL THEN '01k6d4v8m2q9x7c3b5n1r0t6yz' ELSE NULL END"];
        yield 'emergency_local' => ['emergency_local = NOT emergency_local'];
    }

    #[DataProvider('columnTampers')]
    public function test_editing_any_single_column_fails_verification(string $set): void
    {
        Tenant::factory()->create();

        $this->tamper("UPDATE audit_entries SET {$set} WHERE seq = 42");

        $this->artisan('sadmin:audit-verify')->expectsOutputToContain('gagal pada seq 42')->assertExitCode(1);
    }

    /** @return iterable<string, array{string}> */
    public static function scalarParams(): iterable
    {
        yield 'string' => ['"x"'];
        yield 'angka' => ['5'];
        yield 'boolean' => ['true'];
    }

    #[DataProvider('scalarParams')]
    public function test_scalar_params_end_as_audit_mismatch_not_a_crash(string $json): void
    {
        Log::shouldReceive('critical')->once()->withArgs(
            fn (string $message, array $context): bool => $message === 'audit_mismatch' && $context['broken_at_seq'] === 5,
        );

        $this->tamper("UPDATE audit_entries SET params_redacted = '{$json}' WHERE seq = 5");

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('gagal pada seq 5: isi entri tak dapat dikanonisasi')
            ->assertExitCode(1);
    }

    public function test_deleting_a_middle_entry_is_detected_as_a_gap(): void
    {
        $this->tamper('DELETE FROM audit_entries WHERE seq = 100');

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('entri seq 100 hilang')
            ->assertExitCode(1);
    }

    public function test_rewriting_one_entry_with_a_recomputed_hash_breaks_the_next_link(): void
    {
        $hasher = app(AuditHasher::class);
        $row = DB::table('audit_entries')->where('seq', 50)->first();
        $row->outcome = $row->outcome === 'ok' ? 'failed' : 'ok';
        $forged = $hasher->hash($hasher->bodyFromRow($row));

        $this->tamper("UPDATE audit_entries SET outcome = '{$row->outcome}', hash = '{$forged}' WHERE seq = 50");

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('gagal pada seq 51: prev_hash tak sama')
            ->expectsOutputToContain('Entri utuh terakhir: seq 50')
            ->assertExitCode(1);
    }
}
