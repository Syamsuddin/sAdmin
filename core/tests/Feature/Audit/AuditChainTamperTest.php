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

    public function test_editing_any_other_column_fails_verification(): void
    {
        $this->tamper("UPDATE audit_entries SET outcome = 'ok', occurred_at = occurred_at + interval '1 microsecond' WHERE seq = 42");

        $this->artisan('sadmin:audit-verify')->expectsOutputToContain('seq 42')->assertExitCode(1);
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
