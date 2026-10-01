<?php

namespace Tests\Feature\Audit;

use App\Domain\Audit\Services\AuditChainVerifier;
use App\Domain\Audit\Services\CheckpointSigner;
use App\Infrastructure\Vault\Ed25519;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\InteractsWithAuditChain;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/**
 * AC-03 + ADR 0004 §2.5: verify memakai checkpoint untuk menangkap pemotongan ujung dan penulisan ulang rantai dari
 * suatu titik, dua serangan yang lolos pemeriksaan rantai saja (ADR 0001 §4).
 */
class AuditCheckpointTamperTest extends TestCase
{
    use InteractsWithAuditChain, InteractsWithVault, RefreshDatabase;

    /** @var list<int> */
    private array $checkpointSeqs = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->initAuditKey();
        foreach ([50, 70, 80] as $batch) {
            $this->appendEntries($batch);
            $this->checkpointSeqs[] = (int) $this->checkpoint()->seq;
        }
        $this->appendEntries(10);
    }

    private function expectCheckpointMismatch(int $checkpointSeq, string $reason, int $lastIntactSeq): void
    {
        Log::shouldReceive('critical')->once()->withArgs(
            fn (string $message, array $context): bool => $message === 'audit_mismatch'
                && $context['checkpoint_seq'] === $checkpointSeq
                && $context['last_intact_seq'] === $lastIntactSeq
                && str_contains((string) $context['reason'], $reason),
        );
    }

    public function test_intact_chain_of_at_least_200_entries_with_checkpoints_verifies(): void
    {
        [, , $last] = $this->checkpointSeqs;
        $this->assertGreaterThanOrEqual(200, $this->headSeq());

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain("Rantai audit utuh: {$this->headSeq()} entri")
            ->expectsOutputToContain("Checkpoint utuh: 3 checkpoint sah, terakhir seq {$last}; 10 entri sesudahnya belum tercakup checkpoint.")
            ->assertExitCode(0);
    }

    public function test_truncating_the_tail_below_a_checkpoint_is_detected(): void
    {
        [, $second, $third] = $this->checkpointSeqs;
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', '>', $third - 5)->delete());
        $this->assertTrue(app(AuditChainVerifier::class)->verify()->intact, 'Prasyarat: rantai terpotong tetap konsisten.');
        $this->expectCheckpointMismatch($third, 'ujung rantai terpotong', $second);

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain("Verifikasi checkpoint gagal pada seq {$third}")
            ->expectsOutputToContain("Checkpoint sah terakhir: seq {$second} (2 checkpoint lolos)")
            ->assertExitCode(1);
    }

    public function test_rewriting_the_chain_from_a_point_is_detected(): void
    {
        [$first, $second] = $this->checkpointSeqs;
        $this->rewriteChainFrom($first + 10, 'action_key', 'site.archive');
        $this->assertTrue(app(AuditChainVerifier::class)->verify()->intact, 'Prasyarat: rantai yang ditulis ulang tetap konsisten.');
        $this->expectCheckpointMismatch($second, 'rantai ditulis ulang', $first);

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain("Verifikasi checkpoint gagal pada seq {$second}")
            ->doesntExpectOutputToContain('contoh-isi.test')
            ->assertExitCode(1);
    }

    public function test_rewriting_before_the_first_checkpoint_is_reported_at_the_first_checkpoint(): void
    {
        [$first] = $this->checkpointSeqs;
        $this->rewriteChainFrom(3, 'target', 'site:palsu');
        Log::shouldReceive('critical')->once()->withArgs(
            fn (string $message, array $context): bool => $context['checkpoint_seq'] === $first && $context['last_intact_seq'] === 0,
        );

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('Checkpoint sah terakhir: tidak ada (0 checkpoint lolos)')
            ->assertExitCode(1);
    }

    /** @return iterable<string, array{string}> */
    public static function checkpointForgeries(): iterable
    {
        yield 'tanda tangan diganti' => ["UPDATE audit_checkpoints SET signature = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw==' WHERE seq = :seq"];
        yield 'tanda tangan tak kanonik' => ["UPDATE audit_checkpoints SET signature = left(signature, 85) || chr(ascii(substr(signature, 86, 1)) + 1) || '==' WHERE seq = :seq"];
        yield 'hash diganti hash entri lain' => ['UPDATE audit_checkpoints SET hash = (SELECT hash FROM audit_entries WHERE seq = 1) WHERE seq = :seq'];
        yield 'created_at bergeser satu mikrodetik' => ["UPDATE audit_checkpoints SET created_at = created_at + interval '1 microsecond' WHERE seq = :seq"];
        yield 'seq dipindah ke entri lain' => ['UPDATE audit_checkpoints c SET seq = c.seq - 1, hash = (SELECT hash FROM audit_entries WHERE seq = c.seq - 1) WHERE c.seq = :seq'];
    }

    #[DataProvider('checkpointForgeries')]
    public function test_forged_or_altered_checkpoint_is_detected(string $sql): void
    {
        [$first, $second] = $this->checkpointSeqs;
        $this->tamperCheckpoints(fn () => DB::statement(str_replace(':seq', (string) $second, $sql)));
        $altered = (int) DB::table('audit_checkpoints')->where('seq', '>', $first)->min('seq');
        $this->expectCheckpointMismatch($altered, 'tanda tangan checkpoint tidak sah', $first);

        $this->artisan('sadmin:audit-verify')->assertExitCode(1);
    }

    public function test_checkpoint_signed_with_another_key_is_detected(): void
    {
        [, , $third] = $this->checkpointSeqs;
        $attacker = Ed25519::generateSeed();
        $head = DB::table('audit_entries')->orderByDesc('seq')->first();
        $createdAt = '2026-10-01T03:00:00.000000Z';
        DB::table('audit_checkpoints')->insert([
            'seq' => $head->seq,
            'tenant_id' => $this->auditTenantId,
            'hash' => $head->hash,
            'signature' => Ed25519::encode(Ed25519::sign($attacker, CheckpointSigner::message((int) $head->seq, $head->hash, $createdAt))),
            'created_at' => $createdAt,
            'anchored_to' => '{}',
        ]);
        $this->expectCheckpointMismatch((int) $head->seq, 'tanda tangan checkpoint tidak sah', $third);

        $this->artisan('sadmin:audit-verify')->assertExitCode(1);
    }

    public function test_missing_audit_key_is_an_integrity_failure(): void
    {
        DB::table('secrets')->where('purpose', 'audit_key')->update(['status' => 'destroyed']);
        $this->expectCheckpointMismatch($this->checkpointSeqs[0], 'kunci audit aktif tenant tidak ada', 0);

        $this->artisan('sadmin:audit-verify')->assertExitCode(1);
    }

    public function test_wrong_master_key_is_an_integrity_failure(): void
    {
        $this->useVaultKey();
        $this->expectCheckpointMismatch($this->checkpointSeqs[0], 'kunci audit di brankas gagal dibuka', 0);

        $this->artisan('sadmin:audit-verify')->assertExitCode(1);
    }

    public function test_unavailable_vault_reports_incomplete_with_exit_2_not_mismatch(): void
    {
        $this->withoutVaultKey();
        Log::shouldReceive('critical')->never();
        Log::shouldReceive('error')->once()->withArgs(
            fn (string $message, array $context): bool => $message === 'audit_verify_incomplete' && $context['checked_checkpoints'] === 0,
        );

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('Checkpoint tak dapat diperiksa: brankas tak tersedia')
            ->assertExitCode(2);
    }

    public function test_chain_without_checkpoints_verifies_without_the_vault(): void
    {
        $this->tamperCheckpoints(fn () => DB::table('audit_checkpoints')->delete());
        $this->withoutVaultKey();

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('Checkpoint: belum ada')
            ->assertExitCode(0);
    }

    public function test_broken_chain_is_reported_before_checkpoints(): void
    {
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', 42)->update(['outcome' => 'failed']));
        Log::shouldReceive('critical')->once()->withArgs(
            fn (string $message, array $context): bool => $context['broken_at_seq'] === 42 && ! array_key_exists('checkpoint_seq', $context),
        );

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('Verifikasi audit gagal pada seq 42')
            ->assertExitCode(1);
    }
}
