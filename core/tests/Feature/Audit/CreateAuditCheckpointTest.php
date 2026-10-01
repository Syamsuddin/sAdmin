<?php

namespace Tests\Feature\Audit;

use App\Domain\Audit\Actions\CreateAuditCheckpoint;
use App\Domain\Audit\Data\CheckpointStatus;
use App\Domain\Audit\Services\AuditHasher;
use App\Domain\Audit\Services\CheckpointSigner;
use App\Infrastructure\Vault\Ed25519;
use App\Models\Tenant;
use Carbon\CarbonImmutable;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\InteractsWithAuditChain;
use Tests\Support\InteractsWithNotify;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;
use UnexpectedValueException;

/** ADR 0004 §2.3–2.4: checkpoint menandatangani ujung rantai yang sudah dibuktikan, tak pernah rantai yang diubah. */
class CreateAuditCheckpointTest extends TestCase
{
    use InteractsWithAuditChain, InteractsWithNotify, InteractsWithVault, RefreshDatabase;

    private string $publicKey;

    protected function setUp(): void
    {
        parent::setUp();

        $this->publicKey = (string) Ed25519::decode($this->initAuditKey());
    }

    private function checkpoints(): int
    {
        return DB::table('audit_checkpoints')->count();
    }

    private function expectAuditMismatch(int $brokenAtSeq, string $reason): void
    {
        $this->expectUndeliveredIntegrityAlert();
        Log::shouldReceive('critical')->once()->withArgs(
            fn (string $message, array $context): bool => $message === 'audit_mismatch'
                && $context['broken_at_seq'] === $brokenAtSeq
                && str_contains((string) $context['reason'], $reason),
        );
    }

    public function test_first_checkpoint_signs_the_chain_head(): void
    {
        $this->appendEntries(5);
        $head = DB::table('audit_entries')->orderByDesc('seq')->first();

        $this->artisan('sadmin:audit-checkpoint')
            ->expectsOutputToContain("Checkpoint seq {$head->seq} dibuat (hash {$head->hash}")
            ->assertExitCode(0);

        $row = DB::table('audit_checkpoints')->sole();
        $this->assertSame((int) $head->seq, (int) $row->seq);
        $this->assertSame($head->hash, $row->hash);
        $this->assertSame($this->auditTenantId, $row->tenant_id);
        $this->assertSame('{}', $row->anchored_to);
        $this->assertSame(88, strlen($row->signature));

        $createdAt = AuditHasher::formatTime(CarbonImmutable::parse($row->created_at));
        $this->assertTrue(CheckpointSigner::verify($this->publicKey, (int) $row->seq, $row->hash, $createdAt, $row->signature));
        $this->assertSame(7, (int) $row->seq, 'Dua entri pembuatan kunci + lima entri uji.');
    }

    public function test_checkpoint_writes_no_audit_entry(): void
    {
        $this->appendEntries(2);
        $before = $this->headSeq();

        $this->checkpoint();

        $this->assertSame($before, $this->headSeq());
    }

    public function test_nothing_new_since_last_checkpoint_creates_nothing(): void
    {
        $this->appendEntries(2);
        $this->checkpoint();

        $this->artisan('sadmin:audit-checkpoint')
            ->expectsOutputToContain("Tak ada entri baru sejak checkpoint seq {$this->headSeq()}")
            ->assertExitCode(0);

        $this->assertSame(1, $this->checkpoints());
    }

    public function test_empty_chain_creates_nothing(): void
    {
        $this->tamperEntries(fn () => DB::table('audit_entries')->delete());

        $this->artisan('sadmin:audit-checkpoint')
            ->expectsOutputToContain('Rantai audit masih kosong')
            ->assertExitCode(0);

        $this->assertSame(0, $this->checkpoints());
    }

    public function test_if_due_creates_the_first_checkpoint_immediately(): void
    {
        $this->assertSame(CheckpointStatus::Created, $this->checkpoint(onlyIfDue: true)->status);
    }

    public function test_if_due_waits_for_100_entries(): void
    {
        $first = $this->checkpoint();

        $this->appendEntries(99);
        $this->artisan('sadmin:audit-checkpoint --if-due')
            ->expectsOutputToContain("Belum jatuh tempo: checkpoint terakhir seq {$first->seq}")
            ->assertExitCode(0);
        $this->assertSame(1, $this->checkpoints());

        $this->appendEntries(1);
        $result = $this->checkpoint(onlyIfDue: true);
        $this->assertSame(CheckpointStatus::Created, $result->status);
        $this->assertSame($first->seq + 100, $result->seq);
    }

    public function test_if_due_waits_for_15_minutes(): void
    {
        // Jam beku: batas tepat 15:00 sejak created_at teruji, bukan 15:00 ditambah jeda eksekusi tes.
        $this->freezeTime();
        $this->checkpoint();
        $this->appendEntries(1);

        $this->travel(14)->minutes();
        $this->travel(59)->seconds();
        $this->assertSame(CheckpointStatus::NotDue, $this->checkpoint(onlyIfDue: true)->status);

        $this->travel(1)->seconds();
        $this->assertSame(CheckpointStatus::Created, $this->checkpoint(onlyIfDue: true)->status);
    }

    public function test_scheduler_runs_if_due_every_minute(): void
    {
        $events = collect(app(Schedule::class)->events())
            ->filter(fn ($event): bool => str_contains((string) $event->command, 'sadmin:audit-checkpoint --if-due'));

        $this->assertCount(1, $events);
        $this->assertSame('* * * * *', $events->first()->expression);
    }

    public function test_without_audit_key_fails_closed(): void
    {
        DB::table('secrets')->update(['status' => 'destroyed']);
        Log::shouldReceive('error')->once()->withArgs(
            fn (string $message, array $context): bool => $message === 'audit_checkpoint_failed' && str_contains($context['reason'], 'sadmin:audit-key-init'),
        );

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);

        $this->assertSame(0, $this->checkpoints());
    }

    public function test_without_institution_fails_closed(): void
    {
        DB::table('institutions')->delete();

        $this->artisan('sadmin:audit-checkpoint')
            ->expectsOutputToContain('instansi belum diinisialisasi')
            ->assertExitCode(1);

        $this->assertSame(0, $this->checkpoints());
    }

    public function test_without_vault_fails_closed_with_error(): void
    {
        $this->withoutVaultKey();
        Log::shouldReceive('error')->once()->withArgs(fn (string $message): bool => $message === 'audit_checkpoint_failed');

        $this->artisan('sadmin:audit-checkpoint')
            ->expectsOutputToContain('brankas tak tersedia')
            ->assertExitCode(1);

        $this->assertSame(0, $this->checkpoints());
    }

    public function test_wrong_master_key_fails_closed_as_integrity_failure(): void
    {
        $this->useVaultKey();
        $this->expectUndeliveredIntegrityAlert();
        Log::shouldReceive('critical')->once()->withArgs(fn (string $message): bool => $message === 'audit_checkpoint_failed');

        $this->artisan('sadmin:audit-checkpoint')
            ->expectsOutputToContain('kunci audit di brankas gagal dibuka')
            ->assertExitCode(1);

        $this->assertSame(0, $this->checkpoints());
    }

    public function test_refuses_to_sign_a_chain_tampered_before_the_first_checkpoint(): void
    {
        $this->appendEntries(10);
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', 6)->update(['target' => 'site:palsu']));
        $this->expectAuditMismatch(6, 'hash tak cocok dengan isi entri');

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);

        $this->assertSame(0, $this->checkpoints());
    }

    public function test_refuses_to_sign_a_segment_tampered_after_the_last_checkpoint(): void
    {
        $this->appendEntries(5);
        $this->checkpoint();
        $this->appendEntries(5);
        $tampered = $this->headSeq() - 2;
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', $tampered)->update(['outcome' => 'failed']));
        $this->expectAuditMismatch($tampered, 'hash tak cocok dengan isi entri');

        $this->artisan('sadmin:audit-checkpoint')
            ->expectsOutputToContain("rantai audit rusak pada seq {$tampered}")
            ->assertExitCode(1);

        $this->assertSame(1, $this->checkpoints());
    }

    public function test_refuses_when_the_last_checkpoint_signature_is_forged(): void
    {
        $this->appendEntries(3);
        $last = $this->checkpoint()->seq;
        $this->tamperCheckpoints(fn () => DB::table('audit_checkpoints')->update(['signature' => Ed25519::encode(str_repeat("\x07", 64))]));
        $this->appendEntries(1);
        $this->expectAuditMismatch((int) $last, "checkpoint seq {$last}: tanda tangan checkpoint tidak sah");

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);

        $this->assertSame(1, $this->checkpoints());
    }

    public function test_refuses_when_the_chain_was_rewritten_below_the_last_checkpoint(): void
    {
        $this->appendEntries(6);
        $last = (int) $this->checkpoint()->seq;
        $this->rewriteChainFrom($last - 3, 'action_key', 'site.archive');
        $this->appendEntries(1);
        $this->expectAuditMismatch($last, "hash entri seq {$last} berbeda dengan checkpoint (rantai ditulis ulang)");

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);

        $this->assertSame(1, $this->checkpoints());
    }

    public function test_refuses_when_the_rewritten_tip_is_the_checkpointed_entry(): void
    {
        $this->appendEntries(3);
        $last = (int) $this->checkpoint()->seq;
        $this->rewriteChainFrom($last, 'target', 'site:palsu');
        $this->expectAuditMismatch($last, 'rantai ditulis ulang');

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);
    }

    public function test_refuses_when_the_checkpointed_entry_content_changed_but_kept_its_hash(): void
    {
        $this->appendEntries(3);
        $last = (int) $this->checkpoint()->seq;
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', $last)->update(['actor_id' => 'aktor-palsu']));
        $this->appendEntries(1);
        $this->expectAuditMismatch($last, 'hash tak cocok dengan isi entri');

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);
    }

    public function test_refuses_when_the_checkpointed_entry_is_missing(): void
    {
        $this->appendEntries(3);
        $last = (int) $this->checkpoint()->seq;
        $this->appendEntries(2);
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', $last)->delete());
        $this->expectAuditMismatch($last, "entri seq {$last} yang dicakup checkpoint hilang");

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);
    }

    public function test_refuses_when_the_tail_was_truncated_below_the_last_checkpoint(): void
    {
        $this->appendEntries(6);
        $last = (int) $this->checkpoint()->seq;
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', '>', $last - 2)->delete());
        $this->expectAuditMismatch($last, 'ujung rantai terpotong');

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);
    }

    public function test_concurrent_creators_are_serialized_by_the_advisory_lock(): void
    {
        $this->appendEntries(2);
        config(['database.connections.pgsql_kunci' => config('database.connections.pgsql')]);
        $other = DB::connection('pgsql_kunci');
        $other->select('SELECT pg_advisory_lock(?)', [CreateAuditCheckpoint::LOCK_KEY]);
        DB::statement("SET lock_timeout = '200ms'");

        try {
            $this->checkpoint();
            $this->fail('Pembuatan checkpoint seharusnya menunggu kunci advisory yang dipegang koneksi lain.');
        } catch (QueryException $e) {
            $this->assertStringContainsString('lock timeout', $e->getMessage());
        } finally {
            DB::statement('RESET lock_timeout');
            $other->select('SELECT pg_advisory_unlock(?)', [CreateAuditCheckpoint::LOCK_KEY]);
            $other->disconnect();
        }

        $this->assertSame(0, $this->checkpoints());
    }

    public function test_checkpoint_that_does_not_verify_after_writing_is_rolled_back_and_logged_critical(): void
    {
        $this->appendEntries(2);
        $this->corruptCheckpointsOnInsert();
        $this->expectUndeliveredIntegrityAlert();
        Log::shouldReceive('critical')->once()->withArgs(
            fn (string $message, array $context): bool => $message === 'audit_checkpoint_failed' && str_contains($context['reason'], 'pembuatan dibatalkan'),
        );

        $this->artisan('sadmin:audit-checkpoint')->assertExitCode(1);

        $this->assertSame(0, $this->checkpoints());
    }

    private function corruptCheckpointsOnInsert(): void
    {
        $other = Ed25519::encode(str_repeat("\x09", 64));
        DB::unprepared(<<<SQL
            CREATE FUNCTION uji_ubah_checkpoint() RETURNS trigger LANGUAGE plpgsql AS \$\$
            BEGIN NEW.signature := '{$other}'; RETURN NEW; END
            \$\$;
            CREATE TRIGGER uji_ubah_checkpoint BEFORE INSERT ON audit_checkpoints
                FOR EACH ROW EXECUTE FUNCTION uji_ubah_checkpoint();
            SQL);
    }

    public function test_checkpoint_that_does_not_verify_after_writing_is_rolled_back(): void
    {
        $this->appendEntries(2);
        $this->corruptCheckpointsOnInsert();

        try {
            $this->checkpoint();
            $this->fail('Checkpoint yang tak lolos verifikasi saat dibaca ulang seharusnya dibatalkan.');
        } catch (UnexpectedValueException) {
            $this->assertSame(0, $this->checkpoints());
        }
    }

    /** @return iterable<string, array{string}> */
    public static function forbiddenChanges(): iterable
    {
        yield 'hash' => ["UPDATE audit_checkpoints SET hash = repeat('a', 64)"];
        yield 'signature' => ['UPDATE audit_checkpoints SET signature = lpad(\'\', 86, \'A\') || \'==\''];
        yield 'created_at' => ["UPDATE audit_checkpoints SET created_at = created_at + interval '1 microsecond'"];
        yield 'seq' => ['UPDATE audit_checkpoints SET seq = seq + 1'];
        yield 'tenant_id' => ['UPDATE audit_checkpoints SET tenant_id = (SELECT id FROM tenants WHERE id <> audit_checkpoints.tenant_id LIMIT 1)'];
        yield 'anchored_to menyusut' => ["UPDATE audit_checkpoints SET anchored_to = '{}'"];
        yield 'DELETE' => ['DELETE FROM audit_checkpoints'];
        yield 'TRUNCATE' => ['TRUNCATE audit_checkpoints'];
    }

    #[DataProvider('forbiddenChanges')]
    public function test_database_allows_only_growing_anchored_to(string $sql): void
    {
        $this->appendEntries(1);
        $this->checkpoint();
        Tenant::factory()->create();
        DB::statement("UPDATE audit_checkpoints SET anchored_to = '{agents}'");

        try {
            DB::transaction(fn () => DB::statement($sql));
            $this->fail('Perubahan checkpoint seharusnya ditolak trigger.');
        } catch (QueryException $e) {
            $this->assertStringContainsString('hanya boleh menambah anchored_to', $e->getMessage());
        }

        DB::statement("UPDATE audit_checkpoints SET anchored_to = '{agents,offsite,digest}'");
        $this->assertSame('{agents,offsite,digest}', DB::table('audit_checkpoints')->value('anchored_to'));
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function invalidRows(): iterable
    {
        yield 'hash huruf besar' => [['hash' => str_repeat('A', 64)], 'audit_checkpoints_hash_check'];
        yield 'signature base64url' => [['signature' => str_repeat('-', 86).'=='], 'audit_checkpoints_signature_check'];
        yield 'signature tanpa padding' => [['signature' => str_repeat('A', 88)], 'audit_checkpoints_signature_check'];
        yield 'jangkar tak dikenal' => [['anchored_to' => '{agents,email}'], 'audit_checkpoints_anchored_to_check'];
        yield 'jangkar NULL' => [['anchored_to' => '{NULL}'], 'audit_checkpoints_anchored_to_check'];
        yield 'seq nol' => [['seq' => 0], 'audit_checkpoints_seq_check'];
    }

    /** @param array<string, mixed> $override */
    #[DataProvider('invalidRows')]
    public function test_database_rejects_malformed_checkpoint_rows(array $override, string $constraint): void
    {
        try {
            DB::transaction(fn () => DB::table('audit_checkpoints')->insert([
                'seq' => 1,
                'tenant_id' => $this->auditTenantId,
                'hash' => str_repeat('a', 64),
                'signature' => str_repeat('A', 86).'==',
                'created_at' => '2026-10-01T00:00:00.000000Z',
                'anchored_to' => '{}',
                ...$override,
            ]));
            $this->fail("Baris seharusnya ditolak {$constraint}.");
        } catch (QueryException $e) {
            $this->assertStringContainsString($constraint, $e->getMessage());
        }
    }
}
