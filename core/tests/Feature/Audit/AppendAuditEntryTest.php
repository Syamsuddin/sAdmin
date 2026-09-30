<?php

namespace Tests\Feature\Audit;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Audit\Services\AuditHasher;
use App\Models\AuditEntry;
use App\Models\Tenant;
use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use LogicException;
use RuntimeException;
use stdClass;
use Tests\TestCase;

class AppendAuditEntryTest extends TestCase
{
    use RefreshDatabase;

    private Tenant $tenant;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenant = Tenant::factory()->create();
    }

    private function append(string $actionKey = 'console.login', mixed ...$extra): AuditHead
    {
        return app(AppendAuditEntry::class)->handle(new AuditEntryData(
            $this->tenant->id, ActorType::Admin, 'admin-1', $actionKey, AuditOutcome::Ok, ...$extra,
        ));
    }

    public function test_first_entry_links_to_genesis_and_hash_matches_content(): void
    {
        $head = $this->append();

        $row = DB::table('audit_entries')->where('seq', 1)->first();
        $this->assertSame(1, $head->seq);
        $this->assertSame(AuditHead::GENESIS_HASH, $row->prev_hash);
        $this->assertSame($head->hash, $row->hash);
        $this->assertSame($row->hash, app(AuditHasher::class)->hash(app(AuditHasher::class)->bodyFromRow($row)));
    }

    /**
     * Vektor emas format rantai (docs/adr/0001), dihitung oracle independen di luar kode PHP ini.
     * Merah di sini = format rantai berubah = gerbang manusia (docs/22), bukan tes yang perlu disesuaikan.
     */
    public function test_hash_matches_golden_vector_of_documented_format(): void
    {
        $tenant = Tenant::factory()->create(['id' => '01k6d4v8m2q9x7c3b5n1r0t6yz']);

        $head = app(AppendAuditEntry::class)->handle(new AuditEntryData(
            tenantId: $tenant->id,
            actorType: ActorType::Admin,
            actorId: 'admin-1',
            actionKey: 'console.login',
            outcome: AuditOutcome::Ok,
            paramsRedacted: ['b' => [], 'a' => ['ok' => true]],
            occurredAt: CarbonImmutable::parse('2026-09-30T10:11:12.345678+08:00'),
        ));

        $this->assertSame('0676afeb6ed67d29dd0b57eebf2b6c5d3817cb7a8cf0f8d21685d7f45da60695', $head->hash);
    }

    public function test_waits_for_the_chain_lock_held_by_another_writer(): void
    {
        config(['database.connections.penulis_lain' => config('database.connections.pgsql')]);
        $other = DB::connection('penulis_lain');
        $other->beginTransaction();
        $other->select('SELECT pg_advisory_xact_lock(?)', [AppendAuditEntry::CHAIN_LOCK_KEY]);

        try {
            DB::transaction(function (): void {
                DB::statement("SET LOCAL lock_timeout = '300ms'");
                $this->append();
            });
            $this->fail('Penulisan seharusnya menunggu kunci rantai milik penulis lain.');
        } catch (QueryException $e) {
            $this->assertSame('55P03', $e->getCode());
        } finally {
            $other->rollBack();
            $other->disconnect();
        }

        $this->assertSame(0, DB::table('audit_entries')->count());
    }

    public function test_entries_form_a_gapless_chain(): void
    {
        $heads = [$this->append(), $this->append('memory.create'), $this->append('memory.delete')];

        $rows = DB::table('audit_entries')->orderBy('seq')->get();
        $this->assertSame([1, 2, 3], $rows->pluck('seq')->map(fn ($s) => (int) $s)->all());
        $this->assertSame($heads[0]->hash, $rows[1]->prev_hash);
        $this->assertSame($heads[1]->hash, $rows[2]->prev_hash);
    }

    public function test_params_are_stored_canonically_and_survive_jsonb_round_trip(): void
    {
        $this->append('site.create', target: 'site:contoh', paramsRedacted: [
            'kosong' => new stdClass,
            'daftar' => [],
            'teks' => "é 😀 \u{2028} \"kutip\"",
            'angka' => 42,
        ]);

        $row = DB::table('audit_entries')->first();
        $this->assertSame(
            app(AuditHasher::class)->hash(app(AuditHasher::class)->bodyFromRow($row)),
            $row->hash,
        );
        $this->assertSame('{}', json_encode(json_decode($row->params_redacted)->kosong));
    }

    public function test_occurred_at_keeps_microseconds_in_utc(): void
    {
        $at = CarbonImmutable::parse('2026-09-30T10:11:12.345678+08:00');

        $this->append(occurredAt: $at);

        $entry = AuditEntry::query()->firstOrFail();
        $this->assertSame('2026-09-30T02:11:12.345678Z', AuditHasher::formatTime($entry->occurred_at));
    }

    public function test_entry_rolls_back_with_the_callers_transaction(): void
    {
        try {
            DB::transaction(function (): void {
                $this->append('site.archive');
                throw new RuntimeException('perubahan state gagal');
            });
        } catch (RuntimeException) {
            // yang diuji: entri audit ikut batal bersama perubahan state pemanggil
        }

        $this->assertSame(0, DB::table('audit_entries')->count());
    }

    public function test_rejects_fractional_params_without_writing(): void
    {
        try {
            $this->append(paramsRedacted: ['cpu' => 0.5]);
            $this->fail('Angka pecahan seharusnya ditolak.');
        } catch (InvalidArgumentException) {
            $this->assertSame(0, DB::table('audit_entries')->count());
        }
    }

    public function test_rejects_non_ulid_references(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new AuditEntryData('bukan-ulid', ActorType::System, null, 'console.login', AuditOutcome::Ok);
    }

    public function test_database_refuses_update_delete_and_truncate(): void
    {
        $this->append();

        foreach ([
            'UPDATE' => fn () => DB::table('audit_entries')->where('seq', 1)->update(['outcome' => 'failed']),
            'DELETE' => fn () => DB::table('audit_entries')->where('seq', 1)->delete(),
            'TRUNCATE' => fn () => DB::statement('TRUNCATE audit_entries'),
        ] as $operation => $attempt) {
            try {
                DB::transaction($attempt);
                $this->fail("{$operation} seharusnya ditolak trigger.");
            } catch (QueryException $e) {
                $this->assertStringContainsString("append-only: {$operation} ditolak", $e->getMessage());
            }
        }

        $this->assertSame(1, DB::table('audit_entries')->count());
    }

    public function test_eloquent_model_refuses_writes(): void
    {
        $this->append();

        $this->expectException(LogicException::class);

        AuditEntry::query()->firstOrFail()->forceFill(['outcome' => 'failed'])->save();
    }
}
