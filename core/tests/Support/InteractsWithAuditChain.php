<?php

namespace Tests\Support;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Actions\CreateAuditCheckpoint;
use App\Domain\Audit\Actions\InitializeAuditKey;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditHead;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Audit\Data\CheckpointResult;
use App\Domain\Audit\Services\AuditHasher;
use App\Models\Institution;
use Closure;
use Illuminate\Support\Facades\DB;

/**
 * Rantai audit uji milik satu instansi, kunci audit, checkpoint, dan penyerang berhak pemilik tabel (docs/13) yang
 * mematikan trigger sesaat. Pakai bersama InteractsWithVault: kunci audit butuh brankas.
 */
trait InteractsWithAuditChain
{
    protected string $auditTenantId;

    protected function setUpInteractsWithAuditChain(): void
    {
        $this->auditTenantId = Institution::factory()->create()->tenant_id;
    }

    protected function appendEntries(int $count): void
    {
        $append = app(AppendAuditEntry::class);
        $start = (int) DB::table('audit_entries')->max('seq');

        for ($i = $start + 1; $i <= $start + $count; $i++) {
            $append->handle(new AuditEntryData(
                tenantId: $this->auditTenantId,
                actorType: $i % 2 === 0 ? ActorType::Admin : ActorType::Runner,
                actorId: "aktor-{$i}",
                actionKey: $i % 3 === 0 ? 'site.create' : 'console.login',
                outcome: AuditOutcome::Ok,
                target: "site:situs-{$i}",
                paramsRedacted: ['urutan' => $i, 'domain' => "situs-{$i}.contoh-isi.test"],
            ));
        }
    }

    /** @return string kunci publik audit base64 */
    protected function initAuditKey(): string
    {
        return app(InitializeAuditKey::class)->handle()['publicKey'];
    }

    protected function checkpoint(bool $onlyIfDue = false): CheckpointResult
    {
        return app(CreateAuditCheckpoint::class)->handle($onlyIfDue);
    }

    protected function headSeq(): int
    {
        return (int) DB::table('audit_entries')->max('seq');
    }

    protected function tamperEntries(Closure $attack): void
    {
        DB::statement('ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_update_delete');
        $attack();
        DB::statement('ALTER TABLE audit_entries ENABLE TRIGGER audit_entries_no_update_delete');
    }

    protected function tamperCheckpoints(Closure $attack): void
    {
        DB::statement('ALTER TABLE audit_checkpoints DISABLE TRIGGER audit_checkpoints_anchor_only');
        $attack();
        DB::statement('ALTER TABLE audit_checkpoints ENABLE TRIGGER audit_checkpoints_anchor_only');
    }

    /**
     * Penulisan ulang yang lolos verifikasi rantai (ADR 0001 §4): ubah satu kolom entri $seq lalu hitung ulang
     * prev_hash dan hash semua entri sesudahnya.
     */
    protected function rewriteChainFrom(int $seq, string $column, mixed $value): void
    {
        $this->tamperEntries(function () use ($seq, $column, $value): void {
            DB::table('audit_entries')->where('seq', $seq)->update([$column => $value]);

            $hasher = app(AuditHasher::class);
            $prev = DB::table('audit_entries')->where('seq', $seq - 1)->value('hash') ?? AuditHead::GENESIS_HASH;
            foreach (DB::table('audit_entries')->where('seq', '>=', $seq)->orderBy('seq')->get() as $row) {
                $row->prev_hash = $prev;
                $hash = $hasher->hash($hasher->bodyFromRow($row));
                DB::table('audit_entries')->where('seq', $row->seq)->update(['prev_hash' => $prev, 'hash' => $hash]);
                $prev = $hash;
            }
        });
    }
}
