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
use App\Models\Secret;
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

    /**
     * Seed kunci audit aktif, dibuka mandiri dari teks ADR 0003 §2.2–2.3 dengan kunci induk uji. Brankas sendiri
     * menolak mengembalikan seed (ADR 0004 §2.1), jadi tes redaksi butuh jalur di luarnya.
     */
    protected function auditSeed(): string
    {
        $secret = Secret::query()->with('keyWrap')->where('purpose', 'audit_key')->where('status', 'active')->sole();
        $wrapped = (string) $secret->keyWrap?->wrapped_dek;
        $kek = (string) file_get_contents((string) config('sadmin.vault.dev_key_file'));

        $dek = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($wrapped, 24), "sadmin-vault/1/key_wrap/{$secret->tenant_id}/{$secret->key_wrap_id}/1", substr($wrapped, 0, 24), $kek,
        );
        $this->assertIsString($dek, 'Kunci data kunci audit tak terbuka dengan format ADR 0003.');
        $seed = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $secret->ciphertext, "sadmin-vault/1/secret/{$secret->tenant_id}/{$secret->id}/audit_key/{$secret->key_wrap_id}", $secret->nonce, $dek,
        );
        $this->assertIsString($seed, 'Seed kunci audit tak terbuka dengan format ADR 0003.');

        return $seed;
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
