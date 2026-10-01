<?php

namespace Tests\Feature\Alerts;

use App\Models\Alert;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;
use RuntimeException;
use Tests\Support\InteractsWithAuditChain;
use Tests\Support\InteractsWithNotify;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/**
 * AC-03 butir 2 (docs/23): baris audit diubah lewat SQL superuser → verify exit ≠ 0 dan alert `audit_mismatch`
 * critical terkirim ≤ 60 detik. Pemicu lain dan kode exit sesuai ADR 0005 §2.1.
 */
class AuditMismatchAlertTest extends TestCase
{
    use InteractsWithAuditChain, InteractsWithNotify, InteractsWithVault, RefreshDatabase;

    private const ENTRIES = 210;

    protected function setUp(): void
    {
        parent::setUp();

        Sleep::fake();
        $this->appendEntries(self::ENTRIES);
        $this->addTelegramChannel();
        $this->addSmtpChannel();
    }

    public function test_editing_params_redacted_fails_verify_and_sends_a_critical_alert_within_60_seconds(): void
    {
        $this->telegramAccepts();
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', 137)->update([
            'params_redacted' => '{"urutan": 137, "domain": "palsu.contoh-isi.test"}',
        ]));

        $started = microtime(true);
        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('Verifikasi audit gagal pada seq 137')
            ->expectsOutputToContain('terkirim ke 2 kanal')
            ->assertExitCode(1);
        $elapsed = microtime(true) - $started;

        $this->assertLessThan(60, $elapsed);
        $alert = Alert::query()->sole();
        $this->assertSame('critical', $alert->severity->value);
        $this->assertSame('open', $alert->status->value);
        $this->assertSame('audit_mismatch:seq:137', $alert->dedup_key);
        $this->assertSame('chain', $alert->detail['check']);
        $this->assertNotNull($alert->notified_at);
        $this->assertLessThanOrEqual(60, $alert->opened_at->diffInSeconds($alert->notified_at));

        Http::assertSent(fn (Request $request): bool => str_contains((string) $request['text'], 'kerusakan terdeteksi pada seq 137')
            && str_contains((string) $request['text'], "(ID: {$alert->id})"));
        $this->assertCount(1, $this->sentEmails());
    }

    public function test_verifying_again_reports_the_alert_without_resending(): void
    {
        $this->telegramAccepts();
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', 42)->update(['outcome' => 'failed']));
        $this->artisan('sadmin:audit-verify')->assertExitCode(1);

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('sudah terkirim sebelumnya')
            ->assertExitCode(1);

        Http::assertSentCount(1);
        $this->assertCount(1, $this->sentEmails());
        $this->assertSame(1, Alert::query()->count());
    }

    public function test_checkpoint_mismatch_found_by_verify_raises_an_alert(): void
    {
        $this->telegramAccepts();
        $this->initAuditKey();
        $checkpointSeq = (int) $this->checkpoint()->seq;
        $this->rewriteChainFrom(150, 'target', 'site:palsu');

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain("Verifikasi checkpoint gagal pada seq {$checkpointSeq}")
            ->expectsOutputToContain('terkirim ke 2 kanal')
            ->assertExitCode(1);

        $alert = Alert::query()->sole();
        $this->assertSame('checkpoint', $alert->detail['check']);
        $this->assertSame("audit_mismatch:seq:{$checkpointSeq}", $alert->dedup_key);
    }

    public function test_scheduled_checkpoint_refusing_a_truncated_chain_raises_an_alert(): void
    {
        $this->telegramAccepts();
        $this->initAuditKey();
        $checkpointSeq = (int) $this->checkpoint()->seq;
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', '>', $checkpointSeq - 5)->delete());

        $this->artisan('sadmin:audit-checkpoint --if-due')
            ->expectsOutputToContain('Checkpoint tidak dibuat: rantai audit rusak')
            ->expectsOutputToContain('terkirim ke 2 kanal')
            ->assertExitCode(1);

        $alert = Alert::query()->sole();
        $this->assertSame('checkpoint_create', $alert->detail['check']);
        $this->assertSame('sadmin:audit-checkpoint', $alert->detail['detector']);
    }

    public function test_vault_unavailable_exit_2_is_not_an_audit_mismatch(): void
    {
        $this->telegramAccepts();
        $this->initAuditKey();
        $this->checkpoint();
        $this->withoutVaultKey();

        $this->artisan('sadmin:audit-verify')->assertExitCode(2);

        $this->assertSame(0, Alert::query()->count());
        Http::assertNothingSent();
    }

    public function test_intact_chain_raises_nothing(): void
    {
        $this->telegramAccepts();
        $this->artisan('sadmin:audit-verify')->assertExitCode(0);
        // Kunci audit belum ada: prasyarat, bukan kerusakan (ADR 0004 §2.4), jadi tak membuka alert.
        $this->artisan('sadmin:audit-checkpoint --if-due')->assertExitCode(1);

        $this->assertSame(0, Alert::query()->count());
        Http::assertNothingSent();
    }

    public function test_undelivered_alert_keeps_exit_1_and_tells_the_operator(): void
    {
        Http::fake(['api.telegram.org/*' => Http::response(['ok' => false], 500)]);
        $this->smtpFailure = function (): never {
            throw new RuntimeException('Connection refused');
        };
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', 9)->update(['target' => 'site:palsu']));

        $this->artisan('sadmin:audit-verify')
            ->expectsOutputToContain('TIDAK terkirim ke kanal mana pun')
            ->expectsOutputToContain('sadmin:notify-test')
            ->assertExitCode(1);

        $this->assertNull(Alert::query()->sole()->notified_at);
    }
}
