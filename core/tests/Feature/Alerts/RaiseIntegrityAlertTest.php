<?php

namespace Tests\Feature\Alerts;

use App\Domain\Alerts\Actions\RaiseIntegrityAlert;
use App\Domain\Alerts\Data\IntegrityAlert;
use App\Domain\Alerts\Data\RaisedAlert;
use App\Domain\Alerts\Services\AlertDispatcher;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Vault\Actions\DestroySecret;
use App\Infrastructure\Notify\NotificationMessage;
use App\Models\Alert;
use App\Models\Institution;
use App\Models\NotificationChannel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;
use Tests\Support\InteractsWithNotify;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0005 §2.2–2.4: penyimpanan, deduplikasi, audit, dan pengiriman sinkron alert integritas. */
class RaiseIntegrityAlertTest extends TestCase
{
    use InteractsWithNotify, InteractsWithVault, RefreshDatabase;

    /** @var list<array{string, string, array<string, mixed>}> */
    private array $logged = [];

    protected function setUp(): void
    {
        parent::setUp();

        Sleep::fake();
        Log::listen(function (MessageLogged $event): void {
            $this->logged[] = [$event->level, $event->message, $event->context];
        });
    }

    private function raise(?IntegrityAlert $alert = null): RaisedAlert
    {
        return app(RaiseIntegrityAlert::class)->handle($alert ?? IntegrityAlert::chainBroken(57, 'hash entri seq 57 tidak cocok'));
    }

    /** @return list<string> */
    private function loggedMessages(string $level): array
    {
        return array_values(array_map(fn (array $log): string => $log[1], array_filter($this->logged, fn (array $log): bool => $log[0] === $level)));
    }

    /** @return list<object> */
    private function auditEntries(string $actionKey): array
    {
        return DB::table('audit_entries')->where('action_key', $actionKey)->orderBy('seq')->get()->all();
    }

    public function test_new_alert_is_stored_audited_sent_to_every_active_channel_and_marked_notified(): void
    {
        Institution::factory()->create();
        $telegram = $this->addTelegramChannel();
        $smtp = $this->addSmtpChannel();
        $this->addTelegramChannel('-100999')->update(['status' => 'inactive']);
        $this->telegramAccepts();

        $raised = $this->raise();

        $this->assertTrue($raised->stored);
        $this->assertTrue($raised->created);
        $this->assertTrue($raised->delivered());
        $this->assertSame([$telegram->id, $smtp->id], $raised->report?->delivered);

        $alert = Alert::query()->with('rule')->sole();
        $this->assertSame($raised->alertId, $alert->id);
        $this->assertSame('critical', $alert->severity->value);
        $this->assertSame('open', $alert->status->value);
        $this->assertSame('audit_mismatch', $alert->rule?->kind->value);
        $this->assertTrue($alert->rule?->enabled);
        $this->assertNull($alert->server_id);
        $this->assertSame('Audit tidak utuh', $alert->title);
        $this->assertSame('audit_mismatch:seq:57', $alert->dedup_key);
        $this->assertEquals(['detector' => 'sadmin:audit-verify', 'check' => 'chain', 'seq' => 57, 'reason' => 'hash entri seq 57 tidak cocok'], $alert->detail);
        $this->assertNotNull($alert->notified_at);

        Http::assertSentCount(1);
        $this->assertCount(1, $this->sentEmails());

        [$open] = $this->auditEntries('alert.open');
        $this->assertSame('system', $open->actor_type);
        $this->assertSame("alert:{$alert->id}", $open->target);
        $this->assertEquals(['kind' => 'audit_mismatch', 'seq' => 57, 'severity' => 'critical'], json_decode($open->params_redacted, true));
        [$notify] = $this->auditEntries('alert.notify');
        $this->assertSame("alert:{$alert->id}", $notify->target);
        $this->assertEquals(['delivered' => 2, 'failed' => 0, 'reminder' => false], json_decode($notify->params_redacted, true));
    }

    public function test_the_same_incident_is_never_sent_twice(): void
    {
        Institution::factory()->create();
        $this->addTelegramChannel();
        $this->telegramAccepts();

        $first = $this->raise();
        $second = $this->raise(IntegrityAlert::checkpointRefused(57, 'alasan lain dari pendeteksi lain'));

        $this->assertTrue($second->alreadyNotified);
        $this->assertFalse($second->created);
        $this->assertSame($first->alertId, $second->alertId);
        $this->assertNull($second->report);
        Http::assertSentCount(1);
        $this->assertSame(1, Alert::query()->count());
        $this->assertCount(1, $this->auditEntries('alert.open'));
        $this->assertCount(1, $this->auditEntries('alert.notify'));
    }

    public function test_damage_at_another_seq_opens_a_new_alert_while_the_first_is_unresolved(): void
    {
        Institution::factory()->create();
        $this->addTelegramChannel();
        $this->telegramAccepts();

        $first = $this->raise();
        $second = $this->raise(IntegrityAlert::chainBroken(12, 'hash entri seq 12 tidak cocok'));
        $readback = $this->raise(IntegrityAlert::checkpointReadback('Checkpoint tak terbaca ulang'));

        $this->assertNotSame($first->alertId, $second->alertId);
        $this->assertTrue($second->created);
        $this->assertTrue($readback->created);
        $this->assertSame('audit_mismatch:checkpoint_readback', Alert::query()->find($readback->alertId)?->dedup_key);
        $this->assertNull(Alert::query()->find($readback->alertId)?->detail['seq']);
        Http::assertSentCount(3);
    }

    public function test_failed_channel_is_retried_once_after_a_pause(): void
    {
        Institution::factory()->create();
        $this->addTelegramChannel();
        Http::fakeSequence('api.telegram.org/*')
            ->push(['ok' => false, 'description' => 'Internal Server Error'], 500)
            ->push(['ok' => true], 200);

        $raised = $this->raise();

        $this->assertTrue($raised->delivered());
        Http::assertSentCount(2);
        Sleep::assertSequence([Sleep::for(AlertDispatcher::RETRY_PAUSE_SECONDS)->seconds()]);
        $this->assertSame(['alert_notify_failed'], $this->loggedMessages('error'));
        $this->assertNotNull(Alert::query()->sole()->notified_at);
    }

    public function test_undelivered_alert_stays_unnotified_and_is_sent_on_the_next_detection(): void
    {
        Institution::factory()->create();
        $this->addTelegramChannel();
        Http::fakeSequence('api.telegram.org/*')
            ->push(['ok' => false], 502)
            ->push(['ok' => false], 502)
            ->push(['ok' => true], 200);

        $first = $this->raise();

        $this->assertFalse($first->delivered());
        $this->assertSame(['alert_notify_failed', 'alert_notify_failed'], $this->loggedMessages('error'));
        $this->assertSame(['alert_undelivered'], $this->loggedMessages('critical'));
        $this->assertNull(Alert::query()->sole()->notified_at);
        $this->assertCount(0, $this->auditEntries('alert.notify'));

        $second = $this->raise();

        $this->assertSame($first->alertId, $second->alertId);
        $this->assertFalse($second->created);
        $this->assertTrue($second->delivered());
        Http::assertSentCount(3);
        $this->assertNotNull(Alert::query()->sole()->notified_at);
        $this->assertCount(1, $this->auditEntries('alert.open'));
        $this->assertCount(1, $this->auditEntries('alert.notify'));
    }

    public function test_time_budget_bounds_the_whole_delivery(): void
    {
        Sleep::fake(syncWithCarbon: true);
        $this->freezeTime();
        Institution::factory()->create();
        $slow = $this->addTelegramChannel('-1001');
        $starved = $this->addTelegramChannel('-1002');
        Http::fake(function (Request $request) {
            // Kanal pertama menghabiskan hampir seluruh anggaran lalu gagal.
            $this->travel(AlertDispatcher::BUDGET_SECONDS * 1000 - 500)->milliseconds();

            return Http::response(['ok' => false], 504);
        });

        $raised = $this->raise();

        Http::assertSentCount(1);
        $this->assertFalse($raised->delivered());
        $this->assertSame('anggaran waktu pengiriman habis', $raised->report?->failed[$starved->id]);
        $this->assertStringContainsString('504', (string) $raised->report?->failed[$slow->id]);
    }

    public function test_each_attempt_timeout_is_capped_by_the_remaining_budget(): void
    {
        $this->freezeTime();
        $tenantId = Institution::factory()->create()->tenant_id;
        $this->addSmtpChannel();
        $this->addSmtpChannel(['host' => 'smtp2.contoh-instansi.test']);
        $this->smtpFailure = function (): void {
            $this->travel(45)->seconds();
        };

        $report = app(AlertDispatcher::class)->deliver($tenantId, new NotificationMessage('subjek', 'isi'));

        // Kanal kedua hanya punya sisa 5 detik: timeout-nya dipangkas, bukan 10 detik penuh.
        $this->assertSame([10.0, 5.0], array_column($this->smtpConfigs, 'timeout'));
        $this->assertCount(2, $report->delivered);
    }

    public function test_advisory_lock_is_held_while_sending_and_released_afterwards(): void
    {
        Institution::factory()->create();
        $this->addTelegramChannel();
        $held = null;
        Http::fake(function () use (&$held) {
            $held = $this->advisoryLocks();

            return Http::response(['ok' => true]);
        });

        $this->raise();

        $this->assertSame(1, $held);
        $this->assertSame(0, $this->advisoryLocks());
    }

    private function advisoryLocks(): int
    {
        return (int) DB::scalar(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND classid = ?",
            [RaiseIntegrityAlert::LOCK_CLASS],
        );
    }

    public function test_storage_failure_never_stops_delivery(): void
    {
        Institution::factory()->create();
        $this->addTelegramChannel();
        $this->telegramAccepts();
        DB::statement('ALTER TABLE alerts ADD CONSTRAINT uji_tolak_semua CHECK (false) NOT VALID');

        $raised = $this->raise();

        $this->assertFalse($raised->stored);
        $this->assertTrue($raised->delivered());
        $this->assertSame(0, Alert::query()->count());
        $this->assertSame(['alert_store_failed'], $this->loggedMessages('critical'));
        Http::assertSent(fn (Request $request): bool => str_contains((string) $request['text'], "(ID: {$raised->alertId})"));
    }

    public function test_without_an_institution_nothing_can_be_sent_and_it_is_logged_critical(): void
    {
        $raised = $this->raise();

        $this->assertFalse($raised->stored);
        $this->assertFalse($raised->delivered());
        $this->assertSame(['alert_undelivered'], $this->loggedMessages('critical'));
        Http::assertNothingSent();
    }

    public function test_without_channels_the_alert_is_stored_and_logged_undelivered(): void
    {
        Institution::factory()->create();

        $raised = $this->raise();

        $this->assertTrue($raised->stored);
        $this->assertFalse($raised->delivered());
        $this->assertSame(['alert_undelivered'], $this->loggedMessages('critical'));
        $this->assertNull(Alert::query()->sole()->notified_at);
    }

    public function test_channel_pointing_at_a_secret_of_another_purpose_fails_closed_without_retry(): void
    {
        Institution::factory()->create();
        $telegram = $this->addTelegramChannel();
        $smtp = $this->addSmtpChannel();
        // Penyerang berhak tulis DB mengarahkan kanal Telegram ke kata sandi SMTP (ADR 0003 §2.5).
        NotificationChannel::query()->whereKey($telegram->id)->update(['secret_id' => $smtp->secret_id]);
        $this->telegramAccepts();

        $raised = $this->raise();

        Http::assertNothingSent();
        Sleep::assertNeverSlept();
        $this->assertSame([$smtp->id], $raised->report?->delivered);
        $this->assertArrayHasKey($telegram->id, $raised->report->failed);
        $this->assertSame(['alert_notify_failed'], $this->loggedMessages('critical'));
    }

    public function test_unresolved_alert_is_resent_as_a_reminder_after_24_hours(): void
    {
        // Review F-04c SEDANG-4: kerusakan sesudah kerusakan pertama tak membuka alert baru, jadi insidennya diingatkan.
        // Presisi detik: kolom timestamptz(0) menyimpan per detik.
        $this->freezeSecond();
        Institution::factory()->create();
        $this->addTelegramChannel();
        $this->telegramAccepts();

        $first = $this->raise();
        $this->travel(23)->hours();
        $quiet = $this->raise();
        $this->travel(2)->hours();
        $reminder = $this->raise();

        $this->assertTrue($quiet->alreadyNotified);
        $this->assertFalse($reminder->alreadyNotified);
        $this->assertTrue($reminder->reminder);
        $this->assertTrue($reminder->delivered());
        $this->assertSame($first->alertId, $reminder->alertId);
        Http::assertSentCount(2);
        $this->assertSame(1, Alert::query()->count());
        $this->assertTrue(Alert::query()->sole()->notified_at->equalTo(now()));
        $notifies = array_map(fn (object $row): array => json_decode($row->params_redacted, true), $this->auditEntries('alert.notify'));
        $this->assertEquals([['delivered' => 1, 'failed' => 0, 'reminder' => false], ['delivered' => 1, 'failed' => 0, 'reminder' => true]], $notifies);
        $this->assertCount(1, $this->auditEntries('alert.open'));
    }

    public function test_busy_lock_is_waited_for_a_bounded_time_then_delivery_goes_ahead(): void
    {
        // Review F-04c SEDANG-2: sesi lain (atau pengirim yang macet) memegang kunci kejadian ini.
        Institution::factory()->create();
        $this->addTelegramChannel();
        $this->telegramAccepts();
        config(['database.connections.pgsql_pemegang_kunci' => config('database.connections.pgsql')]);
        $holder = DB::connection('pgsql_pemegang_kunci');
        $holder->select('SELECT pg_advisory_lock(?, hashtext(?))', [RaiseIntegrityAlert::LOCK_CLASS, 'audit_mismatch:seq:57']);

        try {
            $raised = $this->raise();
        } finally {
            $holder->select('SELECT pg_advisory_unlock_all()');
            DB::disconnect('pgsql_pemegang_kunci');
        }

        $this->assertTrue($raised->delivered());
        Sleep::assertSleptTimes(RaiseIntegrityAlert::LOCK_ATTEMPTS - 1);
        $this->assertSame(['alert_lock_busy'], $this->loggedMessages('warning'));
        $this->assertSame(0, $this->advisoryLocks());
    }

    public function test_unexpected_error_on_one_channel_never_stops_the_others(): void
    {
        // Review F-04c SEDANG-3: rahasia kanal pertama dihancurkan, config kanal kedua rusak.
        Institution::factory()->create();
        $destroyed = $this->addTelegramChannel('-1001');
        $broken = $this->addSmtpChannel();
        $healthy = $this->addTelegramChannel('-1003');
        app(DestroySecret::class)->handle($destroyed->secret_id, ActorType::LocalRoot, null);
        DB::table('notification_channels')->where('id', $broken->id)->update(['config' => '{"host": "smtp.contoh-instansi.test"}']);
        $this->telegramAccepts();

        $raised = $this->raise();

        $this->assertSame([$healthy->id], $raised->report?->delivered);
        $this->assertArrayHasKey($destroyed->id, $raised->report->failed);
        $this->assertArrayHasKey($broken->id, $raised->report->failed);
        $this->assertNotNull(Alert::query()->sole()->notified_at);
    }

    public function test_telegram_channels_are_tried_before_smtp(): void
    {
        Institution::factory()->create();
        $smtp = $this->addSmtpChannel();
        $telegram = $this->addTelegramChannel();
        $this->telegramAccepts();

        $raised = $this->raise();

        $this->assertSame([$telegram->id, $smtp->id], $raised->report?->delivered);
    }

    public function test_message_has_the_three_parts_of_docs_14_and_the_correlation_id(): void
    {
        Institution::factory()->create(['console_hostname' => 'sadmin.instansi-uji.test']);
        $this->addTelegramChannel();
        $this->addSmtpChannel();
        $this->telegramAccepts();

        $raised = $this->raise(IntegrityAlert::checkpointRefused(57, 'hash entri seq 57 berbeda dengan checkpoint'));

        $expected = "[CRITICAL] sAdmin sadmin.instansi-uji.test: Audit tidak utuh\n"
            ."Langkah: Pembuatan checkpoint audit (sadmin:audit-checkpoint)\n"
            ."Penyebab: kerusakan terdeteksi pada seq 57: hash entri seq 57 berbeda dengan checkpoint.\n"
            .'Tindakan: jangan ubah data apa pun; perlakukan sebagai insiden keamanan, jalankan sadmin:audit-verify, dan bandingkan dengan jangkar audit di agen/offsite.'."\n"
            ."(ID: {$raised->alertId})";
        $subject = '[sAdmin][CRITICAL] Audit tidak utuh — sadmin.instansi-uji.test';

        Http::assertSent(fn (Request $request): bool => $request['text'] === "{$subject}\n\n{$expected}" && ! isset($request['parse_mode']));
        [$email] = $this->sentEmails();
        $this->assertSame($subject, $email->getSubject());
        $this->assertSame($expected, $email->getTextBody());
    }

    public function test_long_reason_is_truncated(): void
    {
        Institution::factory()->create();

        $this->raise(IntegrityAlert::chainBroken(3, str_repeat('x', 5000)));

        $this->assertSame(IntegrityAlert::MAX_REASON, mb_strlen(Alert::query()->sole()->detail['reason']));
    }

    public function test_seq_below_one_is_treated_as_unknown_not_a_crash(): void
    {
        $alert = IntegrityAlert::chainBroken(0, 'seq tak dikenal');

        $this->assertNull($alert->seq);
        $this->assertSame('audit_mismatch:chain', $alert->dedupKey());
    }
}
