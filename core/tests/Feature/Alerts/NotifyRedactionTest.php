<?php

namespace Tests\Feature\Alerts;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;
use Tests\Support\InteractsWithAuditChain;
use Tests\Support\InteractsWithNotify;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/**
 * docs/13 grup redaksi, ADR 0005 §2.6: token bot dan kata sandi SMTP tak pernah muncul di keluaran perintah, log,
 * audit, baris alert, atau config kanal, termasuk ketika pustaka HTTP/SMTP menggemakannya di pesan galat.
 */
#[Group('redaction')]
class NotifyRedactionTest extends TestCase
{
    use InteractsWithAuditChain, InteractsWithNotify, InteractsWithVault, RefreshDatabase;

    private string $token;

    private string $tokenSecretPart;

    private string $password;

    /** @var list<array{string, string, array<string, mixed>}> */
    private array $logged = [];

    protected function setUp(): void
    {
        parent::setUp();

        Sleep::fake();
        $this->token = self::telegramToken('KANARI');
        $this->tokenSecretPart = explode(':', $this->token)[1];
        $this->password = self::smtpPassword('KANARI');
        Log::listen(function (MessageLogged $event): void {
            $this->logged[] = [$event->level, $event->message, $event->context];
        });
    }

    private function assertNoSecretAnywhere(): void
    {
        $haystacks = [
            'log' => (string) json_encode($this->logged, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            'audit_entries' => DB::table('audit_entries')->get()->toJson(),
            'alerts' => DB::table('alerts')->get()->toJson(),
            'alert_rules' => DB::table('alert_rules')->get()->toJson(),
            'notification_channels' => DB::table('notification_channels')->get()->toJson(),
        ];

        foreach ($haystacks as $where => $text) {
            $this->assertStringNotContainsString($this->tokenSecretPart, $text, "Token bot bocor ke {$where}.");
            $this->assertStringNotContainsString($this->password, $text, "Kata sandi SMTP bocor ke {$where}.");
        }
    }

    public function test_secrets_survive_channel_setup_failing_delivery_and_notify_test_without_leaking(): void
    {
        $this->artisan('sadmin:notify-channel-add', ['kind' => 'telegram', '--chat-id' => '-1001234567890'])
            ->expectsQuestion('Token bot Telegram', $this->token)
            ->doesntExpectOutputToContain($this->tokenSecretPart)
            ->assertExitCode(0);
        $this->artisan('sadmin:notify-channel-add', [
            'kind' => 'smtp', '--host' => 'smtp.contoh-instansi.test', '--port' => '587', '--tls' => 'starttls',
            '--username' => 'sadmin@contoh-instansi.test', '--from' => 'sadmin@contoh-instansi.test', '--to' => ['admin@contoh-instansi.test'],
        ])
            ->expectsQuestion('Kata sandi SMTP', $this->password)
            ->doesntExpectOutputToContain($this->password)
            ->assertExitCode(0);

        // Galat cURL asli memuat URL Bot API lengkap dengan token; server SMTP menggemakan kata sandi.
        Http::fake(['api.telegram.org/*' => Http::failedConnection()]);
        $this->smtpFailure = function (array $config): never {
            throw new RuntimeException("535 Authentication failed for {$config['username']} / {$config['password']}");
        };

        $this->appendEntries(20);
        $this->tamperEntries(fn () => DB::table('audit_entries')->where('seq', 12)->update(['target' => 'site:palsu']));

        $this->artisan('sadmin:audit-verify')
            ->doesntExpectOutputToContain($this->tokenSecretPart)
            ->doesntExpectOutputToContain($this->password)
            ->assertExitCode(1);
        $this->artisan('sadmin:notify-test')
            ->expectsOutputToContain('/bot[disamarkan]')
            ->doesntExpectOutputToContain($this->tokenSecretPart)
            ->doesntExpectOutputToContain($this->password)
            ->assertExitCode(1);

        $this->assertNoSecretAnywhere();

        // Pembersihan benar-benar terjadi, bukan sekadar galat yang kebetulan tak memuat rahasia.
        $failures = array_values(array_filter($this->logged, fn (array $log): bool => $log[1] === 'alert_notify_failed'));
        $this->assertNotSame([], $failures);
        $errors = implode("\n", array_map(fn (array $log): string => (string) $log[2]['error'], $failures));
        $this->assertStringContainsString('/bot[disamarkan]', $errors);
        $this->assertStringContainsString('535 Authentication failed for sadmin@contoh-instansi.test / [disamarkan]', $errors);
    }
}
