<?php

namespace Tests\Feature\Alerts;

use App\Models\Alert;
use App\Models\Institution;
use App\Models\NotificationChannel;
use App\Models\Secret;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;
use Tests\Support\InteractsWithNotify;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** `sadmin:notify-channel-add` dan `sadmin:notify-test` (ADR 0005 §2.5, docs/11). */
class NotificationChannelCommandsTest extends TestCase
{
    use InteractsWithNotify, InteractsWithVault, RefreshDatabase;

    private const SMTP_OPTIONS = [
        'kind' => 'smtp',
        '--host' => 'smtp.contoh-instansi.test',
        '--port' => '465',
        '--tls' => 'implicit',
        '--username' => 'sadmin@contoh-instansi.test',
        '--from' => 'sadmin@contoh-instansi.test',
        '--to' => ['admin@contoh-instansi.test', 'saksi@contoh-instansi.test'],
    ];

    protected function setUp(): void
    {
        parent::setUp();

        Sleep::fake();
    }

    private function auditRows(string $actionKey): array
    {
        return DB::table('audit_entries')->where('action_key', $actionKey)->get()->all();
    }

    public function test_adds_a_telegram_channel_with_the_token_in_the_vault_only(): void
    {
        Institution::factory()->create();
        $token = self::telegramToken();

        $this->artisan('sadmin:notify-channel-add', ['kind' => 'telegram', '--chat-id' => '-1001234567890'])
            ->expectsQuestion('Token bot Telegram', $token)
            ->expectsOutputToContain('Kanal telegram')
            ->expectsOutputToContain('sadmin:notify-test')
            ->assertExitCode(0);

        $channel = NotificationChannel::query()->sole();
        $this->assertSame('telegram', $channel->kind->value);
        $this->assertSame('active', $channel->status->value);
        $this->assertSame(['chat_id' => '-1001234567890'], $channel->config);
        $this->assertSame('telegram_token', Secret::query()->findOrFail($channel->secret_id)->purpose->value);

        [$create] = $this->auditRows('notification_channel.create');
        $this->assertSame('local_root', $create->actor_type);
        $this->assertSame("notification_channel:{$channel->id}", $create->target);
        $this->assertSame(['kind' => 'telegram'], json_decode($create->params_redacted, true));
        $this->assertCount(1, $this->auditRows('secret.store'));

        // Data pribadi (chat ID) tak masuk audit yang tak bisa dihapus.
        $this->assertStringNotContainsString('1001234567890', DB::table('audit_entries')->get()->toJson());
    }

    public function test_adds_an_smtp_channel_with_normalized_config(): void
    {
        Institution::factory()->create();

        $this->artisan('sadmin:notify-channel-add', self::SMTP_OPTIONS)
            ->expectsQuestion('Kata sandi SMTP', self::smtpPassword())
            ->assertExitCode(0);

        $channel = NotificationChannel::query()->sole();
        $this->assertEquals([
            'host' => 'smtp.contoh-instansi.test',
            'port' => 465,
            'tls' => 'implicit',
            'username' => 'sadmin@contoh-instansi.test',
            'from' => 'sadmin@contoh-instansi.test',
            'to' => ['admin@contoh-instansi.test', 'saksi@contoh-instansi.test'],
        ], $channel->config);
        $this->assertSame(465, $channel->config['port']);
        $this->assertSame('smtp', Secret::query()->findOrFail($channel->secret_id)->purpose->value);
        $this->assertStringNotContainsString('contoh-instansi.test', DB::table('audit_entries')->get()->toJson());
    }

    public function test_invalid_options_are_rejected_before_any_secret_is_asked_or_stored(): void
    {
        Institution::factory()->create();

        $this->artisan('sadmin:notify-channel-add', ['kind' => 'telegram', '--chat-id' => 'grup sadmin'])
            ->expectsOutputToContain('ID chat Telegram tidak sah.')
            ->assertExitCode(1);

        $this->artisan('sadmin:notify-channel-add', array_merge(self::SMTP_OPTIONS, ['--port' => '70000', '--tls' => 'none', '--to' => ['bukan-email']]))
            ->expectsOutputToContain('port SMTP harus antara 1 dan 65535.')
            ->expectsOutputToContain('mode TLS harus salah satu dari: implicit, starttls.')
            ->expectsOutputToContain('alamat penerima bukan alamat email yang sah.')
            ->assertExitCode(1);

        $this->assertSame(0, NotificationChannel::query()->count());
        $this->assertSame(0, Secret::query()->count());
        $this->assertSame(0, DB::table('audit_entries')->count());
    }

    public function test_invalid_telegram_token_is_rejected_and_nothing_is_stored(): void
    {
        Institution::factory()->create();

        $this->artisan('sadmin:notify-channel-add', ['kind' => 'telegram', '--chat-id' => '@kanal_sadmin'])
            ->expectsQuestion('Token bot Telegram', 'bukan-token-bot')
            ->expectsOutputToContain('Token bot Telegram tidak sah')
            ->doesntExpectOutputToContain('bukan-token-bot')
            ->assertExitCode(1);

        $this->assertSame(0, Secret::query()->count());
        $this->assertSame(0, NotificationChannel::query()->count());
    }

    public function test_empty_secret_and_unknown_kind_are_refused(): void
    {
        Institution::factory()->create();

        $this->artisan('sadmin:notify-channel-add', ['kind' => 'telegram', '--chat-id' => '12345'])
            ->expectsQuestion('Token bot Telegram', '')
            ->expectsOutputToContain('jalankan perintah ini secara interaktif')
            ->assertExitCode(1);

        $this->artisan('sadmin:notify-channel-add', ['kind' => 'whatsapp'])
            ->expectsOutputToContain('Jenis kanal harus telegram atau smtp.')
            ->assertExitCode(1);

        $this->assertSame(0, NotificationChannel::query()->count());
    }

    public function test_adding_a_channel_requires_an_institution(): void
    {
        $this->artisan('sadmin:notify-channel-add', ['kind' => 'telegram', '--chat-id' => '12345'])
            ->expectsQuestion('Token bot Telegram', self::telegramToken())
            ->expectsOutputToContain('Instansi belum diinisialisasi')
            ->assertExitCode(1);

        $this->assertSame(0, Secret::query()->count());
    }

    public function test_notify_test_reaches_every_active_channel_without_opening_an_alert(): void
    {
        Institution::factory()->create();
        $telegram = $this->addTelegramChannel();
        $smtp = $this->addSmtpChannel();
        $this->telegramAccepts();
        $auditCount = DB::table('audit_entries')->count();

        $this->artisan('sadmin:notify-test')
            ->expectsOutputToContain("OK     telegram {$telegram->id}")
            ->expectsOutputToContain("OK     smtp {$smtp->id}")
            ->assertExitCode(0);

        Http::assertSent(fn (Request $request): bool => str_contains((string) $request['text'], 'Pesan uji dari sAdmin sadmin.localhost'));
        $this->assertCount(1, $this->sentEmails());
        $this->assertSame(0, Alert::query()->count());
        $this->assertSame($auditCount, DB::table('audit_entries')->count());
    }

    public function test_notify_test_reports_each_failing_channel(): void
    {
        Institution::factory()->create();
        $telegram = $this->addTelegramChannel();
        $smtp = $this->addSmtpChannel();
        Http::fake(['api.telegram.org/*' => Http::response(['ok' => false, 'description' => 'Unauthorized'], 401)]);

        $this->artisan('sadmin:notify-test')
            ->expectsOutputToContain("GAGAL  telegram {$telegram->id}: Telegram menolak: HTTP 401 Unauthorized")
            ->expectsOutputToContain("OK     smtp {$smtp->id}")
            ->assertExitCode(1);
    }

    public function test_notify_test_without_channels_fails(): void
    {
        Institution::factory()->create();

        $this->artisan('sadmin:notify-test')
            ->expectsOutputToContain('Belum ada kanal notifikasi aktif')
            ->assertExitCode(1);
        Http::assertNothingSent();
    }
}
