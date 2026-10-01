<?php

namespace Tests\Feature\Alerts;

use App\Infrastructure\Notify\NotificationMessage;
use App\Infrastructure\Notify\NotifyFailed;
use App\Infrastructure\Notify\SmtpNotifier;
use App\Infrastructure\Notify\SmtpTransportFactory;
use App\Infrastructure\Notify\TelegramNotifier;
use App\Models\Institution;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use LogicException;
use RuntimeException;
use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mailer\Transport\Smtp\Stream\SocketStream;
use Tests\Support\InteractsWithNotify;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** Adaptor Notify (ADR 0005 §2.4–2.6): bentuk permintaan, TLS wajib, dan galat yang dibersihkan. */
class NotifierTest extends TestCase
{
    use InteractsWithNotify, InteractsWithVault, RefreshDatabase;

    private NotificationMessage $message;

    protected function setUp(): void
    {
        parent::setUp();

        Institution::factory()->create();
        $this->message = new NotificationMessage('[sAdmin][CRITICAL] Uji — host', "Baris satu <b>bukan markup</b>\nBaris dua");
    }

    public function test_telegram_posts_plain_text_to_the_bot_api_with_the_vault_token(): void
    {
        $token = self::telegramToken();
        $channel = $this->addTelegramChannel('@kanal_sadmin', $token);
        $this->telegramAccepts();

        app(TelegramNotifier::class)->send($channel, $this->message, 7.5);

        Http::assertSentCount(1);
        Http::assertSent(function (Request $request) use ($token): bool {
            return $request->method() === 'POST'
                && $request->url() === "https://api.telegram.org/bot{$token}/sendMessage"
                && $request->isJson()
                && $request->data() === [
                    'chat_id' => '@kanal_sadmin',
                    'text' => "[sAdmin][CRITICAL] Uji — host\n\nBaris satu <b>bukan markup</b>\nBaris dua",
                    'disable_web_page_preview' => true,
                ];
        });
    }

    public function test_telegram_rejection_is_a_failure_with_the_api_description(): void
    {
        $channel = $this->addTelegramChannel();
        Http::fake(['api.telegram.org/*' => Http::response(['ok' => false, 'description' => 'Bad Request: chat not found'], 400)]);

        $this->expectException(NotifyFailed::class);
        $this->expectExceptionMessage('Telegram menolak: HTTP 400 Bad Request: chat not found');

        app(TelegramNotifier::class)->send($channel, $this->message, 10);
    }

    public function test_telegram_ok_false_with_http_200_is_still_a_failure(): void
    {
        $channel = $this->addTelegramChannel();
        Http::fake(['api.telegram.org/*' => Http::response(['ok' => false], 200)]);

        $this->expectException(NotifyFailed::class);

        app(TelegramNotifier::class)->send($channel, $this->message, 10);
    }

    public function test_telegram_connection_error_never_carries_the_token_or_the_original_exception(): void
    {
        $token = self::telegramToken();
        $channel = $this->addTelegramChannel(token: $token);
        Http::fake(['api.telegram.org/*' => Http::failedConnection()]);

        try {
            app(TelegramNotifier::class)->send($channel, $this->message, 10);
            $this->fail('Koneksi gagal seharusnya NotifyFailed.');
        } catch (NotifyFailed $e) {
            $this->assertStringNotContainsString($token, $e->getMessage());
            $this->assertStringNotContainsString(explode(':', $token)[1], $e->getMessage());
            $this->assertStringContainsString('/bot[disamarkan]', $e->getMessage());
            $this->assertNull($e->getPrevious(), 'Galat asli memuat URL bertoken; tak boleh dirantai.');
        }
    }

    public function test_percent_encoded_token_in_an_error_url_is_still_scrubbed(): void
    {
        $token = self::telegramToken();
        $encoded = rawurlencode($token);
        $this->assertNotSame($token, $encoded);

        $failure = NotifyFailed::scrubbed("cURL error 28: timeout for https://api.telegram.org/bot{$encoded}/sendMessage", [$token]);

        $this->assertStringNotContainsString(explode(':', $token)[1], $failure->getMessage());
        $this->assertStringContainsString('/bot[disamarkan]/sendMessage', $failure->getMessage());
    }

    public function test_starttls_channel_requires_tls_and_sends_plain_text_email(): void
    {
        $secret = self::smtpPassword();
        $channel = $this->addSmtpChannel(['port' => 587, 'tls' => 'starttls'], password: $secret);

        app(SmtpNotifier::class)->send($channel, $this->message, 9.5);

        $this->assertCount(1, $this->smtpConfigs);
        $this->assertSame([
            'transport' => 'smtp',
            'scheme' => 'smtp',
            'host' => 'smtp.contoh-instansi.test',
            'port' => 587,
            'username' => 'sadmin@contoh-instansi.test',
            'password' => $secret,
            'timeout' => 9.5,
            'require_tls' => true,
        ], $this->smtpConfigs[0]);

        [$email] = $this->sentEmails();
        $this->assertSame('sadmin@contoh-instansi.test', $email->getFrom()[0]->getAddress());
        $this->assertSame('sAdmin', $email->getFrom()[0]->getName());
        $this->assertSame(['admin@contoh-instansi.test', 'saksi@contoh-instansi.test'], array_map(fn ($a) => $a->getAddress(), $email->getTo()));
        $this->assertSame('[sAdmin][CRITICAL] Uji — host', $email->getSubject());
        $this->assertSame("Baris satu <b>bukan markup</b>\nBaris dua", $email->getTextBody());
        $this->assertNull($email->getHtmlBody());
    }

    public function test_implicit_tls_channel_uses_smtps(): void
    {
        $channel = $this->addSmtpChannel(['port' => 465, 'tls' => 'implicit']);

        app(SmtpNotifier::class)->send($channel, $this->message, 10);

        $this->assertSame('smtps', $this->smtpConfigs[0]['scheme']);
        $this->assertFalse($this->smtpConfigs[0]['require_tls']);
    }

    public function test_real_factory_builds_an_encrypted_esmtp_transport_through_the_sendmail_guard(): void
    {
        $factory = new SmtpTransportFactory($this->app);

        $starttls = $factory->create(['transport' => 'smtp', 'scheme' => 'smtp', 'host' => 'smtp.contoh.test', 'port' => 587, 'username' => 'u', 'password' => 'p', 'timeout' => 4.0, 'require_tls' => true])->getSymfonyTransport();
        $this->assertInstanceOf(EsmtpTransport::class, $starttls);
        $this->assertTrue($starttls->isTlsRequired());
        $stream = $starttls->getStream();
        $this->assertInstanceOf(SocketStream::class, $stream);
        $this->assertSame(4.0, $stream->getTimeout());
        $this->assertFalse($stream->isTLS());

        $implicit = $factory->create(['transport' => 'smtp', 'scheme' => 'smtps', 'host' => 'smtp.contoh.test', 'port' => 465, 'username' => 'u', 'password' => 'p', 'timeout' => 4.0, 'require_tls' => false])->getSymfonyTransport();
        $this->assertInstanceOf(EsmtpTransport::class, $implicit);
        $implicitStream = $implicit->getStream();
        $this->assertInstanceOf(SocketStream::class, $implicitStream);
        $this->assertTrue($implicitStream->isTLS());

        $this->expectException(LogicException::class);
        $factory->create(['transport' => 'sendmail', 'path' => '/usr/sbin/sendmail -bs']);
    }

    public function test_smtp_failure_is_scrubbed_of_the_password_and_not_chained(): void
    {
        $canary = self::smtpPassword('KANARI');
        $channel = $this->addSmtpChannel(password: $canary);
        $this->smtpFailure = function (array $config): never {
            throw new RuntimeException("Gagal autentikasi {$config['username']} dengan {$config['password']}");
        };

        try {
            app(SmtpNotifier::class)->send($channel, $this->message, 10);
            $this->fail('Kegagalan SMTP seharusnya NotifyFailed.');
        } catch (NotifyFailed $e) {
            $this->assertStringNotContainsString($canary, $e->getMessage());
            $this->assertStringContainsString('[disamarkan]', $e->getMessage());
            $this->assertNull($e->getPrevious());
        }
    }
}
