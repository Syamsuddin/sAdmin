<?php

namespace Tests\Support;

use App\Domain\Alerts\Actions\AddNotificationChannel;
use App\Domain\Alerts\Data\ChannelKind;
use App\Domain\Audit\Data\ActorType;
use App\Infrastructure\Notify\SmtpTransportFactory;
use App\Infrastructure\Vault\SecretValue;
use App\Models\NotificationChannel;
use Closure;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Mail\Mailer;
use Illuminate\Mail\MailManager;
use Illuminate\Mail\Transport\ArrayTransport;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use SensitiveParameter;
use Symfony\Component\Mime\Email;
use Tests\TestCase;

/**
 * Kanal notifikasi uji (ADR 0005 §2.5) lewat Action sungguhan dan brankas uji, Bot API Telegram palsu (Http::fake,
 * tanpa permintaan keluar), dan SMTP palsu yang mencatat konfigurasi transport lalu menampung email di memori.
 * Pakai bersama InteractsWithVault dan instansi yang sudah ada.
 */
trait InteractsWithNotify
{
    /** @var list<array<string, mixed>> konfigurasi transport SMTP yang diminta, termasuk kata sandi */
    public array $smtpConfigs = [];

    /** @var list<ArrayTransport> */
    public array $smtpTransports = [];

    /** Bila diisi, dipanggil dengan konfigurasi transport dan boleh melempar, meniru server SMTP yang menolak. */
    public ?Closure $smtpFailure = null;

    protected function setUpInteractsWithNotify(): void
    {
        Http::preventStrayRequests();
        $this->smtpConfigs = [];
        $this->smtpTransports = [];
        $this->smtpFailure = null;

        $this->app->instance(SmtpTransportFactory::class, new class($this->app, $this) extends SmtpTransportFactory
        {
            public function __construct(private readonly Application $application, private readonly TestCase $test)
            {
                parent::__construct($application);
            }

            public function create(#[SensitiveParameter] array $config): Mailer
            {
                $this->test->smtpConfigs[] = $config;
                if ($this->test->smtpFailure !== null) {
                    ($this->test->smtpFailure)($config);
                }
                /** @var MailManager $manager */
                $manager = $this->application->make('mail.manager');
                $mailer = $manager->build(['transport' => 'array']);
                $transport = $mailer->getSymfonyTransport();
                assert($transport instanceof ArrayTransport);
                $this->test->smtpTransports[] = $transport;

                return $mailer;
            }
        });
    }

    protected static function telegramToken(string $marker = ''): string
    {
        return '123456789:'.substr('AA'.$marker.Str::random(40), 0, 40);
    }

    /** Kata sandi SMTP palsu yang unik per tes; tak ada nilai rahasia tertulis di fixture (docs/20). */
    protected static function smtpPassword(string $marker = ''): string
    {
        return 'uji-'.$marker.Str::random(24);
    }

    protected function addTelegramChannel(string $chatId = '-1001234567890', #[SensitiveParameter] ?string $token = null): NotificationChannel
    {
        return app(AddNotificationChannel::class)->handle(
            ChannelKind::Telegram,
            ['chat_id' => $chatId],
            new SecretValue($token ?? self::telegramToken()),
            ActorType::LocalRoot,
            null,
        );
    }

    /** @param  array<string, mixed>  $overrides */
    protected function addSmtpChannel(array $overrides = [], #[SensitiveParameter] ?string $password = null): NotificationChannel
    {
        return app(AddNotificationChannel::class)->handle(
            ChannelKind::Smtp,
            array_merge([
                'host' => 'smtp.contoh-instansi.test',
                'port' => 587,
                'tls' => 'starttls',
                'username' => 'sadmin@contoh-instansi.test',
                'from' => 'sadmin@contoh-instansi.test',
                'to' => ['admin@contoh-instansi.test', 'saksi@contoh-instansi.test'],
            ], $overrides),
            new SecretValue($password ?? self::smtpPassword()),
            ActorType::LocalRoot,
            null,
        );
    }

    protected function telegramAccepts(): void
    {
        Http::fake(['api.telegram.org/*' => Http::response(['ok' => true, 'result' => ['message_id' => 1]])]);
    }

    /** @return list<Email> */
    protected function sentEmails(): array
    {
        $emails = [];
        foreach ($this->smtpTransports as $transport) {
            foreach ($transport->messages() as $sent) {
                $original = $sent->getOriginalMessage();
                assert($original instanceof Email);
                $emails[] = $original;
            }
        }

        return $emails;
    }

    /**
     * Pendeteksi integritas di tes tanpa kanal: alert tetap dibuka lalu gagal terkirim, dan itu harus tercatat
     * critical tepat sekali (ADR 0005 §2.3). Dipanggil SEBELUM ekspektasi critical lain di tes yang sama, karena
     * Mockery mencocokkan ekspektasi menurut urutan pendaftarannya.
     */
    protected function expectUndeliveredIntegrityAlert(): void
    {
        Log::shouldReceive('critical')->once()->withArgs(fn (string $message): bool => $message === 'alert_undelivered');
    }
}
