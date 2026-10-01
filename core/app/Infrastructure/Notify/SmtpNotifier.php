<?php

namespace App\Infrastructure\Notify;

use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\Vault;
use App\Models\NotificationChannel;
use Illuminate\Mail\Message;
use Throwable;

/** Kirim email teks polos lewat SMTP instansi yang selalu terenkripsi (ADR 0005 §2.4–2.6). */
final class SmtpNotifier implements Notifier
{
    public function __construct(
        private readonly Vault $vault,
        private readonly SmtpTransportFactory $transports,
    ) {}

    public function send(NotificationChannel $channel, NotificationMessage $message, float $timeoutSeconds): void
    {
        $config = $channel->config;
        $password = $this->vault->reveal($channel->secret_id, SecretPurpose::Smtp, $channel->tenant_id);
        $implicitTls = $config['tls'] === 'implicit';

        try {
            $mailer = $this->transports->create([
                'transport' => 'smtp',
                'scheme' => $implicitTls ? 'smtps' : 'smtp',
                'host' => (string) $config['host'],
                'port' => (int) $config['port'],
                'username' => (string) $config['username'],
                'password' => $password->expose(),
                'timeout' => $timeoutSeconds,
                // STARTTLS wajib: tanpa ini Symfony diam-diam mengirim polos bila server tak menawarkan TLS.
                'require_tls' => ! $implicitTls,
            ]);

            $mailer->raw($message->body, function (Message $mail) use ($config, $message): void {
                $mail->from((string) $config['from'], 'sAdmin')
                    ->to(array_map('strval', (array) $config['to']))
                    ->subject($message->subject);
            });
        } catch (Throwable $e) {
            throw NotifyFailed::from($e, [$password->expose()]);
        }
    }
}
