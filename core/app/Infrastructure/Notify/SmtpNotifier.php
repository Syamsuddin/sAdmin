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
        $password = $this->vault->reveal($channel->secret_id, SecretPurpose::Smtp, $channel->tenant_id);
        $implicitTls = false;

        try {
            $config = $channel->config;
            $implicitTls = $config['tls'] === 'implicit';
            $mailer = $this->transports->create([
                'transport' => 'smtp',
                'scheme' => $implicitTls ? 'smtps' : 'smtp',
                'host' => (string) $config['host'],
                'port' => (int) $config['port'],
                'username' => (string) $config['username'],
                'password' => $password->expose(),
                // Timeout per pembacaan soket, bukan batas total (ADR 0005 §2.3).
                'timeout' => $timeoutSeconds,
                'require_tls' => ! $implicitTls,
            ]);

            $sent = $mailer->raw($message->body, function (Message $mail) use ($config, $message): void {
                $mail->from((string) $config['from'], 'sAdmin')
                    ->to(array_map('strval', (array) $config['to']))
                    ->subject($message->subject);
            });
        } catch (Throwable $e) {
            throw NotifyFailed::from($e, [$password->expose()]);
        }

        if ($sent === null) {
            throw NotifyFailed::scrubbed('Pengiriman email dibatalkan sebelum terkirim.', []);
        }
        // require_tls Symfony terlewati bila server menolak EHLO lalu menerima HELO: kiriman polos tanpa STARTTLS.
        // Kiriman seperti itu dihitung gagal agar tak menjadi bukti kirim palsu (ADR 0005 §2.5).
        if (! $implicitTls && ! self::startTlsNegotiated((string) $sent->getDebug())) {
            throw NotifyFailed::scrubbed('Server SMTP tidak terbukti memakai STARTTLS; kiriman dianggap gagal.', []);
        }
    }

    /**
     * Transkrip Symfony mencatat `> STARTTLS` lalu `< 220` hanya bila server menerima STARTTLS; jabat tangan TLS
     * yang gagal sesudahnya sudah melempar galat sebelum pesan terkirim.
     */
    public static function startTlsNegotiated(string $transcript): bool
    {
        return preg_match('/^\[[^\]\n]*\] > STARTTLS\r?\n\[[^\]\n]*\] < 220[ -]/m', $transcript) === 1;
    }
}
