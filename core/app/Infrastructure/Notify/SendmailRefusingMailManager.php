<?php

namespace App\Infrastructure\Notify;

use Illuminate\Mail\MailManager;
use LogicException;
use ReflectionProperty;
use Symfony\Component\Mailer\Transport\RoundRobinTransport;
use Symfony\Component\Mailer\Transport\SendmailTransport;

/**
 * MailManager yang menolak transport apa pun yang berujung SendmailTransport, karena transport itu
 * menjalankan biner OS lewat proc_open (docs/09, keputusan 1A). Yang diperiksa objek hasil, bukan nama:
 * `sendmail`, `mail`, huruf kapital, `MAIL_URL`, failover, creator kustom, dan Mail::build() semuanya lewat
 * createSymfonyTransport(). Membangun objeknya belum menjalankan proses; proc_open baru terjadi saat mengirim.
 */
final class SendmailRefusingMailManager extends MailManager
{
    /** @param  array<string, mixed>  $config */
    public function createSymfonyTransport(array $config)
    {
        $transport = parent::createSymfonyTransport($config);

        if (self::containsSendmail($transport)) {
            throw new LogicException('Transport mail sendmail dilarang di core (docs/09): pakai SMTP.');
        }

        return $transport;
    }

    /**
     * Failover/roundrobin menyimpan transport anak di properti privat; sendmail bisa bersembunyi di sana.
     * Bila Symfony mengganti nama properti itu, ReflectionException membuat pengiriman gagal-tertutup.
     */
    private static function containsSendmail(object $transport): bool
    {
        if ($transport instanceof SendmailTransport) {
            return true;
        }

        if ($transport instanceof RoundRobinTransport) {
            foreach ((new ReflectionProperty(RoundRobinTransport::class, 'transports'))->getValue($transport) as $child) {
                if (self::containsSendmail($child)) {
                    return true;
                }
            }
        }

        return false;
    }
}
