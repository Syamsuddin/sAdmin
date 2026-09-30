<?php

namespace App\Infrastructure\Notify;

use Illuminate\Mail\MailManager;
use LogicException;
use Symfony\Component\Mailer\Transport\SendmailTransport;

/**
 * MailManager yang menolak transport apa pun yang berujung SendmailTransport, karena transport itu
 * menjalankan biner OS lewat proc_open (docs/09, keputusan 1A). Yang diperiksa objek hasil, bukan nama:
 * `sendmail`, `mail`, huruf kapital, `MAIL_URL`, `native://`, failover, dan Mail::build() semuanya lewat
 * createSymfonyTransport(). Membangun objeknya belum menjalankan proses; proc_open baru terjadi saat mengirim.
 */
final class SendmailRefusingMailManager extends MailManager
{
    /** @param  array<string, mixed>  $config */
    public function createSymfonyTransport(array $config)
    {
        $transport = parent::createSymfonyTransport($config);

        if ($transport instanceof SendmailTransport) {
            throw new LogicException('Transport mail sendmail dilarang di core (docs/09): pakai SMTP.');
        }

        return $transport;
    }
}
