<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Mail;
use LogicException;
use Tests\TestCase;

/** Keputusan 1A: transport sendmail menjalankan biner OS lewat proc_open — terlarang (docs/09). */
class MailTransportGuardTest extends TestCase
{
    /**
     * Laravel menggabungkan config mail bawaan framework (yang memuat mailer `sendmail`) ke config aplikasi,
     * jadi menghapusnya dari config/mail.php saja tak cukup: yang diuji adalah tak ada yang bisa memakainya.
     */
    public function test_no_configured_mailer_can_send_through_sendmail(): void
    {
        $sendmailMailers = array_keys(array_filter(
            config('mail.mailers'),
            static fn (array $mailer): bool => ($mailer['transport'] ?? null) === 'sendmail',
        ));
        $this->assertNotEmpty($sendmailMailers, 'Prasyarat: config bawaan framework memang memuat mailer sendmail.');

        foreach ($sendmailMailers as $name) {
            try {
                Mail::mailer($name);
                $this->fail("Mailer [{$name}] seharusnya ditolak.");
            } catch (LogicException $e) {
                $this->assertStringContainsString('sendmail dilarang', $e->getMessage());
            }
        }
    }

    public function test_sendmail_transport_is_refused_even_when_configured_at_runtime(): void
    {
        config(['mail.mailers.jalan_pintas' => ['transport' => 'sendmail', 'path' => '/usr/sbin/sendmail -bs -i']]);

        $this->expectException(LogicException::class);

        Mail::mailer('jalan_pintas');
    }

    public function test_mail_url_cannot_switch_smtp_to_sendmail(): void
    {
        config(['mail.mailers.smtp.url' => 'sendmail://default']);
        Mail::purge('smtp');

        $this->expectException(LogicException::class);

        Mail::mailer('smtp');
    }
}
