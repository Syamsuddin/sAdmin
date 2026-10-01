<?php

namespace App\Infrastructure\Notify;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Mail\Mailer;
use Illuminate\Mail\MailManager;
use SensitiveParameter;

/**
 * Membangun mailer bertransport SMTP lewat `mail.manager` (SendmailRefusingMailManager, docs/09), sehingga jalur
 * sendmail tetap tertolak dan kode ini tak perlu menyentuh namespace transport Symfony yang dilarang pemindai.
 * Kelas tersendiri agar tes bisa menggantinya tanpa server SMTP.
 */
class SmtpTransportFactory
{
    public function __construct(private readonly Application $app) {}

    /** @param  array<string, mixed>  $config */
    public function create(#[SensitiveParameter] array $config): Mailer
    {
        /** @var MailManager $manager */
        $manager = $this->app->make('mail.manager');

        return $manager->build($config);
    }
}
