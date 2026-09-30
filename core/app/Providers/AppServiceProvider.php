<?php

namespace App\Providers;

use Illuminate\Mail\MailManager;
use Illuminate\Support\ServiceProvider;
use LogicException;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Transport sendmail menjalankan biner OS lewat proc_open (docs/09, keputusan 1A). Pencipta kustom
        // diperiksa MailManager sebelum transport bawaan, jadi config maupun MAIL_URL tak bisa mengaktifkannya.
        $this->callAfterResolving('mail.manager', static function (MailManager $mail): void {
            $mail->extend('sendmail', static function (): never {
                throw new LogicException('Transport mail sendmail dilarang di core (docs/09): pakai SMTP.');
            });
        });
    }
}
