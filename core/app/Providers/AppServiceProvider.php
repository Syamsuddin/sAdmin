<?php

namespace App\Providers;

use App\Infrastructure\Notify\SendmailRefusingMailManager;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Mail\MailManager;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Keputusan 1A (docs/09): semua pengiriman mail lewat MailManager yang menolak SendmailTransport.
        $this->app->extend('mail.manager', static fn (MailManager $manager, Application $app): MailManager => new SendmailRefusingMailManager($app));
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
