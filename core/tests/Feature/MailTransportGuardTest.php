<?php

namespace Tests\Feature;

use Closure;
use Illuminate\Support\Facades\Mail;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionProperty;
use Symfony\Component\Mailer\Transport\RoundRobinTransport;
use Symfony\Component\Mailer\Transport\SendmailTransport;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Tests\TestCase;

/**
 * Keputusan 1A: tak ada jalur konfigurasi yang boleh berujung SendmailTransport, yang menjalankan
 * biner OS lewat proc_open (docs/09). Setiap jalur yang ditemukan review adversarial punya kasus di sini.
 */
class MailTransportGuardTest extends TestCase
{
    /** @return iterable<string, array{Closure(): mixed}> */
    public static function sendmailRoutes(): iterable
    {
        yield 'mailer sendmail bawaan framework' => [static fn () => Mail::mailer('sendmail')];
        yield 'transport mail' => [static function () {
            config(['mail.mailers.jalan' => ['transport' => 'mail']]);

            return Mail::mailer('jalan');
        }];
        yield 'transport Sendmail kapital' => [static function () {
            config(['mail.mailers.jalan' => ['transport' => 'Sendmail']]);

            return Mail::mailer('jalan');
        }];
        yield 'kunci lama mail.driver' => [static function () {
            config(['mail.driver' => 'sendmail', 'mail.mailers.jalan' => []]);

            return Mail::mailer('jalan');
        }];
        foreach ([
            'MAIL_URL sendmail://' => 'sendmail://default',
            'MAIL_URL mail://' => 'mail://default',
            'MAIL_URL SENDMAIL://' => 'SENDMAIL://default',
            'MAIL_URL Sendmail:// dengan path' => 'Sendmail://default?path=/usr/bin/true%20-bs',
            'MAIL_URL native://' => 'native://default',
        ] as $label => $url) {
            yield $label => [static function () use ($url) {
                config(['mail.mailers.smtp.url' => $url]);
                Mail::purge('smtp');

                return Mail::mailer('smtp');
            }];
        }
        yield 'failover berisi mail' => [static function () {
            config([
                'mail.mailers.jalan' => ['transport' => 'mail'],
                'mail.mailers.cadangan' => ['transport' => 'failover', 'mailers' => ['log', 'jalan']],
            ]);

            return Mail::mailer('cadangan');
        }];
        yield 'Mail::build on-demand' => [static fn () => Mail::build(['transport' => 'mail'])];
    }

    #[DataProvider('sendmailRoutes')]
    public function test_no_route_yields_a_sendmail_transport(Closure $route): void
    {
        try {
            $mailer = $route();
        } catch (LogicException|InvalidArgumentException) {
            $this->addToAssertionCount(1);

            return;
        }

        $this->assertFalse(self::containsSendmail($mailer->getSymfonyTransport()), 'Jalur ini berujung SendmailTransport.');
    }

    /** @return iterable<string, array{string}> */
    public static function legitimateMailers(): iterable
    {
        yield 'smtp' => ['smtp'];
        yield 'log' => ['log'];
        yield 'array' => ['array'];
        yield 'failover bawaan' => ['failover'];
    }

    #[DataProvider('legitimateMailers')]
    public function test_legitimate_mailers_still_work(string $name): void
    {
        $this->assertFalse(self::containsSendmail(Mail::mailer($name)->getSymfonyTransport()));
    }

    /** Failover/roundrobin menyimpan transport anak secara privat; SendmailTransport bisa bersembunyi di sana. */
    private static function containsSendmail(TransportInterface $transport): bool
    {
        if ($transport instanceof SendmailTransport) {
            return true;
        }

        if ($transport instanceof RoundRobinTransport) {
            $children = (new ReflectionProperty(RoundRobinTransport::class, 'transports'))->getValue($transport);
            foreach ($children as $child) {
                if (self::containsSendmail($child)) {
                    return true;
                }
            }
        }

        return false;
    }
}
