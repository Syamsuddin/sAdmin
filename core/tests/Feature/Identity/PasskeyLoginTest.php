<?php

namespace Tests\Feature\Identity;

use App\Http\Middleware\EnforceAbsoluteSessionLifetime;
use App\Livewire\Auth\Login;
use App\Models\Admin;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\InteractsWithPasskeys;
use Tests\Support\VirtualAuthenticator;
use Tests\TestCase;

class PasskeyLoginTest extends TestCase
{
    use InteractsWithPasskeys, RefreshDatabase;

    private Admin $admin;

    private VirtualAuthenticator $key;

    protected function setUp(): void
    {
        parent::setUp();
        RateLimiter::clear('passkey-login:127.0.0.1');
        $this->setUpInstitution();
        $this->admin = $this->newAdmin();
        $this->key = VirtualAuthenticator::eddsa();
        $this->enroll($this->admin, $this->key);
    }

    private function rejections(): int
    {
        return DB::table('audit_entries')->where('action_key', 'console.login')->where('outcome', 'rejected')->count();
    }

    public function test_valid_passkey_logs_in_and_starts_an_absolute_session_clock(): void
    {
        $this->key->signCount = 5;
        $sessionBefore = session()->getId();

        $this->loginWith($this->key)->assertRedirect(route('home'));

        $this->assertTrue(Auth::check());
        $this->assertSame($this->admin->id, Auth::id());
        $this->assertNotSame($sessionBefore, session()->getId(), 'ID sesi wajib diregenerasi saat login.');
        $this->assertIsInt(session(EnforceAbsoluteSessionLifetime::STARTED_AT));
        $this->assertSame(5, $this->admin->authenticators()->value('sign_count'));
        $this->assertNotNull($this->admin->fresh()->last_login_at);
        $this->assertSame(1, DB::table('audit_entries')->where('action_key', 'console.login')->where('outcome', 'ok')->where('actor_id', $this->admin->id)->count());
    }

    public function test_es256_passkey_logs_in(): void
    {
        $other = $this->newAdmin();
        $ec = VirtualAuthenticator::es256('ec');
        $this->enroll($other, $ec);

        $this->loginWith($ec)->assertRedirect(route('home'));
        $this->assertSame($other->id, Auth::id());
    }

    /** @return iterable<string, array{callable(VirtualAuthenticator): void, string}> */
    public static function forgedAssertions(): iterable
    {
        yield 'origin palsu' => [static function (VirtualAuthenticator $a): void {
            $a->origin = 'https://jahat.example';
        }, 'verification_failed'];
        yield 'origin subdomain RP' => [static function (VirtualAuthenticator $a): void {
            $a->origin = 'https://jahat.sadmin.localhost';
        }, 'verification_failed'];
        yield 'origin tanpa TLS' => [static function (VirtualAuthenticator $a): void {
            $a->origin = 'http://sadmin.localhost';
        }, 'verification_failed'];
        yield 'RP ID palsu' => [static function (VirtualAuthenticator $a): void {
            $a->rpId = 'jahat.example';
        }, 'verification_failed'];
        yield 'tanpa verifikasi pengguna' => [static function (VirtualAuthenticator $a): void {
            $a->userVerified = false;
        }, 'verification_failed'];
        yield 'tanpa kehadiran pengguna' => [static function (VirtualAuthenticator $a): void {
            $a->userPresent = false;
        }, 'verification_failed'];
        yield 'tipe clientData webauthn.create' => [static function (VirtualAuthenticator $a): void {
            $a->clientDataType = 'webauthn.create';
        }, 'verification_failed'];
        yield 'lintas origin (iframe)' => [static function (VirtualAuthenticator $a): void {
            $a->crossOrigin = true;
        }, 'verification_failed'];
    }

    /** @param  callable(VirtualAuthenticator): void  $forge */
    #[DataProvider('forgedAssertions')]
    public function test_forged_assertion_is_rejected_and_audited(callable $forge, string $reason): void
    {
        $forge($this->key);

        $this->loginWith($this->key)->assertSet('errorReason', $reason)->assertSee('ID: ')->assertNoRedirect();

        $this->assertFalse(Auth::check());
        $this->assertSame(1, $this->rejections());
    }

    public function test_counter_going_backwards_is_rejected_as_a_cloned_authenticator(): void
    {
        $this->admin->authenticators()->update(['sign_count' => 10]);
        $this->key->signCount = 9;

        $this->loginWith($this->key)->assertSet('errorReason', 'verification_failed');
        $this->assertFalse(Auth::check());
    }

    public function test_assertion_claiming_another_admin_is_rejected(): void
    {
        $this->loginWith($this->key, $this->newAdmin()->id)->assertSet('errorReason', 'verification_failed');
        $this->assertFalse(Auth::check());
    }

    public function test_unknown_credential_is_rejected_with_an_anonymous_audit_entry(): void
    {
        $this->loginWith(VirtualAuthenticator::eddsa('asing')->ownedBy($this->admin->id))
            ->assertSet('errorReason', 'unknown_credential');

        $this->assertSame(1, DB::table('audit_entries')->where('action_key', 'console.login')->where('outcome', 'rejected')->whereNull('actor_id')->count());
    }

    public function test_revoked_passkey_and_disabled_admin_cannot_log_in(): void
    {
        $revoked = VirtualAuthenticator::eddsa('dicabut');
        $this->enroll($this->newAdmin(), $revoked, status: 'revoked');
        $this->loginWith($revoked)->assertSet('errorReason', 'unknown_credential');

        $this->admin->forceFill(['status' => 'disabled'])->save();
        $this->loginWith($this->key)->assertSet('errorReason', 'admin_inactive');

        $this->assertFalse(Auth::check());
    }

    public function test_answer_without_a_pending_challenge_is_rejected(): void
    {
        $page = Livewire::test(Login::class);
        $replayed = null;
        $this->ceremony($page, function (string $options) use (&$replayed): string {
            return $replayed = $this->key->assert($options);
        });
        Auth::logout();

        $page->call('complete', $replayed)->assertSet('errorReason', 'challenge_missing');
        $this->assertFalse(Auth::check());
    }

    public function test_login_attempts_are_limited_per_ip(): void
    {
        $this->key->origin = 'https://jahat.example';
        for ($i = 0; $i < 10; $i++) {
            $this->loginWith($this->key)->assertSet('errorReason', 'verification_failed');
        }

        $this->key->origin = 'https://sadmin.localhost';
        $this->loginWith($this->key)->assertSet('errorReason', 'rate_limited');
        $this->assertFalse(Auth::check());
    }

    public function test_rate_limit_window_is_a_full_minute(): void
    {
        $this->key->origin = 'https://jahat.example';
        for ($i = 0; $i < 10; $i++) {
            $this->loginWith($this->key);
        }
        $this->key->origin = 'https://sadmin.localhost';

        $this->travel(59)->seconds();
        $this->loginWith($this->key)->assertSet('errorReason', 'rate_limited');

        $this->travel(2)->seconds();
        $this->loginWith($this->key)->assertRedirect(route('home'));
    }

    public function test_rate_limit_is_counted_per_client_ip(): void
    {
        RateLimiter::clear('passkey-login:10.77.0.9');
        for ($i = 0; $i < 10; $i++) {
            RateLimiter::hit('passkey-login:10.77.0.9', 60);
        }

        $this->loginWith($this->key)->assertRedirect(route('home'));
        Auth::logout();

        for ($i = 0; $i < 10; $i++) {
            RateLimiter::hit('passkey-login:127.0.0.1', 60);
        }
        $this->loginWith($this->key)->assertSet('errorReason', 'rate_limited');
    }

    public function test_challenge_expires_after_five_minutes(): void
    {
        $this->ceremony(Livewire::test(Login::class), function (string $options): string {
            $this->travel(301)->seconds();

            return $this->key->assert($options);
        })->assertSet('errorReason', 'challenge_missing');

        $this->assertFalse(Auth::check());
    }

    public function test_correlation_id_links_the_screen_the_log_and_the_audit_entry(): void
    {
        $details = [];
        Log::listen(function ($event) use (&$details): void {
            if ($event->message === 'passkey_login_rejected') {
                $details[] = $event->context;
            }
        });
        $this->key->origin = 'https://jahat.example';

        $shown = $this->loginWith($this->key)->get('correlationId');

        $this->assertNotEmpty($shown);
        $this->assertSame($shown, $details[0]['correlation_id'] ?? null);
        $this->assertStringContainsString('origin', strtolower($details[0]['detail']));
        $audit = DB::table('audit_entries')->where('action_key', 'console.login')->where('outcome', 'rejected')->value('params_redacted');
        $this->assertSame($shown, json_decode($audit, true)['correlation_id']);
    }

    public function test_browser_errors_map_to_fixed_reasons_and_are_never_echoed(): void
    {
        Livewire::test(Login::class)
            ->call('clientFailed', '<script>alert(1)</script>')
            ->assertSet('errorReason', 'cancelled')
            ->assertDontSee('<script>alert(1)</script>', false)
            ->call('clientFailed', 'NotSupportedError')
            ->assertSet('errorReason', 'unsupported');
    }
}
