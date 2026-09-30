<?php

namespace Tests\Feature\Identity;

use App\Http\Middleware\EnforceAbsoluteSessionLifetime;
use App\Models\Admin;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\URL;
use Tests\Support\InteractsWithPasskeys;
use Tests\TestCase;

/** docs/21: cookie Secure/HttpOnly/SameSite=Strict, idle 30 menit, absolut 12 jam, keluar tercatat. */
class ConsoleSessionTest extends TestCase
{
    use InteractsWithPasskeys, RefreshDatabase;

    private Admin $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpInstitution();
        $this->admin = $this->newAdmin();
    }

    public function test_session_cookie_is_hardened(): void
    {
        $this->assertTrue(config('session.secure'));
        $this->assertTrue(config('session.http_only'));
        $this->assertSame('strict', config('session.same_site'));
        $this->assertSame(30, config('session.lifetime'));
        $this->assertSame('', $this->admin->getRememberTokenName(), 'Tanpa "ingat saya".');
    }

    public function test_guests_are_sent_to_the_passkey_login(): void
    {
        $this->get('/pengaturan/passkey')->assertRedirect(route('login'));
        $this->get(route('login'))->assertOk()->assertSee('Masuk dengan passkey');
    }

    public function test_session_within_twelve_hours_stays_valid(): void
    {
        $this->actingAs($this->admin)
            ->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => time() - 11 * 3600])
            ->get('/pengaturan/passkey')
            ->assertOk();
    }

    public function test_session_older_than_twelve_hours_is_ended_and_audited(): void
    {
        $this->actingAs($this->admin)
            ->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => time() - 12 * 3600 - 1])
            ->get('/pengaturan/passkey')
            ->assertRedirect(route('login'));

        $this->assertGuest();
        $this->assertSame(1, DB::table('audit_entries')->where('action_key', 'console.logout')->where('params_redacted->reason', 'absolute_timeout')->count());
    }

    public function test_session_without_a_login_timestamp_is_not_trusted(): void
    {
        $this->actingAs($this->admin)->get('/pengaturan/passkey')->assertRedirect(route('login'));
        $this->assertGuest();
    }

    public function test_logout_ends_the_session_and_is_audited(): void
    {
        $this->actingAs($this->admin)
            ->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => time()])
            ->post(route('logout'))
            ->assertRedirect(route('login'));

        $this->assertGuest();
        $this->assertSame(1, DB::table('audit_entries')->where('action_key', 'console.logout')->where('actor_id', $this->admin->id)->where('params_redacted->reason', 'manual')->count());
    }

    public function test_logged_in_admin_cannot_open_login_or_an_invitation_page(): void
    {
        $invite = URL::temporarySignedRoute('passkeys.register', now()->addMinutes(15), ['admin' => $this->newAdmin()->id], absolute: false);
        $session = [EnforceAbsoluteSessionLifetime::STARTED_AT => now()->getTimestamp()];

        $this->actingAs($this->admin)->withSession($session)->get(route('login'))->assertRedirect(route('home'));
        $this->actingAs($this->admin)->withSession($session)->get($invite)->assertRedirect(route('home'));
    }

    public function test_disabled_admin_loses_an_open_session_on_the_next_request(): void
    {
        $this->admin->forceFill(['status' => 'disabled'])->save();

        $this->actingAs($this->admin)
            ->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => now()->getTimestamp()])
            ->get('/pengaturan/passkey')
            ->assertRedirect(route('login'));

        $this->assertGuest();
        $this->assertSame(1, DB::table('audit_entries')->where('action_key', 'console.logout')->where('params_redacted->reason', 'admin_disabled')->count());
    }
}
