<?php

namespace Tests\Feature\Identity;

use App\Models\Admin;
use App\Models\Institution;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Tests\TestCase;

/** P1 langkah 3–4 (docs/06): hostname console permanen, lalu tautan pendaftaran 2 passkey. */
class BootstrapCommandsTest extends TestCase
{
    use RefreshDatabase;

    public function test_institution_is_initialized_once_with_a_permanent_hostname(): void
    {
        $this->artisan('sadmin:institution-init', ['hostname' => 'Sadmin.Contoh.Test', '--name' => 'Instansi Uji'])
            ->expectsOutputToContain('RP ID): sadmin.contoh.test')
            ->assertExitCode(0);

        $this->assertSame('sadmin.contoh.test', Institution::query()->value('console_hostname'));
        $this->assertSame(1, DB::table('audit_entries')->where('action_key', 'institution.initialize')->where('actor_type', 'local_root')->count());

        $this->artisan('sadmin:institution-init', ['hostname' => 'lain.contoh.test'])
            ->expectsOutputToContain('tak dapat diubah')
            ->assertExitCode(1);
        $this->assertSame('sadmin.contoh.test', Institution::query()->value('console_hostname'));
    }

    /** @return iterable<string, array{string}> */
    public static function invalidHostnames(): iterable
    {
        yield 'alamat IPv4' => ['10.77.0.1'];
        yield 'alamat IPv6' => ['::1'];
        yield 'dengan skema' => ['https://sadmin.contoh.test'];
        yield 'dengan port' => ['sadmin.contoh.test:8443'];
        yield 'tanpa titik' => ['sadmin'];
    }

    /** RP ID WebAuthn tak boleh IP (landmine docs/_MANIFEST). */
    #[DataProvider('invalidHostnames')]
    public function test_hostname_must_be_an_fqdn(string $hostname): void
    {
        $this->artisan('sadmin:institution-init', ['hostname' => $hostname])->assertExitCode(1);
        $this->assertSame(0, Institution::query()->count());
    }

    public function test_missing_hostname_falls_back_to_sadmin_rp_id_or_fails(): void
    {
        config(['sadmin.webauthn.default_rp_id' => null]);
        $this->artisan('sadmin:institution-init')->assertExitCode(1);
        $this->assertSame(0, Institution::query()->count());

        config(['sadmin.webauthn.default_rp_id' => 'sadmin.localhost']);
        $this->artisan('sadmin:institution-init')->assertExitCode(0);
        $this->assertSame('sadmin.localhost', Institution::query()->value('console_hostname'));
    }

    /** Tautan undangan = rahasia bearer 15 menit: hanya dicetak ke terminal root, tak pernah ke audit/log. */
    #[Group('redaction')]
    public function test_invitation_signature_never_reaches_audit_or_log(): void
    {
        Artisan::call('sadmin:institution-init', ['hostname' => 'sadmin.localhost']);
        $logged = [];
        Log::listen(function ($event) use (&$logged): void {
            $logged[] = $event->message.json_encode($event->context);
        });

        Artisan::call('sadmin:admin-invite', ['name' => 'Budi']);
        preg_match('~signature=([0-9a-f]{64})~', Artisan::output(), $signature);

        $this->assertNotEmpty($signature);
        $audit = DB::table('audit_entries')->pluck('params_redacted')->implode(' ');
        $this->assertStringNotContainsString($signature[1], $audit);
        $this->assertStringNotContainsString('signature', $audit);
        $this->assertStringNotContainsString($signature[1], implode(' ', $logged));
    }

    public function test_invite_requires_an_initialized_institution(): void
    {
        $this->artisan('sadmin:admin-invite', ['name' => 'Budi'])
            ->expectsOutputToContain('sadmin:institution-init')
            ->assertExitCode(1);
        $this->assertSame(0, Admin::query()->count());
    }

    public function test_invite_prints_a_signed_link_on_the_console_hostname_that_expires(): void
    {
        Artisan::call('sadmin:institution-init', ['hostname' => 'sadmin.localhost']);
        Artisan::call('sadmin:admin-invite', ['name' => 'Budi']);
        preg_match('~https://sadmin\.localhost(/daftar-passkey/\S+)~', Artisan::output(), $link);

        $this->assertNotEmpty($link, 'Tautan pendaftaran harus berada di hostname console.');
        $admin = Admin::query()->sole();
        $this->assertSame(1, DB::table('audit_entries')->where('action_key', 'admin.invite')->where('target', 'admin:'.$admin->id)->count());

        $this->get($link[1])->assertOk()->assertSee('Halo, Budi.');
        $this->get(str_replace('signature=', 'signature=0', $link[1]))->assertForbidden();

        $this->travel(16)->minutes();
        $this->get($link[1])->assertForbidden();
    }
}
