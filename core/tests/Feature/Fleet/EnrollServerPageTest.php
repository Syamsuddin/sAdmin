<?php

namespace Tests\Feature\Fleet;

use App\Domain\Fleet\Actions\InitializeCertificateAuthority;
use App\Domain\Fleet\Actions\RegisterServer;
use App\Domain\Fleet\Data\ServerStatus;
use App\Domain\Fleet\Services\CertificateAuthority;
use App\Http\Middleware\EnforceAbsoluteSessionLifetime;
use App\Livewire\Servers\Enroll;
use App\Models\Admin;
use App\Models\Server;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException;
use Livewire\Livewire;
use Tests\Support\InteractsWithPasskeys;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** AC-17 & kriteria UI docs/23: formulir tambah server, perintah enrolment sekali tampil, terbit ulang token. */
class EnrollServerPageTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithVault, RefreshDatabase;

    private Admin $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpInstitution();
        $this->admin = $this->newAdmin();
        $this->actingAs($this->admin);
        app(InitializeCertificateAuthority::class)->handle();
        config(['sadmin.gateway_host' => 'gw.instansi.go.id']);
        $this->travelTo(now()->setTimezone('UTC')->setDate(2026, 10, 2)->setTime(6, 5, 30));
    }

    private function pin(): string
    {
        return app(CertificateAuthority::class)->fingerprint($this->admin->tenant_id);
    }

    public function test_page_renders_the_form_inside_the_console(): void
    {
        $this->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => now()->getTimestamp()])
            ->get('/server/tambah')
            ->assertOk()
            ->assertSee('<title>Tambah server — sAdmin</title>', false)
            ->assertSee('id="field-name"', false)
            ->assertSee('id="field-hostname"', false)
            ->assertSee('id="field-ip"', false)
            ->assertSee('Simpan');
    }

    public function test_saving_shows_the_enrolment_command_once_and_resets_the_form(): void
    {
        $page = Livewire::test(Enroll::class)
            ->set('name', 'web1')
            ->set('hostname', 'web1.instansi.go.id')
            ->set('ip', '203.0.113.10')
            ->call('save')
            ->assertHasNoErrors()
            ->assertSet('name', '')
            ->assertSet('hostname', '')
            ->assertSet('ip', '');

        $command = (string) $page->get('command');
        $this->assertSame(1, preg_match('/^sudo sadmin-agent enroll --gateway gw\.instansi\.go\.id:8443 --ca-sha256 ([0-9a-f]{64}) --token ([0-9a-f]{64})\z/', $command, $m));
        $this->assertSame($this->pin(), $m[1]);
        $this->assertSame(hash('sha256', $m[2]), Server::query()->sole()->getAttributes()['enroll_token_hash']);

        $page->assertSee($command)
            ->assertSee('Token berlaku sampai')
            ->assertSee('2 Okt 2026, 14.20 WITA')
            ->assertSee('Token enrolment untuk web1 diterbitkan.')
            ->assertDontSee('id="field-name"', false);

        // Dimuat ulang: perintah hilang, hanya hash yang tersisa di basis data.
        Livewire::test(Enroll::class)->assertSet('command', null)->assertDontSee($m[2]);
    }

    public function test_invalid_input_is_reported_per_field_without_creating_a_server(): void
    {
        Livewire::test(Enroll::class)
            ->set('name', 'Web 1')
            ->set('hostname', '10.0.0.1')
            ->set('ip', '127.0.0.1')
            ->call('save')
            ->assertHasErrors(['name'])
            ->assertSee('Langkah Tambah server gagal: nama server wajib')
            ->assertSee('aria-invalid="true"', false)
            ->assertSee('aria-describedby="field-name-error field-name-hint"', false)
            ->assertSet('command', null);

        Livewire::test(Enroll::class)
            ->set('name', 'web1')->set('hostname', '10.0.0.1')->set('ip', '203.0.113.10')
            ->call('save')->assertHasErrors(['hostname'])->assertSee('hostname bukan nama host DNS yang sah');

        Livewire::test(Enroll::class)
            ->set('name', 'web1')->set('hostname', 'web1.instansi.go.id')->set('ip', '127.0.0.1')
            ->call('save')->assertHasErrors(['ip'])->assertSee('alamat IP tidak sah');

        $this->assertSame(0, Server::query()->count());
    }

    /** Review F-02c R-1: semua field yang salah dilaporkan sekaligus, bukan satu per kiriman. */
    public function test_every_invalid_field_is_reported_in_one_submit(): void
    {
        Livewire::test(Enroll::class)
            ->set('name', 'Web 1')
            ->set('hostname', '10.0.0.1')
            ->set('ip', '127.0.0.1')
            ->call('save')
            ->assertHasErrors(['name', 'hostname', 'ip'])
            ->assertSee('hostname bukan nama host DNS yang sah')
            ->assertSee('alamat IP tidak sah');
        $this->assertSame(0, Server::query()->count());
    }

    /** Review F-02c S-1: Coba lagi memeriksa ulang prasyarat, alih-alih menahan state Gagal selamanya. */
    public function test_retry_after_a_failed_save_rechecks_and_restores_the_form(): void
    {
        $page = Livewire::test(Enroll::class)->set('name', 'web1')->set('hostname', 'web1.instansi.go.id')->set('ip', '203.0.113.10');
        config(['sadmin.gateway_host' => '']);
        $page->call('save')
            ->assertSee('SADMIN_GATEWAY_HOST')
            ->assertSee('wire:click="retry"', false)
            ->assertDontSee('id="field-name"', false);

        config(['sadmin.gateway_host' => 'gw.instansi.go.id']);
        $page->call('retry')
            ->assertSet('errorReason', null)
            ->assertDontSee('SADMIN_GATEWAY_HOST')
            ->assertSee('id="field-name"', false);
    }

    /** Review F-02c R-8: batas Mode Tunggal diperiksa sebelum formulir tampil. */
    public function test_full_inventory_blocks_the_form_before_any_input(): void
    {
        foreach (['a', 'b', 'c'] as $i => $name) {
            app(RegisterServer::class)->handle($this->admin, $name, "{$name}.instansi.go.id", '203.0.113.'.(10 + $i));
        }

        Livewire::test(Enroll::class)
            ->assertSee('Mode Tunggal hanya mengelola paling banyak tiga server.')
            ->assertDontSee('id="field-name"', false);
    }

    /** Review F-02c R-9: brankas tanpa kunci induk = formulir tak tampil (AC-17). */
    public function test_missing_vault_key_blocks_the_form_with_a_failure_state(): void
    {
        $this->withoutVaultKey();

        Livewire::test(Enroll::class)
            ->assertSee('brankas tidak dapat dibuka')
            ->assertSee('sadmin:vault-check')
            ->assertDontSee('id="field-name"', false);
    }

    /** Review F-02c R-4: halaman terbit ulang tak bisa dipakai mendaftarkan server baru. */
    public function test_save_is_ignored_on_the_reissue_page(): void
    {
        $server = Server::factory()->create(['tenant_id' => $this->admin->tenant_id, 'status' => ServerStatus::Online]);

        Livewire::test(Enroll::class, ['server' => $server])
            ->set('name', 'web9')->set('hostname', 'web9.instansi.go.id')->set('ip', '203.0.113.99')
            ->call('save')
            ->assertSet('command', null);
        $this->assertSame(1, Server::query()->count());
    }

    /** Review F-02c R-7: petunjuk format dibacakan bersama galat; perintah berlabel teks terlihat. */
    public function test_hints_and_command_are_exposed_to_assistive_technology(): void
    {
        Livewire::test(Enroll::class)
            ->assertSee('aria-describedby="field-name-hint"', false)
            ->assertSee('id="field-name-hint"', false)
            ->set('name', 'Web 1')->set('hostname', 'web1.instansi.go.id')->set('ip', '203.0.113.10')
            ->call('save')
            ->assertSee('aria-describedby="field-name-error field-name-hint"', false);

        Livewire::test(Enroll::class)
            ->set('name', 'web1')->set('hostname', 'web1.instansi.go.id')->set('ip', '203.0.113.10')
            ->call('save')
            ->assertSee('<figcaption', false)
            ->assertDontSee('<pre class="ui-command" aria-label', false);
    }

    public function test_missing_gateway_blocks_the_form_with_a_failure_state(): void
    {
        config(['sadmin.gateway_host' => '']);

        Livewire::test(Enroll::class)
            ->assertSee('Langkah Siapkan perintah enrolment gagal: alamat gateway (SADMIN_GATEWAY_HOST) belum diatur')
            ->assertSee('ID: ')
            ->assertSee('Coba lagi')
            ->assertDontSee('id="field-name"', false);
    }

    public function test_missing_ca_blocks_the_form_with_a_failure_state(): void
    {
        DB::table('secrets')->where('purpose', 'ca_key')->update(['status' => 'destroyed']);

        Livewire::test(Enroll::class)
            ->assertSee('CA internal belum dibuat')
            ->assertSee('sadmin:ca-init')
            ->assertDontSee('id="field-name"', false);
    }

    public function test_reaching_the_limit_on_save_shows_a_failure_state(): void
    {
        foreach (['a', 'b', 'c'] as $i => $name) {
            app(RegisterServer::class)->handle($this->admin, $name, "{$name}.instansi.go.id", '203.0.113.'.(10 + $i));
        }

        Livewire::test(Enroll::class)
            ->set('name', 'd')->set('hostname', 'd.instansi.go.id')->set('ip', '203.0.113.20')
            ->call('save')
            ->assertSee('Mode Tunggal hanya mengelola paling banyak tiga server.')
            ->assertSee('ID: ')
            ->assertSet('command', null);
        $this->assertSame(3, Server::query()->count());
    }

    public function test_reissue_page_replaces_the_token_of_an_enrolling_server(): void
    {
        $first = app(RegisterServer::class)->handle($this->admin, 'web1', 'web1.instansi.go.id', '203.0.113.10');
        $server = Server::query()->sole();

        $this->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => now()->getTimestamp()])
            ->get("/server/{$server->id}/enrolmen")
            ->assertOk()
            ->assertSee('<title>Token enrolment — sAdmin</title>', false)
            ->assertSeeInOrder(['web1', 'web1.instansi.go.id', '203.0.113.10'])
            ->assertSee('Terbitkan token baru')
            ->assertDontSee($first->token());

        $page = Livewire::test(Enroll::class, ['server' => $server])->call('reissue');
        $command = (string) $page->get('command');

        $this->assertStringNotContainsString($first->token(), $command);
        $this->assertSame(1, preg_match('/--token ([0-9a-f]{64})\z/', $command, $m));
        $this->assertSame(hash('sha256', $m[1]), $server->fresh()?->getAttributes()['enroll_token_hash']);
        $page->assertSee('Token enrolment untuk web1 diterbitkan.');
    }

    public function test_reissue_page_refuses_servers_that_are_no_longer_enrolling(): void
    {
        $server = Server::factory()->create(['tenant_id' => $this->admin->tenant_id, 'status' => ServerStatus::Online]);

        Livewire::test(Enroll::class, ['server' => $server])
            ->assertSee('server ini tidak lagi menunggu enrolment')
            ->assertDontSee('Terbitkan token baru')
            ->call('reissue')
            ->assertSet('command', null);
        $this->assertNull($server->fresh()?->getAttributes()['enroll_token_hash']);
    }

    public function test_reissue_page_of_another_tenant_is_not_found(): void
    {
        $foreign = Server::factory()->create(['status' => ServerStatus::Enrolling]);

        $this->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => now()->getTimestamp()])
            ->get("/server/{$foreign->id}/enrolmen")
            ->assertNotFound();
    }

    public function test_server_id_cannot_be_swapped_from_the_browser(): void
    {
        $server = Server::factory()->create(['tenant_id' => $this->admin->tenant_id, 'status' => ServerStatus::Enrolling]);
        $foreign = Server::factory()->create(['status' => ServerStatus::Enrolling]);

        $this->expectException(CannotUpdateLockedPropertyException::class);
        Livewire::test(Enroll::class, ['server' => $server])->set('serverId', $foreign->id);
    }
}
