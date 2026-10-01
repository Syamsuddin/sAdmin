<?php

namespace Tests\Feature\Fleet;

use App\Domain\Fleet\Data\AgentConnection;
use App\Domain\Fleet\Data\ServerStatus;
use App\Http\Middleware\EnforceAbsoluteSessionLifetime;
use App\Livewire\Servers\Index;
use App\Models\Admin;
use App\Models\Agent;
use App\Models\Server;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Livewire\Livewire;
use Tests\Support\InteractsWithPasskeys;
use Tests\TestCase;

/** AC-17 & kriteria UI docs/23: inventaris server dengan empat state wajib (docs/26). */
class ServersPageTest extends TestCase
{
    use InteractsWithPasskeys, RefreshDatabase;

    private Admin $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpInstitution();
        $this->admin = $this->newAdmin();
        $this->actingAs($this->admin);
    }

    /** @param  array<string, mixed>  $attributes */
    private function server(array $attributes = []): Server
    {
        return Server::factory()->create(['tenant_id' => $this->admin->tenant_id, ...$attributes]);
    }

    public function test_console_home_is_the_server_inventory(): void
    {
        $this->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => time()])
            ->get('/')
            ->assertRedirect('/server');
    }

    public function test_loading_state_is_a_skeleton_placeholder_and_navigation_marks_the_page(): void
    {
        $html = (string) $this->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => time()])
            ->get('/server')
            ->assertOk()
            ->assertSee('aria-busy="true"', false)
            ->assertSee('ui-skeleton', false)
            ->assertSee('aria-label="Navigasi utama"', false)
            ->getContent();

        $this->assertMatchesRegularExpression('/class="nav-link active" aria-label="Server"\s+aria-current="page"/', $html);
        $this->assertMatchesRegularExpression('/class="nav-link" aria-label="Passkey"\s*>/', $html);
    }

    public function test_guests_are_sent_to_login(): void
    {
        auth()->logout();

        $this->get('/server')->assertRedirect(route('login'));
        $this->get('/server/tambah')->assertRedirect(route('login'));
    }

    public function test_empty_state_offers_adding_a_server(): void
    {
        Livewire::withoutLazyLoading()->test(Index::class)
            ->assertSee('Belum ada server terdaftar.')
            ->assertSee('href="'.route('servers.enroll').'"', false)
            ->assertSee('Tambah server');
    }

    public function test_success_state_lists_own_servers_with_status_text_and_agent(): void
    {
        $online = $this->server(['name' => 'web1', 'hostname' => 'web1.instansi.go.id', 'ip' => '203.0.113.10', 'status' => ServerStatus::Online]);
        Agent::query()->create([
            'tenant_id' => $online->tenant_id, 'server_id' => $online->id, 'agent_version' => '0.1.0', 'cert_serial' => 'abc',
            'cert_expires_at' => now()->addDays(7), 'roster_version' => 1, 'policy_version' => 1, 'connection' => AgentConnection::Connected,
        ]);
        $this->server(['name' => 'db1', 'status' => ServerStatus::NeedsAttention]);
        Server::factory()->create(['name' => 'milik-tenant-lain']);

        Livewire::withoutLazyLoading()->test(Index::class)
            ->assertSeeInOrder(['web1', 'web1.instansi.go.id', '203.0.113.10', 'Online', 'Terhubung · 0.1.0'])
            ->assertSeeInOrder(['db1', 'Perlu perhatian'])
            ->assertSee('ui-badge-success', false)
            ->assertSee('ui-badge-warning', false)
            ->assertDontSee('milik-tenant-lain');
    }

    public function test_enrolling_servers_show_token_validity_in_institution_time_and_a_reissue_link(): void
    {
        $this->travelTo(now()->setTimezone('UTC')->setDate(2026, 10, 2)->setTime(6, 10));
        $valid = $this->server(['name' => 'web1', 'status' => ServerStatus::Enrolling, 'enroll_token_hash' => str_repeat('a', 64), 'enroll_token_expires_at' => now()->addMinutes(10)]);
        $this->server(['name' => 'web2', 'status' => ServerStatus::Enrolling, 'enroll_token_hash' => str_repeat('b', 64), 'enroll_token_expires_at' => now()->subMinute()]);
        $this->server(['name' => 'web3', 'status' => ServerStatus::Enrolling]);

        Livewire::withoutLazyLoading()->test(Index::class)
            ->assertSeeInOrder(['web1', 'Menunggu enrolment', 'Token berlaku sampai 2 Okt 2026, 14.20 WITA.'])
            ->assertSeeInOrder(['web2', 'Token kedaluwarsa 2 Okt 2026, 14.09 WITA.'])
            ->assertSeeInOrder(['web3', 'Tidak ada token aktif.'])
            ->assertSee('href="'.route('servers.reenroll', $valid->id).'"', false)
            ->assertSee('Terbitkan token baru');
    }

    /** Review F-02c R-5: server yang dibuat pada detik yang sama tetap berurutan menurut ULID-nya. */
    public function test_servers_created_in_the_same_second_keep_a_stable_order(): void
    {
        $this->freezeSecond();
        $later = strtolower((string) Str::ulid());
        usleep(2000);
        $latest = strtolower((string) Str::ulid());
        $first = strtolower((string) Str::ulid(now()->subSecond()));
        // Urutan ULID (mike, zulu, alfa) sengaja berbeda dari urutan sisip maupun urutan nama (indeks tenant_id, name):
        // tanpa pemecah seri, basis data bebas mengembalikan salah satunya.
        foreach ([[$latest, 'alfa'], [$later, 'zulu'], [$first, 'mike']] as [$id, $name]) {
            $this->server(['id' => $id, 'name' => $name]);
        }

        Livewire::withoutLazyLoading()->test(Index::class)->assertSeeInOrder(['mike', 'zulu', 'alfa']);
    }

    public function test_add_button_disappears_at_the_single_mode_limit(): void
    {
        $this->server(['name' => 'a']);
        $this->server(['name' => 'b', 'status' => ServerStatus::Retired]);
        Livewire::withoutLazyLoading()->test(Index::class)->assertSee('Tambah server')->assertDontSee('Batas Mode Tunggal');

        $this->server(['name' => 'c']);
        $this->server(['name' => 'd']);
        Livewire::withoutLazyLoading()->test(Index::class)
            ->assertDontSee('Tambah server')
            ->assertSee('Batas Mode Tunggal tercapai: paling banyak 3 server terkelola.');
    }

    public function test_failure_state_shows_cause_action_and_correlation_id(): void
    {
        DB::statement('ALTER TABLE servers RENAME TO servers_tak_terbaca');

        Livewire::withoutLazyLoading()->test(Index::class)
            ->assertSee('Langkah Memuat daftar server gagal')
            ->assertSee('ID: ')
            ->assertSee('Coba lagi')
            ->assertDontSee('Tambah server');
    }
}
