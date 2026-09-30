<?php

namespace Tests\Feature\Identity;

use App\Http\Middleware\EnforceAbsoluteSessionLifetime;
use App\Livewire\Settings\Passkeys;
use App\Models\Admin;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Livewire\Livewire;
use Tests\Support\InteractsWithPasskeys;
use Tests\Support\VirtualAuthenticator;
use Tests\TestCase;

/** Empat state wajib halaman ber-data (docs/26, kriteria UI docs/23). */
class PasskeysPageTest extends TestCase
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

    public function test_loading_state_is_a_skeleton_placeholder(): void
    {
        $this->withSession([EnforceAbsoluteSessionLifetime::STARTED_AT => time()])
            ->get('/pengaturan/passkey')
            ->assertOk()
            ->assertSee('aria-busy="true"', false)
            ->assertSee('ui-skeleton', false);
    }

    public function test_success_state_lists_own_passkeys_in_institution_time(): void
    {
        $this->travelTo(now()->setTimezone('UTC')->setDate(2026, 9, 29)->setTime(6, 5));
        $this->enroll($this->admin, VirtualAuthenticator::eddsa('a'), 'YubiKey kantor');
        $this->enroll($this->admin, VirtualAuthenticator::es256('b'), 'Ponsel');
        $this->enroll($this->newAdmin(), VirtualAuthenticator::eddsa('c'), 'Milik admin lain');

        Livewire::withoutLazyLoading()->test(Passkeys::class)
            ->assertSee('YubiKey kantor')
            ->assertSee('EdDSA')
            ->assertSee('Ponsel')
            ->assertSee('ES256')
            ->assertSee('29 Sep 2026, 14.05 WITA')
            ->assertDontSee('Milik admin lain');
    }

    public function test_empty_state_explains_the_next_step(): void
    {
        Livewire::withoutLazyLoading()->test(Passkeys::class)
            ->assertSee('Belum ada passkey aktif untuk akun ini.')
            ->assertSee('sadmin:admin-invite');
    }

    public function test_failure_state_shows_cause_action_and_correlation_id(): void
    {
        DB::statement('ALTER TABLE authenticators RENAME TO authenticators_tak_terbaca');

        Livewire::withoutLazyLoading()->test(Passkeys::class)
            ->assertSee('Langkah Memuat daftar passkey gagal')
            ->assertSee('ID: ')
            ->assertSee('Coba lagi');
    }
}
