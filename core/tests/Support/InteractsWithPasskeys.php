<?php

namespace Tests\Support;

use App\Livewire\Auth\Login;
use App\Livewire\Auth\RegisterPasskeys;
use App\Models\Admin;
use App\Models\Authenticator;
use App\Models\Institution;
use Livewire\Features\SupportTesting\Testable;
use Livewire\Livewire;

/** Ceremony passkey lewat komponen Livewire sungguhan + autentikator virtual (docs/13). */
trait InteractsWithPasskeys
{
    protected Institution $institution;

    protected function setUpInstitution(): void
    {
        $this->institution = Institution::factory()->create(['console_hostname' => 'sadmin.localhost', 'timezone' => 'Asia/Makassar']);
    }

    protected function newAdmin(string $status = 'active'): Admin
    {
        return Admin::factory()->create(['tenant_id' => $this->institution->tenant_id, 'status' => $status]);
    }

    /** Autentikator yang sudah terdaftar tanpa melewati halaman pendaftaran (untuk tes masuk). */
    protected function enroll(Admin $admin, VirtualAuthenticator $authenticator, string $label = 'Kunci uji', string $status = 'active'): Authenticator
    {
        $authenticator->ownedBy($admin->id);

        return Authenticator::query()->create([
            'tenant_id' => $admin->tenant_id,
            'admin_id' => $admin->id,
            'credential_id' => $authenticator->credentialId,
            'public_key_cose' => $authenticator->coseKey(),
            'alg' => $authenticator->alg,
            'sign_count' => $authenticator->signCount,
            'label' => $label,
            'status' => $status,
        ]);
    }

    /** `expires` datang dari query tautan bertanda tangan, persis seperti rute sungguhan (properti terkunci). */
    protected function registrationPage(Admin $admin, ?int $expiresAt = null): Testable
    {
        return Livewire::withQueryParams(['expires' => $expiresAt ?? time() + 900])
            ->test(RegisterPasskeys::class, ['admin' => $admin]);
    }

    /** Menjalankan begin() lalu complete() seperti passkey.js; mengembalikan komponen untuk diperiksa. */
    protected function ceremony(Testable $page, callable $respond): Testable
    {
        $options = null;
        $page->call('begin')->assertReturned(function ($value) use (&$options): bool {
            $options = $value;

            return true;
        });

        return is_string($options) ? $page->call('complete', $respond($options)) : $page;
    }

    protected function loginWith(VirtualAuthenticator $authenticator, ?string $userHandle = null): Testable
    {
        return $this->ceremony(Livewire::test(Login::class), fn (string $options): string => $authenticator->assert($options, $userHandle));
    }
}
