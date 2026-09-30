<?php

namespace App\Livewire\Auth;

use App\Domain\Identity\Actions\BeginPasskeyRegistration;
use App\Domain\Identity\Actions\CompletePasskeyRegistration;
use App\Domain\Identity\Data\PasskeyRejected;
use App\Livewire\Concerns\ReportsPasskeyErrors;
use App\Models\Admin;
use Illuminate\Contracts\View\View;
use Livewire\Attributes\Layout;
use Livewire\Attributes\Locked;
use Livewire\Attributes\Title;
use Livewire\Component;

/**
 * Tautan bertanda tangan dari sadmin:admin-invite. Tanda tangan hanya diperiksa saat halaman dibuka, jadi
 * kedaluwarsa diperiksa ulang di setiap aksi; admin & batas waktu dikunci agar tak bisa diubah klien.
 */
#[Layout('layouts::guest')]
#[Title('Daftarkan passkey — sAdmin')]
class RegisterPasskeys extends Component
{
    use ReportsPasskeyErrors;

    #[Locked]
    public string $adminId;

    #[Locked]
    public int $expiresAt;

    #[Locked]
    public ?string $savedLabel = null;

    public string $label = '';

    public function mount(Admin $admin): void
    {
        $this->adminId = $admin->id;
        $this->expiresAt = (int) request()->query('expires');
    }

    public function begin(BeginPasskeyRegistration $begin): ?string
    {
        $this->clearError();
        $this->savedLabel = null;

        try {
            $this->guardInvite();
            if (trim($this->label) === '') {
                throw new PasskeyRejected('invalid_label');
            }

            return $begin->handle($this->admin());
        } catch (PasskeyRejected $e) {
            $this->fail($e->reason);

            return null;
        }
    }

    public function complete(string $credential, CompletePasskeyRegistration $complete): void
    {
        try {
            $this->guardInvite();
            $authenticator = $complete->handle($this->admin(), $credential, $this->label);
        } catch (PasskeyRejected $e) {
            $this->fail($e->reason);

            return;
        }

        $this->savedLabel = $authenticator->label;
        $this->label = '';
    }

    private function guardInvite(): void
    {
        if (time() > $this->expiresAt) {
            throw new PasskeyRejected('invite_expired');
        }
    }

    private function admin(): Admin
    {
        return Admin::query()->findOrFail($this->adminId);
    }

    public function render(): View
    {
        $admin = $this->admin();

        return view('livewire.auth.register-passkeys', [
            'admin' => $admin,
            'registered' => $admin->activeAuthenticators()->orderBy('created_at')->get(),
            'required' => BeginPasskeyRegistration::REQUIRED_AUTHENTICATORS,
        ]);
    }
}
