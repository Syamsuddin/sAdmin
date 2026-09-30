<?php

namespace App\Livewire\Auth;

use App\Domain\Identity\Actions\BeginPasskeyLogin;
use App\Domain\Identity\Actions\CompletePasskeyLogin;
use App\Domain\Identity\Data\PasskeyRejected;
use App\Http\Middleware\EnforceAbsoluteSessionLifetime;
use App\Livewire\Concerns\ReportsPasskeyErrors;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Livewire\Attributes\Layout;
use Livewire\Attributes\Title;
use Livewire\Component;

#[Layout('layouts::guest')]
#[Title('Masuk — sAdmin')]
class Login extends Component
{
    use ReportsPasskeyErrors;

    public function begin(BeginPasskeyLogin $begin): string
    {
        $this->clearError();

        return $begin->handle();
    }

    public function complete(string $credential, CompletePasskeyLogin $complete): void
    {
        // 10 percobaan/menit/IP wg (docs/21); dihitung sebelum verifikasi agar tebakan pun terbatas.
        $key = 'passkey-login:'.request()->ip();
        if (RateLimiter::tooManyAttempts($key, (int) config('sadmin.login_attempts_per_minute'))) {
            $this->fail('rate_limited');

            return;
        }
        RateLimiter::hit($key, 60);

        try {
            $admin = $complete->handle($credential, request()->ip());
        } catch (PasskeyRejected $e) {
            $this->fail($e->reason);

            return;
        }

        Auth::login($admin);
        session()->regenerate();
        session()->put(EnforceAbsoluteSessionLifetime::STARTED_AT, time());

        $this->redirect(route('home'));
    }

    public function render(): View
    {
        return view('livewire.auth.login');
    }
}
