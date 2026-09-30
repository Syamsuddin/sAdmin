<?php

namespace App\Livewire\Settings;

use App\Models\Admin;
use App\Models\Authenticator;
use App\Models\Institution;
use Illuminate\Contracts\View\View;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Livewire\Attributes\Lazy;
use Livewire\Attributes\Title;
use Livewire\Component;

/** Daftar passkey milik admin yang masuk (baca saja). Empat state: memuat (placeholder), kosong, gagal, sukses. */
#[Lazy]
#[Title('Passkey — sAdmin')]
class Passkeys extends Component
{
    private const ALGORITHMS = [-7 => 'ES256', -8 => 'EdDSA'];

    private const ZONES = ['Asia/Jakarta' => 'WIB', 'Asia/Pontianak' => 'WIB', 'Asia/Makassar' => 'WITA', 'Asia/Jayapura' => 'WIT'];

    public function placeholder(): View
    {
        return view('livewire.settings.passkeys-placeholder');
    }

    public function render(): View
    {
        try {
            /** @var Admin $admin */
            $admin = Auth::user();
            $timezone = Institution::query()->value('timezone') ?? 'Asia/Makassar';
            $passkeys = $admin->activeAuthenticators()->orderBy('created_at')->get()
                ->map(fn (Authenticator $passkey): array => [
                    'label' => $passkey->label,
                    'algorithm' => self::ALGORITHMS[$passkey->alg] ?? (string) $passkey->alg,
                    'created' => $passkey->created_at?->setTimezone($timezone)->locale('id')->isoFormat('D MMM YYYY, HH.mm')
                        .' '.(self::ZONES[$timezone] ?? $timezone),
                ]);
            $errorId = null;
        } catch (QueryException $e) {
            $errorId = (string) Str::ulid();
            Log::error('passkeys_load_failed', ['correlation_id' => $errorId, 'detail' => $e->getMessage()]);
            $passkeys = collect();
        }

        return view('livewire.settings.passkeys', ['passkeys' => $passkeys, 'errorId' => $errorId]);
    }
}
