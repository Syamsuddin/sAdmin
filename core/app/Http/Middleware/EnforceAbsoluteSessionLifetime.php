<?php

namespace App\Http\Middleware;

use App\Domain\Identity\Actions\RecordLogout;
use App\Models\Admin;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * Batas mutlak sesi console 12 jam sejak login, di samping batas idle 30 menit (docs/21). Berlaku juga untuk
 * permintaan Livewire karena keduanya lewat grup middleware `web`.
 */
class EnforceAbsoluteSessionLifetime
{
    public const STARTED_AT = 'console.logged_in_at';

    public function __construct(private readonly RecordLogout $recordLogout) {}

    public function handle(Request $request, Closure $next): Response
    {
        $admin = Auth::user();
        if ($admin instanceof Admin) {
            $startedAt = $request->session()->get(self::STARTED_AT);
            $limit = (int) config('sadmin.session_absolute_minutes') * 60;

            if (! is_int($startedAt) || time() - $startedAt > $limit) {
                $this->recordLogout->handle($admin, 'absolute_timeout');
                Auth::logout();
                $request->session()->invalidate();
                $request->session()->regenerateToken();

                return redirect()->route('login')->with('status', 'Sesi berakhir setelah 12 jam. Silakan masuk lagi.');
            }
        }

        return $next($request);
    }
}
