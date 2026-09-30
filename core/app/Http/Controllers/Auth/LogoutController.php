<?php

namespace App\Http\Controllers\Auth;

use App\Domain\Identity\Actions\RecordLogout;
use App\Http\Controllers\Controller;
use App\Models\Admin;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LogoutController extends Controller
{
    public function __invoke(Request $request, RecordLogout $recordLogout): RedirectResponse
    {
        $admin = Auth::user();
        if ($admin instanceof Admin) {
            $recordLogout->handle($admin, 'manual');
        }

        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }
}
