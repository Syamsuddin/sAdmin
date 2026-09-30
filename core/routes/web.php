<?php

use App\Http\Controllers\Auth\LogoutController;
use App\Livewire\Auth\Login;
use App\Livewire\Auth\RegisterPasskeys;
use App\Livewire\Settings\Passkeys;
use Illuminate\Support\Facades\Route;

Route::middleware('guest')->group(function () {
    Route::livewire('/masuk', Login::class)->name('login');
    // Tanda tangan relatif: origin tautan = hostname console, bukan APP_URL (InviteAdmin).
    Route::livewire('/daftar-passkey/{admin}', RegisterPasskeys::class)
        ->middleware('signed:relative')
        ->name('passkeys.register');
});

Route::middleware('auth')->group(function () {
    Route::redirect('/', '/pengaturan/passkey')->name('home');
    Route::livewire('/pengaturan/passkey', Passkeys::class)->name('settings.passkeys');
    Route::post('/keluar', LogoutController::class)->name('logout');
});
