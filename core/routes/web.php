<?php

use App\Http\Controllers\Auth\LogoutController;
use App\Http\Controllers\Settings\ThemeController;
use App\Livewire\Auth\Login;
use App\Livewire\Auth\RegisterPasskeys;
use App\Livewire\Servers\Enroll;
use App\Livewire\Servers\Index as ServersIndex;
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
    Route::redirect('/', '/server')->name('home');
    Route::livewire('/server', ServersIndex::class)->name('servers.index');
    Route::livewire('/server/tambah', Enroll::class)->name('servers.enroll');
    // Token baru untuk server yang masih menunggu enrolment; token lama langsung tak berlaku.
    Route::livewire('/server/{server}/enrolmen', Enroll::class)->name('servers.reenroll');
    Route::livewire('/pengaturan/passkey', Passkeys::class)->name('settings.passkeys');
    Route::put('/pengaturan/tema', ThemeController::class)->name('settings.theme');
    Route::post('/keluar', LogoutController::class)->name('logout');
});
