<?php

namespace App\Http\Controllers\Settings;

use App\Domain\Identity\Actions\UpdateThemePreference;
use App\Domain\Identity\Data\ThemePreference;
use App\Http\Controllers\Controller;
use App\Models\Admin;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

/** Pengalih tema di topbar (docs/26): simpan pilihan lalu muat ulang halaman asal agar `data-bs-theme` dirender server. */
class ThemeController extends Controller
{
    public function __invoke(Request $request, UpdateThemePreference $updateTheme): RedirectResponse
    {
        $validated = $request->validate(
            ['theme' => ['required', Rule::enum(ThemePreference::class)]],
            ['theme.*' => __('errors.format', __('errors.theme.invalid'))],
        );

        /** @var Admin $admin */
        $admin = $request->user();
        $updateTheme->handle($admin, ThemePreference::from($validated['theme']));

        return back()->with('status', 'Tema disimpan.');
    }
}
