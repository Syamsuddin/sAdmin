@use('App\Domain\Identity\Data\ThemePreference')
@php($theme = auth()->user()?->theme ?? ThemePreference::System)
<!DOCTYPE html>
{{-- F-17 (docs/26): pilihan light/dark dirender server agar tak berkedip; `system` diserahkan ke OS lewat skrip di bawah. --}}
<html lang="id" @if ($theme !== ThemePreference::System) data-bs-theme="{{ $theme->value }}" @endif>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title ?? 'sAdmin' }}</title>
    @if ($theme === ThemePreference::System)
        <script>
            (function (media) {
                const apply = () => document.documentElement.setAttribute('data-bs-theme', media.matches ? 'dark' : 'light');
                apply();
                media.addEventListener('change', apply);
            })(window.matchMedia('(prefers-color-scheme: dark)'));
        </script>
    @endif
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body>
    <div class="page">
        <header class="navbar navbar-expand-md d-print-none">
            <div class="container-xl">
                <span class="navbar-brand">sAdmin</span>
                {{-- Navigasi sementara di topbar: sidebar docs/26 menunggu keputusan pemilik soal lebar sidebar ringkas. --}}
                <nav class="navbar-nav flex-row gap-3 me-auto" aria-label="Navigasi utama">
                    @foreach ([['servers.*', 'servers.index', 'server', 'Server'], ['settings.passkeys', 'settings.passkeys', 'key', 'Passkey']] as [$pattern, $route, $icon, $label])
                        @php($current = request()->routeIs($pattern))
                        <a href="{{ route($route) }}" @class(['nav-link', 'active' => $current]) aria-label="{{ $label }}" @if ($current) aria-current="page" @endif>
                            <x-ui.icon :name="$icon" /><span class="d-none d-md-inline ms-1">{{ $label }}</span>
                        </a>
                    @endforeach
                </nav>
                <div class="navbar-nav flex-row order-md-last align-items-center gap-3">
                    <x-ui.theme-switch :current="$theme" />
                    <span class="text-secondary d-none d-sm-inline">{{ auth()->user()?->display_name }}</span>
                    <form method="POST" action="{{ route('logout') }}">
                        @csrf
                        <x-ui.button type="submit" variant="secondary">
                            <x-ui.icon name="logout" /> Keluar
                        </x-ui.button>
                    </form>
                </div>
            </div>
        </header>
        <main class="page-wrapper">
            {{ $slot }}
        </main>
    </div>
    @if (session('status'))
        <x-ui.toast :message="session('status')" />
    @endif
    @error('theme')
        <x-ui.toast variant="danger" :message="$message" />
    @enderror
</body>
</html>
