<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title ?? 'sAdmin' }}</title>
    <script>document.documentElement.setAttribute('data-bs-theme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');</script>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body>
    <div class="page">
        <header class="navbar navbar-expand-md d-print-none">
            <div class="container-xl">
                <span class="navbar-brand">sAdmin</span>
                <div class="navbar-nav flex-row order-md-last align-items-center gap-3">
                    <span class="text-secondary">{{ auth()->user()?->display_name }}</span>
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
</body>
</html>
