<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title ?? 'sAdmin' }}</title>
    {{-- Halaman tamu belum mengenal admin: tema selalu `system`, mengikuti OS sebelum CSS dimuat (docs/26, F-17). --}}
    <script>
        (function (media) {
            const apply = () => document.documentElement.setAttribute('data-bs-theme', media.matches ? 'dark' : 'light');
            apply();
            media.addEventListener('change', apply);
        })(window.matchMedia('(prefers-color-scheme: dark)'));
    </script>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body>
    <div class="page page-center">
        <div class="container container-tight py-4">
            {{ $slot }}
        </div>
    </div>
</body>
</html>
