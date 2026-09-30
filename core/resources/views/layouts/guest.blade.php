<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title ?? 'sAdmin' }}</title>
    {{-- Mode tema mengikuti OS sebelum CSS dimuat (docs/26); pilihan per admin menyusul di F-17. --}}
    <script>document.documentElement.setAttribute('data-bs-theme', window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');</script>
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
