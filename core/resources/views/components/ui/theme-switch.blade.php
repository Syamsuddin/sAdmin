@use('App\Domain\Identity\Data\ThemePreference')
@props(['current'])
@php
    $options = [
        ['theme' => ThemePreference::System, 'icon' => 'device-desktop', 'label' => 'Ikuti sistem'],
        ['theme' => ThemePreference::Light, 'icon' => 'sun', 'label' => 'Terang'],
        ['theme' => ThemePreference::Dark, 'icon' => 'moon', 'label' => 'Gelap'],
    ];
@endphp
{{-- Pengalih tema (docs/26): pilihan disimpan per admin, lalu halaman dimuat ulang agar server merender data-bs-theme. --}}
<form method="POST" action="{{ route('settings.theme') }}">
    @csrf
    @method('PUT')
    <div class="btn-group" role="group" aria-label="Mode tema">
        @foreach ($options as $option)
            {{-- Pilihan aktif = tombol primer: warna token (--color-primary/--color-on-accent-button), bukan abu bawaan Tabler. --}}
            <x-ui.button type="submit" :variant="$current === $option['theme'] ? 'primary' : 'secondary'" class="btn-icon"
                name="theme" :value="$option['theme']->value" :title="$option['label']"
                :aria-pressed="$current === $option['theme'] ? 'true' : 'false'">
                <x-ui.icon :name="$option['icon']" />
                <span class="visually-hidden">{{ $option['label'] }}</span>
            </x-ui.button>
        @endforeach
    </div>
</form>
