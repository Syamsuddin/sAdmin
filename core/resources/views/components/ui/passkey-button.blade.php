@props(['label' => 'Setujui dengan passkey'])
{{-- Dipakai di dalam x-data="passkeyCeremony(...)"; state memuat = tombol nonaktif + teks menunggu. --}}
<x-ui.button {{ $attributes->class(['w-100']) }} x-on:click="run()" x-bind:disabled="busy" x-bind:aria-busy="busy">
    <x-ui.icon name="fingerprint" />
    <span x-show="!busy">{{ $label }}</span>
    <span x-show="busy" x-cloak>Menunggu passkey…</span>
</x-ui.button>
