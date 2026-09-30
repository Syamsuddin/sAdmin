@props(['variant' => 'primary', 'type' => 'button'])
@php
    $variants = ['primary' => 'btn-primary', 'secondary' => 'btn-outline-secondary', 'danger' => 'btn-danger'];
@endphp
<button type="{{ $type }}" {{ $attributes->class(['btn', $variants[$variant] ?? 'btn-primary']) }}>
    {{ $slot }}
</button>
