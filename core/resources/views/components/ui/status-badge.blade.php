@props(['tone' => 'muted', 'label'])
@php
    // Warna hanya penguat: teks status selalu tampil (docs/26 §Larangan UI).
    if (! in_array($tone, ['info', 'success', 'warning', 'danger', 'muted'], true)) {
        throw new InvalidArgumentException('Nada lencana status tidak dikenal.');
    }
@endphp
<span {{ $attributes->class(['badge', 'ui-badge', "ui-badge-{$tone}"]) }}>{{ $label }}</span>
