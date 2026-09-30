@props(['message', 'variant' => 'success'])
@php
    $danger = $variant === 'danger';
@endphp
<div {{ $attributes->class(['ui-toast', 'alert', $danger ? 'alert-danger' : 'alert-success']) }} role="{{ $danger ? 'alert' : 'status' }}">
    <div class="d-flex gap-2">
        <x-ui.icon :name="$danger ? 'alert-triangle' : 'circle-check'" />
        <span>{{ $message }}</span>
    </div>
</div>
