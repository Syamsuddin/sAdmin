@props(['message'])
<div {{ $attributes->class(['ui-toast', 'alert', 'alert-success']) }} role="status">
    <div class="d-flex gap-2">
        <x-ui.icon name="circle-check" />
        <span>{{ $message }}</span>
    </div>
</div>
