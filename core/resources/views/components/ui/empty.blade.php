@props(['icon' => 'key', 'message'])
<div {{ $attributes->class(['ui-empty', 'text-secondary']) }} role="status">
    <x-ui.icon :name="$icon" />
    <div>
        <p class="mb-1">{{ $message }}</p>
        {{ $slot }}
    </div>
</div>
