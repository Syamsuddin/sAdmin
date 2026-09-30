@props(['label', 'name', 'hint' => null])
<div class="mb-3">
    <label class="form-label" for="field-{{ $name }}">{{ $label }}</label>
    <input type="text" id="field-{{ $name }}" name="{{ $name }}" {{ $attributes->class(['form-control']) }}>
    @if ($hint)
        <small class="form-hint">{{ $hint }}</small>
    @endif
</div>
