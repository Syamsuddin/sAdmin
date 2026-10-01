@props(['label', 'name', 'hint' => null])
@php
    // Galat validasi tampil per field (docs/14 §Klasifikasi); galat dan petunjuk format dibacakan bersama input.
    $invalid = $errors->has($name);
    $describedBy = trim(($invalid ? "field-{$name}-error " : '').($hint ? "field-{$name}-hint" : ''));
@endphp
<div class="mb-3">
    <label class="form-label" for="field-{{ $name }}">{{ $label }}</label>
    <input type="text" id="field-{{ $name }}" name="{{ $name }}"
        @if ($invalid) aria-invalid="true" @endif
        @if ($describedBy !== '') aria-describedby="{{ $describedBy }}" @endif
        {{ $attributes->class(['form-control', 'is-invalid' => $invalid]) }}>
    @error($name)
        <div class="invalid-feedback" id="field-{{ $name }}-error">{{ $message }}</div>
    @enderror
    @if ($hint)
        <small class="form-hint" id="field-{{ $name }}-hint">{{ $hint }}</small>
    @endif
</div>
