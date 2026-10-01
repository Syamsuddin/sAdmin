@props(['label', 'name', 'hint' => null])
{{-- Galat validasi tampil per field (docs/14 §Klasifikasi), terhubung ke input lewat aria-describedby. --}}
<div class="mb-3">
    <label class="form-label" for="field-{{ $name }}">{{ $label }}</label>
    <input type="text" id="field-{{ $name }}" name="{{ $name }}"
        @error($name) aria-invalid="true" aria-describedby="field-{{ $name }}-error" @enderror
        {{ $attributes->class(['form-control', 'is-invalid' => $errors->has($name)]) }}>
    @error($name)
        <div class="invalid-feedback" id="field-{{ $name }}-error">{{ $message }}</div>
    @enderror
    @if ($hint)
        <small class="form-hint">{{ $hint }}</small>
    @endif
</div>
