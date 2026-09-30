@props(['name'])
@php
    // Hanya Tabler Icons yang disalin apa adanya ke resources/icons/tabler (docs/26; dijaga tes asal-usul).
    if (preg_match('/^[a-z0-9-]+$/', $name) !== 1) {
        throw new InvalidArgumentException('Nama ikon tidak sah.');
    }
    $svg = file_get_contents(resource_path("icons/tabler/{$name}.svg"));
@endphp
{!! str_replace('class="icon ', 'aria-hidden="true" focusable="false" class="ui-icon icon ', $svg) !!}
