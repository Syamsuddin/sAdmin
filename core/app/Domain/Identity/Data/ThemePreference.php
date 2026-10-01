<?php

namespace App\Domain\Identity\Data;

/** Nilai `admins.theme` (docs/07_DATA_MODEL.md): `system` mengikuti `prefers-color-scheme` OS (docs/26). */
enum ThemePreference: string
{
    case System = 'system';
    case Light = 'light';
    case Dark = 'dark';
}
