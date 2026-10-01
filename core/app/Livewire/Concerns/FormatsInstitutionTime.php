<?php

namespace App\Livewire\Concerns;

use App\Models\Institution;
use Carbon\CarbonInterface;

/** Waktu tampilan dalam zona instansi, format docs/26 §Mikroteks: `29 Sep 2026, 14.05 WITA`. */
trait FormatsInstitutionTime
{
    private ?string $institutionTimezone = null;

    protected function institutionTime(CarbonInterface $time): string
    {
        $timezone = $this->institutionTimezone ??= (Institution::query()->value('timezone') ?? 'Asia/Makassar');
        $label = ['Asia/Jakarta' => 'WIB', 'Asia/Pontianak' => 'WIB', 'Asia/Makassar' => 'WITA', 'Asia/Jayapura' => 'WIT'][$timezone] ?? $timezone;

        return $time->setTimezone($timezone)->locale('id')->isoFormat('D MMM YYYY, HH.mm').' '.$label;
    }
}
