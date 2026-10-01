<?php

use Illuminate\Support\Facades\Schedule;

// withoutOverlapping: kiriman alert yang macet tak boleh menumpuk satu proses (dan satu koneksi DB) per jadwal (ADR 0005 §2.3).
Schedule::command('sadmin:audit-verify')->daily()->withoutOverlapping(120);

// Janji docs/21 "tiap 15 menit atau 100 entri" dengan resolusi satu menit (ADR 0004 §2.4).
Schedule::command('sadmin:audit-checkpoint --if-due')->everyMinute()->withoutOverlapping(10);
