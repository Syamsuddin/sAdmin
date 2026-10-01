<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('sadmin:audit-verify')->daily();

// Janji docs/21 "tiap 15 menit atau 100 entri" dengan resolusi satu menit (ADR 0004 §2.4).
Schedule::command('sadmin:audit-checkpoint --if-due')->everyMinute();
