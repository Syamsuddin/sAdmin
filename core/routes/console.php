<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('sadmin:audit-verify')->daily();
