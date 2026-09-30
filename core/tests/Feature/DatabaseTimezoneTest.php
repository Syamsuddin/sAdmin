<?php

namespace Tests\Feature;

use App\Models\Tenant;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/** docs/07: semua waktu disimpan UTC. Tanpa zona sesi UTC, Eloquent menyimpan waktu tergeser zona server PG. */
class DatabaseTimezoneTest extends TestCase
{
    use RefreshDatabase;

    public function test_database_session_runs_in_utc_like_the_application(): void
    {
        $this->assertSame('UTC', config('app.timezone'));
        $this->assertSame('UTC', DB::selectOne('show timezone')->TimeZone);
    }

    public function test_eloquent_timestamps_are_stored_as_the_same_instant(): void
    {
        $this->travelTo(now()->setDate(2026, 9, 29)->setTime(6, 5));
        $tenant = Tenant::factory()->create();

        $stored = DB::selectOne("select to_char(created_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI') as utc from tenants where id = ?", [$tenant->id]);
        $this->assertSame('2026-09-29 06:05', $stored->utc);
    }
}
