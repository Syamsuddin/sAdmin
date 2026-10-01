<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /** Tepat satu kunci layanan aktif per tenant (ADR 0006 §2.1); mengganti kunci = rotasi, gerbang docs/22. */
    public function up(): void
    {
        DB::statement("CREATE UNIQUE INDEX secrets_one_active_service_key ON secrets (tenant_id) WHERE purpose = 'service_key' AND status = 'active'");
    }

    public function down(): void
    {
        DB::statement('DROP INDEX IF EXISTS secrets_one_active_service_key');
    }
};
