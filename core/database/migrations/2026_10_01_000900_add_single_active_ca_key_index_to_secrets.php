<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /** Tepat satu CA internal aktif per tenant (ADR 0007 §2.1); mengganti CA = rotasi, gerbang docs/22. */
    public function up(): void
    {
        DB::statement("CREATE UNIQUE INDEX secrets_one_active_ca_key ON secrets (tenant_id) WHERE purpose = 'ca_key' AND status = 'active'");
    }

    public function down(): void
    {
        DB::statement('DROP INDEX IF EXISTS secrets_one_active_ca_key');
    }
};
