<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /** Tepat satu kunci audit aktif per tenant (ADR 0004 §2.1); mengganti kunci = rotasi, gerbang docs/22. */
    public function up(): void
    {
        DB::statement("CREATE UNIQUE INDEX secrets_one_active_audit_key ON secrets (tenant_id) WHERE purpose = 'audit_key' AND status = 'active'");
    }

    public function down(): void
    {
        DB::statement('DROP INDEX IF EXISTS secrets_one_active_audit_key');
    }
};
