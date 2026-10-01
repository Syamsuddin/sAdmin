<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('alert_rules', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->text('kind');
            $table->jsonb('threshold');
            $table->boolean('enabled')->default(true);
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');

            $table->unique(['tenant_id', 'kind']);
        });

        DB::statement("ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_kind_check CHECK (kind IN ('disk_low','mem_high','service_down','cert_expiring','backup_failed','agent_disconnected','audit_mismatch'))");
        DB::statement("ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_threshold_check CHECK (jsonb_typeof(threshold) = 'object')");
        // Integritas tak boleh disembunyikan (docs/14, ADR 0005 §2.2).
        DB::statement("ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_audit_mismatch_enabled_check CHECK (kind <> 'audit_mismatch' OR enabled)");
    }

    public function down(): void
    {
        Schema::dropIfExists('alert_rules');
    }
};
