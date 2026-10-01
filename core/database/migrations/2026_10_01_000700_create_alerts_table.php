<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('alerts', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->foreignUlid('rule_id')->nullable()->constrained('alert_rules');
            // FK→servers.id ditambahkan migrasi yang membuat tabel servers (docs/07 §Armada).
            $table->char('server_id', 26)->nullable();
            $table->text('severity');
            $table->text('title');
            $table->jsonb('detail');
            $table->text('status')->default('open');
            $table->text('dedup_key')->nullable();
            $table->timestampTz('opened_at');
            $table->timestampTz('notified_at')->nullable();
            $table->timestampTz('resolved_at')->nullable();
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });

        DB::statement("ALTER TABLE alerts ADD CONSTRAINT alerts_severity_check CHECK (severity IN ('info','warning','critical'))");
        DB::statement("ALTER TABLE alerts ADD CONSTRAINT alerts_status_check CHECK (status IN ('open','acknowledged','resolved'))");
        DB::statement("ALTER TABLE alerts ADD CONSTRAINT alerts_detail_check CHECK (jsonb_typeof(detail) = 'object')");
        DB::statement("ALTER TABLE alerts ADD CONSTRAINT alerts_resolved_at_check CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))");

        // Paling banyak satu alert belum selesai per kejadian, juga bila dua pendeteksi berpacu (ADR 0005 §2.2).
        DB::statement("CREATE UNIQUE INDEX alerts_unresolved_dedup ON alerts (tenant_id, dedup_key) WHERE dedup_key IS NOT NULL AND status <> 'resolved'");
    }

    public function down(): void
    {
        Schema::dropIfExists('alerts');
    }
};
