<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('institutions', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->unique()->constrained('tenants');
            $table->text('name');
            $table->text('timezone')->default('Asia/Makassar');
            $table->jsonb('maintenance_window');
            $table->jsonb('backup_retention');
            $table->text('recovery_kit_location')->nullable();
            $table->timestampTz('recovery_kit_confirmed_at')->nullable();
            $table->text('console_hostname');
            $table->text('deployment_mode')->default('single');
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });

        DB::statement("ALTER TABLE institutions ADD CONSTRAINT institutions_deployment_mode_check CHECK (deployment_mode IN ('single','fleet'))");
    }

    public function down(): void
    {
        Schema::dropIfExists('institutions');
    }
};
