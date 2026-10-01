<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('notification_channels', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->text('kind');
            // Tanpa rahasia: token bot dan kata sandi SMTP hanya di secrets (ADR 0005 §2.5).
            $table->jsonb('config');
            $table->foreignUlid('secret_id')->constrained('secrets');
            $table->text('status')->default('active');
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });

        DB::statement("ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_kind_check CHECK (kind IN ('telegram','smtp'))");
        DB::statement("ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_status_check CHECK (status IN ('active','inactive'))");
        DB::statement("ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_config_check CHECK (jsonb_typeof(config) = 'object')");
    }

    public function down(): void
    {
        Schema::dropIfExists('notification_channels');
    }
};
