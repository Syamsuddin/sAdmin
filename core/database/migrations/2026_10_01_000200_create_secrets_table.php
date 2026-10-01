<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('secrets', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->text('purpose');
            // XChaCha20-Poly1305 dengan kunci data; nilai rahasia tak pernah tersimpan polos (ADR 0003 §2.3).
            $table->binary('ciphertext');
            $table->binary('nonce');
            $table->foreignUlid('key_wrap_id')->unique()->constrained('key_wraps');
            $table->text('status')->default('active');
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });

        DB::statement("ALTER TABLE secrets ADD CONSTRAINT secrets_purpose_check CHECK (purpose IN ('db_password','env','deploy_key','api_token','telegram_token','smtp','upload','service_key','audit_key','ca_key','gateway_hmac','ai_api_key'))");
        DB::statement("ALTER TABLE secrets ADD CONSTRAINT secrets_status_check CHECK (status IN ('active','rotated','destroyed'))");
    }

    public function down(): void
    {
        Schema::dropIfExists('secrets');
    }
};
