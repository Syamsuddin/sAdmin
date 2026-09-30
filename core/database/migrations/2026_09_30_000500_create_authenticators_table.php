<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('authenticators', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->foreignUlid('admin_id')->constrained('admins');
            $table->binary('credential_id')->unique();
            // Hanya kunci publik COSE mentah; tak pernah kunci privat (docs/21).
            $table->binary('public_key_cose');
            $table->integer('alg');
            $table->bigInteger('sign_count')->default(0);
            $table->text('label');
            $table->text('status')->default('active');
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });

        // Hanya ES256 (-7) dan EdDSA (-8): docs/07, ADR 0002.
        DB::statement('ALTER TABLE authenticators ADD CONSTRAINT authenticators_alg_check CHECK (alg IN (-7, -8))');
        DB::statement("ALTER TABLE authenticators ADD CONSTRAINT authenticators_status_check CHECK (status IN ('active','revoked'))");
    }

    public function down(): void
    {
        Schema::dropIfExists('authenticators');
    }
};
