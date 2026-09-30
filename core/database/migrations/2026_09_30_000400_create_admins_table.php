<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('admins', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->text('display_name');
            $table->text('email')->nullable();
            $table->text('status')->default('active');
            $table->text('theme')->default('system');
            $table->timestampTz('last_login_at')->nullable();
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');

            $table->unique(['tenant_id', 'email']);
        });

        DB::statement("ALTER TABLE admins ADD CONSTRAINT admins_status_check CHECK (status IN ('active','disabled'))");
        DB::statement("ALTER TABLE admins ADD CONSTRAINT admins_theme_check CHECK (theme IN ('system','light','dark'))");
    }

    public function down(): void
    {
        Schema::dropIfExists('admins');
    }
};
