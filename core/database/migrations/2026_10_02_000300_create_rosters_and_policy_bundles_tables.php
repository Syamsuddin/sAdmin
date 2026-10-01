<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        foreach (['rosters', 'policy_bundles'] as $name) {
            Schema::create($name, function (Blueprint $table) {
                $table->ulid('id')->primary();
                $table->foreignUlid('tenant_id')->constrained('tenants');
                $table->integer('version');
                $table->jsonb('document');
                $table->char('document_hash', 64);
                $table->text('status');
                $table->timestampTz('effective_at')->nullable();
                $table->timestampTz('created_at');
                $table->timestampTz('updated_at');
                $table->unique(['tenant_id', 'version']);
            });

            DB::statement("ALTER TABLE {$name} ADD CONSTRAINT {$name}_status_check CHECK (status IN ('pending','active','superseded','cancelled'))");
            DB::statement("ALTER TABLE {$name} ADD CONSTRAINT {$name}_version_check CHECK (version >= 1)");
            DB::statement("ALTER TABLE {$name} ADD CONSTRAINT {$name}_document_hash_check CHECK (document_hash ~ '^[0-9a-f]{64}\$')");
            DB::statement("ALTER TABLE {$name} ADD CONSTRAINT {$name}_document_object_check CHECK (jsonb_typeof(document) = 'object')");
            // Satu dokumen aktif per tenant (ADR 0008 §2.4): versi baru baru aktif setelah yang lama superseded.
            DB::statement("CREATE UNIQUE INDEX {$name}_one_active ON {$name} (tenant_id) WHERE status = 'active'");
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('policy_bundles');
        Schema::dropIfExists('rosters');
    }
};
