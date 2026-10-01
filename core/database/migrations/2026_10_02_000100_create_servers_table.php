<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('servers', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->text('name');
            $table->text('hostname');
            $table->ipAddress('ip');
            $table->text('platform_id')->nullable();
            $table->jsonb('os_release')->nullable();
            $table->text('ownership')->default('managed');
            $table->boolean('is_control_plane_host')->default(false);
            $table->text('status');
            // Hanya hash SHA-256 token sekali pakai; teksnya tampil sekali ke admin dan tak pernah disimpan.
            $table->char('enroll_token_hash', 64)->nullable();
            $table->timestampTz('enroll_token_expires_at')->nullable();
            $table->timestampTz('onboarded_at')->nullable();
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');

            $table->unique(['tenant_id', 'name']);
        });

        DB::statement("ALTER TABLE servers ADD CONSTRAINT servers_ownership_check CHECK (ownership IN ('managed','observed','ignored'))");
        DB::statement("ALTER TABLE servers ADD CONSTRAINT servers_status_check CHECK (status IN ('enrolling','online','offline','needs_attention','retired'))");
        DB::statement("ALTER TABLE servers ADD CONSTRAINT servers_os_release_check CHECK (os_release IS NULL OR jsonb_typeof(os_release) = 'object')");
        DB::statement("ALTER TABLE servers ADD CONSTRAINT servers_enroll_token_hash_check CHECK (enroll_token_hash ~ '^[0-9a-f]{64}$')");
        // Token hanya ada selama server menunggu enrolment, dan selalu bersama batas waktunya.
        DB::statement('ALTER TABLE servers ADD CONSTRAINT servers_enroll_token_pair_check CHECK ((enroll_token_hash IS NULL) = (enroll_token_expires_at IS NULL))');
        DB::statement("ALTER TABLE servers ADD CONSTRAINT servers_enroll_token_status_check CHECK (enroll_token_hash IS NULL OR status = 'enrolling')");
        // Enroll mencari server lewat hash token; dua server tak boleh berbagi satu token.
        DB::statement('CREATE UNIQUE INDEX servers_enroll_token_hash_unique ON servers (enroll_token_hash) WHERE enroll_token_hash IS NOT NULL');

        DB::statement('ALTER TABLE alerts ADD CONSTRAINT alerts_server_id_foreign FOREIGN KEY (server_id) REFERENCES servers (id)');
    }

    public function down(): void
    {
        DB::statement('ALTER TABLE alerts DROP CONSTRAINT alerts_server_id_foreign');
        Schema::dropIfExists('servers');
    }
};
