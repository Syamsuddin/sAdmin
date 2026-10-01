<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('agents', function (Blueprint $table) {
            $table->ulid('id')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->foreignUlid('server_id')->unique()->constrained('servers');
            $table->text('agent_version');
            $table->text('cert_serial');
            $table->timestampTz('cert_expires_at');
            $table->integer('roster_version');
            $table->integer('policy_version');
            $table->timestampTz('last_seen_at')->nullable();
            $table->text('connection');
            $table->bigInteger('audit_head_seq')->nullable();
            $table->char('audit_head_hash', 64)->nullable();
            $table->timestampTz('created_at');
            $table->timestampTz('updated_at');
        });

        DB::statement("ALTER TABLE agents ADD CONSTRAINT agents_connection_check CHECK (connection IN ('connected','disconnected'))");
        // Serial sertifikat klien: hex huruf kecil tanpa nol di depan, 1..2^63−1 (KONTRAK §2).
        DB::statement("ALTER TABLE agents ADD CONSTRAINT agents_cert_serial_check CHECK (cert_serial ~ '^([1-9a-f][0-9a-f]{0,14}|[1-7][0-9a-f]{15})$')");
        DB::statement("ALTER TABLE agents ADD CONSTRAINT agents_audit_head_hash_check CHECK (audit_head_hash ~ '^[0-9a-f]{64}$')");
        DB::statement('ALTER TABLE agents ADD CONSTRAINT agents_audit_head_pair_check CHECK ((audit_head_seq IS NULL) = (audit_head_hash IS NULL))');
    }

    public function down(): void
    {
        Schema::dropIfExists('agents');
    }
};
