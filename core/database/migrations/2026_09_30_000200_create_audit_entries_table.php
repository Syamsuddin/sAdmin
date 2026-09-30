<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('audit_entries', function (Blueprint $table) {
            $table->bigInteger('seq')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->char('prev_hash', 64);
            $table->char('hash', 64)->unique();
            $table->timestampTz('occurred_at', 6);
            $table->text('actor_type');
            $table->text('actor_id')->nullable();
            $table->text('action_key');
            $table->text('target')->nullable();
            $table->jsonb('params_redacted')->nullable();
            $table->text('outcome');
            $table->char('envelope_ref', 26)->nullable();
            $table->boolean('emergency_local')->default(false);
        });

        DB::statement("ALTER TABLE audit_entries ADD CONSTRAINT audit_entries_actor_type_check CHECK (actor_type IN ('admin','witness','runner','agent','system','ai','local_root'))");
        DB::statement("ALTER TABLE audit_entries ADD CONSTRAINT audit_entries_outcome_check CHECK (outcome IN ('ok','rejected','failed','cancelled'))");

        // Pertahanan lapis DB: tak ada jalur aplikasi yang boleh mengubah riwayat (docs/07, docs/20).
        // OR REPLACE: db:wipe (migrate:fresh, RefreshDatabase) menghapus tabel tetapi tidak fungsi.
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION audit_entries_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'audit_entries bersifat append-only: % ditolak', TG_OP;
            END
            $$;

            CREATE TRIGGER audit_entries_no_update_delete
                BEFORE UPDATE OR DELETE ON audit_entries
                FOR EACH ROW EXECUTE FUNCTION audit_entries_append_only();

            CREATE TRIGGER audit_entries_no_truncate
                BEFORE TRUNCATE ON audit_entries
                FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only();
            SQL);
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_entries');
        DB::statement('DROP FUNCTION IF EXISTS audit_entries_append_only()');
    }
};
