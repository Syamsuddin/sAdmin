<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('audit_checkpoints', function (Blueprint $table) {
            // seq entri terakhir yang dicakup. Sengaja tanpa FK ke audit_entries: FK membuat PostgreSQL menolak
            // TRUNCATE audit_entries sebelum trigger append-only-nya berjalan (ADR 0001 §2.5); keberadaan entri
            // diperiksa verify (ADR 0004 §2.5).
            $table->bigInteger('seq')->primary();
            $table->foreignUlid('tenant_id')->constrained('tenants');
            $table->char('hash', 64);
            $table->text('signature');
            $table->timestampTz('created_at', 6);
        });

        // Laravel tak punya tipe larik PostgreSQL; himpunan jangkar hanya bertambah (ADR 0004 §2.3).
        DB::statement('ALTER TABLE audit_checkpoints ADD COLUMN anchored_to text[] NOT NULL');
        DB::statement('ALTER TABLE audit_checkpoints ADD CONSTRAINT audit_checkpoints_seq_check CHECK (seq >= 1)');
        DB::statement("ALTER TABLE audit_checkpoints ADD CONSTRAINT audit_checkpoints_hash_check CHECK (hash ~ '^[0-9a-f]{64}$')");
        DB::statement("ALTER TABLE audit_checkpoints ADD CONSTRAINT audit_checkpoints_signature_check CHECK (signature ~ '^[A-Za-z0-9+/]{86}==$')");
        DB::statement("ALTER TABLE audit_checkpoints ADD CONSTRAINT audit_checkpoints_anchored_to_check CHECK (anchored_to <@ ARRAY['agents','offsite','digest']::text[])");

        // OR REPLACE: db:wipe (migrate:fresh, RefreshDatabase) menghapus tabel tetapi tidak fungsi.
        DB::unprepared(<<<'SQL'
            CREATE OR REPLACE FUNCTION audit_checkpoints_anchor_only() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                IF TG_OP = 'UPDATE' THEN
                    IF NEW.seq IS NOT DISTINCT FROM OLD.seq
                        AND NEW.tenant_id IS NOT DISTINCT FROM OLD.tenant_id
                        AND NEW.hash IS NOT DISTINCT FROM OLD.hash
                        AND NEW.signature IS NOT DISTINCT FROM OLD.signature
                        AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at
                        AND NEW.anchored_to @> OLD.anchored_to THEN
                        RETURN NEW;
                    END IF;
                END IF;
                RAISE EXCEPTION 'audit_checkpoints hanya boleh menambah anchored_to: % ditolak', TG_OP;
            END
            $$;

            CREATE TRIGGER audit_checkpoints_anchor_only
                BEFORE UPDATE OR DELETE ON audit_checkpoints
                FOR EACH ROW EXECUTE FUNCTION audit_checkpoints_anchor_only();

            CREATE TRIGGER audit_checkpoints_no_truncate
                BEFORE TRUNCATE ON audit_checkpoints
                FOR EACH STATEMENT EXECUTE FUNCTION audit_checkpoints_anchor_only();
            SQL);
    }

    public function down(): void
    {
        Schema::dropIfExists('audit_checkpoints');
        DB::statement('DROP FUNCTION IF EXISTS audit_checkpoints_anchor_only()');
    }
};
