<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Sidik jari kepercayaan enrolment (ADR 0008 §2.6). NOT NULL tanpa default: tak ada jalur yang membuat baris agents
 * sebelum slice ini, sehingga tak ada baris lama yang perlu diisi. Bila ada, migrasi gagal keras, bukan mengisi tebakan.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::statement('ALTER TABLE agents ADD COLUMN trust_fingerprint char(64) NOT NULL');
        DB::statement("ALTER TABLE agents ADD CONSTRAINT agents_trust_fingerprint_check CHECK (trust_fingerprint ~ '^[0-9a-f]{64}\$')");
    }

    public function down(): void
    {
        DB::statement('ALTER TABLE agents DROP COLUMN trust_fingerprint');
    }
};
