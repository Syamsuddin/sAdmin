<?php

namespace App\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Dokumen kepercayaan agen (docs/07 §rosters, ADR 0008). Dibuat hanya oleh App\Domain\Fleet\Services\TrustDocuments;
 * `document_hash` = SHA-256 byte JCS `document` dan dihitung ulang setiap dibaca.
 *
 * @property array<string, mixed> $document
 * @property string $document_hash
 * @property int $version
 * @property CarbonImmutable|null $effective_at
 */
class Roster extends Model
{
    use HasUlids;

    protected $table = 'rosters';

    protected $fillable = ['tenant_id', 'version', 'document', 'document_hash', 'status', 'effective_at'];

    protected function casts(): array
    {
        return ['document' => 'array', 'version' => 'integer', 'effective_at' => 'immutable_datetime'];
    }
}
