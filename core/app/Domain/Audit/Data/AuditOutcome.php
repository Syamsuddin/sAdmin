<?php

namespace App\Domain\Audit\Data;

/** Nilai `audit_entries.outcome` (docs/07_DATA_MODEL.md). */
enum AuditOutcome: string
{
    case Ok = 'ok';
    case Rejected = 'rejected';
    case Failed = 'failed';
    case Cancelled = 'cancelled';
}
