<?php

namespace App\Domain\Audit\Data;

/** Nilai `audit_entries.actor_type` (docs/07_DATA_MODEL.md). */
enum ActorType: string
{
    case Admin = 'admin';
    case Witness = 'witness';
    case Runner = 'runner';
    case Agent = 'agent';
    case System = 'system';
    case Ai = 'ai';
    case LocalRoot = 'local_root';
}
