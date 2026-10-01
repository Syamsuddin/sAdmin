<?php

namespace App\Domain\Alerts\Data;

/** Nilai `alert_rules.kind` (docs/07_DATA_MODEL.md, ambang bawaan docs/15). */
enum AlertKind: string
{
    case DiskLow = 'disk_low';
    case MemHigh = 'mem_high';
    case ServiceDown = 'service_down';
    case CertExpiring = 'cert_expiring';
    case BackupFailed = 'backup_failed';
    case AgentDisconnected = 'agent_disconnected';
    /** Selalu critical dan tak bisa dinonaktifkan (docs/14, ADR 0005 §2.2). */
    case AuditMismatch = 'audit_mismatch';
}
