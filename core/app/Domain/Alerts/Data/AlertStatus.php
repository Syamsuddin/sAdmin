<?php

namespace App\Domain\Alerts\Data;

/** Nilai `alerts.status` (docs/07_DATA_MODEL.md). */
enum AlertStatus: string
{
    case Open = 'open';
    case Acknowledged = 'acknowledged';
    case Resolved = 'resolved';
}
