<?php

namespace App\Domain\Alerts\Data;

/** Nilai `alerts.severity` (docs/07_DATA_MODEL.md). */
enum AlertSeverity: string
{
    case Info = 'info';
    case Warning = 'warning';
    case Critical = 'critical';
}
