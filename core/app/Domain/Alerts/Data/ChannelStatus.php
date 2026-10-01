<?php

namespace App\Domain\Alerts\Data;

/** Nilai `notification_channels.status` (docs/07_DATA_MODEL.md). */
enum ChannelStatus: string
{
    case Active = 'active';
    case Inactive = 'inactive';
}
