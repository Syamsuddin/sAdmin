<?php

namespace App\Domain\Alerts\Data;

use App\Domain\Vault\Data\SecretPurpose;

/** Nilai `notification_channels.kind` (docs/07_DATA_MODEL.md) dan purpose rahasianya (ADR 0005 §2.5). */
enum ChannelKind: string
{
    case Telegram = 'telegram';
    case Smtp = 'smtp';

    public function secretPurpose(): SecretPurpose
    {
        return match ($this) {
            self::Telegram => SecretPurpose::TelegramToken,
            self::Smtp => SecretPurpose::Smtp,
        };
    }
}
