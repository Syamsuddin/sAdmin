<?php

namespace App\Domain\Alerts\Data;

/**
 * Akhir satu pembukaan alert integritas (ADR 0005 §2.2–2.3). `report` null bila tidak dikirim karena alert yang
 * sama sudah terkirim kurang dari 24 jam lalu, atau karena tenant tak diketahui. `reminder` = kiriman ulang
 * untuk alert lama yang masih terdeteksi.
 */
final readonly class RaisedAlert
{
    public function __construct(
        public string $alertId,
        public bool $stored,
        public bool $created,
        public bool $alreadyNotified,
        public ?DeliveryReport $report,
        public bool $reminder = false,
    ) {}

    public function delivered(): bool
    {
        return $this->alreadyNotified || ($this->report?->anyDelivered() ?? false);
    }
}
