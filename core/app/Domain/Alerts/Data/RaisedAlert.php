<?php

namespace App\Domain\Alerts\Data;

/**
 * Akhir satu pembukaan alert integritas (ADR 0005 §2.2–2.3). `report` null bila tidak dikirim karena alert yang
 * sama sudah terkirim sebelumnya, atau karena tenant tak diketahui.
 */
final readonly class RaisedAlert
{
    public function __construct(
        public string $alertId,
        public bool $stored,
        public bool $created,
        public bool $alreadyNotified,
        public ?DeliveryReport $report,
    ) {}

    public function delivered(): bool
    {
        return $this->alreadyNotified || ($this->report?->anyDelivered() ?? false);
    }
}
