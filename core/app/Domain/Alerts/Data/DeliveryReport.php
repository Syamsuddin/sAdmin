<?php

namespace App\Domain\Alerts\Data;

/** Hasil pengiriman satu pesan ke kanal aktif: ID kanal yang berhasil dan alasan (sudah dibersihkan) yang gagal. */
final readonly class DeliveryReport
{
    /**
     * @param  list<string>  $delivered
     * @param  array<string, string>  $failed
     */
    public function __construct(
        public array $delivered,
        public array $failed,
    ) {}

    public function anyDelivered(): bool
    {
        return $this->delivered !== [];
    }
}
