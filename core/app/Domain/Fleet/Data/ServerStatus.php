<?php

namespace App\Domain\Fleet\Data;

/** Nilai `servers.status` (docs/07_DATA_MODEL.md); label selalu tampil bersama warna lencana (docs/26). */
enum ServerStatus: string
{
    case Enrolling = 'enrolling';
    case Online = 'online';
    case Offline = 'offline';
    case NeedsAttention = 'needs_attention';
    case Retired = 'retired';

    public function label(): string
    {
        return match ($this) {
            self::Enrolling => 'Menunggu enrolment',
            self::Online => 'Online',
            self::Offline => 'Offline',
            self::NeedsAttention => 'Perlu perhatian',
            self::Retired => 'Dipensiunkan',
        };
    }

    /** Nada lencana: kunci warna token docs/26, bukan nilai warna. */
    public function tone(): string
    {
        return match ($this) {
            self::Enrolling => 'info',
            self::Online => 'success',
            self::NeedsAttention => 'warning',
            self::Offline, self::Retired => 'muted',
        };
    }
}
