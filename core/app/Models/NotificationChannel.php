<?php

namespace App\Models;

use App\Domain\Alerts\Data\ChannelKind;
use App\Domain\Alerts\Data\ChannelStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Satu tujuan notifikasi (docs/07, ADR 0005 §2.5). `config` tanpa rahasia; token bot atau kata sandi SMTP ada di
 * `secret_id` dan hanya dibuka adaptor App\Infrastructure\Notify.
 *
 * @property ChannelKind $kind
 * @property ChannelStatus $status
 * @property array<string, mixed> $config
 */
class NotificationChannel extends Model
{
    use HasUlids;

    protected $fillable = ['id', 'tenant_id', 'kind', 'config', 'secret_id', 'status'];

    protected function casts(): array
    {
        return [
            'kind' => ChannelKind::class,
            'status' => ChannelStatus::class,
            'config' => 'array',
        ];
    }
}
