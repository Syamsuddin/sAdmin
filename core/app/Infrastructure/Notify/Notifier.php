<?php

namespace App\Infrastructure\Notify;

use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use App\Models\NotificationChannel;

/** Adaptor pengirim satu jenis kanal. Rahasia kanal dibuka di dalam adaptor, tepat sebelum koneksi (ADR 0005 §2.6). */
interface Notifier
{
    /**
     * @throws NotifyFailed kanal menolak atau tak terjangkau
     * @throws VaultUnavailable kunci induk tak termuat
     * @throws VaultIntegrityError rahasia kanal gagal dibuka atau ber-purpose lain
     */
    public function send(NotificationChannel $channel, NotificationMessage $message, float $timeoutSeconds): void;
}
