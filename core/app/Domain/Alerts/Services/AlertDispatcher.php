<?php

namespace App\Domain\Alerts\Services;

use App\Domain\Alerts\Data\ChannelKind;
use App\Domain\Alerts\Data\ChannelStatus;
use App\Domain\Alerts\Data\DeliveryReport;
use App\Infrastructure\Notify\NotificationMessage;
use App\Infrastructure\Notify\Notifier;
use App\Infrastructure\Notify\NotifyFailed;
use App\Infrastructure\Notify\SmtpNotifier;
use App\Infrastructure\Notify\TelegramNotifier;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use App\Models\NotificationChannel;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Sleep;

/**
 * Mengirim satu pesan ke semua kanal aktif tenant secara sinkron dalam anggaran waktu tetap (ADR 0005 §2.3):
 * putaran pertama tiap kanal sekali, lalu kanal yang gagal dicoba sekali lagi. Kode domain hanya memegang ID
 * kanal; rahasianya dibuka adaptor Notify.
 */
final class AlertDispatcher
{
    public const BUDGET_SECONDS = 50;

    public const ATTEMPT_TIMEOUT_SECONDS = 10;

    public const RETRY_PAUSE_SECONDS = 2;

    public const ATTEMPTS = 2;

    private const MIN_ATTEMPT_SECONDS = 1;

    public function __construct(
        private readonly TelegramNotifier $telegram,
        private readonly SmtpNotifier $smtp,
    ) {}

    public function deliver(string $tenantId, NotificationMessage $message, ?string $alertId = null): DeliveryReport
    {
        $pending = NotificationChannel::query()
            ->where('tenant_id', $tenantId)
            ->where('status', ChannelStatus::Active->value)
            ->orderBy('id')
            ->get()
            ->all();
        $deadline = CarbonImmutable::now()->addSeconds(self::BUDGET_SECONDS);
        $delivered = [];
        $failed = [];

        for ($attempt = 1; $attempt <= self::ATTEMPTS && $pending !== []; $attempt++) {
            if ($attempt > 1) {
                Sleep::for(self::RETRY_PAUSE_SECONDS)->seconds();
            }

            $retry = [];
            foreach ($pending as $channel) {
                $remaining = CarbonImmutable::now()->diffInMilliseconds($deadline, false) / 1000;
                if ($remaining < self::MIN_ATTEMPT_SECONDS) {
                    // Kanal yang sudah gagal mempertahankan penyebab aslinya; itu yang berguna bagi operator.
                    $failed[$channel->id] ??= 'anggaran waktu pengiriman habis';

                    continue;
                }

                try {
                    $this->notifier($channel->kind)->send($channel, $message, min(self::ATTEMPT_TIMEOUT_SECONDS, $remaining));
                    $delivered[] = $channel->id;
                    unset($failed[$channel->id]);
                } catch (NotifyFailed|VaultUnavailable $e) {
                    $failed[$channel->id] = $e->getMessage();
                    $retry[] = $channel;
                    Log::error('alert_notify_failed', $this->context($alertId, $channel, $attempt, $e));
                } catch (VaultIntegrityError $e) {
                    // Rahasia kanal diubah atau ditukar: tak akan pulih dengan mencoba lagi (kelas Integritas docs/14).
                    $failed[$channel->id] = $e->getMessage();
                    Log::critical('alert_notify_failed', $this->context($alertId, $channel, $attempt, $e));
                }
            }
            $pending = $retry;
        }

        return new DeliveryReport($delivered, $failed);
    }

    private function notifier(ChannelKind $kind): Notifier
    {
        return match ($kind) {
            ChannelKind::Telegram => $this->telegram,
            ChannelKind::Smtp => $this->smtp,
        };
    }

    /** @return array<string, int|string|null> */
    private function context(?string $alertId, NotificationChannel $channel, int $attempt, NotifyFailed|VaultUnavailable|VaultIntegrityError $e): array
    {
        return [
            'alert_id' => $alertId,
            'channel_id' => $channel->id,
            'kind' => $channel->kind->value,
            'attempt' => $attempt,
            'error' => class_basename($e).': '.$e->getMessage(),
        ];
    }
}
