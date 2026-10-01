<?php

namespace App\Console\Commands;

use App\Domain\Alerts\Data\ChannelStatus;
use App\Domain\Alerts\Services\AlertDispatcher;
use App\Infrastructure\Notify\NotificationMessage;
use App\Models\Institution;
use App\Models\NotificationChannel;
use Illuminate\Console\Command;
use Illuminate\Support\Str;

class NotifyTestCommand extends Command
{
    protected $signature = 'sadmin:notify-test';

    protected $description = 'Kirim pesan uji ke semua kanal notifikasi aktif lewat jalur alert critical (ADR 0005 §2.5)';

    public function handle(AlertDispatcher $dispatcher): int
    {
        $institution = Institution::query()->first(['tenant_id', 'console_hostname']);
        if ($institution === null) {
            $this->error('Instansi belum diinisialisasi; jalankan sadmin:institution-init lebih dulu.');

            return self::FAILURE;
        }

        $channels = NotificationChannel::query()
            ->where('tenant_id', $institution->tenant_id)
            ->where('status', ChannelStatus::Active->value)
            ->orderBy('id')
            ->get();
        if ($channels->isEmpty()) {
            $this->error('Belum ada kanal notifikasi aktif; tambahkan dengan sadmin:notify-channel-add.');

            return self::FAILURE;
        }

        $id = strtolower((string) Str::ulid());
        $host = (string) $institution->console_hostname;
        $report = $dispatcher->deliver((string) $institution->tenant_id, new NotificationMessage(
            self::text('alerts.test.subject', ['host' => $host]),
            self::text('alerts.test.body', ['host' => $host, 'id' => $id]),
        ));

        foreach ($channels as $channel) {
            if (in_array($channel->id, $report->delivered, true)) {
                $this->info("OK     {$channel->kind->value} {$channel->id}");
            } else {
                $this->error("GAGAL  {$channel->kind->value} {$channel->id}: ".($report->failed[$channel->id] ?? 'tidak dicoba'));
            }
        }

        return $report->failed === [] ? self::SUCCESS : self::FAILURE;
    }

    /** @param  array<string, string>  $replace */
    private static function text(string $key, array $replace): string
    {
        $line = __($key, $replace, 'id');

        return is_string($line) ? $line : $key;
    }
}
