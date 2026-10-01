<?php

namespace App\Console\Commands\Concerns;

use App\Domain\Alerts\Actions\RaiseIntegrityAlert;
use App\Domain\Alerts\Data\IntegrityAlert;
use Illuminate\Support\Facades\Log;
use Throwable;

/** Membuka alert `audit_mismatch` dan melaporkan hasil kirimnya ke operator (ADR 0005 §2.1). */
trait RaisesIntegrityAlerts
{
    private function raiseIntegrityAlert(RaiseIntegrityAlert $alerts, IntegrityAlert $alert): void
    {
        try {
            $raised = $alerts->handle($alert);
        } catch (Throwable $e) {
            // RaiseIntegrityAlert tak seharusnya melempar; bila terjadi, kode exit pendeteksi tetap tak berubah.
            Log::critical('alert_undelivered', ['dedup_key' => $alert->dedupKey(), 'reason' => class_basename($e).': '.$e->getMessage()]);
            $this->error('Alert audit_mismatch gagal dibuka: '.class_basename($e).'.');

            return;
        }

        if ($raised->alreadyNotified) {
            $this->line("Alert audit_mismatch {$raised->alertId} untuk kejadian ini sudah terkirim dalam 24 jam terakhir.");

            return;
        }
        if ($raised->delivered()) {
            $count = count($raised->report->delivered ?? []);
            $what = $raised->reminder ? 'Pengingat alert' : 'Alert';
            $this->line("{$what} audit_mismatch critical {$raised->alertId} terkirim ke {$count} kanal.");

            return;
        }

        $this->error("Alert audit_mismatch {$raised->alertId} TIDAK terkirim ke kanal mana pun.");
        $this->line('Tindakan: periksa kanal dengan sadmin:notify-test; alert dikirim ulang pada deteksi berikutnya.');
    }
}
