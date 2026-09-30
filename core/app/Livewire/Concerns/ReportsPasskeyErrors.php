<?php

namespace App\Livewire\Concerns;

use App\Domain\Identity\Data\PasskeyRejected;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Livewire\Attributes\Locked;

/** State "Gagal" untuk ceremony passkey: alasan tetap dari PasskeyRejected::REASONS + ID korelasi (docs/14). */
trait ReportsPasskeyErrors
{
    #[Locked]
    public ?string $errorReason = null;

    #[Locked]
    public ?string $correlationId = null;

    /** Galat dari browser: hanya nama DOMException yang dikenal dipetakan; isinya tak pernah digemakan. */
    public function clientFailed(string $name): void
    {
        $this->fail(match ($name) {
            'NotSupportedError' => 'unsupported',
            'SecurityError' => 'origin_mismatch',
            default => 'cancelled',
        });
    }

    /** @param  string|null  $correlationId  dari PasskeyRejected, agar ID yang tampil = ID di log detail & audit */
    protected function fail(string $reason, ?string $correlationId = null): void
    {
        $this->errorReason = in_array($reason, PasskeyRejected::REASONS, true) ? $reason : 'verification_failed';
        $this->correlationId = $correlationId ?? (string) Str::ulid();
        Log::warning('passkey_rejected', ['reason' => $this->errorReason, 'correlation_id' => $this->correlationId]);
    }

    protected function clearError(): void
    {
        $this->reset('errorReason', 'correlationId');
    }

    public function errorMessage(): ?string
    {
        if ($this->errorReason === null) {
            return null;
        }
        $parts = __("errors.passkey.{$this->errorReason}");

        return __('errors.format', is_array($parts) ? $parts : []);
    }
}
