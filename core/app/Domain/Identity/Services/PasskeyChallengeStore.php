<?php

namespace App\Domain\Identity\Services;

/**
 * Opsi ceremony (berisi challenge) disimpan di sesi sampai dijawab. Diambil sekali pakai (pull), sehingga
 * satu challenge tak bisa dipakai ulang, dan kedaluwarsa setelah TTL.
 */
final class PasskeyChallengeStore
{
    private const TTL_SECONDS = 300;

    public function put(string $purpose, string $optionsJson): void
    {
        session()->put($this->key($purpose), ['options' => $optionsJson, 'at' => now()->getTimestamp()]);
    }

    public function pull(string $purpose): ?string
    {
        $entry = session()->pull($this->key($purpose));
        if (! is_array($entry) || ! isset($entry['options'], $entry['at']) || now()->getTimestamp() - (int) $entry['at'] > self::TTL_SECONDS) {
            return null;
        }

        return (string) $entry['options'];
    }

    private function key(string $purpose): string
    {
        return 'passkey_ceremony.'.$purpose;
    }
}
