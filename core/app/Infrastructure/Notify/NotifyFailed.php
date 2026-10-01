<?php

namespace App\Infrastructure\Notify;

use RuntimeException;
use SensitiveParameter;
use Throwable;

/**
 * Pengiriman ke satu kanal gagal. Pesannya sudah dibersihkan dari nilai rahasia, dan galat asli pustaka HTTP/SMTP
 * sengaja tidak dirantai: pesan dan jejaknya bisa memuat URL Bot API yang berisi token (ADR 0005 §2.6).
 */
final class NotifyFailed extends RuntimeException
{
    private const MAX_MESSAGE = 300;

    /**
     * Pesan mentah dan galat asli ditandai sensitif: keduanya ikut tercatat sebagai argumen di jejak exception ini
     * bila zend.exception_ignore_args mati, dan bisa memuat URL bertoken.
     *
     * @param  list<string>  $secrets
     */
    public static function scrubbed(#[SensitiveParameter] string $message, #[SensitiveParameter] array $secrets): self
    {
        foreach ($secrets as $secret) {
            if ($secret !== '') {
                $message = str_replace($secret, '[disamarkan]', $message);
            }
        }
        $message = (string) preg_replace('#/bot[^/\s]*#i', '/bot[disamarkan]', $message);

        return new self(mb_strimwidth($message, 0, self::MAX_MESSAGE, '…'));
    }

    /** @param  list<string>  $secrets */
    public static function from(#[SensitiveParameter] Throwable $e, #[SensitiveParameter] array $secrets): self
    {
        return self::scrubbed(class_basename($e).': '.$e->getMessage(), $secrets);
    }
}
