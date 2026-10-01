<?php

namespace App\Infrastructure\Notify;

use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\Vault;
use App\Models\NotificationChannel;
use Illuminate\Support\Facades\Http;
use Throwable;

/** Kirim lewat Bot API Telegram `sendMessage`, teks polos (ADR 0005 §2.4–2.6). */
final class TelegramNotifier implements Notifier
{
    public const API = 'https://api.telegram.org';

    /** `D`: `$` tak boleh cocok sebelum baris baru di akhir. */
    private const TOKEN_PATTERN = '/^[0-9]{5,20}:[A-Za-z0-9_-]{30,64}$/D';

    private const CONNECT_TIMEOUT = 5.0;

    public function __construct(private readonly Vault $vault) {}

    public static function isValidToken(SecretValue $token): bool
    {
        return preg_match(self::TOKEN_PATTERN, $token->expose()) === 1;
    }

    public function send(NotificationChannel $channel, NotificationMessage $message, float $timeoutSeconds): void
    {
        $token = $this->vault->reveal($channel->secret_id, SecretPurpose::TelegramToken, $channel->tenant_id);

        try {
            $response = Http::connectTimeout(min(self::CONNECT_TIMEOUT, $timeoutSeconds))
                ->timeout($timeoutSeconds)
                ->acceptJson()
                ->asJson()
                ->post(self::API.'/bot'.$token->expose().'/sendMessage', [
                    'chat_id' => (string) $channel->config['chat_id'],
                    'text' => $message->asText(),
                    'disable_web_page_preview' => true,
                ]);
        } catch (Throwable $e) {
            throw NotifyFailed::from($e, [$token->expose()]);
        }

        if (! $response->successful() || $response->json('ok') !== true) {
            $description = $response->json('description');

            throw NotifyFailed::scrubbed(
                'Telegram menolak: HTTP '.$response->status().(is_string($description) ? " {$description}" : ''),
                [$token->expose()],
            );
        }
    }
}
