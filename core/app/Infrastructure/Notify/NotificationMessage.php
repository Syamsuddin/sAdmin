<?php

namespace App\Infrastructure\Notify;

/** Isi satu notifikasi: teks polos, tanpa markup dan tanpa nilai rahasia (ADR 0005 §2.4). */
final readonly class NotificationMessage
{
    public function __construct(
        public string $subject,
        public string $body,
    ) {}

    /** Telegram tak punya subjek: subjek jadi baris pertama. */
    public function asText(): string
    {
        return $this->subject."\n\n".$this->body;
    }
}
