<?php

namespace App\Domain\Fleet\Data;

/** Nilai `agents.connection` (docs/07_DATA_MODEL.md). */
enum AgentConnection: string
{
    case Connected = 'connected';
    case Disconnected = 'disconnected';

    public function label(): string
    {
        return match ($this) {
            self::Connected => 'Terhubung',
            self::Disconnected => 'Terputus',
        };
    }
}
