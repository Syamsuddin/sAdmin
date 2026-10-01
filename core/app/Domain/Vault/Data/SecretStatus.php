<?php

namespace App\Domain\Vault\Data;

/** Nilai `secrets.status` (docs/07_DATA_MODEL.md). `destroyed` = ciphertext & kunci data ditimpa nol (ADR 0003 §2.4). */
enum SecretStatus: string
{
    case Active = 'active';
    case Rotated = 'rotated';
    case Destroyed = 'destroyed';
}
