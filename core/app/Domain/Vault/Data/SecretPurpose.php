<?php

namespace App\Domain\Vault\Data;

/** Nilai `secrets.purpose` (docs/07_DATA_MODEL.md); ikut diikat ke ciphertext lewat AAD (ADR 0003 §2.3). */
enum SecretPurpose: string
{
    case DbPassword = 'db_password';
    case Env = 'env';
    case DeployKey = 'deploy_key';
    case ApiToken = 'api_token';
    case TelegramToken = 'telegram_token';
    case Smtp = 'smtp';
    case Upload = 'upload';
    case ServiceKey = 'service_key';
    case AuditKey = 'audit_key';
    case CaKey = 'ca_key';
    case GatewayHmac = 'gateway_hmac';
    case AiApiKey = 'ai_api_key';
}
