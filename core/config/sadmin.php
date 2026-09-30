<?php

return [
    'webauthn' => [
        // Kosong = https://<institutions.console_hostname>. Diisi hanya di dev bila origin memuat port (ADR 0002).
        'origin' => env('SADMIN_ORIGIN'),
        // Nilai bawaan `sadmin:institution-init`; RP ID sebenarnya = institutions.console_hostname.
        'default_rp_id' => env('SADMIN_RP_ID'),
    ],

    // Tautan pendaftaran passkey dari `sadmin:admin-invite`.
    'invite_ttl_minutes' => 15,

    // Sesi console: idle diatur SESSION_LIFETIME (30), batas mutlak di sini (docs/21).
    'session_absolute_minutes' => 720,

    'login_attempts_per_minute' => 10,
];
