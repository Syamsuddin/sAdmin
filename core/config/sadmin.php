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

    // Brankas (ADR 0003 §2.1). Produksi: kunci induk dari $CREDENTIALS_DIRECTORY/<credential>, dibaca saat runtime.
    'vault' => [
        'credential' => env('SADMIN_VAULT_CRED', 'sadmin-vault-master'),
        // Dev/tes saja: path berkas 32 byte mentah bermode 0600. Ditolak bila APP_ENV=production.
        'dev_key_file' => env('SADMIN_VAULT_DEV_KEY'),
    ],
];
