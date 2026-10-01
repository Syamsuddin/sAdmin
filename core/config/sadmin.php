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

    // Nama host DNS (huruf kecil) atau IPv4 publik gateway di host sAdmin, untuk `--gateway <host>:8443` perintah
    // enrolment; wajib sama dengan SAN sertifikat server gateway (KONTRAK §2). Kosong = tambah server ditolak.
    'gateway_host' => env('SADMIN_GATEWAY_HOST'),

    // Berkas katalog aksi (../catalog/CATALOG.md) untuk menyusun kebijakan awal agen (ADR 0008 §2.5). Kosong = di sebelah
    // paket core (monorepo); install.sh (F-01) mengisinya untuk instalasi produksi.
    'catalog_path' => env('SADMIN_CATALOG_PATH') ?: base_path('../catalog/CATALOG.md'),

    // Brankas (ADR 0003 §2.1). Produksi: kunci induk dari $CREDENTIALS_DIRECTORY/<credential>, dibaca saat runtime.
    'vault' => [
        'credential' => env('SADMIN_VAULT_CRED', 'sadmin-vault-master'),
        // Dev/tes saja: path berkas 32 byte mentah bermode 0600. Hanya diterima bila APP_ENV local/testing.
        'dev_key_file' => env('SADMIN_VAULT_DEV_KEY'),
    ],
];
