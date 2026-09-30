<?php

// Pesan galat untuk admin (docs/14): langkah, penyebab, tindakan. Tak pernah memuat stack trace atau isi dari klien.
return [
    'format' => 'Langkah :langkah gagal: :penyebab Tindakan: :tindakan',

    'load' => [
        'passkeys' => [
            'langkah' => 'Memuat daftar passkey',
            'penyebab' => 'data tidak dapat dibaca dari basis data.',
            'tindakan' => 'klik Coba lagi. Bila berulang, laporkan ID berikut.',
        ],
    ],

    'passkey' => [
        'challenge_missing' => [
            'langkah' => 'Verifikasi passkey',
            'penyebab' => 'permintaan passkey sudah kedaluwarsa atau sudah dipakai.',
            'tindakan' => 'klik Coba lagi, lalu sentuh passkey Anda dalam satu menit.',
        ],
        'unknown_credential' => [
            'langkah' => 'Masuk dengan passkey',
            'penyebab' => 'passkey ini tidak terdaftar di console ini atau sudah dicabut.',
            'tindakan' => 'pilih passkey lain yang terdaftar untuk console ini.',
        ],
        'verification_failed' => [
            'langkah' => 'Verifikasi passkey',
            'penyebab' => 'jawaban autentikator tidak lolos verifikasi (alamat console, verifikasi pengguna, atau tanda tangan tidak cocok).',
            'tindakan' => 'pastikan Anda membuka console dari alamat resminya, lalu coba lagi. Bila berulang, laporkan ID berikut.',
        ],
        'admin_inactive' => [
            'langkah' => 'Masuk dengan passkey',
            'penyebab' => 'akun admin ini dinonaktifkan.',
            'tindakan' => 'hubungi pemegang root host sAdmin.',
        ],
        'registration_complete' => [
            'langkah' => 'Daftarkan passkey',
            'penyebab' => 'akun ini sudah memiliki dua passkey.',
            'tindakan' => 'masuk ke console. Menambah atau mencabut passkey adalah perubahan roster (L3).',
        ],
        'credential_exists' => [
            'langkah' => 'Daftarkan passkey',
            'penyebab' => 'passkey ini sudah terdaftar.',
            'tindakan' => 'gunakan autentikator lain untuk passkey kedua.',
        ],
        'invalid_label' => [
            'langkah' => 'Daftarkan passkey',
            'penyebab' => 'nama perangkat wajib diisi, maksimal 60 karakter.',
            'tindakan' => 'isi nama perangkat, mis. "YubiKey kantor", lalu coba lagi.',
        ],
        'invite_expired' => [
            'langkah' => 'Daftarkan passkey',
            'penyebab' => 'tautan pendaftaran sudah kedaluwarsa (berlaku 15 menit).',
            'tindakan' => 'minta pemegang root menjalankan ulang sadmin:admin-invite.',
        ],
        'cancelled' => [
            'langkah' => 'Verifikasi passkey',
            'penyebab' => 'permintaan passkey dibatalkan atau waktunya habis di perangkat Anda.',
            'tindakan' => 'klik Coba lagi, lalu sentuh passkey Anda.',
        ],
        'unsupported' => [
            'langkah' => 'Verifikasi passkey',
            'penyebab' => 'browser ini tidak mendukung passkey.',
            'tindakan' => 'gunakan versi terbaru Firefox, Chrome, Edge, atau Safari.',
        ],
        'origin_mismatch' => [
            'langkah' => 'Verifikasi passkey',
            'penyebab' => 'alamat halaman tidak cocok dengan hostname console yang terdaftar.',
            'tindakan' => 'buka console lewat alamat resminya (lewat WireGuard).',
        ],
        'rate_limited' => [
            'langkah' => 'Masuk dengan passkey',
            'penyebab' => 'terlalu banyak percobaan dalam satu menit.',
            'tindakan' => 'tunggu satu menit, lalu coba lagi.',
        ],
    ],
];
