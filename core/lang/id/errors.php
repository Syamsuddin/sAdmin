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
        'servers' => [
            'langkah' => 'Memuat daftar server',
            'penyebab' => 'data tidak dapat dibaca dari basis data.',
            'tindakan' => 'klik Coba lagi. Bila berulang, laporkan ID berikut.',
        ],
    ],

    'server' => [
        'invalid_name' => [
            'langkah' => 'Tambah server',
            'penyebab' => 'nama server wajib 1–63 karakter berupa huruf kecil, angka, atau tanda hubung, dan tidak diawali atau diakhiri tanda hubung.',
            'tindakan' => 'isi nama seperti web1, lalu Simpan.',
        ],
        'name_taken' => [
            'langkah' => 'Tambah server',
            'penyebab' => 'nama server ini sudah dipakai, termasuk oleh server yang sudah dipensiunkan.',
            'tindakan' => 'pilih nama lain, lalu Simpan.',
        ],
        'invalid_hostname' => [
            'langkah' => 'Tambah server',
            'penyebab' => 'hostname bukan nama host DNS yang sah.',
            'tindakan' => 'isi nama host seperti web1.instansi.go.id (huruf, angka, tanda hubung, dan titik), lalu Simpan.',
        ],
        'invalid_ip' => [
            'langkah' => 'Tambah server',
            'penyebab' => 'alamat IP tidak sah, atau termasuk rentang yang tak bisa menjadi alamat server (mis. 127.0.0.1).',
            'tindakan' => 'isi alamat IPv4 atau IPv6 server, lalu Simpan.',
        ],
        'server_limit' => [
            'langkah' => 'Tambah server',
            'penyebab' => 'Mode Tunggal hanya mengelola paling banyak tiga server.',
            'tindakan' => 'pensiunkan server yang tidak dipakai lebih dulu.',
        ],
        'not_enrolling' => [
            'langkah' => 'Terbitkan token enrolment',
            'penyebab' => 'server ini tidak lagi menunggu enrolment.',
            'tindakan' => 'kembali ke daftar server untuk melihat statusnya.',
        ],
        'gateway_unset' => [
            'langkah' => 'Siapkan perintah enrolment',
            'penyebab' => 'alamat gateway (SADMIN_GATEWAY_HOST) belum diatur atau tidak sah.',
            'tindakan' => 'minta pemegang root host sAdmin mengisinya dengan nama host DNS atau IPv4 publik host sAdmin, lalu klik Coba lagi.',
        ],
        'ca_missing' => [
            'langkah' => 'Siapkan perintah enrolment',
            'penyebab' => 'CA internal belum dibuat.',
            'tindakan' => 'minta pemegang root host sAdmin menjalankan sadmin:ca-init, lalu klik Coba lagi.',
        ],
        'vault_unavailable' => [
            'langkah' => 'Siapkan perintah enrolment',
            'penyebab' => 'brankas tidak dapat dibuka karena kunci induk tidak termuat.',
            'tindakan' => 'minta pemegang root host sAdmin memeriksa sadmin:vault-check, lalu klik Coba lagi.',
        ],
    ],

    'theme' => [
        'invalid' => [
            'langkah' => 'Simpan tema',
            'penyebab' => 'pilihan tema tidak dikenal.',
            'tindakan' => 'pilih Ikuti sistem, Terang, atau Gelap.',
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
