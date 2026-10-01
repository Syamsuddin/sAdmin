<?php

// Teks peringatan & kanal notifikasi (ADR 0005 §2.4). Teks polos: tak ada markup, dan tak pernah memuat nilai rahasia.
return [
    'subject' => '[sAdmin][:severity] :title — :host',
    'body' => "[:severity] sAdmin :host: :title\nLangkah: :langkah\nPenyebab: :penyebab\nTindakan: :tindakan\n(ID: :id)",

    'audit_mismatch' => [
        'title' => 'Audit tidak utuh',
        'langkah' => [
            'chain' => 'Verifikasi rantai audit (sadmin:audit-verify)',
            'checkpoint' => 'Verifikasi checkpoint audit (sadmin:audit-verify)',
            'checkpoint_create' => 'Pembuatan checkpoint audit (sadmin:audit-checkpoint)',
            'checkpoint_readback' => 'Pembuatan checkpoint audit (sadmin:audit-checkpoint)',
        ],
        'penyebab_seq' => 'kerusakan terdeteksi pada seq :seq: :reason.',
        'penyebab' => ':reason.',
        'tindakan' => 'jangan ubah data apa pun; perlakukan sebagai insiden keamanan, jalankan sadmin:audit-verify, dan bandingkan dengan jangkar audit di agen/offsite.',
    ],

    'test' => [
        'subject' => '[sAdmin] Uji notifikasi — :host',
        'body' => "Pesan uji dari sAdmin :host. Kanal ini akan menerima peringatan critical, misalnya audit tidak utuh.\n(ID: :id)",
    ],

    'attributes' => [
        'chat_id' => 'ID chat Telegram',
        'host' => 'host SMTP',
        'port' => 'port SMTP',
        'tls' => 'mode TLS',
        'username' => 'nama pengguna SMTP',
        'from' => 'alamat pengirim',
        'to' => 'daftar penerima',
        'to.*' => 'alamat penerima',
    ],

    'validation' => [
        'required' => ':attribute wajib diisi.',
        'string' => ':attribute harus berupa teks.',
        'regex' => ':attribute tidak sah.',
        'email' => ':attribute bukan alamat email yang sah.',
        'integer' => ':attribute harus bilangan bulat.',
        'between' => ':attribute harus antara :min dan :max.',
        'in' => ':attribute harus salah satu dari: :values.',
        'array' => ':attribute harus berupa daftar.',
        'min' => ':attribute minimal :min.',
        'max' => ':attribute maksimal :max.',
        'distinct' => ':attribute tidak boleh ganda.',
        'token' => 'Token bot Telegram tidak sah (format: <angka>:<kode dari BotFather>).',
    ],
];
