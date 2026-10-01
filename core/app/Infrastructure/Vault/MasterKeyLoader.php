<?php

namespace App\Infrastructure\Vault;

/**
 * Memuat kunci induk (ADR 0003 §2.1): berkas dev bila SADMIN_VAULT_DEV_KEY diisi (hanya APP_ENV local/testing),
 * selain itu kredensial systemd $CREDENTIALS_DIRECTORY/<SADMIN_VAULT_CRED>. Dibaca setiap kali dipakai, tanpa
 * cache: core tak pernah menyalin kunci induk ke tempat lain.
 */
final class MasterKeyLoader
{
    private const CREDENTIAL_NAME = '/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z/';

    /**
     * @param  string  $systemdCredentialsRoot  systemd.exec menaruh kredensial unit di /run/credentials/<unit>/. Bukan
     *                                          config/env: hanya tes yang menggantinya, agar jalur ketat bisa dibuktikan.
     */
    public function __construct(private readonly string $systemdCredentialsRoot = '/run/credentials/') {}

    public function load(): MasterKey
    {
        // Dibaca saat runtime, bukan lewat config, agar config:cache tak membekukan lokasi kredensial.
        $directory = getenv('CREDENTIALS_DIRECTORY');
        $directory = is_string($directory) && $directory !== '' ? $directory : null;
        // Daftar izin, bukan daftar tolak: APP_ENV yang salah ketik (mis. "Production") jatuh ke jalur ketat.
        $development = app()->environment(['local', 'testing']);

        $devFile = (string) config('sadmin.vault.dev_key_file');
        if ($devFile !== '') {
            if (! $development) {
                throw new VaultUnavailable('SADMIN_VAULT_DEV_KEY hanya untuk APP_ENV local/testing; di luar itu kunci induk wajib dari kredensial systemd (ADR 0003 §2.1).');
            }
            if ($directory !== null) {
                throw new VaultUnavailable('SADMIN_VAULT_DEV_KEY dan CREDENTIALS_DIRECTORY sama-sama terisi; kosongkan salah satunya (ADR 0003 §2.1).');
            }

            return new MasterKey(MasterKey::CURRENT_VERSION, $this->read($devFile, privateFile: true), 'berkas dev SADMIN_VAULT_DEV_KEY');
        }

        $name = (string) config('sadmin.vault.credential');
        if (preg_match(self::CREDENTIAL_NAME, $name) !== 1) {
            throw new VaultUnavailable('Nama kredensial SADMIN_VAULT_CRED tak sah: hanya huruf, angka, titik, garis bawah, dan tanda hubung (maks. 64).');
        }
        if ($directory === null) {
            throw new VaultUnavailable("Kunci induk tak tersedia: CREDENTIALS_DIRECTORY kosong. Core harus berjalan sebagai unit systemd yang memuat kredensial \"{$name}\" (ADR 0003 §2.1).");
        }
        // Di luar dev, .env yang diubah tak boleh mengarahkan kunci induk ke berkas polos sembarang.
        if (! $development && ! $this->isSystemdCredentialsDirectory($directory)) {
            throw new VaultUnavailable("CREDENTIALS_DIRECTORY wajib direktori kredensial systemd di bawah {$this->systemdCredentialsRoot} (ADR 0003 §2.1).");
        }

        // Izin berkas kredensial diatur systemd (bisa lewat ACL), jadi tak diperiksa di sini.
        return new MasterKey(MasterKey::CURRENT_VERSION, $this->read(rtrim($directory, '/').'/'.$name, privateFile: false), "kredensial systemd {$name}");
    }

    private function isSystemdCredentialsDirectory(string $directory): bool
    {
        $real = realpath($directory);
        $root = rtrim($this->systemdCredentialsRoot, '/').'/';

        return $real !== false && str_starts_with($real, $root) && strlen($real) > strlen($root);
    }

    /** Diperiksa dan dibaca lewat satu handle: tanpa celah cek-lalu-pakai, dan tak pernah membaca lebih dari 32 byte. */
    private function read(string $path, bool $privateFile): SecretValue
    {
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            throw new VaultUnavailable("Berkas kunci induk tidak ada atau tak dapat dibaca: {$path}");
        }

        try {
            $stat = fstat($handle);
            if ($stat === false || ($stat['mode'] & 0o170000) !== 0o100000) {
                throw new VaultUnavailable("Kunci induk harus berkas biasa: {$path}");
            }
            if ($privateFile && ($stat['mode'] & 0o077) !== 0) {
                throw new VaultUnavailable("Berkas kunci induk {$path} dapat diakses pengguna lain; jalankan chmod 600.");
            }
            if ($stat['size'] !== MasterKey::BYTES) {
                throw new VaultUnavailable('Kunci induk harus tepat '.MasterKey::BYTES." byte mentah; berkas {$path} berisi {$stat['size']} byte.");
            }

            $bytes = fread($handle, MasterKey::BYTES);
        } finally {
            fclose($handle);
        }

        if ($bytes === false || strlen($bytes) !== MasterKey::BYTES) {
            throw new VaultUnavailable("Berkas kunci induk tak terbaca utuh: {$path}");
        }

        return new SecretValue($bytes);
    }
}
