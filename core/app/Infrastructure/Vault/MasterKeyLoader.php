<?php

namespace App\Infrastructure\Vault;

/**
 * Memuat kunci induk (ADR 0003 §2.1): berkas dev bila SADMIN_VAULT_DEV_KEY diisi (ditolak di produksi), selain itu
 * kredensial systemd $CREDENTIALS_DIRECTORY/<SADMIN_VAULT_CRED>. Dibaca setiap kali dipakai, tanpa cache: core
 * tak pernah menyalin kunci induk ke tempat lain.
 */
final class MasterKeyLoader
{
    private const CREDENTIAL_NAME = '/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/';

    public function load(): MasterKey
    {
        $devFile = (string) config('sadmin.vault.dev_key_file');
        if ($devFile !== '') {
            if (app()->environment('production')) {
                throw new VaultUnavailable('SADMIN_VAULT_DEV_KEY dilarang di produksi; kunci induk wajib dari kredensial systemd (ADR 0003 §2.1).');
            }

            return new MasterKey(MasterKey::CURRENT_VERSION, $this->read($devFile, privateFile: true), 'berkas dev SADMIN_VAULT_DEV_KEY');
        }

        $name = (string) config('sadmin.vault.credential');
        if (preg_match(self::CREDENTIAL_NAME, $name) !== 1) {
            throw new VaultUnavailable('Nama kredensial SADMIN_VAULT_CRED tak sah: hanya huruf, angka, titik, garis bawah, dan tanda hubung (maks. 64).');
        }

        // Dibaca saat runtime, bukan lewat config, agar config:cache tak membekukan lokasi kredensial.
        $directory = getenv('CREDENTIALS_DIRECTORY');
        if ($directory === false || $directory === '') {
            throw new VaultUnavailable("Kunci induk tak tersedia: CREDENTIALS_DIRECTORY kosong. Core harus berjalan sebagai unit systemd yang memuat kredensial \"{$name}\" (ADR 0003 §2.1).");
        }

        // Izin berkas kredensial diatur systemd (bisa lewat ACL), jadi tak diperiksa di sini.
        return new MasterKey(MasterKey::CURRENT_VERSION, $this->read(rtrim($directory, '/').'/'.$name, privateFile: false), "kredensial systemd {$name}");
    }

    private function read(string $path, bool $privateFile): SecretValue
    {
        clearstatcache(true, $path);
        if (! is_file($path) || ! is_readable($path)) {
            throw new VaultUnavailable("Berkas kunci induk tidak ada atau tak dapat dibaca: {$path}");
        }
        if ($privateFile && (fileperms($path) & 0o077) !== 0) {
            throw new VaultUnavailable("Berkas kunci induk {$path} dapat diakses pengguna lain; jalankan chmod 600.");
        }

        $bytes = file_get_contents($path);
        if ($bytes === false) {
            throw new VaultUnavailable("Berkas kunci induk tak dapat dibaca: {$path}");
        }
        $length = strlen($bytes);
        if ($length !== MasterKey::BYTES) {
            sodium_memzero($bytes);

            throw new VaultUnavailable('Kunci induk harus tepat '.MasterKey::BYTES." byte mentah; berkas {$path} berisi {$length} byte.");
        }

        $key = new SecretValue($bytes);
        sodium_memzero($bytes);

        return $key;
    }
}
