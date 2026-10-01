<?php

namespace App\Infrastructure\Vault;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use RuntimeException;
use SensitiveParameter;

/**
 * CA internal ECDSA P-256 yang kunci privatnya hanya hidup di brankas (ADR 0007 §2.1). Satu-satunya pemanggil fungsi
 * OpenSSL yang memegang kunci privat. Isi rahasia `ca_key` = blok PEM kunci privat (PKCS#8 `PRIVATE KEY`, atau SEC1
 * `EC PRIVATE KEY` dari build PHP yang mengekspor format itu) disusul blok PEM CERTIFICATE; bentuk lain, kunci yang
 * bukan P-256, atau kunci yang tak cocok dengan sertifikatnya = VaultIntegrityError.
 */
final class X509Authority
{
    private const CURVE = 'prime256v1';

    private const SECTION = 'sadmin_ext';

    /** Nama & nilai ekstensi di config OpenSSL: tanpa LF, `[`, `$`, `@`, `=`, atau `#`, jadi tak bisa menyisipkan bagian atau variabel. */
    private const SAFE_NAME = '/^[A-Za-z]+$/';

    private const SAFE_VALUE = '/^[A-Za-z0-9:\/,. _-]+$/';

    /** Kedua bentuk kunci diterima saat dibuka agar rahasia tetap terbaca setelah PHP diperbarui (ADR 0007 §2.1). */
    private const BUNDLE = '/\A(-----BEGIN ((?:EC )?PRIVATE KEY)-----\n(?:[A-Za-z0-9+\/=]+\n)+-----END \2-----\n)(-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+\/=]+\n)+-----END CERTIFICATE-----\n)\z/';

    /**
     * Kunci P-256 baru beserta sertifikat CA swa-tanda-tangan, sebagai isi rahasia `ca_key`.
     *
     * @param  array<string, string>  $extensions  ekstensi sertifikat CA (nama config OpenSSL => nilai)
     */
    public static function generate(string $commonName, array $extensions, int $days, int $serial): SecretValue
    {
        return self::withConfig($extensions, function (array $options) use ($commonName, $days, $serial): SecretValue {
            $key = self::call(fn () => openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => self::CURVE] + $options));
            if (! $key instanceof OpenSSLAsymmetricKey) {
                throw new RuntimeException('OpenSSL gagal membuat kunci CA.');
            }
            $csr = self::call(fn () => openssl_csr_new(['commonName' => $commonName], $key, $options));
            $cert = $csr === false ? false : self::call(fn () => openssl_csr_sign($csr, null, $key, $days, $options + ['x509_extensions' => self::SECTION], $serial));
            if ($cert === false) {
                throw new RuntimeException('OpenSSL gagal membuat sertifikat CA.');
            }
            $keyPem = '';
            $certPem = '';
            // Closure biasa dengan referensi: arrow fn menangkap $keyPem by value, jadi keluaran by-ref akan hilang.
            $exported = self::call(function () use ($key, &$keyPem, $options): bool {
                return openssl_pkey_export($key, $keyPem, null, $options);
            });
            if (! $exported || ! openssl_x509_export($cert, $certPem)) {
                throw new RuntimeException('OpenSSL gagal membuat sertifikat CA.');
            }

            try {
                $bundle = new SecretValue($keyPem.$certPem);
            } finally {
                sodium_memzero($keyPem);
            }
            self::certificate($bundle);

            return $bundle;
        });
    }

    /** Sertifikat CA (PEM) dari isi rahasia `ca_key`, setelah bentuk dan kecocokan kuncinya diperiksa. */
    public static function certificate(#[SensitiveParameter] SecretValue $bundle): string
    {
        [, $certPem] = self::open($bundle);

        return $certPem;
    }

    /**
     * Menandatangani CSR dengan kunci CA. CSR sudah diperiksa pemanggil (KONTRAK §2); OpenSSL yang tetap menolaknya
     * adalah galat, bukan hasil.
     *
     * @param  array<string, string>  $extensions  ekstensi sertifikat terbitan (nama config OpenSSL => nilai)
     */
    public static function sign(#[SensitiveParameter] SecretValue $bundle, string $csrPem, array $extensions, int $days, int $serial): string
    {
        [$key, $caPem] = self::open($bundle);

        return self::withConfig($extensions, function (array $options) use ($key, $caPem, $csrPem, $days, $serial): string {
            $cert = self::call(fn () => openssl_csr_sign($csrPem, $caPem, $key, $days, $options + ['x509_extensions' => self::SECTION], $serial));
            $certPem = '';
            if ($cert === false || ! openssl_x509_export($cert, $certPem)) {
                throw new InvalidArgumentException('OpenSSL menolak menandatangani CSR.');
            }

            return $certPem;
        });
    }

    /** @return array{OpenSSLAsymmetricKey, string} kunci privat dan sertifikat CA (PEM) */
    private static function open(#[SensitiveParameter] SecretValue $bundle): array
    {
        if (preg_match(self::BUNDLE, $bundle->expose(), $parts) !== 1) {
            throw new VaultIntegrityError('Isi rahasia CA bukan blok kunci privat disusul blok CERTIFICATE (ADR 0007 §2.1).');
        }
        try {
            $key = self::call(fn () => openssl_pkey_get_private($parts[1]));
        } finally {
            sodium_memzero($parts[1]);
            sodium_memzero($parts[0]);
        }

        $details = $key instanceof OpenSSLAsymmetricKey ? openssl_pkey_get_details($key) : false;
        $publicKey = $details === false ? false : self::call(fn () => openssl_pkey_get_public($details['key']));
        $isP256 = $details !== false && $details['type'] === OPENSSL_KEYTYPE_EC && ($details['ec']['curve_name'] ?? null) === self::CURVE;
        if (! $key instanceof OpenSSLAsymmetricKey || ! $publicKey instanceof OpenSSLAsymmetricKey || ! $isP256
            || self::call(fn () => openssl_x509_check_private_key($parts[3], $key)) !== true
            || self::call(fn () => openssl_x509_verify($parts[3], $publicKey)) !== 1) {
            throw new VaultIntegrityError('Kunci CA bukan P-256 atau tak cocok dengan sertifikat CA yang tersimpan bersamanya (ADR 0007 §2.1).');
        }

        return [$key, $parts[3]];
    }

    /**
     * Menjalankan $fn dengan config OpenSSL sementara (0600, dihapus sesudahnya) berisi satu bagian ekstensi. Tanpa
     * config sendiri OpenSSL memakai openssl.cnf sistem, yang isinya di luar kendali sAdmin.
     *
     * @template T
     *
     * @param  array<string, string>  $extensions
     * @param  callable(array{config: string, digest_alg: string}): T  $fn
     * @return T
     */
    private static function withConfig(array $extensions, callable $fn): mixed
    {
        $lines = ['[req]', 'distinguished_name = sadmin_dn', '[sadmin_dn]', '['.self::SECTION.']'];
        foreach ($extensions as $name => $value) {
            if (preg_match(self::SAFE_NAME, $name) !== 1 || preg_match(self::SAFE_VALUE, $value) !== 1) {
                throw new InvalidArgumentException("Ekstensi X.509 {$name} memuat karakter di luar himpunan aman config OpenSSL.");
            }
            $lines[] = "{$name} = {$value}";
        }

        $path = tempnam(sys_get_temp_dir(), 'sadmin-x509-');
        if ($path === false) {
            throw new RuntimeException('Berkas config OpenSSL sementara gagal dibuat.');
        }
        try {
            chmod($path, 0600);
            if (file_put_contents($path, implode("\n", $lines)."\n") === false) {
                throw new RuntimeException('Berkas config OpenSSL sementara gagal ditulis.');
            }

            return $fn(['config' => $path, 'digest_alg' => 'sha256']);
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    /**
     * Fungsi OpenSSL melapor gagal lewat nilai kembali dan warning PHP. Warning-nya ditelan di sini (Laravel
     * menjadikannya exception yang bisa membawa isi argumen) dan antrean galat OpenSSL dikosongkan agar tak
     * terbawa ke pemanggilan berikutnya; pemanggil memeriksa nilai kembali.
     *
     * @template T
     *
     * @param  callable(): T  $fn
     * @return T
     */
    private static function call(callable $fn): mixed
    {
        set_error_handler(static fn (): bool => true);
        try {
            return $fn();
        } finally {
            restore_error_handler();
            while (openssl_error_string() !== false) {
                // kosongkan antrean
            }
        }
    }
}
