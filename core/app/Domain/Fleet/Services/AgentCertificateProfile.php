<?php

namespace App\Domain\Fleet\Services;

use App\Domain\Fleet\Data\CertificateRequestRejected;
use App\Domain\Fleet\Data\CertificateVerification;
use App\Domain\Fleet\Data\IssuedCertificate;
use DateTimeImmutable;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;

/**
 * Aturan sertifikat & pin CA ../kontrak/KONTRAK.md §2 di sisi core (ADR 0007): profil ekstensi CA dan sertifikat
 * klien, pemeriksaan CSR, aturan penerimaan sertifikat yang sama dengan gateway, dan pin `ca_sha256`. Hanya memakai
 * kunci publik; kunci privat CA tak pernah lewat sini. Teks dari agen hanya diteruskan ke OpenSSL sebagai PEM yang
 * dibangun ulang dari DER hasil urai sendiri, jadi bentuk lain (mis. `file://…`) tak pernah sampai ke OpenSSL.
 */
final class AgentCertificateProfile
{
    public const CA_COMMON_NAME = 'sAdmin internal CA';

    public const CA_DAYS = 3650;

    public const AGENT_CERT_DAYS = 7;

    public const AGENT_CERT_SECONDS = 604800;

    public const CSR_MAX_BYTES = 4096;

    private const ULID = '[0-7][0-9a-hjkmnp-tv-z]{25}';

    private const SAN_PREFIX = 'sadmin://server/';

    private const CURVE = 'prime256v1';

    /** DER AlgorithmIdentifier ecdsa-with-SHA256 (1.2.840.10045.4.3.2) tanpa parameter. */
    private const ECDSA_WITH_SHA256 = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";

    private const EMPTY_NAME = "\x30\x00";

    /** OID DER ekstensi profil sertifikat klien => kritis (KONTRAK §2: tepat lima, tiga kritis). */
    private const AGENT_EXTENSIONS = [
        "\x06\x03\x55\x1d\x11" => true,  // subjectAltName
        "\x06\x03\x55\x1d\x13" => true,  // basicConstraints
        "\x06\x03\x55\x1d\x0f" => true,  // keyUsage
        "\x06\x03\x55\x1d\x25" => false, // extendedKeyUsage
        "\x06\x03\x55\x1d\x23" => false, // authorityKeyIdentifier
    ];

    /** @return array<string, string> ekstensi sertifikat CA, nama config OpenSSL => nilai */
    public static function authorityExtensions(): array
    {
        return [
            'basicConstraints' => 'critical, CA:TRUE, pathlen:0',
            'keyUsage' => 'critical, keyCertSign, cRLSign',
            'subjectKeyIdentifier' => 'hash',
        ];
    }

    /** @return array<string, string> ekstensi sertifikat klien agen, nama config OpenSSL => nilai */
    public static function agentExtensions(string $serverId): array
    {
        if (! self::isServerId($serverId)) {
            throw new InvalidArgumentException('server_id harus ULID huruf kecil (KONTRAK §8).');
        }

        return [
            'subjectAltName' => 'critical, URI:'.self::SAN_PREFIX.$serverId,
            'basicConstraints' => 'critical, CA:FALSE',
            'keyUsage' => 'critical, digitalSignature',
            'extendedKeyUsage' => 'clientAuth',
            'authorityKeyIdentifier' => 'keyid:always',
        ];
    }

    /**
     * Masa berlaku terbitan sesuai profil: tepat $days hari, atau satu detik lebih. OpenSSL lewat PHP mengisi notBefore
     * dan notAfter dari dua pembacaan jam, jadi detik bisa berganti di antaranya (terukur ≈1 dari 50.000 terbitan).
     */
    public static function issuedValidityConforms(int $seconds, int $days): bool
    {
        return $seconds === $days * 86400 || $seconds === $days * 86400 + 1;
    }

    public static function isServerId(string $id): bool
    {
        return preg_match('/\A'.self::ULID.'\z/', $id) === 1;
    }

    /** Pin CA (`--ca-sha256`): SHA-256 atas DER sertifikat CA, 64 hex huruf kecil. */
    public static function fingerprint(string $caPem): string
    {
        $der = self::pemBlock($caPem, 'CERTIFICATE') ?? throw new InvalidArgumentException('Sertifikat CA bukan satu blok PEM CERTIFICATE.');

        return hash('sha256', $der);
    }

    /**
     * Memeriksa CSR agen menurut KONTRAK §2 secara berurutan; pelanggaran pertama dilempar sebagai
     * CertificateRequestRejected. Tanda tangan diverifikasi eksplisit atas DER CertificationRequestInfo.
     *
     * @return array{csr: string, publicKey: string} CSR (PEM dibangun ulang dari DER) dan kunci publiknya (PEM)
     */
    public static function checkRequest(string $csrPem): array
    {
        if (strlen($csrPem) > self::CSR_MAX_BYTES) {
            throw new CertificateRequestRejected('size');
        }
        $der = self::pemBlock($csrPem, 'CERTIFICATE REQUEST') ?? throw new CertificateRequestRejected('pem');

        $parts = self::children($der);
        $info = $parts !== null && count($parts) === 3 ? self::children($parts[0]) : null;
        $signature = $parts !== null && count($parts) === 3 ? self::bitString($parts[2]) : null;
        if ($parts === null || $info === null || count($info) !== 4 || $signature === null) {
            throw new CertificateRequestRejected('structure');
        }
        $csr = self::pem($der, 'CERTIFICATE REQUEST');
        $publicKey = self::quietly(fn () => openssl_csr_get_public_key($csr));
        if (! $publicKey instanceof OpenSSLAsymmetricKey) {
            throw new CertificateRequestRejected('structure');
        }

        $publicKeyPem = self::p256Pem($publicKey) ?? throw new CertificateRequestRejected('key');
        if ($info[1] !== self::EMPTY_NAME) {
            throw new CertificateRequestRejected('subject');
        }
        if ($parts[1] !== self::ECDSA_WITH_SHA256 || self::quietly(fn () => openssl_verify($parts[0], $signature, $publicKey, OPENSSL_ALGO_SHA256)) !== 1) {
            throw new CertificateRequestRejected('signature');
        }

        return ['csr' => $csr, 'publicKey' => $publicKeyPem];
    }

    /**
     * Aturan penerimaan sertifikat klien di gateway (KONTRAK §2), berurutan, pada waktu $now (detik Unix). Sertifikat
     * CA adalah masukan tepercaya (dipin), jadi CA yang tak terurai = galat masukan, bukan penolakan.
     */
    public static function verify(string $certPem, string $caPem, int $now): CertificateVerification
    {
        $caDer = self::pemBlock($caPem, 'CERTIFICATE');
        $caNames = $caDer === null ? null : self::names($caDer);
        $ca = $caDer === null ? false : self::quietly(fn () => openssl_x509_read(self::pem($caDer, 'CERTIFICATE')));
        $caInfo = $ca instanceof OpenSSLCertificate ? openssl_x509_parse($ca) : false;
        $caKey = $ca instanceof OpenSSLCertificate ? self::quietly(fn () => openssl_pkey_get_public($ca)) : false;
        if ($caNames === null || $caInfo === false || ! $caKey instanceof OpenSSLAsymmetricKey) {
            throw new InvalidArgumentException('Sertifikat CA tak dapat diurai.');
        }

        $der = self::pemBlock($certPem, 'CERTIFICATE');
        if ($der === null) {
            return CertificateVerification::rejected('pem');
        }
        $names = self::names($der);
        $cert = $names === null ? false : self::quietly(fn () => openssl_x509_read(self::pem($der, 'CERTIFICATE')));
        $info = $cert instanceof OpenSSLCertificate ? openssl_x509_parse($cert) : false;
        $key = $cert instanceof OpenSSLCertificate ? self::quietly(fn () => openssl_pkey_get_public($cert)) : false;
        if ($names === null || ! $cert instanceof OpenSSLCertificate || $info === false || ! $key instanceof OpenSSLAsymmetricKey) {
            return CertificateVerification::rejected('structure');
        }

        $extensions = $info['extensions'] ?? [];
        $clientAuth = in_array('TLS Web Client Authentication', explode(', ', (string) ($extensions['extendedKeyUsage'] ?? '')), true);
        $san = preg_match('#\AURI:'.preg_quote(self::SAN_PREFIX, '#').'('.self::ULID.')\z#', (string) ($extensions['subjectAltName'] ?? ''), $match) === 1;

        return match (true) {
            $names['issuer'] !== $caNames['subject'] => CertificateVerification::rejected('issuer'),
            self::quietly(fn () => openssl_x509_verify($cert, $caKey)) !== 1 => CertificateVerification::rejected('signature'),
            ! self::within($info, $now) || ! self::within($caInfo, $now) => CertificateVerification::rejected('validity'),
            self::p256Pem($key) === null => CertificateVerification::rejected('key'),
            ($extensions['basicConstraints'] ?? null) !== 'CA:FALSE' => CertificateVerification::rejected('basic_constraints'),
            ! $clientAuth => CertificateVerification::rejected('eku'),
            ! $san => CertificateVerification::rejected('san'),
            default => CertificateVerification::accepted($match[1]),
        };
    }

    /**
     * Profil penerbitan ADR 0007 §2.3 langkah 5: sertifikat terbitan wajib lolos aturan gateway pada notBefore-nya
     * dengan server_id yang diminta, bersubjek kosong, berumur 7 hari (issuedValidityConforms), berkunci CSR, berserial yang dibuat,
     * bertanda tangan ecdsa-with-SHA256, dan tepat lima ekstensi profil dengan flag kritis yang benar (dibaca dari DER,
     * karena openssl_x509_parse tak menampilkan flag kritis). Null bila ada yang tak cocok.
     */
    public static function conformingIssued(string $certPem, string $caPem, string $serverId, string $publicKeyPem, int $serial): ?IssuedCertificate
    {
        $der = self::pemBlock($certPem, 'CERTIFICATE');
        $names = $der === null ? null : self::names($der);
        $info = $der === null ? false : self::quietly(fn () => openssl_x509_parse(self::pem($der, 'CERTIFICATE')));
        $key = $der === null ? false : self::quietly(fn () => openssl_pkey_get_public(self::pem($der, 'CERTIFICATE')));
        if ($names === null || $info === false || ! $key instanceof OpenSSLAsymmetricKey) {
            return null;
        }

        $expectedExtensions = self::AGENT_EXTENSIONS;
        ksort($expectedExtensions);
        $notBefore = (int) $info['validFrom_time_t'];
        $notAfter = (int) $info['validTo_time_t'];

        $conforms = self::verify($certPem, $caPem, $notBefore)->serverId === $serverId
            && $names['subject'] === self::EMPTY_NAME
            && self::issuedValidityConforms($notAfter - $notBefore, self::AGENT_CERT_DAYS)
            && self::p256Pem($key) === $publicKeyPem
            && ($info['serialNumber'] ?? null) === (string) $serial
            && ($info['signatureTypeSN'] ?? null) === 'ecdsa-with-SHA256'
            && self::extensionCriticality((string) $der) === $expectedExtensions;

        return $conforms ? new IssuedCertificate(
            certificatePem: self::pem((string) $der, 'CERTIFICATE'),
            serial: dechex($serial),
            notBefore: new DateTimeImmutable("@{$notBefore}"),
            notAfter: new DateTimeImmutable("@{$notAfter}"),
            serverId: $serverId,
        ) : null;
    }

    /**
     * OID DER ekstensi sertifikat => flag kritis, dalam urutan aslinya, atau null bila bagian ekstensi tak terurai.
     *
     * @return array<string, bool>|null
     */
    private static function extensionCriticality(string $der): ?array
    {
        $certificate = self::children($der);
        $tbs = $certificate !== null && count($certificate) === 3 ? self::children($certificate[0]) : null;
        $wrapper = null;
        foreach ($tbs ?? [] as $item) {
            if (ord($item[0]) === 0xA3) {
                $wrapper = $item; // [3] EXPLICIT Extensions
            }
        }
        $head = $wrapper === null ? null : self::header($wrapper, 0, strlen($wrapper));
        $extensions = $head === null ? null : self::children(substr($wrapper, $head['start'], $head['end'] - $head['start']));
        if ($extensions === null) {
            return null;
        }

        $flags = [];
        foreach ($extensions as $extension) {
            $fields = self::children($extension);
            if ($fields === null || count($fields) < 2 || count($fields) > 3 || isset($flags[$fields[0]])) {
                return null;
            }
            $flags[$fields[0]] = count($fields) === 3 && $fields[1] === "\x01\x01\xff";
        }
        ksort($flags);

        return $flags;
    }

    /** @param array<string, mixed> $info hasil openssl_x509_parse */
    private static function within(array $info, int $now): bool
    {
        return (int) $info['validFrom_time_t'] <= $now && $now <= (int) $info['validTo_time_t'];
    }

    /** PEM kunci publik bila ECDSA P-256; selain itu null. */
    private static function p256Pem(OpenSSLAsymmetricKey $key): ?string
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC || ($details['ec']['curve_name'] ?? null) !== self::CURVE) {
            return null;
        }

        return (string) $details['key'];
    }

    /** DER satu blok PEM berlabel $label menurut aturan `pem` KONTRAK §2, atau null. */
    private static function pemBlock(string $text, string $label): ?string
    {
        $pattern = '/\A-----BEGIN '.$label.'-----\n((?:[A-Za-z0-9+\/=]+\n)+)-----END '.$label.'-----\n?\z/';
        if (preg_match($pattern, $text, $match) !== 1) {
            return null;
        }
        $der = base64_decode(str_replace("\n", '', $match[1]), true);

        return $der === false || $der === '' ? null : $der;
    }

    private static function pem(string $der, string $label): string
    {
        return "-----BEGIN {$label}-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END {$label}-----\n";
    }

    /**
     * Byte DER mentah penerbit dan subjek dari satu sertifikat X.509, atau null bila strukturnya bukan sertifikat.
     *
     * @return array{issuer: string, subject: string}|null
     */
    private static function names(string $der): ?array
    {
        $certificate = self::children($der);
        $tbs = $certificate !== null && count($certificate) === 3 ? self::children($certificate[0]) : null;
        if ($tbs !== null && $tbs !== [] && ord($tbs[0][0]) === 0xA0) {
            array_shift($tbs); // [0] EXPLICIT version
        }

        return $tbs !== null && count($tbs) >= 6 ? ['issuer' => $tbs[2], 'subject' => $tbs[4]] : null;
    }

    /** Isi BIT STRING DER tanpa bit sisa, atau null. */
    private static function bitString(string $tlv): ?string
    {
        $head = self::header($tlv, 0, strlen($tlv));
        if ($head === null || $head['tag'] !== 0x03 || $head['end'] !== strlen($tlv) || $head['start'] >= $head['end'] || $tlv[$head['start']] !== "\x00") {
            return null;
        }

        return substr($tlv, $head['start'] + 1);
    }

    /**
     * TLV mentah anak-anak satu SEQUENCE DER yang mengisi $der persis (tanpa sisa byte), atau null.
     *
     * @return list<string>|null
     */
    private static function children(string $der): ?array
    {
        $outer = self::header($der, 0, strlen($der));
        if ($outer === null || $outer['tag'] !== 0x30 || $outer['end'] !== strlen($der)) {
            return null;
        }

        $items = [];
        for ($offset = $outer['start']; $offset < $outer['end']; $offset = $item['end']) {
            $item = self::header($der, $offset, $outer['end']);
            if ($item === null) {
                return null;
            }
            $items[] = substr($der, $offset, $item['end'] - $offset);
        }

        return $items;
    }

    /**
     * Kepala TLV DER di $offset: tag satu byte, panjang bentuk minimal (tanpa panjang tak tentu BER).
     *
     * @return array{tag: int, start: int, end: int}|null start = awal isi, end = akhir TLV
     */
    private static function header(string $der, int $offset, int $limit): ?array
    {
        if ($offset + 2 > $limit || (ord($der[$offset]) & 0x1F) === 0x1F) {
            return null;
        }
        $tag = ord($der[$offset]);
        $length = ord($der[$offset + 1]);
        $start = $offset + 2;
        if ($length > 0x7F) {
            $bytes = $length & 0x7F;
            if ($bytes === 0 || $bytes > 3 || $start + $bytes > $limit || $der[$start] === "\x00") {
                return null;
            }
            $length = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $length = ($length << 8) | ord($der[$start + $i]);
            }
            if ($length < 0x80) {
                return null;
            }
            $start += $bytes;
        }

        return $start + $length > $limit ? null : ['tag' => $tag, 'start' => $start, 'end' => $start + $length];
    }

    /**
     * Fungsi OpenSSL melapor gagal lewat nilai kembali dan warning PHP; warning ditelan (Laravel menjadikannya
     * exception) dan antrean galat OpenSSL dikosongkan. Pemanggil memeriksa nilai kembali.
     *
     * @template T
     *
     * @param  callable(): T  $fn
     * @return T
     */
    private static function quietly(callable $fn): mixed
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
