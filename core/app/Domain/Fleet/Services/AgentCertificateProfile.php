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

    /** DER AlgorithmIdentifier ecdsa-with-SHA256 (1.2.840.10045.4.3.2) tanpa parameter. */
    private const ECDSA_WITH_SHA256 = "\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";

    private const EMPTY_NAME = "\x30\x00";

    private const VERSION_0 = "\x02\x01\x00";

    /**
     * SubjectPublicKeyInfo ECDSA P-256 berkurva bernama dengan titik tak terkompresi: awalan ini + 64 byte X‖Y (91 byte).
     * OpenSSL juga menerima kurva eksplisit dan titik terkompresi, padahal Go `crypto/x509` menolak keduanya; karena
     * itu aturan `key` memeriksa byte SPKI mentah (KONTRAK §2), bukan nama kurva hasil OpenSSL.
     */
    private const P256_SPKI_PREFIX = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04";

    private const P256_SPKI_BYTES = 91;

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
     * CertificateRequestRejected. Tata letak DER, versi, dan SPKI diperiksa atas byte mentah sebelum OpenSSL mengurai
     * apa pun; tanda tangan diverifikasi eksplisit atas DER CertificationRequestInfo.
     *
     * @return array{csr: string, publicKey: string} CSR (PEM dibangun ulang dari DER) dan kunci publiknya (PEM)
     */
    public static function checkRequest(string $csrPem): array
    {
        if (strlen($csrPem) > self::CSR_MAX_BYTES) {
            throw new CertificateRequestRejected('size');
        }
        $der = self::pemBlock($csrPem, 'CERTIFICATE REQUEST') ?? throw new CertificateRequestRejected('pem');

        // CertificationRequest = SEQUENCE { CertificationRequestInfo, AlgorithmIdentifier, BIT STRING };
        // CertificationRequestInfo = SEQUENCE { INTEGER 0, Name, SubjectPublicKeyInfo, [0] atribut }.
        $parts = self::children($der);
        $info = $parts !== null && count($parts) === 3 ? self::children($parts[0]) : null;
        if ($parts === null || $info === null || count($info) !== 4 || $info[0] !== self::VERSION_0
            || ord($info[3][0]) !== 0xA0 || ord($parts[1][0]) !== 0x30 || ord($parts[2][0]) !== 0x03) {
            throw new CertificateRequestRejected('structure');
        }
        if (! self::isP256Spki($info[2])) {
            throw new CertificateRequestRejected('key');
        }
        $csr = self::pem($der, 'CERTIFICATE REQUEST');
        $publicKey = self::quietly(fn () => openssl_csr_get_public_key($csr));
        $publicKeyPem = $publicKey instanceof OpenSSLAsymmetricKey ? self::publicKeyPem($publicKey) : null;
        if (! $publicKey instanceof OpenSSLAsymmetricKey || $publicKeyPem === null) {
            throw new CertificateRequestRejected('structure');
        }
        if ($info[1] !== self::EMPTY_NAME) {
            throw new CertificateRequestRejected('subject');
        }
        $signature = self::bitString($parts[2]);
        if ($parts[1] !== self::ECDSA_WITH_SHA256 || $signature === null
            || self::quietly(fn () => openssl_verify($parts[0], $signature, $publicKey, OPENSSL_ALGO_SHA256)) !== 1) {
            throw new CertificateRequestRejected('signature');
        }

        return ['csr' => $csr, 'publicKey' => $publicKeyPem];
    }

    /**
     * Aturan penerimaan sertifikat klien di gateway (KONTRAK §2), berurutan, pada waktu $now (detik Unix). Tata letak
     * DER dan SPKI diperiksa atas byte mentah sebelum OpenSSL mengurai. Sertifikat CA adalah masukan tepercaya (dipin),
     * jadi CA yang tak terurai = galat masukan, bukan penolakan.
     */
    public static function verify(string $certPem, string $caPem, int $now): CertificateVerification
    {
        $caDer = self::pemBlock($caPem, 'CERTIFICATE');
        $caFields = $caDer === null ? null : self::tbsFields($caDer);
        $ca = $caDer === null ? false : self::quietly(fn () => openssl_x509_read(self::pem($caDer, 'CERTIFICATE')));
        $caInfo = $ca instanceof OpenSSLCertificate ? self::parsed($ca) : null;
        $caKey = $ca instanceof OpenSSLCertificate ? self::quietly(fn () => openssl_pkey_get_public($ca)) : false;
        if ($caFields === null || $caInfo === null || ! $caKey instanceof OpenSSLAsymmetricKey
            || $caFields['notBefore'] === null || $caFields['notAfter'] === null) {
            throw new InvalidArgumentException('Sertifikat CA tak dapat diurai.');
        }

        $der = self::pemBlock($certPem, 'CERTIFICATE');
        if ($der === null) {
            return CertificateVerification::rejected('pem');
        }
        $fields = self::tbsFields($der);
        if ($fields === null) {
            return CertificateVerification::rejected('structure');
        }
        if (! self::isP256Spki($fields['spki'])) {
            return CertificateVerification::rejected('key');
        }
        $cert = self::quietly(fn () => openssl_x509_read(self::pem($der, 'CERTIFICATE')));
        $info = $cert instanceof OpenSSLCertificate ? self::parsed($cert) : null;
        if (! $cert instanceof OpenSSLCertificate || $info === null || $fields['notBefore'] === null || $fields['notAfter'] === null) {
            return CertificateVerification::rejected('structure');
        }

        $extensions = $info['extensions'] ?? [];
        $clientAuth = in_array('TLS Web Client Authentication', explode(', ', (string) ($extensions['extendedKeyUsage'] ?? '')), true);
        $san = preg_match('#\AURI:'.preg_quote(self::SAN_PREFIX, '#').'('.self::ULID.')\z#', (string) ($extensions['subjectAltName'] ?? ''), $match) === 1;

        return match (true) {
            $fields['issuer'] !== $caFields['subject'] => CertificateVerification::rejected('issuer'),
            self::quietly(fn () => openssl_x509_verify($cert, $caKey)) !== 1 => CertificateVerification::rejected('signature'),
            ! self::within($fields, $now) || ! self::within($caFields, $now) => CertificateVerification::rejected('validity'),
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
        $fields = $der === null ? null : self::tbsFields($der);
        $info = $der === null ? null : self::parsed(self::pem($der, 'CERTIFICATE'));
        $key = $der === null ? false : self::quietly(fn () => openssl_pkey_get_public(self::pem($der, 'CERTIFICATE')));
        if ($fields === null || $info === null || ! $key instanceof OpenSSLAsymmetricKey || $fields['notBefore'] === null || $fields['notAfter'] === null) {
            return null;
        }

        $expectedExtensions = self::AGENT_EXTENSIONS;
        ksort($expectedExtensions);
        $notBefore = $fields['notBefore'];
        $notAfter = $fields['notAfter'];

        $conforms = self::verify($certPem, $caPem, $notBefore)->serverId === $serverId
            && $fields['subject'] === self::EMPTY_NAME
            && self::issuedValidityConforms($notAfter - $notBefore, self::AGENT_CERT_DAYS)
            && self::publicKeyPem($key) === $publicKeyPem
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

    /** @param array{notBefore: ?int, notAfter: ?int} $fields */
    private static function within(array $fields, int $now): bool
    {
        return $fields['notBefore'] !== null && $fields['notAfter'] !== null && $fields['notBefore'] <= $now && $now <= $fields['notAfter'];
    }

    /** SPKI mentah = ECDSA P-256 berkurva bernama, titik tak terkompresi (KONTRAK §2 aturan `key`). */
    private static function isP256Spki(string $spki): bool
    {
        return strlen($spki) === self::P256_SPKI_BYTES && str_starts_with($spki, self::P256_SPKI_PREFIX);
    }

    private static function publicKeyPem(OpenSSLAsymmetricKey $key): ?string
    {
        $details = openssl_pkey_get_details($key);

        return $details === false ? null : (string) $details['key'];
    }

    /**
     * openssl_x509_parse yang total: warning ditelan, dan waktu yang tak terurai (time_t negatif) = tak terurai.
     *
     * @return array<string, mixed>|null
     */
    private static function parsed(OpenSSLCertificate|string $certificate): ?array
    {
        $info = self::quietly(fn () => openssl_x509_parse($certificate));
        if (! is_array($info) || ! is_int($info['validFrom_time_t'] ?? null) || ! is_int($info['validTo_time_t'] ?? null)
            || $info['validFrom_time_t'] < 0 || $info['validTo_time_t'] < 0) {
            return null;
        }

        return $info;
    }

    /**
     * DER satu blok PEM berlabel $label menurut aturan `pem` KONTRAK §2 (base64 standar berpadding yang kanonik), atau
     * null.
     */
    private static function pemBlock(string $text, string $label): ?string
    {
        $pattern = '/\A-----BEGIN '.$label.'-----\n((?:[A-Za-z0-9+\/=]+\n)+)-----END '.$label.'-----\n?\z/';
        if (preg_match($pattern, $text, $match) !== 1) {
            return null;
        }
        $body = str_replace("\n", '', $match[1]);
        $der = base64_decode($body, true);

        return $der === false || $der === '' || base64_encode($der) !== $body ? null : $der;
    }

    private static function pem(string $der, string $label): string
    {
        return "-----BEGIN {$label}-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END {$label}-----\n";
    }

    /**
     * Byte DER mentah penerbit, subjek, dan SPKI satu sertifikat X.509, beserta masa berlakunya (detik Unix), atau null
     * bila tata letaknya bukan Certificate = SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING }. Waktu
     * diurai sendiri dari DER karena konversi PHP menormalkan tanggal mustahil (bulan 13 menjadi Januari).
     *
     * @return array{issuer: string, subject: string, spki: string, notBefore: ?int, notAfter: ?int}|null
     */
    private static function tbsFields(string $der): ?array
    {
        $certificate = self::children($der);
        if ($certificate === null || count($certificate) !== 3 || ord($certificate[1][0]) !== 0x30 || ord($certificate[2][0]) !== 0x03) {
            return null;
        }
        $tbs = self::children($certificate[0]);
        if ($tbs !== null && $tbs !== [] && ord($tbs[0][0]) === 0xA0) {
            array_shift($tbs); // [0] EXPLICIT version
        }
        if ($tbs === null || count($tbs) < 6 || ord($tbs[2][0]) !== 0x30 || ord($tbs[4][0]) !== 0x30 || ord($tbs[5][0]) !== 0x30) {
            return null;
        }

        $validity = self::children($tbs[3]);

        return [
            'issuer' => $tbs[2],
            'subject' => $tbs[4],
            'spki' => $tbs[5],
            'notBefore' => $validity !== null && count($validity) === 2 ? self::time($validity[0]) : null,
            'notAfter' => $validity !== null && count($validity) === 2 ? self::time($validity[1]) : null,
        ];
    }

    /**
     * Detik Unix dari UTCTime `YYMMDDHHMMSSZ` atau GeneralizedTime `YYYYMMDDHHMMSSZ` (RFC 5280 §4.1.2.5), atau null bila
     * bentuknya lain atau tanggal/jamnya mustahil.
     */
    private static function time(string $tlv): ?int
    {
        $head = self::header($tlv, 0, strlen($tlv));
        $text = $head === null ? '' : substr($tlv, $head['start'], $head['end'] - $head['start']);
        $pattern = match ($head['tag'] ?? null) {
            0x17 => '/\A(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z\z/',
            0x18 => '/\A(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z\z/',
            default => null,
        };
        if ($pattern === null || preg_match($pattern, $text, $m) !== 1) {
            return null;
        }
        [, $year, $month, $day, $hour, $minute, $second] = array_map('intval', $m);
        if (strlen($m[1]) === 2) {
            $year += $year < 50 ? 2000 : 1900;
        }
        if (! checkdate($month, $day, $year) || $hour > 23 || $minute > 59 || $second > 59) {
            return null;
        }

        return gmmktime($hour, $minute, $second, $month, $day, $year);
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
