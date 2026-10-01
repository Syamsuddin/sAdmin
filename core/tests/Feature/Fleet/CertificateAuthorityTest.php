<?php

namespace Tests\Feature\Fleet;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Fleet\Actions\InitializeCertificateAuthority;
use App\Domain\Fleet\Data\CertificateRequestRejected;
use App\Domain\Fleet\Services\AgentCertificateProfile;
use App\Domain\Fleet\Services\CertificateAuthority;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\X509Authority;
use App\Models\Institution;
use App\Models\Secret;
use App\Models\Tenant;
use DomainException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0007 §2.3: penerbitan sertifikat klien agen, verifikasi sendiri, dan batas brankas CA. */
class CertificateAuthorityTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private const SERVER_ID = '01k6f3h9m2q7r4s8t0v5w1x3y6';

    private string $tenantId;

    /** @var list<string> */
    private array $tempFiles = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenantId = Institution::factory()->create()->tenant_id;
        app(InitializeCertificateAuthority::class)->handle();
    }

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        parent::tearDown();
    }

    private function ca(): CertificateAuthority
    {
        return app(CertificateAuthority::class);
    }

    private function tempFile(string $contents): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'sadmin-uji-');
        file_put_contents($path, $contents);
        $this->tempFiles[] = $path;

        return $path;
    }

    /** Config OpenSSL uji: tes tak bergantung pada openssl.cnf sistem. */
    private function opensslOptions(string $extensions = ''): array
    {
        // default_bits: PHP 8.3 menolak openssl_pkey_new tanpanya, juga untuk kunci EC (ADR 0007 §2.3 langkah 4).
        return ['config' => $this->tempFile("[req]\ndefault_bits = 2048\ndistinguished_name = dn\n[dn]\n[ext]\n{$extensions}\n"), 'digest_alg' => 'sha256'];
    }

    /** @return array{OpenSSLAsymmetricKey, string} kunci agen P-256 dan CSR-nya (PEM) */
    private function agentCsr(array $subject = []): array
    {
        $options = $this->opensslOptions();
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] + $options);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $csr = openssl_csr_new($subject, $key, $options);
        $this->assertNotFalse($csr);
        $this->assertTrue(openssl_csr_export($csr, $pem));

        return [$key, $pem];
    }

    /** @return array<string, mixed> */
    private function parse(string $certPem): array
    {
        $info = openssl_x509_parse($certPem);
        $this->assertIsArray($info);

        return $info;
    }

    /**
     * Kunci P-256 acak dalam bentuk SEC1 (`EC PRIVATE KEY`), seperti ekspor sebagian build PHP lama (ADR 0007 §2.1).
     * Dibangun saat tes dari ekspor PKCS#8 tata letak OpenSSL, supaya repo tak memuat kunci privat literal (docs/20):
     * ECPrivateKey di dalam PKCS#8 tak membawa parameter kurva, jadi [0] prime256v1 disisipkan kembali.
     */
    private function sec1Key(): string
    {
        $options = $this->opensslOptions();
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] + $options);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $this->assertTrue(openssl_pkey_export($key, $pkcs8, null, $options));
        $der = (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $pkcs8), true);
        $this->assertSame("\x30\x81\x87\x02\x01\x00\x30\x13", substr($der, 0, 8), 'Tata letak PKCS#8 P-256 OpenSSL berubah.');
        $this->assertSame("\x04\x6d\x30\x6b\x02\x01\x01\x04\x20", substr($der, 27, 9));

        $inner = substr($der, 29); // ECPrivateKey: versi, d, [1] kunci publik
        $sec1 = "\x30\x77".substr($inner, 2, 37)."\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07".substr($inner, 39);
        $pem = self::pem($sec1, 'EC PRIVATE KEY');

        $reloaded = openssl_pkey_get_private($pem);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $reloaded);
        $this->assertSame(openssl_pkey_get_details($key)['key'], openssl_pkey_get_details($reloaded)['key']);

        return $pem;
    }

    private static function pem(string $der, string $label): string
    {
        return "-----BEGIN {$label}-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END {$label}-----\n";
    }

    /** @return list<string> */
    private function temporaryConfigs(): array
    {
        return glob(sys_get_temp_dir().'/sadmin-x509-*') ?: [];
    }

    /**
     * Tak ada config sementara baru yang menetap. Suite lain yang berjalan paralel di host yang sama juga membuat
     * berkas ini, tetapi hanya hidup beberapa milidetik; yang bocor tetap ada setelah ditunggu.
     *
     * @param  list<string>  $before
     */
    private function assertNoTemporaryConfigLeft(array $before): void
    {
        $deadline = microtime(true) + 2;
        while (($left = array_values(array_diff($this->temporaryConfigs(), $before))) !== [] && microtime(true) < $deadline) {
            usleep(50_000);
        }

        $this->assertSame([], $left, 'Config OpenSSL sementara tertinggal.');
    }

    public function test_issues_a_client_certificate_that_openssl_accepts_only_for_client_auth(): void
    {
        [$agentKey, $csr] = $this->agentCsr();
        $auditBefore = DB::table('audit_entries')->count();

        $issued = $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $csr);

        $this->assertSame(self::SERVER_ID, $issued->serverId);
        $this->assertTrue(AgentCertificateProfile::issuedValidityConforms($issued->notAfter->getTimestamp() - $issued->notBefore->getTimestamp(), 7));
        $this->assertEqualsWithDelta(time(), $issued->notBefore->getTimestamp(), 60);
        $this->assertMatchesRegularExpression('/\A[1-9a-f][0-9a-f]*\z/', $issued->serial);

        $info = $this->parse($issued->certificatePem);
        $this->assertSame([], $info['subject']);
        $this->assertSame(['CN' => 'sAdmin internal CA'], $info['issuer']);
        $this->assertSame($issued->serial, ltrim(strtolower($info['serialNumberHex']), '0'));
        $this->assertSame('ecdsa-with-SHA256', $info['signatureTypeSN']);
        $this->assertSame('URI:sadmin://server/'.self::SERVER_ID, $info['extensions']['subjectAltName']);
        $this->assertSame('CA:FALSE', $info['extensions']['basicConstraints']);
        $this->assertSame('Digital Signature', $info['extensions']['keyUsage']);
        $this->assertSame('TLS Web Client Authentication', $info['extensions']['extendedKeyUsage']);
        $this->assertEqualsCanonicalizing(['subjectAltName', 'basicConstraints', 'keyUsage', 'extendedKeyUsage', 'authorityKeyIdentifier'], array_keys($info['extensions']));
        // Flag kritis tak tampil di openssl_x509_parse: periksa langsung byte DER (OID, BOOLEAN TRUE).
        $der = (string) base64_decode((string) preg_replace('/-----[^-]+-----|\s/', '', $issued->certificatePem), true);
        foreach (['subjectAltName' => "\x55\x1d\x11", 'basicConstraints' => "\x55\x1d\x13", 'keyUsage' => "\x55\x1d\x0f"] as $name => $oid) {
            $this->assertStringContainsString("\x06\x03{$oid}\x01\x01\xff", $der, "{$name} wajib kritis (KONTRAK §2).");
        }
        foreach (['extendedKeyUsage' => "\x55\x1d\x25", 'authorityKeyIdentifier' => "\x55\x1d\x23"] as $name => $oid) {
            $this->assertStringContainsString("\x06\x03{$oid}\x04", $der, "{$name} tidak kritis (KONTRAK §2).");
        }

        // Saksi independen: verifikasi rantai OpenSSL sendiri, bukan kode profil core.
        $caFile = $this->tempFile($this->ca()->certificatePem($this->tenantId));
        $this->assertTrue(openssl_x509_checkpurpose($issued->certificatePem, X509_PURPOSE_SSL_CLIENT, [$caFile]));
        $this->assertFalse(openssl_x509_checkpurpose($issued->certificatePem, X509_PURPOSE_SSL_SERVER, [$caFile]));
        $this->assertTrue(openssl_x509_check_private_key($issued->certificatePem, $agentKey));

        $this->assertSame(self::SERVER_ID, AgentCertificateProfile::verify($issued->certificatePem, $this->ca()->certificatePem($this->tenantId), time())->serverId);
        $this->assertSame($auditBefore, DB::table('audit_entries')->count(), 'Penerbitan tak mengubah state, jadi tak menulis audit (ADR 0007 §2.3).');
    }

    /**
     * Regresi: openssl_csr_sign membaca jam dua kali, jadi ≈1 dari 50.000 terbitan berumur 604801 detik. Tanpa toleransi
     * ini, verifikasi sendiri menolak sertifikat yang sah dan penerbitan gagal acak (ADR 0007 §2.3 langkah 5).
     */
    public function test_issued_validity_tolerates_one_clock_tick_between_openssl_time_reads(): void
    {
        $this->assertTrue(AgentCertificateProfile::issuedValidityConforms(604800, 7));
        $this->assertTrue(AgentCertificateProfile::issuedValidityConforms(604801, 7));
        $this->assertFalse(AgentCertificateProfile::issuedValidityConforms(604799, 7));
        $this->assertFalse(AgentCertificateProfile::issuedValidityConforms(604802, 7));
        $this->assertFalse(AgentCertificateProfile::issuedValidityConforms(518400, 7));
        $this->assertTrue(AgentCertificateProfile::issuedValidityConforms(3650 * 86400 + 1, 3650));
    }

    public function test_validity_is_seven_days_with_inclusive_bounds(): void
    {
        $issued = $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $this->agentCsr()[1]);
        $caPem = $this->ca()->certificatePem($this->tenantId);
        $notBefore = $issued->notBefore->getTimestamp();
        $notAfter = $issued->notAfter->getTimestamp();

        $this->assertTrue(AgentCertificateProfile::verify($issued->certificatePem, $caPem, $notBefore)->valid());
        $this->assertTrue(AgentCertificateProfile::verify($issued->certificatePem, $caPem, $notAfter)->valid());
        $this->assertSame('validity', AgentCertificateProfile::verify($issued->certificatePem, $caPem, $notAfter + 1)->reason);
        $this->assertSame('validity', AgentCertificateProfile::verify($issued->certificatePem, $caPem, $notBefore - 1)->reason);
    }

    public function test_requested_extensions_are_never_copied_into_the_certificate(): void
    {
        $vector = json_decode((string) file_get_contents(base_path('../kontrak/vectors/agent-csr/02-extension-request-ignored.json')), true);
        $this->assertTrue($vector['valid']);

        $issued = $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $vector['csr_pem']);

        $info = $this->parse($issued->certificatePem);
        $this->assertSame('URI:sadmin://server/'.self::SERVER_ID, $info['extensions']['subjectAltName']);
        $this->assertStringNotContainsString('DNS:', $issued->certificatePem.json_encode($info));
    }

    public function test_rejects_every_contract_csr_violation_before_signing(): void
    {
        $rejected = 0;
        foreach (glob(base_path('../kontrak/vectors/agent-csr/*.json')) ?: [] as $path) {
            $vector = json_decode((string) file_get_contents($path), true);
            if ($vector['valid']) {
                continue;
            }
            try {
                $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $vector['csr_pem']);
                $this->fail(basename($path).' seharusnya ditolak.');
            } catch (CertificateRequestRejected $e) {
                $this->assertSame($vector['reason'], $e->reason, basename($path));
                $this->assertStringNotContainsString('BEGIN', $e->getMessage(), 'Pesan penolakan tak memuat isi CSR.');
                $rejected++;
            }
        }

        $this->assertGreaterThanOrEqual(10, $rejected);
        [, $withSubject] = $this->agentCsr(['commonName' => 'agen']);
        $this->expectExceptionObject(new CertificateRequestRejected('subject'));
        $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $withSubject);
    }

    public function test_file_paths_are_never_handed_to_openssl(): void
    {
        foreach (['file://'.base_path('composer.json'), base_path('composer.json')] as $path) {
            try {
                $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $path);
                $this->fail('Path berkas seharusnya ditolak sebagai bukan PEM.');
            } catch (CertificateRequestRejected $e) {
                $this->assertSame('pem', $e->reason);
            }
        }
    }

    public function test_rejects_server_ids_that_are_not_lowercase_ulids(): void
    {
        $csr = $this->agentCsr()[1];
        foreach ([strtoupper(self::SERVER_ID), '81k6f3h9m2q7r4s8t0v5w1x3y6', 'server', self::SERVER_ID."\n[sadmin_ext]", self::SERVER_ID.', DNS:x'] as $serverId) {
            try {
                $this->ca()->issueAgentCertificate($this->tenantId, $serverId, $csr);
                $this->fail("server_id {$serverId} seharusnya ditolak.");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('ULID huruf kecil', $e->getMessage());
            }
        }
    }

    public function test_fails_closed_for_a_tenant_without_an_authority(): void
    {
        $other = Tenant::factory()->create()->id;

        try {
            $this->ca()->issueAgentCertificate($other, self::SERVER_ID, $this->agentCsr()[1]);
            $this->fail('Tenant tanpa CA seharusnya gagal tertutup.');
        } catch (DomainException $e) {
            $this->assertStringContainsString('sadmin:ca-init', $e->getMessage());
        }

        $this->assertSame(0, Secret::query()->where('tenant_id', $other)->count(), 'CA tak pernah dibuat implisit.');
    }

    public function test_a_destroyed_authority_fails_closed(): void
    {
        $secret = Secret::query()->where('purpose', SecretPurpose::CaKey->value)->sole();
        app(DestroySecret::class)->handle($secret->id, ActorType::LocalRoot, null);

        try {
            $this->ca()->fingerprint($this->tenantId);
            $this->fail('CA yang dihancurkan seharusnya gagal tertutup.');
        } catch (DomainException $e) {
            // Pesan tak buntu: sadmin:ca-init akan menolak CA yang pernah ada, jadi rotasi ikut disebut.
            $this->assertStringContainsString('sadmin:ca-init', $e->getMessage());
            $this->assertStringContainsString('rotasi CA', $e->getMessage());
        }
    }

    public function test_certificates_never_chain_to_another_tenants_authority(): void
    {
        $other = Tenant::factory()->create()->id;
        $bundle = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 7);
        app(StoreSecret::class)->handle($other, SecretPurpose::CaKey, $bundle, ActorType::LocalRoot, null);
        $csr = $this->agentCsr()[1];

        $mine = $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $csr);
        $theirs = $this->ca()->issueAgentCertificate($other, self::SERVER_ID, $csr);

        $this->assertNotSame($this->ca()->fingerprint($this->tenantId), $this->ca()->fingerprint($other));
        $this->assertTrue(AgentCertificateProfile::verify($theirs->certificatePem, $this->ca()->certificatePem($other), time())->valid());
        $this->assertSame('signature', AgentCertificateProfile::verify($theirs->certificatePem, $this->ca()->certificatePem($this->tenantId), time())->reason);
        $this->assertSame('signature', AgentCertificateProfile::verify($mine->certificatePem, $this->ca()->certificatePem($other), time())->reason);
    }

    public function test_each_issuance_gets_a_fresh_random_serial(): void
    {
        $csr = $this->agentCsr()[1];

        $first = $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $csr);
        $second = $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $csr);

        $this->assertNotSame($first->serial, $second->serial);
        $this->assertNotSame($first->certificatePem, $second->certificatePem);
    }

    public function test_a_swapped_or_malformed_authority_bundle_fails_closed(): void
    {
        $a = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 7);
        $b = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 8);
        preg_match('/\A(.+?-----END (?:EC )?PRIVATE KEY-----\n)(.+)\z/s', $a->expose(), $partsA);
        preg_match('/\A(.+?-----END (?:EC )?PRIVATE KEY-----\n)(.+)\z/s', $b->expose(), $partsB);
        $csr = $this->agentCsr()[1];

        // Sertifikat bertanda tangan kunci A yang sah, tetapi kunci publiknya milik kunci lain: hanya cek kecocokan
        // kunci–sertifikat yang menolaknya, verifikasi tanda tangan saja tidak.
        $keyA = openssl_pkey_get_private($partsA[1]);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $keyA);
        [, $otherCsr] = $this->agentCsr(['commonName' => AgentCertificateProfile::CA_COMMON_NAME]);
        $options = $this->opensslOptions("basicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign");
        $foreignKeyCert = openssl_csr_sign($otherCsr, null, $keyA, 30, $options + ['x509_extensions' => 'ext'], 11);
        $this->assertNotFalse($foreignKeyCert);
        $this->assertTrue(openssl_x509_export($foreignKeyCert, $foreignKeyPem));
        $this->assertSame(1, openssl_x509_verify($foreignKeyPem, openssl_pkey_get_details($keyA)['key']));

        $cases = [
            'kunci A + sertifikat B' => $partsA[1].$partsB[2],
            'kunci A + sertifikat berkunci lain bertanda tangan A' => $partsA[1].$foreignKeyPem,
            'bukan PEM' => 'bukan pem',
            'tanpa sertifikat' => $partsA[1],
            'urutan terbalik' => $partsA[2].$partsA[1],
        ];
        foreach ($cases as $case => $contents) {
            $tenant = Tenant::factory()->create()->id;
            app(StoreSecret::class)->handle($tenant, SecretPurpose::CaKey, new SecretValue($contents), ActorType::LocalRoot, null);

            foreach ([fn () => $this->ca()->fingerprint($tenant), fn () => $this->ca()->issueAgentCertificate($tenant, self::SERVER_ID, $csr)] as $call) {
                try {
                    $call();
                    $this->fail("Isi rahasia CA '{$case}' seharusnya gagal dibuka.");
                } catch (VaultIntegrityError $e) {
                    $this->assertStringContainsString('ADR 0007', $e->getMessage(), $case);
                }
            }
        }
    }

    public function test_a_sec1_private_key_from_older_php_builds_is_accepted(): void
    {
        $sec1 = $this->sec1Key();
        $key = openssl_pkey_get_private($sec1);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $options = $this->opensslOptions("basicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash");
        $request = openssl_csr_new(['commonName' => AgentCertificateProfile::CA_COMMON_NAME], $key, $options);
        $this->assertNotFalse($request);
        $cert = openssl_csr_sign($request, null, $key, 30, $options + ['x509_extensions' => 'ext'], 9);
        $this->assertNotFalse($cert);
        $this->assertTrue(openssl_x509_export($cert, $caPem));
        $tenant = Tenant::factory()->create()->id;
        app(StoreSecret::class)->handle($tenant, SecretPurpose::CaKey, new SecretValue($sec1.$caPem), ActorType::LocalRoot, null);

        $issued = $this->ca()->issueAgentCertificate($tenant, self::SERVER_ID, $this->agentCsr()[1]);

        $this->assertSame($caPem, $this->ca()->certificatePem($tenant));
        $this->assertSame(self::SERVER_ID, AgentCertificateProfile::verify($issued->certificatePem, $caPem, time())->serverId);
    }

    public function test_unsafe_extension_values_never_reach_the_openssl_config(): void
    {
        $cases = [
            ['subjectAltName' => "critical, URI:x\n[sadmin_ext]\nbasicConstraints = CA:TRUE"],
            ['basicConstraints' => 'critical, CA:FALSE, $ENV::HOME'],
            ['keyUsage' => '@bagian_lain'],
            ['extendedKeyUsage' => 'clientAuth # komentar'],
            ['subjectAltName' => 'URI:sadmin://server/x=y'],
            ['bukan nama' => 'clientAuth'],
            ['basicConstraints' => "critical, CA:TRUE, pathlen:0\n"],
            ["basicConstraints\n" => 'critical, CA:TRUE, pathlen:0'],
        ];
        $before = $this->temporaryConfigs();

        foreach ($cases as $extensions) {
            try {
                X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, $extensions, 30, 7);
                $this->fail('Ekstensi tak aman seharusnya ditolak: '.json_encode($extensions));
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('himpunan aman', $e->getMessage());
            }
        }

        $this->assertNoTemporaryConfigLeft($before);
    }

    public function test_temporary_openssl_configs_are_removed_after_success_and_failure(): void
    {
        $before = $this->temporaryConfigs();
        $bundle = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 7);
        $this->ca()->issueAgentCertificate($this->tenantId, self::SERVER_ID, $this->agentCsr()[1]);

        try {
            X509Authority::sign($bundle, "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n", AgentCertificateProfile::agentExtensions(self::SERVER_ID), 7, 5);
            $this->fail('OpenSSL seharusnya menolak CSR rusak.');
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString('OpenSSL menolak', $e->getMessage());
            // TEM-11: akar masalah dari OpenSSL ikut di pesan, bukan hilang ditelan penangan warning.
            $this->assertStringContainsString('Rincian: ', $e->getMessage());
        }

        $this->assertNoTemporaryConfigLeft($before);
    }

    /**
     * Sertifikat bertanda tangan kunci CA uji dengan profil yang bisa diatur, untuk menguji profil penerbitan.
     *
     * @return array{cert: string, ca: string, key: string, serial: int}
     */
    private function signedWithProfile(string $extensions, int $days, ?string $csr = null): array
    {
        $bundle = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 7);
        preg_match('/\A(.+?-----END (?:EC )?PRIVATE KEY-----\n)(.+)\z/s', $bundle->expose(), $parts);
        [$agentKey, $agentCsr] = $this->agentCsr();
        $serial = 4242;
        $options = $this->opensslOptions($extensions);
        $cert = openssl_csr_sign($csr ?? $agentCsr, $parts[2], $parts[1], $days, $options + ['x509_extensions' => 'ext'], $serial);
        $this->assertNotFalse($cert);
        $this->assertTrue(openssl_x509_export($cert, $pem));

        return ['cert' => $pem, 'ca' => $parts[2], 'key' => (string) openssl_pkey_get_details($agentKey)['key'], 'serial' => $serial];
    }

    /** Regresi TEM-04: gerbang "tertulis ⇒ terverifikasi" menolak tiap penyimpangan profil penerbitan, bukan hanya serial. */
    public function test_issuance_profile_rejects_every_deviation(): void
    {
        $profile = 'subjectAltName = critical, URI:sadmin://server/'.self::SERVER_ID."\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = clientAuth\nauthorityKeyIdentifier = keyid:always";
        $good = $this->signedWithProfile($profile, 7);
        $this->assertNotNull(AgentCertificateProfile::conformingIssued($good['cert'], $good['ca'], self::SERVER_ID, $good['key'], $good['serial']), 'Kontrol positif harus lolos.');

        $deviations = [
            'SAN tidak kritis' => [str_replace('subjectAltName = critical, ', 'subjectAltName = ', $profile), 7],
            'basicConstraints tidak kritis' => [str_replace('basicConstraints = critical, ', 'basicConstraints = ', $profile), 7],
            'ekstensi keenam' => [$profile."\nsubjectKeyIdentifier = hash", 7],
            'ekstensi kurang' => [str_replace("\nauthorityKeyIdentifier = keyid:always", '', $profile), 7],
            'umur 6 hari' => [$profile, 6],
            'umur 8 hari' => [$profile, 8],
        ];
        foreach ($deviations as $what => [$extensions, $days]) {
            $cert = $this->signedWithProfile($extensions, $days);
            $this->assertNull(AgentCertificateProfile::conformingIssued($cert['cert'], $cert['ca'], self::SERVER_ID, $cert['key'], $cert['serial']), "{$what} seharusnya tak lolos profil penerbitan.");
        }

        [, $withSubject] = $this->agentCsr(['commonName' => 'agen']);
        $subject = $this->signedWithProfile($profile, 7, $withSubject);
        $this->assertNull(AgentCertificateProfile::conformingIssued($subject['cert'], $subject['ca'], self::SERVER_ID, (string) openssl_pkey_get_details(openssl_pkey_get_public($subject['cert']))['key'], $subject['serial']), 'Subjek tak kosong seharusnya tak lolos.');
        $this->assertNull(AgentCertificateProfile::conformingIssued($good['cert'], $good['ca'], self::SERVER_ID, (string) openssl_pkey_get_details(openssl_pkey_get_public($subject['cert']))['key'], $good['serial']), 'Kunci selain kunci CSR seharusnya tak lolos.');

        // Vektor 20 lolos aturan gateway (subjek diabaikan), tetapi bukan sertifikat terbitan core.
        $vector = json_decode((string) file_get_contents(base_path('../kontrak/vectors/agent-cert/20-subject-ignored.json')), true);
        $info = openssl_x509_parse($vector['cert_pem']);
        $this->assertTrue(AgentCertificateProfile::verify($vector['cert_pem'], $vector['ca_pem'], (new \DateTimeImmutable($vector['now']))->getTimestamp())->valid());
        $this->assertNull(AgentCertificateProfile::conformingIssued($vector['cert_pem'], $vector['ca_pem'], self::SERVER_ID, (string) openssl_pkey_get_details(openssl_pkey_get_public($vector['cert_pem']))['key'], (int) $info['serialNumber']));
    }

    /** Regresi TEM-04 (open): bundel CA berkunci bukan P-256 atau bertanda tangan kunci lain gagal tertutup. */
    public function test_authority_bundle_must_be_p256_and_self_signed(): void
    {
        $p384 = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1'] + $this->opensslOptions());
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $p384);
        $options = $this->opensslOptions("basicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign");
        $p384Cert = openssl_csr_sign(openssl_csr_new(['commonName' => AgentCertificateProfile::CA_COMMON_NAME], $p384, $options), null, $p384, 30, $options + ['x509_extensions' => 'ext'], 12);
        $this->assertNotFalse($p384Cert);
        $this->assertTrue(openssl_pkey_export($p384, $p384Pem, null, $options) && openssl_x509_export($p384Cert, $p384CertPem));

        // Sertifikat berkunci A (cocok dengan kunci privat A) tetapi ditandatangani kunci B: hanya cek tanda tangan sendiri yang menolaknya.
        $a = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 13);
        $b = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 14);
        preg_match('/\A(.+?-----END (?:EC )?PRIVATE KEY-----\n)(.+)\z/s', $a->expose(), $partsA);
        preg_match('/\A(.+?-----END (?:EC )?PRIVATE KEY-----\n)/s', $b->expose(), $partsB);
        $keyA = openssl_pkey_get_private($partsA[1]);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $keyA);
        $requestA = openssl_csr_new(['commonName' => AgentCertificateProfile::CA_COMMON_NAME], $keyA, $options);
        $crossSigned = openssl_csr_sign($requestA, null, $partsB[1], 30, $options + ['x509_extensions' => 'ext'], 15);
        $this->assertNotFalse($crossSigned);
        $this->assertTrue(openssl_x509_export($crossSigned, $crossSignedPem));
        $this->assertTrue(openssl_x509_check_private_key($crossSignedPem, $keyA));

        foreach (['P-384' => $p384Pem.$p384CertPem, 'tanda tangan kunci lain' => $partsA[1].$crossSignedPem] as $case => $contents) {
            $tenant = Tenant::factory()->create()->id;
            app(StoreSecret::class)->handle($tenant, SecretPurpose::CaKey, new SecretValue($contents), ActorType::LocalRoot, null);
            try {
                $this->ca()->certificatePem($tenant);
                $this->fail("Bundel CA {$case} seharusnya gagal dibuka.");
            } catch (VaultIntegrityError $e) {
                $this->assertStringContainsString('ADR 0007', $e->getMessage(), $case);
            }
        }
    }

    /** Regresi TEM-09: brankas hanya menandatangani teks CSR PEM menjadi sertifikat ujung. */
    public function test_vault_signing_accepts_only_csr_text_and_leaf_profiles(): void
    {
        $bundle = X509Authority::generate(AgentCertificateProfile::CA_COMMON_NAME, AgentCertificateProfile::authorityExtensions(), 30, 7);
        $csr = $this->agentCsr()[1];
        $csrFile = $this->tempFile($csr);

        foreach (['file://'.$csrFile, $csrFile, $csr."x\n", str_replace("\n", "\r\n", $csr)] as $input) {
            try {
                X509Authority::sign($bundle, $input, AgentCertificateProfile::agentExtensions(self::SERVER_ID), 7, 5);
                $this->fail('Masukan selain teks satu blok CSR seharusnya ditolak.');
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('CERTIFICATE REQUEST', $e->getMessage());
            }
        }

        foreach ([['basicConstraints' => 'critical, CA:TRUE'], ['keyUsage' => 'critical, keyCertSign'], ['keyUsage' => 'cRLSign']] as $extensions) {
            try {
                X509Authority::sign($bundle, $csr, $extensions, 7, 5);
                $this->fail('Ekstensi CA seharusnya ditolak: '.json_encode($extensions));
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('sertifikat ujung', $e->getMessage());
            }
        }

        $this->assertStringStartsWith('-----BEGIN CERTIFICATE-----', X509Authority::sign($bundle, $csr, AgentCertificateProfile::agentExtensions(self::SERVER_ID), 7, 5));
    }
}
