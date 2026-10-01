<?php

namespace Tests\Feature\Fleet;

use App\Domain\Audit\Actions\InitializeAuditKey;
use App\Domain\Audit\Services\AuditChainVerifier;
use App\Domain\Execution\Actions\InitializeServiceKey;
use App\Domain\Execution\Dispatch\ServiceSigner;
use App\Domain\Fleet\Actions\AcceptEnrollment;
use App\Domain\Fleet\Actions\InitializeCertificateAuthority;
use App\Domain\Fleet\Actions\IssueEnrollmentToken;
use App\Domain\Fleet\Actions\RegisterServer;
use App\Domain\Fleet\Data\AcceptedEnrollment;
use App\Domain\Fleet\Data\EnrollmentRejected;
use App\Domain\Fleet\Data\ServerStatus;
use App\Domain\Fleet\Data\TrustDocumentCorrupt;
use App\Domain\Fleet\Services\AgentCertificateProfile;
use App\Domain\Fleet\Services\CertificateAuthority;
use App\Domain\Fleet\Services\TrustDocuments;
use App\Domain\Fleet\Services\TrustFingerprint;
use App\Infrastructure\Vault\Ed25519;
use App\Models\Admin;
use App\Models\Agent;
use App\Models\Server;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use stdClass;
use Tests\Support\InteractsWithPasskeys;
use Tests\Support\InteractsWithVault;
use Tests\Support\VirtualAuthenticator;
use Tests\TestCase;

/** AC-18 docs/23 (ADR 0008): penukaran token enrolment menjadi EnrollAccept, atomik dan tanpa membakar token pada galat. */
class AcceptEnrollmentTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithVault, RefreshDatabase;

    private Admin $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpInstitution();
        $this->admin = $this->newAdmin();
        $this->enroll($this->admin, VirtualAuthenticator::eddsa('a'), 'Kunci A');
        $this->enroll($this->admin, VirtualAuthenticator::es256('b'), 'Kunci B');
        app(InitializeCertificateAuthority::class)->handle();
        app(InitializeServiceKey::class)->handle();
        app(InitializeAuditKey::class)->handle();
        config(['sadmin.gateway_host' => 'gw.instansi.go.id']);
    }

    private function register(string $name = 'web1', string $ip = '203.0.113.10'): array
    {
        $registered = app(RegisterServer::class)->handle($this->admin, $name, "{$name}.instansi.go.id", $ip);

        return [$registered->serverId, $registered->token()];
    }

    private static function csr(): string
    {
        $vector = json_decode((string) file_get_contents(base_path('../kontrak/vectors/agent-csr/01-valid.json')), true, 512, JSON_THROW_ON_ERROR);

        return $vector['csr_pem'];
    }

    /** @return array<string, mixed> */
    private function enrollBody(string $token, array $override = []): array
    {
        return $override + [
            'kontrak' => TrustDocuments::CONTRACT,
            'token' => $token,
            'csr' => self::csr(),
            'platform_id' => 'ubuntu-24.04',
            'hostname' => 'web1.instansi.go.id',
            'agent_version' => '0.1.0',
        ];
    }

    private function accept(array $body): AcceptedEnrollment
    {
        return app(AcceptEnrollment::class)->handle($body);
    }

    private function assertRejected(string $code, string $reason, array $body): void
    {
        try {
            $this->accept($body);
            $this->fail("Seharusnya ditolak {$code}.");
        } catch (EnrollmentRejected $e) {
            $this->assertSame([$code, $reason], [$e->errorCode, $e->reason]);
        }
    }

    private function servicePublicKey(): string
    {
        $signer = app(ServiceSigner::class);

        return $signer->publicKey((string) $signer->activeKeyId($this->institution->tenant_id), $this->institution->tenant_id);
    }

    private function tokenIsStillRedeemable(string $serverId): bool
    {
        $server = Server::query()->findOrFail($serverId);

        return $server->status === ServerStatus::Enrolling && $server->enroll_token_hash !== null;
    }

    public function test_valid_enroll_returns_a_signed_enroll_accept_with_certificate_trust_documents_and_fingerprint(): void
    {
        [$serverId, $token] = $this->register();

        $accepted = $this->accept($this->enrollBody($token));

        $this->assertSame($serverId, $accepted->serverId);
        $this->assertTrue(ServiceSigner::verifyFrame($this->servicePublicKey(), $accepted->frame));
        $frame = json_decode($accepted->frame);
        $this->assertSame('EnrollAccept', $frame->type);
        $this->assertMatchesRegularExpression('/\A[0-7][0-9a-hjkmnp-tv-z]{25}\z/', $frame->id);
        $body = $frame->body;
        $this->assertSame(['audit_pubkey', 'ca_cert', 'cert', 'kontrak', 'policy', 'roster', 'server_id', 'service_pubkey'], $this->sortedMembers($body));
        $this->assertSame('0.6', $body->kontrak);
        $this->assertSame($serverId, $body->server_id);

        // Sertifikat lolos aturan penerimaan gateway untuk server ini, dan CA yang dikirim = pin yang dicocokkan admin.
        $this->assertSame(app(CertificateAuthority::class)->fingerprint($this->institution->tenant_id), AgentCertificateProfile::fingerprint($body->ca_cert));
        $this->assertSame($serverId, AgentCertificateProfile::verify($body->cert, $body->ca_cert, time())->serverId);

        // Sidik jari dihitung dari dokumen yang benar-benar dikirim.
        $this->assertSame($accepted->trustFingerprint, TrustFingerprint::compute([
            'roster_hash' => $body->roster->document_hash,
            'policy_hash' => $body->policy->document_hash,
            'service_pubkey' => $body->service_pubkey,
            'audit_pubkey' => $body->audit_pubkey,
            'server_id' => $serverId,
        ]));
        $this->assertSame(Ed25519::encode($this->servicePublicKey()), $body->service_pubkey);
        $this->assertSame(TrustDocuments::hash((array) json_decode(json_encode($body->roster->document), true)), $body->roster->document_hash);
    }

    public function test_roster_v1_lists_active_credentials_in_byte_order_without_labels(): void
    {
        [, $token] = $this->register();
        $inactive = $this->newAdmin();
        $this->enroll($inactive, VirtualAuthenticator::eddsa('c'), 'Admin lain', 'revoked');

        $body = json_decode($this->accept($this->enrollBody($token))->frame)->body;
        $document = $body->roster->document;

        $this->assertSame(['credentials', 'kontrak', 'origin', 'rp_id', 'tenant_id', 'version'], $this->sortedMembers($document));
        $this->assertSame(1, $document->version);
        $this->assertSame('sadmin.localhost', $document->rp_id);
        $this->assertSame('https://sadmin.localhost', $document->origin);
        $this->assertSame($this->institution->tenant_id, $document->tenant_id);
        $this->assertCount(2, $document->credentials);
        $ids = array_map(fn (stdClass $c): string => (string) base64_decode(strtr($c->credential_id, '-_', '+/'), true), $document->credentials);
        $sorted = $ids;
        sort($sorted, SORT_STRING);
        $this->assertSame($sorted, $ids);
        foreach ($document->credentials as $credential) {
            $this->assertSame(['admin_id', 'alg', 'credential_id', 'public_key_cose'], $this->sortedMembers($credential));
            $this->assertContains($credential->alg, [-7, -8]);
            $this->assertSame($this->admin->id, $credential->admin_id);
            $this->assertDoesNotMatchRegularExpression('/[=+\/]/', $credential->credential_id.$credential->public_key_cose);
        }
        $this->assertSame([], $body->roster->approvals);
        $this->assertStringNotContainsString('Kunci A', $this->accept($this->enrollBodyForNewServer())->frame);
    }

    public function test_policy_v1_holds_only_l0_catalog_actions_and_the_decided_thresholds(): void
    {
        [, $token] = $this->register();

        $policy = json_decode($this->accept($this->enrollBody($token))->frame)->body->policy;

        $this->assertSame(['actions', 'approvals_required', 'kontrak', 'l3_delay_seconds', 'tenant_id', 'version'], $this->sortedMembers($policy->document));
        $this->assertSame(1, $policy->document->version);
        $this->assertSame(900, $policy->document->l3_delay_seconds);
        $this->assertEquals((object) ['L2' => 1, 'L3' => 1], $policy->document->approvals_required);
        $keys = array_map(fn (stdClass $a): string => $a->key, $policy->document->actions);
        $this->assertSame(['backup.list', 'cert.status', 'db.list', 'firewall.status', 'log.tail_redacted', 'server.inventory', 'server.metrics', 'service.status', 'site.status'], $keys);
        foreach ($policy->document->actions as $action) {
            $this->assertSame(['key', 'risk', 'version'], $this->sortedMembers($action));
            $this->assertSame('L0', $action->risk);
            $this->assertSame(1, $action->version);
        }
        $this->assertSame([], $policy->approvals);
    }

    public function test_state_after_enrolment_is_consistent_and_the_token_is_spent(): void
    {
        [$serverId, $token] = $this->register();

        $accepted = $this->accept($this->enrollBody($token));

        $server = Server::query()->findOrFail($serverId);
        $this->assertSame(ServerStatus::Offline, $server->status);
        $this->assertNull($server->enroll_token_hash);
        $this->assertNull($server->enroll_token_expires_at);
        $agent = Agent::query()->where('server_id', $serverId)->sole();
        $this->assertSame($accepted->trustFingerprint, $agent->trust_fingerprint);
        $this->assertSame('0.1.0', $agent->agent_version);
        $this->assertSame([1, 1], [$agent->roster_version, $agent->policy_version]);
        $this->assertSame('disconnected', $agent->connection->value);
        $this->assertSame(1, DB::table('rosters')->where('status', 'active')->count());
        $this->assertSame(1, DB::table('policy_bundles')->where('status', 'active')->count());

        $this->assertRejected('E_ENROLL_TOKEN', 'invalid', $this->enrollBody($token));
        $this->assertTrue(app(AuditChainVerifier::class)->verify()->intact);
    }

    #[Group('redaction')]
    public function test_audit_records_the_enrolment_without_token_or_csr(): void
    {
        [$serverId, $token] = $this->register();
        $accepted = $this->accept($this->enrollBody($token, ['hostname' => 'vm-lain.local']));

        $entry = DB::table('audit_entries')->where('action_key', 'server.enroll')->sole();
        $this->assertSame('agent', $entry->actor_type);
        $this->assertSame($serverId, $entry->actor_id);
        $this->assertSame("server:{$serverId}", $entry->target);
        $params = json_decode((string) $entry->params_redacted, true);
        $this->assertSame(['agent_version', 'cert_expires_at', 'platform_id', 'policy_hash', 'reported_hostname', 'roster_hash', 'serial', 'trust_fingerprint'], $this->sortedKeys($params));
        $this->assertSame('vm-lain.local', $params['reported_hostname']);
        $this->assertSame($accepted->trustFingerprint, $params['trust_fingerprint']);
        $everything = json_encode(DB::table('audit_entries')->get());
        $this->assertStringNotContainsString($token, $everything);
        $this->assertStringNotContainsString('CERTIFICATE REQUEST', $everything);
        $this->assertStringNotContainsString(hash('sha256', $token), (string) json_encode(DB::table('servers')->get()));
    }

    public function test_hostname_that_differs_from_the_registered_one_does_not_block_enrolment(): void
    {
        [$serverId, $token] = $this->register();

        $this->accept($this->enrollBody($token, ['hostname' => 'alias-lain.example']));

        $this->assertSame(ServerStatus::Offline, Server::query()->findOrFail($serverId)->status);
    }

    /** @return iterable<string, array{string}> */
    public static function invalidTokens(): iterable
    {
        yield 'tak dikenal' => [str_repeat('a', 64)];
        yield 'bukan hex' => [str_repeat('z', 64)];
        yield 'huruf besar' => [str_repeat('A', 64)];
        yield 'terlalu pendek' => ['abc'];
        yield 'kosong' => [''];
    }

    #[DataProvider('invalidTokens')]
    public function test_unknown_or_malformed_tokens_are_rejected_without_a_reason(string $token): void
    {
        $this->register();

        $this->assertRejected('E_ENROLL_TOKEN', 'invalid', $this->enrollBody($token));
        $this->assertSame(0, Agent::query()->count());
    }

    public function test_expired_token_is_rejected_like_an_unknown_one(): void
    {
        [$serverId, $token] = $this->register();

        $this->travel(16)->minutes();

        $this->assertRejected('E_ENROLL_TOKEN', 'invalid', $this->enrollBody($token));
        $this->assertSame(ServerStatus::Enrolling, Server::query()->findOrFail($serverId)->status);
    }

    public function test_token_of_a_server_that_is_no_longer_enrolling_is_rejected(): void
    {
        [$serverId, $token] = $this->register();
        Server::query()->whereKey($serverId)->update(['status' => ServerStatus::Retired->value, 'enroll_token_hash' => null, 'enroll_token_expires_at' => null]);

        $this->assertRejected('E_ENROLL_TOKEN', 'invalid', $this->enrollBody($token));
    }

    public function test_replaced_token_no_longer_works_but_the_new_one_does(): void
    {
        [$serverId, $old] = $this->register();
        $new = app(IssueEnrollmentToken::class)->handle($this->admin, $serverId)->token();

        $this->assertRejected('E_ENROLL_TOKEN', 'invalid', $this->enrollBody($old));
        $this->assertSame($serverId, $this->accept($this->enrollBody($new))->serverId);
    }

    /** @return iterable<string, array{string, string}> */
    public static function badCsrs(): iterable
    {
        foreach (['03-subject-not-empty' => 'subject', '04-key-p384' => 'key', '06-signature-tampered' => 'signature', '10-not-pem' => 'pem'] as $file => $reason) {
            yield $file => [$file, $reason];
        }
    }

    #[DataProvider('badCsrs')]
    public function test_bad_csr_is_rejected_with_its_reason_and_does_not_burn_the_token(string $file, string $reason): void
    {
        [$serverId, $token] = $this->register();
        $vector = json_decode((string) file_get_contents(base_path("../kontrak/vectors/agent-csr/{$file}.json")), true, 512, JSON_THROW_ON_ERROR);

        $this->assertRejected('E_CSR', $reason, $this->enrollBody($token, ['csr' => $vector['csr_pem']]));

        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
        $this->assertSame(0, Agent::query()->count());
        $this->assertSame(0, DB::table('rosters')->count(), 'Roster v1 tak boleh tertinggal dari percobaan yang gagal.');
        $this->assertSame(0, DB::table('audit_entries')->where('action_key', 'server.enroll')->count());
        // Perbaikan agen: token yang sama masih bisa dipakai dengan CSR yang benar.
        $this->assertSame($serverId, $this->accept($this->enrollBody($token))->serverId);
    }

    public function test_oversized_csr_is_an_e_csr_size_error_not_a_schema_error(): void
    {
        [$serverId, $token] = $this->register();

        $this->assertRejected('E_CSR', 'size', $this->enrollBody($token, ['csr' => str_repeat('A', 9000)]));

        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
    }

    #[Group('redaction')]
    public function test_a_failure_inside_the_token_lookup_does_not_leak_the_token_into_the_stack_trace(): void
    {
        [, $token] = $this->register();
        DB::beforeExecuting(function (string $query) {
            if (str_contains($query, 'enroll_token_hash')) {
                throw new \RuntimeException('galat DB yang disuntikkan');
            }
        });

        try {
            $this->accept($this->enrollBody($token));
            $this->fail('Galat DB seharusnya meluncur.');
        } catch (\RuntimeException $e) {
            $this->assertStringNotContainsString(substr($token, 0, 12), $e->getTraceAsString());
        }
    }

    public function test_unsupported_platform_is_rejected_and_does_not_burn_the_token(): void
    {
        [$serverId, $token] = $this->register();

        $this->assertRejected('E_PLATFORM', 'unsupported_platform', $this->enrollBody($token, ['platform_id' => 'debian-12']));

        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
    }

    public function test_unknown_contract_version_is_rejected_before_the_token_is_touched(): void
    {
        [$serverId, $token] = $this->register();

        $this->assertRejected('E_KONTRAK_VERSION', 'unknown_major', $this->enrollBody($token, ['kontrak' => '0.5']));
        $this->assertRejected('E_KONTRAK_VERSION', 'unknown_major', $this->enrollBody($token, ['kontrak' => '1.0']));

        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
    }

    /** @return iterable<string, array{string, mixed}> */
    public static function schemaViolations(): iterable
    {
        yield 'kontrak hilang' => ['kontrak', null];
        yield 'token bukan string' => ['token', 12];
        yield 'csr bukan string' => ['csr', ['x']];
        yield 'platform kosong' => ['platform_id', ''];
        yield 'hostname dengan spasi' => ['hostname', 'web 1'];
        yield 'hostname dengan newline' => ['hostname', "web1\nINJEKSI"];
        yield 'versi agen dengan newline' => ['agent_version', "0.1.0\n"];
        yield 'versi agen terlalu panjang' => ['agent_version', str_repeat('1', 65)];
    }

    #[DataProvider('schemaViolations')]
    public function test_malformed_body_is_rejected_as_schema_error(string $field, mixed $value): void
    {
        [$serverId, $token] = $this->register();

        $this->assertRejected('E_SCHEMA', $field, array_merge($this->enrollBody($token), [$field => $value]));
        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
    }

    public function test_enrolment_is_unavailable_and_keeps_the_token_when_the_admin_has_fewer_than_two_active_passkeys(): void
    {
        DB::table('authenticators')->where('admin_id', $this->admin->id)->limit(1)->update(['status' => 'revoked']);
        [$serverId, $token] = $this->register();

        $this->assertRejected('E_CORE_UNAVAILABLE', 'trust_not_ready', $this->enrollBody($token));

        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
        $this->assertSame(0, DB::table('rosters')->count());
        $this->assertSame(0, DB::table('policy_bundles')->count());
    }

    public function test_enrolment_is_unavailable_when_the_catalog_cannot_be_read(): void
    {
        [$serverId, $token] = $this->register();
        config(['sadmin.catalog_path' => '/tidak/ada/CATALOG.md']);

        $this->assertRejected('E_CORE_UNAVAILABLE', 'trust_not_ready', $this->enrollBody($token));

        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
        $this->assertSame(0, DB::table('rosters')->count(), 'Roster yang sempat dibuat harus ikut dibatalkan.');
    }

    public function test_enrolment_is_unavailable_without_a_service_key_or_audit_key(): void
    {
        [$serverId, $token] = $this->register();
        DB::table('secrets')->whereIn('purpose', ['service_key'])->delete();

        $this->assertRejected('E_CORE_UNAVAILABLE', 'trust_not_ready', $this->enrollBody($token));
        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
    }

    public function test_enrolment_is_unavailable_and_keeps_the_token_when_the_vault_cannot_load_its_key(): void
    {
        [$serverId, $token] = $this->register();
        $this->withoutVaultKey();

        $this->assertRejected('E_CORE_UNAVAILABLE', 'vault_unavailable', $this->enrollBody($token));

        $this->assertTrue($this->tokenIsStillRedeemable($serverId));
    }

    public function test_second_server_gets_the_same_trust_documents_but_its_own_fingerprint(): void
    {
        [$firstId, $firstToken] = $this->register('web1');
        $first = $this->accept($this->enrollBody($firstToken));
        [$secondId, $secondToken] = $this->register('web2', '203.0.113.11');

        $second = $this->accept($this->enrollBody($secondToken, ['hostname' => 'web2.instansi.go.id']));

        $a = json_decode($first->frame)->body;
        $b = json_decode($second->frame)->body;
        $this->assertSame($a->roster->document_hash, $b->roster->document_hash);
        $this->assertSame($a->policy->document_hash, $b->policy->document_hash);
        $this->assertNotSame($first->trustFingerprint, $second->trustFingerprint);
        $this->assertNotSame($a->cert, $b->cert);
        $this->assertSame(1, DB::table('rosters')->count());
        $this->assertSame(1, DB::table('policy_bundles')->count());
        $this->assertSame([$firstId, $secondId], [$first->serverId, $second->serverId]);
    }

    public function test_passkey_changes_after_roster_v1_do_not_change_what_later_enrolments_send(): void
    {
        [, $firstToken] = $this->register('web1');
        $first = json_decode($this->accept($this->enrollBody($firstToken))->frame)->body;
        $this->enroll($this->admin, VirtualAuthenticator::eddsa('d'), 'Kunci baru');
        [, $secondToken] = $this->register('web2', '203.0.113.11');

        $second = json_decode($this->accept($this->enrollBody($secondToken))->frame)->body;

        $this->assertCount(2, $second->roster->document->credentials);
        $this->assertSame($first->roster->document_hash, $second->roster->document_hash);
    }

    public function test_a_roster_row_changed_outside_core_is_never_sent_to_an_agent(): void
    {
        [, $firstToken] = $this->register('web1');
        $this->accept($this->enrollBody($firstToken));
        [$secondId, $secondToken] = $this->register('web2', '203.0.113.11');
        DB::table('rosters')->update(['document' => DB::raw("jsonb_set(document, '{rp_id}', '\"penyerang.example\"')")]);

        try {
            $this->accept($this->enrollBody($secondToken));
            $this->fail('Dokumen yang diubah harus ditolak.');
        } catch (TrustDocumentCorrupt) {
            $this->assertTrue($this->tokenIsStillRedeemable($secondId));
        }
    }

    public function test_database_allows_only_one_active_roster_and_policy_per_tenant(): void
    {
        [, $token] = $this->register();
        $this->accept($this->enrollBody($token));

        foreach (['rosters', 'policy_bundles'] as $table) {
            $row = (array) DB::table($table)->first();
            $row['id'] = strtolower((string) Str::ulid());
            $row['version'] = 2;
            $row['document'] = json_encode(json_decode((string) $row['document']));
            try {
                DB::transaction(fn () => DB::table($table)->insert($row));
                $this->fail("{$table}: dua dokumen aktif seharusnya ditolak DB.");
            } catch (QueryException $e) {
                $this->assertStringContainsString("{$table}_one_active", $e->getMessage());
            }
        }
    }

    private function enrollBodyForNewServer(): array
    {
        [, $token] = $this->register('web9', '203.0.113.99');

        return $this->enrollBody($token);
    }

    /** @return list<string> */
    private function sortedMembers(object $object): array
    {
        return $this->sortedKeys(get_object_vars($object));
    }

    /** @param  array<string, mixed>  $array @return list<string> */
    private function sortedKeys(array $array): array
    {
        $keys = array_keys($array);
        sort($keys);

        return $keys;
    }
}
