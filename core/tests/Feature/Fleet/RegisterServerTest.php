<?php

namespace Tests\Feature\Fleet;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Services\AuditChainVerifier;
use App\Domain\Fleet\Actions\InitializeCertificateAuthority;
use App\Domain\Fleet\Actions\RegisterServer;
use App\Domain\Fleet\Data\EnrollmentToken;
use App\Domain\Fleet\Data\ServerRegistrationRejected;
use App\Domain\Fleet\Data\ServerStatus;
use App\Domain\Fleet\Services\CertificateAuthority;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Models\Admin;
use App\Models\Secret;
use App\Models\Server;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Tests\Support\InteractsWithPasskeys;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** AC-17 docs/23: admin menambah server; core menyimpan hash token sekali pakai 15 menit dan mencatat audit tanpa token. */
class RegisterServerTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithVault, RefreshDatabase;

    private const GATEWAY = 'gw.instansi.go.id';

    private Admin $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpInstitution();
        $this->admin = $this->newAdmin();
        app(InitializeCertificateAuthority::class)->handle();
        config(['sadmin.gateway_host' => self::GATEWAY]);
    }

    private function register(string $name = 'web1', string $hostname = 'web1.instansi.go.id', string $ip = '203.0.113.10', ?Admin $admin = null): EnrollmentToken
    {
        return app(RegisterServer::class)->handle($admin ?? $this->admin, $name, $hostname, $ip);
    }

    private function assertRejected(string $reason, callable $act): void
    {
        $servers = Server::query()->count();
        $audit = DB::table('audit_entries')->count();
        try {
            $act();
            $this->fail("Seharusnya ditolak: {$reason}");
        } catch (ServerRegistrationRejected $e) {
            $this->assertSame($reason, $e->reason);
        }
        $this->assertSame($servers, Server::query()->count(), 'Penolakan tak boleh membuat server.');
        $this->assertSame($audit, DB::table('audit_entries')->count(), 'Penolakan tak boleh menulis audit.');
    }

    public function test_registers_an_enrolling_server_and_stores_only_the_token_hash(): void
    {
        $this->travelTo(now()->setTimezone('UTC')->setDate(2026, 10, 2)->setTime(6, 5, 30, 250000));

        $token = $this->register();

        $server = Server::query()->sole();
        $this->assertSame(ServerStatus::Enrolling, $server->status);
        $this->assertSame(['web1', 'web1.instansi.go.id', '203.0.113.10'], [$server->name, $server->hostname, $server->ip]);
        $this->assertSame('managed', DB::table('servers')->value('ownership'));
        $this->assertFalse($server->is_control_plane_host);
        $this->assertSame($server->id, $token->serverId);
        $this->assertSame('web1', $token->serverName);

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}\z/', $token->token());
        $this->assertSame(hash('sha256', $token->token()), DB::table('servers')->value('enroll_token_hash'));
        $this->assertStringNotContainsString($token->token(), (string) DB::table('servers')->get()->toJson());

        // 15 menit dari detik penerbitan, dibulatkan ke bawah: tak pernah lebih lama dari KONTRAK §5.
        $this->assertSame('2026-10-02 06:20:30.000000', $server->enroll_token_expires_at?->utc()->format('Y-m-d H:i:s.u'));
        $this->assertTrue($token->expiresAt->equalTo($server->enroll_token_expires_at));
    }

    public function test_command_carries_the_gateway_the_ca_pin_and_the_token(): void
    {
        $token = $this->register();
        $pin = app(CertificateAuthority::class)->fingerprint($this->admin->tenant_id);

        $this->assertSame(self::GATEWAY.':8443', $token->target->gateway);
        $this->assertSame($pin, $token->target->caSha256);
        $this->assertSame(
            'sudo sadmin-agent enroll --gateway '.self::GATEWAY.':8443 --ca-sha256 '.$pin.' --token '.$token->token(),
            $token->command(),
        );
    }

    public function test_registration_and_token_issue_are_audited_without_the_token(): void
    {
        $this->travelTo(now()->setTimezone('UTC')->setDate(2026, 10, 2)->setTime(6, 5, 30));
        $token = $this->register();
        $serverId = $token->serverId;

        $entries = DB::table('audit_entries')->whereIn('action_key', ['server.register', 'server.enroll_token_issue'])->orderBy('seq')->get();
        $this->assertSame(['server.register', 'server.enroll_token_issue'], $entries->pluck('action_key')->all());
        foreach ($entries as $entry) {
            $this->assertSame('admin', $entry->actor_type);
            $this->assertSame($this->admin->id, $entry->actor_id);
            $this->assertSame("server:{$serverId}", $entry->target);
            $this->assertSame('ok', $entry->outcome);
        }
        $this->assertEquals(['hostname' => 'web1.instansi.go.id', 'ip' => '203.0.113.10', 'name' => 'web1'], json_decode($entries[0]->params_redacted, true));
        $this->assertSame(['expires_at' => '2026-10-02T06:20:30Z'], json_decode($entries[1]->params_redacted, true));
        $this->assertTrue(app(AuditChainVerifier::class)->verify()->intact);
    }

    #[Group('redaction')]
    public function test_token_never_reaches_audit_logs_or_debug_output(): void
    {
        $logged = [];
        Log::listen(function (MessageLogged $event) use (&$logged): void {
            $logged[] = [$event->message, $event->context];
        });

        $token = $this->register();

        $this->assertStringNotContainsString($token->token(), DB::table('audit_entries')->get()->toJson());
        $this->assertStringNotContainsString($token->token(), (string) json_encode($logged));
        // Konteks log objek dinormalkan Monolog lewat json_encode; print_r/var_dump memakai __debugInfo.
        Log::info('enrolment_issued', ['token' => $token]);
        $this->assertStringNotContainsString($token->token(), (string) json_encode($logged));
        $this->assertStringNotContainsString($token->token(), (string) json_encode($token));
        $this->assertStringNotContainsString($token->token(), (string) json_encode($token->__debugInfo()));
        $this->assertStringNotContainsString($token->token(), var_export(Server::query()->sole()->toArray(), true));
    }

    /** Review F-02c R-1: penolakan masukan membawa semua field yang salah. */
    public function test_rejection_lists_every_invalid_field(): void
    {
        try {
            $this->register('Web 1', '10.0.0.1', '127.0.0.1');
            $this->fail('Seharusnya ditolak.');
        } catch (ServerRegistrationRejected $e) {
            $this->assertSame(['name' => 'invalid_name', 'hostname' => 'invalid_hostname', 'ip' => 'invalid_ip'], $e->fieldReasons());
        }
    }

    /** Review F-02c R-6: token tak bisa ikut terserialisasi (antrean, cache, sesi). */
    public function test_token_refuses_serialization(): void
    {
        $token = $this->register();

        $this->expectException(\LogicException::class);
        serialize($token);
    }

    public function test_hostname_is_lowercased_and_ip_is_stored_in_canonical_form(): void
    {
        $this->register('db1', ' DB1.Instansi.Go.Id ', ' 2001:DB8:0:0::0:1 ');

        $server = Server::query()->sole();
        $this->assertSame('db1.instansi.go.id', $server->hostname);
        $this->assertSame('2001:db8::1', $server->ip);
    }

    /** @return array<string, array{string}> */
    public static function acceptedNames(): array
    {
        return ['satu huruf' => ['a'], 'huruf dan angka' => ['web1'], 'tanda hubung di tengah' => ['web-prod-1'], '63 karakter' => [str_repeat('a', 63)]];
    }

    #[DataProvider('acceptedNames')]
    public function test_accepts_dns_label_names(string $name): void
    {
        $this->register($name);

        $this->assertSame($name, Server::query()->value('name'));
    }

    /** @return array<string, array{string}> */
    public static function invalidNames(): array
    {
        return [
            'kosong' => [''],
            'spasi saja' => ['   '],
            'huruf besar' => ['Web1'],
            'diawali tanda hubung' => ['-web'],
            'diakhiri tanda hubung' => ['web-'],
            'garis bawah' => ['web_1'],
            'spasi di tengah' => ['web 1'],
            'titik' => ['web.1'],
            '64 karakter' => [str_repeat('a', 64)],
            'LF di tengah' => ["web\n1"],
            'NUL di tengah' => ["web\0001"],
        ];
    }

    #[DataProvider('invalidNames')]
    public function test_rejects_invalid_names(string $name): void
    {
        $this->assertRejected('invalid_name', fn () => $this->register($name));
    }

    /** @return array<string, array{string}> */
    public static function invalidHostnames(): array
    {
        return [
            'kosong' => [''],
            'alamat IPv4' => ['10.0.0.1'],
            'label teratas angka' => ['web1.123'],
            'titik ganda' => ['web1..instansi.go.id'],
            'titik di akhir' => ['web1.instansi.go.id.'],
            'label diawali tanda hubung' => ['-web1.instansi.go.id'],
            'label 64 karakter' => [str_repeat('a', 64).'.go.id'],
            'lebih dari 253 karakter' => [implode('.', array_fill(0, 5, str_repeat('a', 50))).'.go'],
            'garis bawah' => ['web_1.instansi.go.id'],
            'skema URL' => ['https://web1.instansi.go.id'],
            'LF di tengah' => ["web1\n.go.id"],
            'label teratas heksadesimal' => ['1.2.3.0x4'],
            'IPv4 heksadesimal' => ['0x7f000001'],
        ];
    }

    #[DataProvider('invalidHostnames')]
    public function test_rejects_invalid_hostnames(string $hostname): void
    {
        $this->assertRejected('invalid_hostname', fn () => $this->register(hostname: $hostname));
    }

    public function test_accepts_a_single_label_hostname_and_a_253_character_name(): void
    {
        $this->register('a', 'web1');
        $long = implode('.', array_fill(0, 3, str_repeat('a', 63))).'.'.str_repeat('b', 61);
        $this->assertSame(253, strlen($long));
        $this->register('b', $long, '203.0.113.11');

        $this->assertSame(['web1', $long], Server::query()->orderBy('name')->pluck('hostname')->all());
    }

    /** @return array<string, array{string}> */
    public static function invalidIps(): array
    {
        return [
            'kosong' => [''],
            'loopback' => ['127.0.0.1'],
            'tak spesifik' => ['0.0.0.0'],
            'link-local' => ['169.254.10.1'],
            'loopback IPv6' => ['::1'],
            'link-local IPv6' => ['fe80::1'],
            'oktet di luar rentang' => ['999.1.1.1'],
            'notasi CIDR' => ['10.0.0.1/24'],
            'nol di depan' => ['010.0.0.1'],
            'nama host' => ['web1.instansi.go.id'],
            'zona IPv6' => ['fe80::1%eth0'],
            'multicast IPv4' => ['224.0.0.1'],
            'multicast SSDP' => ['239.255.255.250'],
            'multicast IPv6' => ['ff02::1'],
        ];
    }

    #[DataProvider('invalidIps')]
    public function test_rejects_ips_that_cannot_address_a_server(string $ip): void
    {
        $this->assertRejected('invalid_ip', fn () => $this->register(ip: $ip));
    }

    public function test_accepts_private_and_ipv6_addresses(): void
    {
        $this->register('a', ip: '10.0.0.5');
        $this->register('b', ip: '2001:db8::1');

        $this->assertSame(['10.0.0.5', '2001:db8::1'], Server::query()->orderBy('name')->pluck('ip')->all());
    }

    public function test_name_stays_taken_after_the_server_is_retired(): void
    {
        $this->register('web1');
        $this->assertRejected('name_taken', fn () => $this->register('web1', ip: '203.0.113.11'));

        Server::query()->update(['status' => ServerStatus::Retired, 'enroll_token_hash' => null, 'enroll_token_expires_at' => null]);
        $this->assertRejected('name_taken', fn () => $this->register('web1', ip: '203.0.113.11'));
    }

    public function test_single_mode_allows_at_most_three_unretired_servers(): void
    {
        $this->register('a');
        $this->register('b');
        $this->register('c');
        $this->assertRejected('server_limit', fn () => $this->register('d'));

        Server::query()->where('name', 'a')->update(['status' => ServerStatus::Retired, 'enroll_token_hash' => null, 'enroll_token_expires_at' => null]);
        $this->register('d');
        $this->assertSame(4, Server::query()->count());
    }

    public function test_limit_and_names_are_counted_per_tenant(): void
    {
        $this->register('web1');
        $other = Server::factory()->count(3)->create();
        Server::factory()->create(['tenant_id' => $other[0]->tenant_id, 'name' => 'web2', 'status' => ServerStatus::Retired]);

        $this->register('web2');
        $this->register('web3');
        $this->assertSame(3, Server::query()->where('tenant_id', $this->admin->tenant_id)->count());
    }

    /** @return array<string, array{mixed}> */
    public static function unusableGateways(): array
    {
        return [
            'kosong' => [''],
            'tak diatur' => [null],
            'huruf besar' => ['GW.instansi.go.id'],
            'dengan port' => ['gw.instansi.go.id:8443'],
            'skema URL' => ['https://gw.instansi.go.id'],
            'IPv6' => ['2001:db8::1'],
            'LF di akhir' => ["gw.instansi.go.id\n"],
            'loopback' => ['127.0.0.1'],
            'tak spesifik' => ['0.0.0.0'],
            'siaran' => ['255.255.255.255'],
            'multicast' => ['224.0.0.1'],
            'IPv4 heksadesimal' => ['1.2.3.0x4'],
        ];
    }

    #[DataProvider('unusableGateways')]
    public function test_refuses_to_register_without_a_usable_gateway_host(mixed $host): void
    {
        config(['sadmin.gateway_host' => $host]);

        $this->assertRejected('gateway_unset', fn () => $this->register());
    }

    public function test_accepts_an_ipv4_gateway(): void
    {
        config(['sadmin.gateway_host' => '203.0.113.1']);

        $this->assertSame('203.0.113.1:8443', $this->register()->target->gateway);
    }

    public function test_refuses_to_register_without_an_active_ca(): void
    {
        $ca = Secret::query()->where('purpose', SecretPurpose::CaKey->value)->sole();
        app(DestroySecret::class)->handle($ca->id, ActorType::LocalRoot, null);

        $this->assertRejected('ca_missing', fn () => $this->register());
    }

    public function test_refuses_to_register_when_the_vault_cannot_open_the_ca(): void
    {
        $this->withoutVaultKey();

        $this->assertRejected('vault_unavailable', fn () => $this->register());
    }
}
