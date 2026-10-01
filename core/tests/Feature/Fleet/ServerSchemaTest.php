<?php

namespace Tests\Feature\Fleet;

use App\Models\Server;
use App\Models\Tenant;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/** docs/07 §Armada: constraint `servers`, `agents`, dan FK `alerts.server_id` menjaga invarian di bawah kode. */
class ServerSchemaTest extends TestCase
{
    use RefreshDatabase;

    private string $tenantId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenantId = Tenant::factory()->create()->id;
    }

    /** @param  array<string, mixed>  $overrides */
    private function insertServer(array $overrides = []): string
    {
        $id = strtolower((string) Str::ulid());
        DB::table('servers')->insert([
            'id' => $id,
            'tenant_id' => $this->tenantId,
            'name' => 'web-'.substr($id, -6),
            'hostname' => 'web1.instansi.go.id',
            'ip' => '203.0.113.10',
            'status' => 'enrolling',
            'created_at' => now(),
            'updated_at' => now(),
            ...$overrides,
        ]);

        return $id;
    }

    /** @param  array<string, mixed>  $overrides */
    private function insertAgent(string $serverId, array $overrides = []): void
    {
        DB::table('agents')->insert([
            'id' => strtolower((string) Str::ulid()),
            'tenant_id' => $this->tenantId,
            'server_id' => $serverId,
            'agent_version' => '0.1.0',
            'cert_serial' => '1a2b',
            'cert_expires_at' => now()->addDays(7),
            'roster_version' => 1,
            'policy_version' => 1,
            'connection' => 'disconnected',
            'trust_fingerprint' => str_repeat('a', 64),
            'created_at' => now(),
            'updated_at' => now(),
            ...$overrides,
        ]);
    }

    private function assertRejectedByDatabase(callable $write): void
    {
        try {
            DB::transaction($write);
            $this->fail('Basis data seharusnya menolak baris ini.');
        } catch (QueryException $e) {
            $this->assertMatchesRegularExpression('/23505|23514|23503|22P02/', (string) $e->getCode());
        }
    }

    public function test_defaults_follow_the_data_model(): void
    {
        $id = $this->insertServer();
        $row = DB::table('servers')->where('id', $id)->first();

        $this->assertSame('managed', $row?->ownership);
        $this->assertFalse($row?->is_control_plane_host);
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function invalidServers(): array
    {
        $hash = str_repeat('a', 64);

        return [
            'status tak dikenal' => [['status' => 'active']],
            'kepemilikan tak dikenal' => [['ownership' => 'owned']],
            'alamat bukan inet' => [['ip' => 'web1']],
            'os_release bukan objek' => [['os_release' => '[]']],
            'hash token huruf besar' => [['enroll_token_hash' => strtoupper($hash), 'enroll_token_expires_at' => now()]],
            'hash token tanpa batas waktu' => [['enroll_token_hash' => $hash]],
            'batas waktu tanpa hash token' => [['enroll_token_expires_at' => now()]],
            'token pada server online' => [['status' => 'online', 'enroll_token_hash' => $hash, 'enroll_token_expires_at' => now()]],
        ];
    }

    /** @param  array<string, mixed>  $overrides */
    #[DataProvider('invalidServers')]
    public function test_rejects_invalid_server_rows(array $overrides): void
    {
        $this->assertRejectedByDatabase(fn () => $this->insertServer($overrides));
    }

    public function test_names_are_unique_per_tenant_and_tokens_unique_overall(): void
    {
        $this->insertServer(['name' => 'web1']);
        $this->assertRejectedByDatabase(fn () => $this->insertServer(['name' => 'web1', 'status' => 'retired']));

        $other = Tenant::factory()->create()->id;
        $this->insertServer(['tenant_id' => $other, 'name' => 'web1']);

        $token = ['enroll_token_hash' => str_repeat('b', 64), 'enroll_token_expires_at' => now()];
        $this->insertServer($token);
        $this->assertRejectedByDatabase(fn () => $this->insertServer($token));
    }

    public function test_alerts_may_only_point_at_existing_servers(): void
    {
        $alert = [
            'id' => strtolower((string) Str::ulid()), 'tenant_id' => $this->tenantId, 'severity' => 'critical', 'title' => 't',
            'detail' => '{}', 'status' => 'open', 'opened_at' => now(), 'created_at' => now(), 'updated_at' => now(),
        ];
        $this->assertRejectedByDatabase(fn () => DB::table('alerts')->insert([...$alert, 'server_id' => strtolower((string) Str::ulid())]));

        DB::table('alerts')->insert([...$alert, 'server_id' => $this->insertServer()]);
        $this->assertSame(1, DB::table('alerts')->count());
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function invalidAgents(): array
    {
        return [
            'koneksi tak dikenal' => [['connection' => 'online']],
            'serial nol di depan' => [['cert_serial' => '01']],
            'serial huruf besar' => [['cert_serial' => 'AB']],
            'serial nol' => [['cert_serial' => '0']],
            'serial lewat 2^63-1' => [['cert_serial' => '8000000000000000']],
            'serial 17 digit' => [['cert_serial' => '10000000000000000']],
            'sidik jari kepercayaan bukan hex' => [['trust_fingerprint' => str_repeat('G', 64)]],
            'sidik jari kepercayaan kurang panjang' => [['trust_fingerprint' => str_repeat('a', 63)]],
            'kepala audit tanpa hash' => [['audit_head_seq' => 5]],
            'hash kepala audit bukan hex' => [['audit_head_seq' => 5, 'audit_head_hash' => str_repeat('z', 64)]],
        ];
    }

    /** @param  array<string, mixed>  $overrides */
    #[DataProvider('invalidAgents')]
    public function test_rejects_invalid_agent_rows(array $overrides): void
    {
        $server = $this->insertServer(['status' => 'online']);

        $this->assertRejectedByDatabase(fn () => $this->insertAgent($server, $overrides));
    }

    public function test_one_agent_per_server_and_largest_serial_is_accepted(): void
    {
        $server = $this->insertServer(['status' => 'online']);
        $this->insertAgent($server, ['cert_serial' => '7fffffffffffffff', 'audit_head_seq' => 3, 'audit_head_hash' => str_repeat('c', 64)]);

        $this->assertRejectedByDatabase(fn () => $this->insertAgent($server));
        $this->assertSame('7fffffffffffffff', Server::query()->sole()->agent?->cert_serial);
    }
}
