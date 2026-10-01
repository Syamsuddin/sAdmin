<?php

namespace Tests\Feature\Fleet;

use App\Domain\Fleet\Actions\InitializeCertificateAuthority;
use App\Domain\Fleet\Actions\IssueEnrollmentToken;
use App\Domain\Fleet\Actions\RegisterServer;
use App\Domain\Fleet\Data\ServerRegistrationRejected;
use App\Domain\Fleet\Data\ServerStatus;
use App\Models\Admin;
use App\Models\Server;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\Support\InteractsWithPasskeys;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** AC-17 docs/23: token baru hanya untuk server yang masih menunggu enrolment, dan langsung menggantikan token lama. */
class IssueEnrollmentTokenTest extends TestCase
{
    use InteractsWithPasskeys, InteractsWithVault, RefreshDatabase;

    private Admin $admin;

    private string $serverId;

    private string $firstToken;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpInstitution();
        $this->admin = $this->newAdmin();
        app(InitializeCertificateAuthority::class)->handle();
        config(['sadmin.gateway_host' => 'gw.instansi.go.id']);

        $this->travelTo(now()->setTimezone('UTC')->setDate(2026, 10, 2)->setTime(6, 0));
        $first = app(RegisterServer::class)->handle($this->admin, 'web1', 'web1.instansi.go.id', '203.0.113.10');
        $this->serverId = $first->serverId;
        $this->firstToken = $first->token();
    }

    private function storedHash(): ?string
    {
        return DB::table('servers')->where('id', $this->serverId)->value('enroll_token_hash');
    }

    public function test_new_token_replaces_the_old_one_and_restarts_the_fifteen_minutes(): void
    {
        $this->travelTo(now()->setTimezone('UTC')->setDate(2026, 10, 2)->setTime(6, 30, 45));

        $token = app(IssueEnrollmentToken::class)->handle($this->admin, $this->serverId);

        $this->assertNotSame($this->firstToken, $token->token());
        $this->assertSame(hash('sha256', $token->token()), $this->storedHash());
        $this->assertSame(0, DB::table('servers')->where('enroll_token_hash', hash('sha256', $this->firstToken))->count());
        $this->assertSame('2026-10-02 06:45:45', Server::query()->sole()->enroll_token_expires_at?->utc()->format('Y-m-d H:i:s'));
        $this->assertSame(ServerStatus::Enrolling, Server::query()->sole()->status);

        $entry = DB::table('audit_entries')->where('action_key', 'server.enroll_token_issue')->orderByDesc('seq')->first();
        $this->assertSame("server:{$this->serverId}", $entry?->target);
        $this->assertSame(['expires_at' => '2026-10-02T06:45:45Z'], json_decode((string) $entry?->params_redacted, true));
    }

    public function test_every_token_is_fresh(): void
    {
        $tokens = [$this->firstToken];
        for ($i = 0; $i < 5; $i++) {
            $tokens[] = app(IssueEnrollmentToken::class)->handle($this->admin, $this->serverId)->token();
        }

        $this->assertCount(6, array_unique($tokens));
    }

    public function test_refuses_servers_that_no_longer_wait_for_enrolment(): void
    {
        foreach ([ServerStatus::Online, ServerStatus::Offline, ServerStatus::NeedsAttention, ServerStatus::Retired] as $status) {
            DB::table('servers')->where('id', $this->serverId)
                ->update(['status' => $status->value, 'enroll_token_hash' => null, 'enroll_token_expires_at' => null]);
            $audit = DB::table('audit_entries')->count();

            try {
                app(IssueEnrollmentToken::class)->handle($this->admin, $this->serverId);
                $this->fail("Server {$status->value} tak boleh mendapat token.");
            } catch (ServerRegistrationRejected $e) {
                $this->assertSame('not_enrolling', $e->reason);
            }
            $this->assertNull($this->storedHash());
            $this->assertSame($audit, DB::table('audit_entries')->count());
        }
    }

    public function test_refuses_servers_of_another_tenant_and_unknown_ids(): void
    {
        $foreign = Server::factory()->create(['status' => ServerStatus::Enrolling]);

        foreach ([$foreign->id, '01k6abcdefghjkmnpqrstvwxyz'] as $id) {
            try {
                app(IssueEnrollmentToken::class)->handle($this->admin, $id);
                $this->fail('Server di luar tenant admin tak boleh mendapat token.');
            } catch (ServerRegistrationRejected $e) {
                $this->assertSame('not_enrolling', $e->reason);
            }
        }
        $this->assertNull(DB::table('servers')->where('id', $foreign->id)->value('enroll_token_hash'));
    }

    public function test_refuses_without_a_usable_gateway_before_touching_the_old_token(): void
    {
        config(['sadmin.gateway_host' => null]);

        try {
            app(IssueEnrollmentToken::class)->handle($this->admin, $this->serverId);
            $this->fail('Tanpa gateway, token tak boleh diterbitkan.');
        } catch (ServerRegistrationRejected $e) {
            $this->assertSame('gateway_unset', $e->reason);
        }
        $this->assertSame(hash('sha256', $this->firstToken), $this->storedHash());
    }
}
