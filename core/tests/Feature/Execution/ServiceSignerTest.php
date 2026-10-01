<?php

namespace Tests\Feature\Execution;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Execution\Actions\InitializeServiceKey;
use App\Domain\Execution\Dispatch\ServiceSigner;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\VaultUnavailable;
use App\Models\Institution;
use App\Models\Secret;
use App\Models\Tenant;
use DomainException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use stdClass;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/** ADR 0006 §2.3: penyusunan bingkai core→agen bertanda tangan kunci layanan dan verifikasi sendiri. */
class ServiceSignerTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private string $tenantId;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenantId = Institution::factory()->create()->tenant_id;
    }

    private function signer(): ServiceSigner
    {
        return app(ServiceSigner::class);
    }

    /** @return string kunci publik 32 byte mentah */
    private function initServiceKey(): string
    {
        return (string) Ed25519::decode(app(InitializeServiceKey::class)->handle()['publicKey']);
    }

    private static function ulid(): string
    {
        return strtolower((string) Str::ulid());
    }

    /** @return array<string, mixed> */
    private static function envelopeBody(): array
    {
        return [
            'kontrak' => '0.4',
            'envelope_id' => self::ulid(),
            'phase' => 'apply',
            'action_key' => 'source.fetch_git',
            'action_version' => 1,
            'params' => [
                'repo_url' => 'git@example.test:dinas/situs.git',
                'deploy_key' => ['$secret' => '01m3tpf3w0secret0000000000', 'salt' => 'c2FsdA', 'commit' => str_repeat('c', 64)],
            ],
            'risk' => 'L1',
            'plan_hash' => null,
            'secret_values' => ['01m3tpf3w0secret0000000000' => "-----BEGIN TEST-ONLY-----\nrahasia/canary+1\n-----END TEST-ONLY-----\n"],
        ];
    }

    /**
     * Bingkai dengan sig yang sah dari seed uji, sehingga pemeriksaan bentuk teruji terpisah dari sig.
     *
     * @param  array{type: string, id: string, body: array<string, mixed>|stdClass}  $frame
     */
    private static function selfSigned(string $seed, array $frame): string
    {
        $message = ServiceSigner::message($frame['type'], $frame['id'], $frame['body']);
        $frame['sig'] = Ed25519::encode(Ed25519::sign(new SecretValue($seed), $message));

        return json_encode($frame, JSON_THROW_ON_ERROR);
    }

    /** @param callable(stdClass): void $edit */
    private static function tampered(string $frame, callable $edit): string
    {
        $decoded = json_decode($frame, false, 512, JSON_THROW_ON_ERROR);
        $edit($decoded);

        return json_encode($decoded, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public function test_frame_has_exactly_four_members_and_verifies_with_the_key_derived_from_the_vault(): void
    {
        $publicKey = $this->initServiceKey();
        $id = self::ulid();

        $frame = $this->signer()->frame($this->tenantId, 'Envelope', $id, self::envelopeBody());

        $decoded = json_decode($frame, true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(['type', 'id', 'body', 'sig'], array_keys($decoded));
        $this->assertSame('Envelope', $decoded['type']);
        $this->assertSame($id, $decoded['id']);
        $this->assertSame(self::envelopeBody()['params'], $decoded['body']['params']);
        $this->assertMatchesRegularExpression('#^[A-Za-z0-9+/]{86}==$#', $decoded['sig']);
        $this->assertTrue(ServiceSigner::verifyFrame($publicKey, $frame));

        // Pesan dibangun ulang dari bingkai (seperti agen): secret_values tidak ikut.
        $message = ServiceSigner::message('Envelope', $id, json_decode($frame)->body);
        $this->assertStringStartsWith("sadmin-service/1\n{\"body\":{", $message);
        $this->assertStringNotContainsString('secret_values', $message);
        $this->assertStringNotContainsString('canary', $message);
        $this->assertTrue(Ed25519::verify($publicKey, $message, (string) Ed25519::decode($decoded['sig'])));
    }

    public function test_envelope_secret_values_are_outside_the_signature_but_everything_else_is_bound(): void
    {
        $publicKey = $this->initServiceKey();
        $frame = $this->signer()->frame($this->tenantId, 'Envelope', self::ulid(), self::envelopeBody());

        $replaced = self::tampered($frame, function (stdClass $f): void {
            $f->body->secret_values->{'01m3tpf3w0secret0000000000'} = 'nilai lain';
        });
        $removed = self::tampered($frame, function (stdClass $f): void {
            unset($f->body->secret_values);
        });
        $this->assertTrue(ServiceSigner::verifyFrame($publicKey, $replaced), 'secret_values Envelope di luar cakupan sig (agen menangkapnya lewat E_SECRET_COMMIT).');
        $this->assertTrue(ServiceSigner::verifyFrame($publicKey, $removed));

        $attacks = [
            'type' => fn (stdClass $f) => $f->type = 'Cancel',
            'id' => fn (stdClass $f) => $f->id = self::ulid(),
            'params' => fn (stdClass $f) => $f->body->params->repo_url = 'git@example.test:penyerang/situs.git',
            'commit' => fn (stdClass $f) => $f->body->params->deploy_key->commit = str_repeat('d', 64),
            'risk' => fn (stdClass $f) => $f->body->risk = 'L0',
            'anggota baru' => fn (stdClass $f) => $f->body->plan = null,
            'secret_values bersarang' => fn (stdClass $f) => $f->body->params->secret_values = 'disisipkan',
        ];
        foreach ($attacks as $what => $attack) {
            $this->assertFalse(ServiceSigner::verifyFrame($publicKey, self::tampered($frame, $attack)), "Mengubah {$what} seharusnya membatalkan sig.");
        }
    }

    public function test_secret_values_are_signed_in_every_message_type_other_than_envelope(): void
    {
        $publicKey = $this->initServiceKey();
        $frame = $this->signer()->frame($this->tenantId, 'Cancel', self::ulid(), ['plan_hash' => str_repeat('a', 64), 'secret_values' => ['x' => 'y']]);

        $this->assertTrue(ServiceSigner::verifyFrame($publicKey, $frame));
        $this->assertFalse(ServiceSigner::verifyFrame($publicKey, self::tampered($frame, fn (stdClass $f) => $f->body->secret_values->x = 'z')));
        $this->assertFalse(ServiceSigner::verifyFrame($publicKey, self::tampered($frame, function (stdClass $f): void {
            unset($f->body->secret_values);
        })));
    }

    public function test_body_must_be_an_object_and_empty_objects_stay_objects(): void
    {
        $publicKey = $this->initServiceKey();

        foreach ([[], ['a', 'b']] as $list) {
            try {
                $this->signer()->frame($this->tenantId, 'Ack', self::ulid(), $list);
                $this->fail('Badan berupa list seharusnya ditolak.');
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('stdClass', $e->getMessage());
            }
        }

        $frame = $this->signer()->frame($this->tenantId, 'Envelope', self::ulid(), ['params' => new stdClass, 'secret_values' => new stdClass]);
        $this->assertStringContainsString('"params":{}', $frame);
        $this->assertTrue(ServiceSigner::verifyFrame($publicKey, $frame));

        // Envelope yang hanya berisi secret_values tersisa {} (bukan []) setelah anggota itu dikeluarkan.
        $this->assertStringEndsWith('{"body":{},"id":"01m3tpf3w0q6dk22dsdr1mxdn7","type":"Envelope"}', ServiceSigner::message('Envelope', '01m3tpf3w0q6dk22dsdr1mxdn7', ['secret_values' => ['k' => 'v']]));
        $this->assertStringEndsWith('{"body":{},"id":"01m3tpf3w0q6dk22dsdr1mxdn7","type":"Ack"}', ServiceSigner::message('Ack', '01m3tpf3w0q6dk22dsdr1mxdn7', new stdClass));
    }

    public function test_rejects_bodies_that_are_not_i_json(): void
    {
        $this->initServiceKey();

        foreach (['pecahan' => ['n' => 1.5], 'integer besar' => ['n' => PHP_INT_MAX], 'UTF-8 rusak' => ['s' => "\xC3\x28"]] as $what => $body) {
            try {
                $this->signer()->frame($this->tenantId, 'Ack', self::ulid(), $body);
                $this->fail("Badan dengan {$what} seharusnya ditolak.");
            } catch (InvalidArgumentException $e) {
                $this->assertStringStartsWith('JCS:', $e->getMessage());
            }
        }
    }

    public function test_requires_a_type_and_a_ulid_id(): void
    {
        $this->initServiceKey();

        foreach ([['', self::ulid()], ['Ack', 'bukan-ulid'], ['Ack', '81jabcdefghjkmnpqrstvwxyz0']] as [$type, $id]) {
            try {
                $this->signer()->frame($this->tenantId, $type, $id, new stdClass);
                $this->fail("Bingkai type='{$type}' id='{$id}' seharusnya ditolak.");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('ULID', $e->getMessage());
            }
        }
    }

    public function test_fails_closed_without_an_active_key_and_never_creates_one(): void
    {
        try {
            $this->signer()->frame($this->tenantId, 'Ack', self::ulid(), new stdClass);
            $this->fail('Tanpa kunci layanan, bingkai seharusnya tidak disusun.');
        } catch (DomainException $e) {
            $this->assertStringContainsString('sadmin:service-key-init', $e->getMessage());
        }

        $this->initServiceKey();
        $key = Secret::query()->where('purpose', SecretPurpose::ServiceKey->value)->sole();
        app(DestroySecret::class)->handle($key->id, ActorType::LocalRoot, null);

        $this->expectException(DomainException::class);
        try {
            $this->signer()->frame($this->tenantId, 'Ack', self::ulid(), new stdClass);
        } finally {
            $this->assertSame(1, Secret::query()->where('purpose', SecretPurpose::ServiceKey->value)->count());
        }
    }

    public function test_signs_only_with_the_key_of_the_requested_tenant(): void
    {
        $publicKey = $this->initServiceKey();
        $foreign = Tenant::factory()->create();
        app(StoreSecret::class)->handle($foreign->id, SecretPurpose::ServiceKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
        $foreignKey = app(ServiceSigner::class)->publicKey((string) app(ServiceSigner::class)->activeKeyId($foreign->id), $foreign->id);

        $ours = $this->signer()->frame($this->tenantId, 'Ack', self::ulid(), new stdClass);
        $theirs = $this->signer()->frame($foreign->id, 'Ack', self::ulid(), new stdClass);

        $this->assertNotSame($publicKey, $foreignKey);
        $this->assertTrue(ServiceSigner::verifyFrame($publicKey, $ours));
        $this->assertFalse(ServiceSigner::verifyFrame($publicKey, $theirs));
        $this->assertTrue(ServiceSigner::verifyFrame($foreignKey, $theirs));
    }

    public function test_vault_unavailability_propagates_and_no_frame_is_returned(): void
    {
        $this->initServiceKey();
        $this->withoutVaultKey();

        $this->expectException(VaultUnavailable::class);

        $this->signer()->frame($this->tenantId, 'Ack', self::ulid(), new stdClass);
    }

    public function test_rejects_frames_larger_than_one_mebibyte(): void
    {
        $publicKey = $this->initServiceKey();
        $overhead = strlen($this->signer()->frame($this->tenantId, 'Ack', '01m3tpf3w0q6dk22dsdr1mxdn7', ['p' => '']));

        $fits = $this->signer()->frame($this->tenantId, 'Ack', '01m3tpf3w0q6dk22dsdr1mxdn7', ['p' => str_repeat('a', ServiceSigner::MAX_FRAME_BYTES - $overhead)]);
        $this->assertSame(ServiceSigner::MAX_FRAME_BYTES, strlen($fits));
        $this->assertTrue(ServiceSigner::verifyFrame($publicKey, $fits));

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('1 MiB');
        $this->signer()->frame($this->tenantId, 'Ack', '01m3tpf3w0q6dk22dsdr1mxdn7', ['p' => str_repeat('a', ServiceSigner::MAX_FRAME_BYTES - $overhead + 1)]);
    }

    public function test_signs_with_the_active_key_never_a_rotated_one(): void
    {
        $this->initServiceKey();
        $store = app(StoreSecret::class);
        foreach ([1, 2] as $_) {
            DB::table('secrets')->where('purpose', 'service_key')->where('status', 'active')->update(['status' => 'rotated']);
            $store->handle($this->tenantId, SecretPurpose::ServiceKey, Ed25519::generateSeed(), ActorType::LocalRoot, null);
        }
        $active = (string) $this->signer()->activeKeyId($this->tenantId);
        $this->assertSame('active', Secret::query()->findOrFail($active)->status->value);

        $frame = $this->signer()->frame($this->tenantId, 'Ack', self::ulid(), new stdClass);

        $this->assertTrue(ServiceSigner::verifyFrame($this->signer()->publicKey($active, $this->tenantId), $frame));
        foreach (Secret::query()->where('status', 'rotated')->pluck('id') as $rotated) {
            $this->assertFalse(ServiceSigner::verifyFrame($this->signer()->publicKey($rotated, $this->tenantId), $frame), 'Kunci rotated tak boleh menandatangani.');
        }
    }

    public function test_verify_frame_rejects_every_shape_the_agent_rejects(): void
    {
        $publicKey = $this->initServiceKey();
        $frame = $this->signer()->frame($this->tenantId, 'Ack', self::ulid(), ['id' => self::ulid()]);
        $f = json_decode($frame, true, 512, JSON_THROW_ON_ERROR);
        $encode = fn (mixed $v): string => json_encode($v, JSON_THROW_ON_ERROR);

        $rejected = [
            'bukan JSON' => 'bukan json',
            'larik' => $encode([$f]),
            'tanpa sig' => $encode(array_diff_key($f, ['sig' => 1])),
            'sig bukan string' => $encode(['sig' => null] + $f),
            'anggota tambahan' => $encode($f + ['extra' => 1]),
            'body larik' => $encode(['body' => []] + $f),
            'id bukan ULID' => $encode(['id' => 'bukan-ulid'] + $f),
            'type kosong' => $encode(['type' => ''] + $f),
            'kunci ganda' => substr($frame, 0, -1).',"sig":'.$encode($f['sig']).'}',
            'BOM' => "\xEF\xBB\xBF".$frame,
            'base64 tak kanonik' => $encode(['sig' => substr($f['sig'], 0, 85).chr(ord($f['sig'][85]) ^ 1).'=='] + $f),
            'sig base64url' => $encode(['sig' => strtr($f['sig'], '+/', '-_')] + $f),
        ];
        foreach ($rejected as $what => $text) {
            $this->assertFalse(ServiceSigner::verifyFrame($publicKey, $text), "Bingkai {$what} seharusnya ditolak.");
        }

        $this->assertTrue(ServiceSigner::verifyFrame($publicKey, $frame));
        $this->assertFalse(ServiceSigner::verifyFrame(str_repeat("\0", 32), $frame), 'Kunci publik lain tak boleh memverifikasi.');

        // sig sah atas bentuk yang salah: yang menolak adalah pemeriksaan bentuk, bukan sig.
        $seed = random_bytes(32);
        $testKey = Ed25519::publicKey(new SecretValue($seed));
        $this->assertTrue(ServiceSigner::verifyFrame($testKey, self::selfSigned($seed, ['type' => 'Ack', 'id' => self::ulid(), 'body' => new stdClass])));
        $this->assertFalse(ServiceSigner::verifyFrame($testKey, self::selfSigned($seed, ['type' => 'Ack', 'id' => 'bukan-ulid', 'body' => new stdClass])));
        $this->assertFalse(ServiceSigner::verifyFrame($testKey, self::selfSigned($seed, ['type' => '', 'id' => self::ulid(), 'body' => new stdClass])));
    }
}
