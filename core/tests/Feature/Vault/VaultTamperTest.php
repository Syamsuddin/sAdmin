<?php

namespace Tests\Feature\Vault;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\Vault;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use App\Models\Casts\Bytea;
use App\Models\Secret;
use App\Models\Tenant;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;

/**
 * ADR 0003 §2.3, §2.5, §2.8: baris yang diubah lewat SQL (penyerang dengan akses DB tanpa kunci induk) gagal
 * dibuka, tak pernah menghasilkan nilai yang salah; vektor emas terbuka persis.
 */
class VaultTamperTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private Tenant $tenant;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tenant = Tenant::factory()->create();
    }

    private function store(string $value, SecretPurpose $purpose = SecretPurpose::ApiToken): Secret
    {
        return app(StoreSecret::class)->handle($this->tenant->id, $purpose, new SecretValue($value), ActorType::System, null);
    }

    private function reveal(Secret $secret): string
    {
        $fresh = Secret::query()->with('keyWrap')->findOrFail($secret->id);

        return app(Vault::class)->reveal($fresh)->expose();
    }

    private function assertRevealFails(Secret $secret, string $exception = VaultIntegrityError::class): void
    {
        try {
            $this->reveal($secret);
            $this->fail('Rahasia yang diubah seharusnya gagal dibuka.');
        } catch (VaultIntegrityError|VaultUnavailable $e) {
            $this->assertInstanceOf($exception, $e);
        }
    }

    /** @param  array<string, string>  $bytea */
    private function updateBytea(string $table, string $id, array $bytea): void
    {
        DB::table($table)->where('id', $id)->update(array_map(Bytea::literal(...), $bytea));
    }

    private function wrappedDek(Secret $secret): string
    {
        return (string) Secret::query()->with('keyWrap')->findOrFail($secret->id)->keyWrap?->wrapped_dek;
    }

    public function test_golden_vector_opens(): void
    {
        $hex = static fn (int $from, int $n): string => implode('', array_map('chr', range($from, $from + $n - 1)));
        $this->useVaultKey($hex(0x00, 32));
        $tenant = '01k6gz7t0000000000000000t1';
        $wrap = '01k6gz7t0000000000000000w1';
        $secret = '01k6gz7t0000000000000000s1';
        DB::table('tenants')->insert(['id' => $tenant, 'name' => 'Vektor ADR 0003', 'created_at' => now(), 'updated_at' => now()]);
        DB::table('key_wraps')->insert(['id' => $wrap, 'tenant_id' => $tenant, 'master_key_version' => 1, 'created_at' => now(),
            'wrapped_dek' => '\\x404142434445464748494a4b4c4d4e4f5051525354555657f4182753f4c55f31a7ddad9583b14bbda28b9ff7276c65ad5208c77e35391daf4bb77814e72375c562a3f794bc4f9d08']);
        DB::table('secrets')->insert(['id' => $secret, 'tenant_id' => $tenant, 'purpose' => 'api_token', 'key_wrap_id' => $wrap,
            'status' => 'active', 'created_at' => now(), 'updated_at' => now(),
            'nonce' => '\\x606162636465666768696a6b6c6d6e6f7071727374757677',
            'ciphertext' => '\\x9a462847f618faecdf6bfc2253e57db447dc9c26ea8c5dca6e53712219fdbe33b0697793']);

        $this->assertSame('rahasia-uji-ADR-0003', $this->reveal(Secret::query()->findOrFail($secret)));
        $this->assertSame($hex(0x20, 32), sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            hex2bin('f4182753f4c55f31a7ddad9583b14bbda28b9ff7276c65ad5208c77e35391daf4bb77814e72375c562a3f794bc4f9d08') ?: '',
            "sadmin-vault/1/key_wrap/{$tenant}/{$wrap}/1", $hex(0x40, 24), $hex(0x00, 32),
        ), 'Vektor emas harus sesuai teks ADR 0003 §2.2 (DEK 0x20..0x3f).');
    }

    public function test_swapping_ciphertexts_between_secrets_fails(): void
    {
        $a = $this->store('nilai-a');
        $b = $this->store('nilai-b');

        $this->updateBytea('secrets', $a->id, ['ciphertext' => $b->ciphertext, 'nonce' => $b->nonce]);
        $this->updateBytea('secrets', $b->id, ['ciphertext' => $a->ciphertext, 'nonce' => $a->nonce]);

        $this->assertRevealFails($a);
        $this->assertRevealFails($b);
    }

    public function test_relabelling_the_purpose_fails(): void
    {
        $secret = $this->store('nilai', SecretPurpose::ApiToken);

        DB::table('secrets')->where('id', $secret->id)->update(['purpose' => 'upload']);

        $this->assertRevealFails($secret);
    }

    public function test_moving_a_secret_to_another_tenant_fails(): void
    {
        $secret = $this->store('nilai');
        $other = Tenant::factory()->create();

        DB::table('secrets')->where('id', $secret->id)->update(['tenant_id' => $other->id]);
        $this->assertRevealFails($secret);

        DB::table('secrets')->where('id', $secret->id)->update(['tenant_id' => $this->tenant->id]);
        DB::table('key_wraps')->where('id', $secret->key_wrap_id)->update(['tenant_id' => $other->id]);
        $this->assertRevealFails($secret);
    }

    public function test_pointing_a_secret_at_a_copied_key_wrap_fails(): void
    {
        $secret = $this->store('nilai');
        $copy = strtolower((string) Str::ulid());
        DB::table('key_wraps')->insert(['id' => $copy, 'tenant_id' => $this->tenant->id, 'master_key_version' => 1,
            'created_at' => now(), 'wrapped_dek' => Bytea::literal($this->wrappedDek($secret))]);

        DB::table('secrets')->where('id', $secret->id)->update(['key_wrap_id' => $copy]);

        $this->assertRevealFails($secret);
    }

    public function test_single_bit_flips_fail(): void
    {
        $flip = static fn (string $bytes, int $at): string => substr_replace($bytes, chr(ord($bytes[$at]) ^ 0x01), $at, 1);

        $c = $this->store('nilai-c');
        $this->updateBytea('secrets', $c->id, ['ciphertext' => $flip($c->ciphertext, 3)]);
        $this->assertRevealFails($c);

        $n = $this->store('nilai-n');
        $this->updateBytea('secrets', $n->id, ['nonce' => $flip($n->nonce, 0)]);
        $this->assertRevealFails($n);

        $w = $this->store('nilai-w');
        $this->updateBytea('key_wraps', $w->key_wrap_id, ['wrapped_dek' => $flip($this->wrappedDek($w), 40)]);
        $this->assertRevealFails($w);

        $wn = $this->store('nilai-wn');
        $this->updateBytea('key_wraps', $wn->key_wrap_id, ['wrapped_dek' => $flip($this->wrappedDek($wn), 5)]);
        $this->assertRevealFails($wn);
    }

    public function test_wrong_lengths_fail_closed_without_sodium_errors(): void
    {
        $short = $this->store('nilai-pendek');
        $this->updateBytea('key_wraps', $short->key_wrap_id, ['wrapped_dek' => substr($this->wrappedDek($short), 0, 71)]);
        $this->assertRevealFails($short);

        $nonce = $this->store('nilai-nonce');
        $this->updateBytea('secrets', $nonce->id, ['nonce' => substr($nonce->nonce, 0, 12)]);
        $this->assertRevealFails($nonce);

        $tag = $this->store('nilai-tag');
        $this->updateBytea('secrets', $tag->id, ['ciphertext' => substr($tag->ciphertext, 0, 16)]);
        $this->assertRevealFails($tag);
    }

    public function test_other_master_key_version_is_unavailable(): void
    {
        $secret = $this->store('nilai');

        DB::table('key_wraps')->where('id', $secret->key_wrap_id)->update(['master_key_version' => 2]);

        $this->assertRevealFails($secret, VaultUnavailable::class);
    }

    public function test_wrong_master_key_fails(): void
    {
        $secret = $this->store('nilai');

        $this->useVaultKey();

        $this->assertRevealFails($secret);
    }
}
