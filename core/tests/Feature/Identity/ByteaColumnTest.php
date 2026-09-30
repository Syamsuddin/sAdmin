<?php

namespace Tests\Feature\Identity;

use App\Models\Authenticator;
use App\Models\Casts\Bytea;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\InteractsWithPasskeys;
use Tests\TestCase;

/** PDO pgsql memotong biner mentah di byte NUL tanpa galat; cast Bytea wajib menjaga byte utuh. */
class ByteaColumnTest extends TestCase
{
    use InteractsWithPasskeys, RefreshDatabase;

    public function test_binary_with_nul_bytes_round_trips_and_is_searchable(): void
    {
        $this->setUpInstitution();
        $admin = $this->newAdmin();
        $credentialId = "\x00\x00\xff\x00".random_bytes(28);
        $cose = "\xa5\x00\x01".random_bytes(60);

        Authenticator::query()->create([
            'tenant_id' => $admin->tenant_id, 'admin_id' => $admin->id, 'credential_id' => $credentialId,
            'public_key_cose' => $cose, 'alg' => -8, 'label' => 'Uji NUL',
        ]);

        $found = Authenticator::query()->where('credential_id', Bytea::literal($credentialId))->sole();
        $this->assertSame($credentialId, $found->credential_id);
        $this->assertSame($cose, $found->public_key_cose);
    }
}
