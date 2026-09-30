<?php

namespace Tests\Feature\Identity;

use App\Models\Admin;
use App\Models\Authenticator;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\InteractsWithPasskeys;
use Tests\Support\VirtualAuthenticator;
use Tests\TestCase;

class PasskeyRegistrationTest extends TestCase
{
    use InteractsWithPasskeys, RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpInstitution();
    }

    public function test_registers_two_passkeys_with_their_cose_keys_and_audit_entries(): void
    {
        $admin = $this->newAdmin();
        $ed = VirtualAuthenticator::eddsa('kantor');
        $ec = VirtualAuthenticator::es256('ponsel');

        $page = $this->registrationPage($admin)->assertSee('Belum ada passkey terdaftar.');
        $this->ceremony($page->set('label', 'YubiKey kantor'), $ed->register(...))
            ->assertSee('Passkey “YubiKey kantor” tersimpan.')
            ->assertSee('Daftarkan passkey ke-2');
        $this->ceremony($page->set('label', 'Ponsel'), $ec->register(...))
            ->assertSee('Kedua passkey tersimpan.');

        $stored = Authenticator::query()->orderBy('created_at')->get();
        $this->assertSame([-8, -7], $stored->pluck('alg')->all());
        $this->assertSame($ed->coseKey(), $stored[0]->public_key_cose);
        $this->assertSame($ec->credentialId, $stored[1]->credential_id);
        $this->assertSame(2, DB::table('audit_entries')->where('action_key', 'authenticator.register')->where('actor_id', $admin->id)->count());
    }

    public function test_a_third_passkey_is_refused_because_it_is_a_roster_change(): void
    {
        $admin = $this->newAdmin();
        $this->enroll($admin, VirtualAuthenticator::eddsa('a'));
        $this->enroll($admin, VirtualAuthenticator::eddsa('b'));

        $this->registrationPage($admin)->set('label', 'Ketiga')->call('begin')
            ->assertReturned(null)
            ->assertSet('errorReason', 'registration_complete');
    }

    /** Dua tab memulai pendaftaran saat baru ada 1 passkey: yang menyelesaikan terakhir ditolak saat commit. */
    public function test_limit_is_rechecked_when_the_ceremony_completes(): void
    {
        $admin = $this->newAdmin();
        $this->enroll($admin, VirtualAuthenticator::eddsa('pertama'));

        $page = $this->registrationPage($admin)->set('label', 'Tab A');
        $this->ceremony($page, function (string $options) use ($admin): string {
            $this->enroll($admin, VirtualAuthenticator::eddsa('tab-b'));

            return VirtualAuthenticator::eddsa('tab-a')->register($options);
        })->assertSet('errorReason', 'registration_complete');

        $this->assertSame(2, $admin->activeAuthenticators()->count());
    }

    public function test_invite_expiry_cannot_be_extended_by_the_client(): void
    {
        $page = $this->registrationPage($this->newAdmin());

        $this->expectException(CannotUpdateLockedPropertyException::class);
        $page->set('expiresAt', PHP_INT_MAX);
    }

    public function test_invitation_expiring_mid_ceremony_is_refused_at_completion(): void
    {
        $page = $this->registrationPage($this->newAdmin())->set('label', 'Kunci');
        $this->ceremony($page, function (string $options): string {
            $this->travel(16)->minutes();

            return VirtualAuthenticator::eddsa()->register($options);
        })->assertSet('errorReason', 'invite_expired');

        $this->assertSame(0, Authenticator::query()->count());
    }

    public function test_disabled_admin_cannot_register_at_either_step(): void
    {
        $this->registrationPage($this->newAdmin('disabled'))->set('label', 'Kunci')->call('begin')
            ->assertReturned(null)
            ->assertSet('errorReason', 'admin_inactive');

        $admin = $this->newAdmin();
        $this->ceremony($this->registrationPage($admin)->set('label', 'Kunci'), function (string $options) use ($admin): string {
            $admin->forceFill(['status' => 'disabled'])->save();

            return VirtualAuthenticator::eddsa()->register($options);
        })->assertSet('errorReason', 'admin_inactive');

        $this->assertSame(0, Authenticator::query()->count());
    }

    /**
     * Pemeriksaan batas 2 di dalam transaksi hanya aman bila baris admin dikunci FOR UPDATE: tanpa itu, dua
     * pendaftaran paralel hanya saling memegang kunci KEY SHARE dari cek FK dan bisa menghasilkan 3 passkey.
     * Uji dua koneksi sungguhan butuh baris ter-commit di luar transaksi tes (dan bisa mengunci dirinya sendiri
     * bila kode salah), jadi yang dipatok di sini: kunci diambil sebelum passkey dihitung ulang.
     */
    public function test_completion_locks_the_admin_row_before_recounting(): void
    {
        $admin = $this->newAdmin();
        $page = $this->registrationPage($admin)->set('label', 'Kunci');
        $queries = [];
        $options = null;
        $page->call('begin')->assertReturned(function ($value) use (&$options): bool {
            $options = $value;

            return true;
        });
        DB::listen(function ($query) use (&$queries): void {
            $queries[] = strtolower($query->sql);
        });

        $page->call('complete', VirtualAuthenticator::eddsa()->register($options));

        $lockAt = array_key_first(array_filter($queries, fn (string $sql): bool => str_contains($sql, 'from "admins"') && str_contains($sql, 'for update')));
        $countAt = array_key_first(array_filter($queries, fn (string $sql): bool => str_contains($sql, 'count(*)') && str_contains($sql, '"authenticators"')));
        $this->assertNotNull($lockAt, 'Baris admin harus dikunci FOR UPDATE saat penyelesaian.');
        $this->assertNotNull($countAt);
        $this->assertLessThan($countAt, $lockAt, 'Kunci harus diambil sebelum passkey dihitung ulang.');
        $this->assertSame(1, Authenticator::query()->count());
    }

    public function test_label_is_required_before_the_ceremony_starts(): void
    {
        $this->registrationPage($this->newAdmin())->call('begin')
            ->assertReturned(null)
            ->assertSet('errorReason', 'invalid_label')
            ->assertSee('nama perangkat wajib diisi');
    }

    public function test_expired_invitation_is_refused_on_every_action(): void
    {
        $this->registrationPage($this->newAdmin(), time() - 1)->set('label', 'Kunci')->call('begin')
            ->assertReturned(null)
            ->assertSet('errorReason', 'invite_expired');
    }

    public function test_locked_state_cannot_be_changed_by_the_client(): void
    {
        $page = $this->registrationPage($this->newAdmin());

        $this->expectException(CannotUpdateLockedPropertyException::class);
        $page->set('adminId', $this->newAdmin()->id);
    }

    /** @return iterable<string, array{callable(VirtualAuthenticator): void}> */
    public static function forgedAttestations(): iterable
    {
        yield 'origin palsu' => [static function (VirtualAuthenticator $a): void {
            $a->origin = 'https://jahat.example';
        }];
        yield 'RP ID palsu' => [static function (VirtualAuthenticator $a): void {
            $a->rpId = 'jahat.example';
        }];
        yield 'tanpa verifikasi pengguna' => [static function (VirtualAuthenticator $a): void {
            $a->userVerified = false;
        }];
        yield 'tanpa kehadiran pengguna' => [static function (VirtualAuthenticator $a): void {
            $a->userPresent = false;
        }];
        yield 'tipe clientData webauthn.get' => [static function (VirtualAuthenticator $a): void {
            $a->clientDataType = 'webauthn.get';
        }];
        yield 'lintas origin (iframe)' => [static function (VirtualAuthenticator $a): void {
            $a->crossOrigin = true;
        }];
    }

    /** @param  callable(VirtualAuthenticator): void  $forge */
    #[DataProvider('forgedAttestations')]
    public function test_forged_attestation_is_rejected_without_storing_anything(callable $forge): void
    {
        $authenticator = VirtualAuthenticator::eddsa();
        $forge($authenticator);

        $this->ceremony($this->registrationPage($this->newAdmin())->set('label', 'Kunci'), $authenticator->register(...))
            ->assertSet('errorReason', 'verification_failed')
            ->assertSee('ID: ');

        $this->assertSame(0, Authenticator::query()->count());
    }

    public function test_a_challenge_cannot_be_answered_twice(): void
    {
        $page = $this->registrationPage($this->newAdmin())->set('label', 'Kunci');
        $answer = null;
        $this->ceremony($page, function (string $options) use (&$answer): string {
            return $answer = VirtualAuthenticator::eddsa()->register($options);
        });

        // Label diisi lagi (dikosongkan setelah sukses): satu-satunya penghalang = challenge sudah terpakai.
        $page->set('label', 'Kunci')->call('complete', $answer)->assertSet('errorReason', 'challenge_missing');
        $this->assertSame(1, Authenticator::query()->count());
    }

    public function test_the_same_authenticator_cannot_be_registered_for_two_admins(): void
    {
        $shared = VirtualAuthenticator::eddsa('bersama');
        $this->ceremony($this->registrationPage($this->newAdmin())->set('label', 'Kunci'), $shared->register(...));

        $this->ceremony($this->registrationPage($this->newAdmin())->set('label', 'Kunci'), $shared->register(...))
            ->assertSet('errorReason', 'credential_exists');
        $this->assertSame(1, Authenticator::query()->count());
    }
}
