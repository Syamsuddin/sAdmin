<?php

namespace Tests\Contract;

use App\Domain\Execution\Dispatch\ServiceSigner;
use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\SecretValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Vektor bersama PHP↔Go untuk `sig` kunci layanan: ../kontrak/vectors/service-sig (../kontrak/KONTRAK.md §3),
 * dihitung oracle independen (ADR 0006 §2.2). Merah di sini = format berubah = gerbang manusia, bukan tes yang disesuaikan.
 */
#[Group('contract')]
class ServiceSignatureVectorsTest extends TestCase
{
    private static function vectorDir(): string
    {
        return dirname(__DIR__, 3).'/kontrak/vectors/service-sig';
    }

    /** @return iterable<string, array{string}> */
    public static function vectors(): iterable
    {
        foreach (glob(self::vectorDir().'/*.json') ?: [] as $path) {
            yield basename($path) => [$path];
        }
    }

    public function test_vector_set_covers_valid_invalid_and_the_secret_values_exception(): void
    {
        $vectors = array_map(
            fn (array $args): object => json_decode((string) file_get_contents($args[0]), false, 512, JSON_THROW_ON_ERROR),
            iterator_to_array(self::vectors()),
        );

        $this->assertContains(true, array_column($vectors, 'valid'), 'Vektor sig sah tak ditemukan di '.self::vectorDir());
        $this->assertContains(false, array_column($vectors, 'valid'), 'Vektor sig tolak tak ditemukan di '.self::vectorDir());
        $envelopesWithSecrets = array_filter($vectors, fn (object $v): bool => $v->valid && $v->frame->type === 'Envelope' && isset($v->frame->body->secret_values));
        $othersWithSecrets = array_filter($vectors, fn (object $v): bool => $v->valid && $v->frame->type !== 'Envelope' && isset($v->frame->body->secret_values));
        $this->assertNotSame([], $envelopesWithSecrets, 'Vektor Envelope ber-secret_values (di luar cakupan sig) tak ditemukan.');
        $this->assertNotSame([], $othersWithSecrets, 'Vektor non-Envelope ber-secret_values (ikut ditandatangani) tak ditemukan.');
    }

    #[DataProvider('vectors')]
    public function test_php_matches_shared_service_signature_vector(string $path): void
    {
        $vector = json_decode((string) file_get_contents($path), false, 512, JSON_THROW_ON_ERROR);
        $seed = new SecretValue((string) hex2bin($vector->seed_hex));
        $frame = $vector->frame;

        $publicKey = Ed25519::publicKey($seed);
        $this->assertSame($vector->public_key, Ed25519::encode($publicKey));

        $message = ServiceSigner::message($frame->type, $frame->id, $frame->body);
        $this->assertSame($vector->message, $message);

        if ($vector->valid) {
            $this->assertSame($frame->sig, Ed25519::encode(Ed25519::sign($seed, $message)), 'Ed25519 deterministik: tanda tangan wajib identik.');
        }

        // Teks bingkai dari dua pengodean yang berbeda escape-nya: verifikasi bergantung pada JCS, bukan byte kiriman.
        foreach ([0, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES] as $flags) {
            $text = json_encode($frame, JSON_THROW_ON_ERROR | $flags);
            $this->assertSame($vector->valid, ServiceSigner::verifyFrame($publicKey, $text));
        }
    }

    /**
     * Dispatch kelak menyusun badan sebagai larik PHP. Larik asosiatif menghasilkan pesan yang sama dengan vektor,
     * kecuali objek kosong bersarang: PHP menjadikannya [] (ADR 0006 §2.3 langkah 1), sehingga pesannya berbeda dan
     * skema pesan yang menolaknya. Tes ini menjaga agar ranjau itu tetap terlihat, bukan diam-diam dianggap setara.
     */
    #[DataProvider('vectors')]
    public function test_associative_arrays_sign_the_vector_message_unless_an_empty_object_is_nested(string $path): void
    {
        $raw = (string) file_get_contents($path);
        $vector = json_decode($raw, false, 512, JSON_THROW_ON_ERROR);
        $frame = json_decode($raw, true, 512, JSON_THROW_ON_ERROR)['frame'];

        $message = ServiceSigner::message($frame['type'], $frame['id'], $frame['body']);

        if (self::hasEmptyObject($vector->frame->body)) {
            $this->assertNotSame($vector->message, $message);
            $this->assertStringContainsString('[]', $message);
        } else {
            $this->assertSame($vector->message, $message);
        }
    }

    private static function hasEmptyObject(mixed $value): bool
    {
        if ($value instanceof \stdClass) {
            $value = get_object_vars($value);
            if ($value === []) {
                return true;
            }
        }

        return is_array($value) && array_filter($value, self::hasEmptyObject(...)) !== [];
    }
}
