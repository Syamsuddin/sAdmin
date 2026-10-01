<?php

namespace Tests\Feature\Vault;

use App\Domain\Audit\Data\ActorType;
use App\Domain\Vault\Actions\DestroySecret;
use App\Domain\Vault\Actions\StoreSecret;
use App\Domain\Vault\Data\SecretPurpose;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\Vault;
use App\Models\Casts\Bytea;
use App\Models\Secret;
use App\Models\Tenant;
use Closure;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\Group;
use ReflectionFunction;
use SplObjectStorage;
use Tests\Support\InteractsWithVault;
use Tests\TestCase;
use Throwable;

/**
 * docs/13 grup redaction + ADR 0003 §2.4: nilai canary yang disimpan lalu dipakai di jalur sukses maupun gagal
 * tak pernah muncul di audit, baris brankas, log, pesan exception, atau jejak tumpukan (polos, hex, base64).
 */
#[Group('redaction')]
class VaultRedactionTest extends TestCase
{
    use InteractsWithVault, RefreshDatabase;

    private string $canary;

    private string $logFile;

    private Tenant $tenant;

    /** @var list<Throwable> */
    private array $thrown = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->canary = 'CANARY-'.bin2hex(random_bytes(8));
        $this->logFile = (string) tempnam(sys_get_temp_dir(), 'sadmin-redaction-');
        config(['logging.default' => 'single', 'logging.channels.single.path' => $this->logFile, 'logging.channels.single.level' => 'debug']);
        // Paksa argumen jejak tumpukan terkumpul utuh, seperti konfigurasi PHP terburuk.
        ini_set('zend.exception_ignore_args', '0');
        ini_set('zend.exception_string_param_max_len', '1000000');
        $this->tenant = Tenant::factory()->create();
    }

    protected function tearDown(): void
    {
        @unlink($this->logFile);
        parent::tearDown();
    }

    private function store(string $suffix, ?string $tenantId = null): Secret
    {
        return app(StoreSecret::class)->handle($tenantId ?? $this->tenant->id, SecretPurpose::ApiToken, new SecretValue($this->canary.$suffix), ActorType::Admin, 'admin-uji');
    }

    private function capture(callable $failing): void
    {
        try {
            $failing();
            $this->fail('Skenario gagal seharusnya melempar exception.');
        } catch (Throwable $e) {
            $this->thrown[] = $e;
            report($e);
        }
    }

    public function test_canary_never_leaks_on_success_or_failure_paths(): void
    {
        $kept = $this->store('-tetap');
        $this->assertSame($this->canary.'-tetap', app(Vault::class)->reveal($kept->id, SecretPurpose::ApiToken, $this->tenant->id)->expose());
        app(DestroySecret::class)->handle($this->store('-hancur')->id, ActorType::Admin, 'admin-uji');

        $this->capture(fn () => $this->store('-tenant-asing', strtolower((string) Str::ulid())));

        $tampered = $this->store('-diubah');
        DB::table('secrets')->where('id', $tampered->id)->update(['ciphertext' => Bytea::literal(strrev($tampered->ciphertext))]);
        $this->capture(fn () => app(Vault::class)->reveal($tampered->id, SecretPurpose::ApiToken, $this->tenant->id));

        $this->withoutVaultKey();
        $this->capture(fn () => $this->store('-tanpa-kunci'));

        $this->useVaultKey();
        $this->artisan('sadmin:vault-check')->doesntExpectOutputToContain($this->canary)->assertExitCode(1);

        $this->assertCount(3, $this->thrown);
        foreach ($this->thrown as $e) {
            $this->assertNoCanary((string) $e, get_class($e).' (string)');
            $this->assertNoCanary($e->getTraceAsString(), get_class($e).' getTraceAsString');
            $this->assertNoCanary($this->stringsIn($e->getTrace()), get_class($e).' argumen getTrace');
        }

        $log = (string) file_get_contents($this->logFile);
        $this->assertStringContainsString('vault_key_mismatch', $log, 'Log tes harus benar-benar tertulis.');
        $this->assertNoCanary($log, 'log');

        foreach (['audit_entries', 'secrets', 'key_wraps'] as $table) {
            $rows = array_column(DB::select("SELECT row_to_json(t)::text AS j FROM {$table} t"), 'j');
            $this->assertNotEmpty($rows, $table);
            $this->assertNoCanary(implode("\n", $rows), $table);
        }

        $this->assertNoCanary((string) json_encode(Secret::query()->with('keyWrap')->get()), 'serialisasi model');
    }

    /**
     * Semua string yang terjangkau dari argumen jejak tumpukan: larik, properti objek (termasuk privat lewat cast),
     * variabel tangkapan closure. Tiap objek dikunjungi sekali agar graf container tak meledak.
     */
    private function stringsIn(mixed $value, ?SplObjectStorage $seen = null, int $depth = 0): string
    {
        $seen ??= new SplObjectStorage;
        if (is_string($value)) {
            return $value."\n";
        }
        if ($depth > 12 || (! is_array($value) && ! is_object($value))) {
            return '';
        }
        if (is_object($value)) {
            // Objek kasus tes ini sendiri memegang canary sebagai properti; ia terjangkau lewat closure tes, bukan kode produksi.
            if ($seen->contains($value) || $value instanceof self) {
                return '';
            }
            $seen->attach($value);
            if ($value instanceof Closure) {
                $reflection = new ReflectionFunction($value);
                $value = [$reflection->getStaticVariables(), $reflection->getClosureThis()];
            } elseif ($value instanceof SecretValue) {
                $value = $value->__debugInfo();
            } else {
                $value = (array) $value;
            }
        }

        $out = '';
        foreach ($value as $key => $item) {
            $out .= $key."\n".$this->stringsIn($item, $seen, $depth + 1);
        }

        return $out;
    }

    private function assertNoCanary(string $haystack, string $where): void
    {
        foreach (['polos' => $this->canary, 'hex' => bin2hex($this->canary), 'base64' => base64_encode($this->canary)] as $form => $needle) {
            $this->assertStringNotContainsString($needle, $haystack, "Nilai rahasia bocor ({$form}) di {$where}.");
        }
    }
}
