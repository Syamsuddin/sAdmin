<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\File;
use Tests\TestCase;

class ForbiddenScanTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir().'/sadmin-forbidden-'.bin2hex(random_bytes(4));
        File::makeDirectory($this->dir);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->dir);
        parent::tearDown();
    }

    private function fixture(string $code): string
    {
        $path = $this->dir.'/Fixture'.bin2hex(random_bytes(3)).'.php';
        File::put($path, "<?php\n".$code);

        return $path;
    }

    public function test_core_code_is_clean(): void
    {
        $this->artisan('sadmin:forbidden-scan')->assertExitCode(0);
    }

    public function test_reports_each_forbidden_execution_form(): void
    {
        $path = $this->fixture(<<<'PHP'
            exec('id');
            \shell_exec('id');
            $out = `id`;
            use Illuminate\Support\Facades\Process;
            Process::run('id');
            use phpseclib3\Net\SSH2;
            ssh2_connect('host');
            proc_open('id', [], $pipes);
            PHP);

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])
            ->expectsOutputToContain(':2 — fungsi terlarang exec()')
            ->expectsOutputToContain(':3 — fungsi terlarang shell_exec()')
            ->expectsOutputToContain(':4 — operator backtick')
            ->expectsOutputToContain(':5 — pustaka terlarang Illuminate\Support\Facades\Process')
            ->expectsOutputToContain(':6 — facade Process')
            ->expectsOutputToContain(':7 — pustaka terlarang phpseclib3\Net\SSH2')
            ->expectsOutputToContain(':8 — fungsi terlarang ssh2_connect()')
            ->expectsOutputToContain(':9 — fungsi terlarang proc_open()')
            ->assertExitCode(1);
    }

    public function test_catches_aliased_relative_and_ffi_bypasses(): void
    {
        $path = $this->fixture(<<<'PHP'
            use function shell_exec as jalankan;
            jalankan('id');
            namespace\passthru('id');
            \FFI::cdef('int system(const char *);')->system('id');
            use function strlen, proc_open as buka;
            PHP);

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])
            ->expectsOutputToContain(':2 — impor fungsi terlarang shell_exec')
            ->expectsOutputToContain(':4 — fungsi terlarang passthru()')
            ->expectsOutputToContain(':5 — FFI')
            ->expectsOutputToContain(':6 — impor fungsi terlarang proc_open')
            ->assertExitCode(1);
    }

    public function test_reports_mail_functions_that_spawn_sendmail(): void
    {
        $path = $this->fixture(<<<'PHP'
            mail('a@contoh.test', 'subjek', 'isi', '', '-X/tmp/log');
            \mb_send_mail('a@contoh.test', 'subjek', 'isi');
            use Symfony\Component\Mailer\Transport\SendmailTransport;
            PHP);

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])
            ->expectsOutputToContain(':2 — fungsi terlarang mail()')
            ->expectsOutputToContain(':3 — fungsi terlarang mb_send_mail()')
            ->expectsOutputToContain(':4 — pustaka terlarang Symfony\Component\Mailer\Transport\SendmailTransport')
            ->assertExitCode(1);
    }

    public function test_scans_php_inside_blade_templates_but_not_their_html(): void
    {
        $path = $this->dir.'/halaman.blade.php';
        File::put($path, <<<'BLADE'
            <p>Teks biasa yang menyebut exec('id') bukan kode.</p>
            @php shell_exec('id'); @endphp
            <span>{{ exec('id') }}</span>
            BLADE);

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])
            ->expectsOutputToContain('halaman.blade.php:2 — fungsi terlarang shell_exec()')
            ->expectsOutputToContain('halaman.blade.php:3 — fungsi terlarang exec()')
            ->doesntExpectOutputToContain('halaman.blade.php:1')
            ->assertExitCode(1);
    }

    public function test_default_scope_covers_all_project_code_that_runs_in_production(): void
    {
        $this->artisan('sadmin:forbidden-scan')
            ->expectsOutputToContain('app, bootstrap, config, database, public, routes, artisan')
            ->assertExitCode(0);
    }

    public function test_ignores_methods_strings_comments_and_declarations(): void
    {
        $path = $this->fixture(<<<'PHP'
            namespace Contoh;
            $pdo->exec('SELECT 1');
            $obj?->system();
            Klas::exec();
            $s = 'exec("id") `id`';
            // exec('id');
            function passthru_label(): string { return 'passthru'; }
            enum Aktor: string { case System = 'system'; case Ffi = 'ffi'; }
            $klien->ffi();
            use function strlen as panjang;
            PHP);

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])
            ->expectsOutputToContain('Bersih: 1 berkas')
            ->assertExitCode(0);
    }

    public function test_unknown_path_is_invalid(): void
    {
        $this->artisan('sadmin:forbidden-scan', ['paths' => [$this->dir.'/tak-ada']])->assertExitCode(2);
    }
}
