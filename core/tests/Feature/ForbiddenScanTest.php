<?php

namespace Tests\Feature;

use App\Console\Commands\ForbiddenScanCommand;
use Illuminate\Support\Facades\File;
use Symfony\Component\Finder\Finder;
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
            ->expectsOutputToContain('halaman.blade.php:2 (hasil kompilasi Blade) — fungsi terlarang shell_exec()')
            ->expectsOutputToContain('halaman.blade.php:3 (hasil kompilasi Blade) — fungsi terlarang exec()')
            ->doesntExpectOutputToContain('halaman.blade.php:1')
            ->assertExitCode(1);
    }

    public function test_default_scope_covers_every_project_php_file(): void
    {
        $outside = [];
        $finder = Finder::create()->files()->ignoreDotFiles(false)->in(base_path())
            ->exclude(['vendor', 'node_modules', 'storage', 'tests', 'bootstrap/cache']);
        foreach ($finder as $file) {
            if (strtolower($file->getExtension()) !== 'php') {
                continue;
            }
            $relative = $file->getRelativePathname();
            $covered = array_filter(
                ForbiddenScanCommand::DEFAULT_PATHS,
                static fn (string $root): bool => str_starts_with($relative, $root.'/'),
            );
            if ($covered === []) {
                $outside[] = $relative;
            }
        }

        $this->assertSame([], $outside, 'Berkas PHP milik proyek di luar DEFAULT_PATHS (docs/09 vs docs/11).');
    }

    public function test_default_run_scans_project_code_but_not_bootstrap_cache(): void
    {
        $generated = base_path('bootstrap/cache/zz-uji-forbidden-scan.php');
        $project = base_path('bootstrap/zz-uji-forbidden-scan.php');
        File::put($generated, "<?php\nexec('id');\n");

        try {
            $this->artisan('sadmin:forbidden-scan')->assertExitCode(0);

            File::put($project, "<?php\nexec('id');\n");
            $this->artisan('sadmin:forbidden-scan')
                ->expectsOutputToContain('bootstrap/zz-uji-forbidden-scan.php:2 — fungsi terlarang exec()')
                ->doesntExpectOutputToContain('bootstrap/cache/zz-uji-forbidden-scan.php')
                ->assertExitCode(1);
        } finally {
            File::delete([$generated, $project]);
        }
    }

    public function test_reports_every_other_route_to_sendmail_or_mail_transports(): void
    {
        $path = $this->fixture(<<<'PHP'
            imap_mail('a@contoh.test', 's', 'm');
            error_log('pesan', 1, 'a@contoh.test');
            error_log(...$argumen);
            $h = new \Monolog\Handler\NativeMailerHandler('a@contoh.test', 's', 'b@contoh.test');
            \Symfony\Component\Mailer\Transport::fromDsn('smtp://relay');
            $dsn = 'Sendmail://default';
            $lain = "native://default";
            PHP);

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])
            ->expectsOutputToContain(':2 — fungsi terlarang imap_mail()')
            ->expectsOutputToContain(':3 — error_log() dengan tujuan (tipe 1 = email lewat sendmail)')
            ->expectsOutputToContain(':4 — error_log() dengan tujuan (tipe 1 = email lewat sendmail)')
            ->expectsOutputToContain(':5 — pustaka terlarang \Monolog\Handler\NativeMailerHandler')
            ->expectsOutputToContain(':6 — pustaka terlarang \Symfony\Component\Mailer\Transport')
            ->expectsOutputToContain(':7 — DSN transport mail terlarang')
            ->expectsOutputToContain(':8 — DSN transport mail terlarang')
            ->assertExitCode(1);
    }

    public function test_blade_echo_at_line_end_does_not_hide_a_violation(): void
    {
        $path = $this->dir.'/bergeser.blade.php';
        File::put($path, "<p>{{ \$a }}</p>\n<p>{{ \$b }}</p>\n@php exec('id'); @endphp\n");

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])
            ->expectsOutputToContain('(hasil kompilasi Blade) — fungsi terlarang exec()')
            ->assertExitCode(1);
    }

    public function test_scans_hidden_files_uppercase_extensions_and_symlinked_directories(): void
    {
        $target = $this->dir.'-sasaran';
        File::makeDirectory($target);
        File::put($target.'/w.php', "<?php\nexec('id');\n");
        File::put($this->dir.'/.x.php', "<?php\nexec('id');\n");
        File::makeDirectory($this->dir.'/.tersembunyi');
        File::put($this->dir.'/.tersembunyi/y.php', "<?php\nexec('id');\n");
        File::makeDirectory($this->dir.'/sub');
        File::put($this->dir.'/sub/z.PHP', "<?php\nexec('id');\n");
        symlink($target, $this->dir.'/tautan');

        try {
            $this->artisan('sadmin:forbidden-scan', ['paths' => [$this->dir]])
                ->expectsOutputToContain('.x.php:2')
                ->expectsOutputToContain('.tersembunyi/y.php:2')
                ->expectsOutputToContain('sub/z.PHP:2')
                ->expectsOutputToContain('tautan/w.php:2')
                ->assertExitCode(1);
        } finally {
            File::deleteDirectory($target);
        }
    }

    public function test_storage_link_uploads_are_not_scanned_as_project_code(): void
    {
        $link = base_path('public/storage');
        $this->assertFileDoesNotExist($link, 'Prasyarat: tes berjalan tanpa `storage:link` agar symlink uji tak menimpa milik instalasi.');
        $uploads = $this->dir.'-unggahan';
        File::makeDirectory($uploads);
        File::put($uploads.'/unggahan.php', "<?php\nexec('id');\n");
        symlink($uploads, $link);

        try {
            $this->artisan('sadmin:forbidden-scan')->assertExitCode(0);
        } finally {
            unlink($link);
            File::deleteDirectory($uploads);
        }
    }

    public function test_resolves_group_use_and_namespace_aliases(): void
    {
        $path = $this->fixture(<<<'PHP'
            use Symfony\Component\Process\{Process};
            use Symfony\Component as SC;
            use Symfony\Component\Mailer\{Transport};
            use function error_log as catat;
            (new SC\Process\Process(['id']))->run();
            $dsn = <<<DSN
                sendmail://default
                DSN;
            PHP);

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])
            ->expectsOutputToContain(':2 — pustaka terlarang Symfony\Component\Process\Process')
            ->expectsOutputToContain(':4 — pustaka terlarang Symfony\Component\Mailer\Transport')
            ->expectsOutputToContain(':5 — impor alias error_log')
            ->expectsOutputToContain(':6 — pustaka terlarang Symfony\Component\Process\Process')
            ->expectsOutputToContain('— DSN transport mail terlarang')
            ->assertExitCode(1);
    }

    public function test_legitimate_group_imports_are_not_flagged(): void
    {
        $path = $this->fixture(<<<'PHP'
            use Illuminate\{Support\Str, Http\Request};
            use Illuminate\Support\Facades\{File, DB as Basis};
            use Symfony\Component\Finder\Finder;
            use function strlen as panjang;
            $f = function () use ($path) { return $path; };
            PHP);

        $this->artisan('sadmin:forbidden-scan', ['paths' => [$path]])->assertExitCode(0);
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
            error_log('satu argumen saja');
            error_log('koma di akhir',);
            $relay = 'smtp://relay.contoh.test';
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
