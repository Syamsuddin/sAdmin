<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\File;
use PhpToken;

/**
 * Tripwire P1 (docs/09_STACK.md §Teknologi terlarang, docs/20_GUARDRAILS.md): core tak pernah
 * mengeksekusi perintah OS atau SSH. Pemindaian berbasis token, jadi string & komentar tak ikut terhitung;
 * Blade dikompilasi dulu agar blok @php dan {{ }} ikut terpindai. Cakupan bawaan: docs/11_COMMANDS.md.
 */
class ForbiddenScanCommand extends Command
{
    protected $signature = 'sadmin:forbidden-scan {paths?* : Direktori atau berkas yang dipindai (bawaan: semua kode milik proyek, docs/11)}';

    protected $description = 'Gagal bila ada eksekusi OS/SSH terlarang di kode core';

    /** Semua kode PHP milik proyek yang berjalan di produksi; vendor/ tests/ storage/ di luar cakupan. */
    public const DEFAULT_PATHS = ['app', 'bootstrap', 'config', 'database', 'lang', 'public', 'resources/views', 'routes', 'artisan'];

    /** Hasil generator framework, bukan kode proyek. */
    private const EXCLUDED = ['bootstrap/cache'];

    private const FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec', 'mail', 'mb_send_mail'];

    private const FUNCTION_PREFIXES = ['ssh2_'];

    private const NAMESPACES = [
        'illuminate\\support\\facades\\process',
        'illuminate\\process\\',
        'symfony\\component\\process\\',
        'phpseclib',
        'spatie\\ssh\\',
        'ffi\\',
        'symfony\\component\\mailer\\transport\\sendmailtransport',
    ];

    private const NOT_A_CALL_BEFORE = [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST];

    public function handle(): int
    {
        /** @var list<string> $requested */
        $requested = $this->argument('paths');
        $defaults = $requested === [];
        $paths = $defaults
            ? array_values(array_filter(array_map(base_path(...), self::DEFAULT_PATHS), file_exists(...)))
            : $requested;

        $files = [];
        $roots = [];
        foreach ($paths as $path) {
            $found = $this->phpFiles($path);
            if ($found === null) {
                $this->error("Path tak ditemukan: {$path}");

                return self::INVALID;
            }
            if ($found !== []) {
                $roots[] = str_replace(base_path().'/', '', $path);
                array_push($files, ...$found);
            }
        }

        $violations = [];
        foreach ($files as $file) {
            array_push($violations, ...$this->scan($file));
        }

        if ($violations === []) {
            $this->info('Bersih: '.count($files).' berkas PHP/Blade dipindai ('.implode(', ', $roots).'), tak ada eksekusi OS/SSH.');

            return self::SUCCESS;
        }

        foreach ($violations as $violation) {
            $this->error($violation);
        }
        $this->line(count($violations).' pelanggaran. Butuh sesuatu dilakukan di server → aksi katalog lewat agen.');

        return self::FAILURE;
    }

    /** @return list<string>|null null bila path tak ada */
    private function phpFiles(string $path): ?array
    {
        if (is_file($path)) {
            return [$path];
        }
        if (! is_dir($path)) {
            return null;
        }

        $excluded = array_map(static fn (string $dir): string => base_path($dir).'/', self::EXCLUDED);
        $files = [];
        foreach (File::allFiles($path) as $file) {
            $pathname = $file->getPathname();
            if ($file->getExtension() !== 'php' || array_filter($excluded, static fn (string $dir): bool => str_starts_with($pathname, $dir)) !== []) {
                continue;
            }
            $files[] = $pathname;
        }

        return $files;
    }

    /** @return list<string> */
    private function scan(string $file): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize($this->source($file)),
            static fn (PhpToken $token): bool => ! $token->isIgnorable(),
        ));
        $where = static fn (PhpToken $token): string => str_replace(base_path().'/', '', $file).':'.$token->line;

        $violations = [];
        $inUseFunction = false;
        foreach ($tokens as $i => $token) {
            $prev = $tokens[$i - 1] ?? null;
            $next = $tokens[$i + 1] ?? null;

            if ($token->is(T_USE) && $next?->is(T_FUNCTION)) {
                $inUseFunction = true;
            } elseif ($token->text === ';') {
                $inUseFunction = false;
            }

            if ($token->text === '`') {
                $violations[] = $where($token).' — operator backtick (eksekusi shell)';

                continue;
            }

            if (! $token->is([T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NAME_RELATIVE])) {
                continue;
            }

            $name = ltrim(strtolower($token->text), '\\');
            if (str_starts_with($name, 'namespace\\')) {
                $name = substr($name, strlen('namespace\\'));
            }

            // `use function strlen, shell_exec as jalankan;` — alias menyamarkan pemanggilan berikutnya.
            if ($inUseFunction && ! $prev?->is(T_AS)
                && $this->isForbiddenFunction(ltrim((string) strrchr('\\'.$name, '\\'), '\\'))) {
                $violations[] = $where($token)." — impor fungsi terlarang {$name}";

                continue;
            }

            if ($name === 'ffi' && ! $prev?->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_CASE, T_CONST, T_FUNCTION])) {
                $violations[] = $where($token).' — FFI (pemanggilan kode native)';

                continue;
            }

            foreach (self::NAMESPACES as $namespace) {
                if (str_starts_with($name, $namespace)) {
                    $violations[] = $where($token)." — pustaka terlarang {$token->text}";

                    continue 2;
                }
            }

            if ($name === 'process' && $next?->is(T_DOUBLE_COLON)) {
                $violations[] = $where($token).' — facade Process';

                continue;
            }

            $isCall = $next?->text === '(' && ! $prev?->is(self::NOT_A_CALL_BEFORE);
            if ($isCall && $this->isForbiddenFunction($name)) {
                $violations[] = $where($token)." — fungsi terlarang {$name}()";
            }
        }

        return $violations;
    }

    private function source(string $file): string
    {
        $code = (string) file_get_contents($file);

        return str_ends_with($file, '.blade.php') ? Blade::compileString($code) : $code;
    }

    private function isForbiddenFunction(string $name): bool
    {
        if (in_array($name, self::FUNCTIONS, true)) {
            return true;
        }

        foreach (self::FUNCTION_PREFIXES as $prefix) {
            if (str_starts_with($name, $prefix)) {
                return true;
            }
        }

        return false;
    }
}
