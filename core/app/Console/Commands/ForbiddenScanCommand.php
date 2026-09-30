<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use PhpToken;

/**
 * Tripwire P1 (docs/09_STACK.md §Teknologi terlarang, docs/20_GUARDRAILS.md): core tak pernah
 * mengeksekusi perintah OS atau SSH. Pemindaian berbasis token, jadi string & komentar tak ikut terhitung.
 */
class ForbiddenScanCommand extends Command
{
    protected $signature = 'sadmin:forbidden-scan {paths?* : Direktori atau berkas yang dipindai (bawaan: app, routes, config)}';

    protected $description = 'Gagal bila ada eksekusi OS/SSH terlarang di kode core';

    private const FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec'];

    private const FUNCTION_PREFIXES = ['ssh2_'];

    private const NAMESPACES = [
        'illuminate\\support\\facades\\process',
        'illuminate\\process\\',
        'symfony\\component\\process\\',
        'phpseclib',
        'spatie\\ssh\\',
        'ffi\\',
    ];

    private const NOT_A_CALL_BEFORE = [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST];

    public function handle(): int
    {
        /** @var list<string> $paths */
        $paths = $this->argument('paths') ?: [base_path('app'), base_path('routes'), base_path('config')];

        $files = [];
        foreach ($paths as $path) {
            if (is_file($path)) {
                $files[] = $path;
            } elseif (is_dir($path)) {
                foreach (File::allFiles($path) as $file) {
                    if ($file->getExtension() === 'php') {
                        $files[] = $file->getPathname();
                    }
                }
            } else {
                $this->error("Path tak ditemukan: {$path}");

                return self::INVALID;
            }
        }

        $violations = [];
        foreach ($files as $file) {
            array_push($violations, ...$this->scan($file));
        }

        if ($violations === []) {
            $this->info('Bersih: '.count($files).' berkas PHP dipindai, tak ada eksekusi OS/SSH.');

            return self::SUCCESS;
        }

        foreach ($violations as $violation) {
            $this->error($violation);
        }
        $this->line(count($violations).' pelanggaran. Butuh sesuatu dilakukan di server → aksi katalog lewat agen.');

        return self::FAILURE;
    }

    /** @return list<string> */
    private function scan(string $file): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize((string) file_get_contents($file)),
            static fn (PhpToken $token): bool => ! $token->isIgnorable(),
        ));
        $where = static fn (PhpToken $token): string => str_replace(base_path().'/', '', $file).':'.$token->line;

        $violations = [];
        foreach ($tokens as $i => $token) {
            $prev = $tokens[$i - 1] ?? null;
            $next = $tokens[$i + 1] ?? null;

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

            // `use function shell_exec as jalankan;` — alias menyamarkan pemanggilan berikutnya.
            if ($prev?->is(T_FUNCTION) && ($tokens[$i - 2] ?? null)?->is(T_USE)
                && $this->isForbiddenFunction(ltrim((string) strrchr('\\'.$name, '\\'), '\\'))) {
                $violations[] = $where($token)." — impor fungsi terlarang {$name}";

                continue;
            }

            if ($name === 'ffi') {
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
