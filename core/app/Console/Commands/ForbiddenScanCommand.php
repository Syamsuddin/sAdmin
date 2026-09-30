<?php

namespace App\Console\Commands;

use Closure;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Blade;
use PhpToken;
use Symfony\Component\Finder\Finder;

/**
 * Tripwire P1 (docs/09_STACK.md §Teknologi terlarang, docs/20_GUARDRAILS.md): core tak pernah
 * mengeksekusi perintah OS atau SSH. Pemindaian berbasis token, jadi komentar tak ikut terhitung;
 * Blade dikompilasi dulu agar blok @php dan {{ }} ikut terpindai. Cakupan bawaan: docs/11_COMMANDS.md.
 */
class ForbiddenScanCommand extends Command
{
    protected $signature = 'sadmin:forbidden-scan {paths?* : Direktori atau berkas yang dipindai (bawaan: semua kode milik proyek, docs/11)}';

    protected $description = 'Gagal bila ada eksekusi OS/SSH terlarang di kode core';

    /** Semua kode PHP milik proyek yang berjalan di produksi; vendor/ tests/ storage/ di luar cakupan. */
    public const DEFAULT_PATHS = ['app', 'bootstrap', 'config', 'database', 'lang', 'public', 'resources/views', 'routes', 'artisan'];

    /** Hasil generator framework dan symlink unggahan (storage:link), bukan kode proyek. */
    private const EXCLUDED = ['bootstrap/cache', 'public/storage'];

    private const FUNCTIONS = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen', 'pcntl_exec', 'mail', 'mb_send_mail', 'imap_mail'];

    private const FUNCTION_PREFIXES = ['ssh2_'];

    private const NAMESPACES = [
        'illuminate\\support\\facades\\process',
        'illuminate\\process\\',
        'symfony\\component\\process\\',
        'phpseclib',
        'spatie\\ssh\\',
        'ffi\\',
        // Transport Symfony Mailer langsung melewati penjaga MailManager (sendmail/native = proc_open).
        'symfony\\component\\mailer\\transport',
        'monolog\\handler\\nativemailerhandler',
    ];

    /**
     * Satu-satunya pengecualian: penjaga yang menyebut kelas terlarang untuk MENOLAKNYA.
     * Pengecualian baru = keputusan docs/09 + review, bukan jalan pintas agar pemindaian hijau.
     */
    private const ALLOWED_REFERENCES = [
        'app/Infrastructure/Notify/SendmailRefusingMailManager.php' => [
            'symfony\\component\\mailer\\transport\\sendmailtransport',
            'symfony\\component\\mailer\\transport\\roundrobintransport',
        ],
    ];

    /** Skema DSN yang memilih transport sendmail (termasuk `mail`/`native` Laravel & Symfony). */
    private const FORBIDDEN_DSN = '~^(sendmail(\+smtp)?|native|mail)://~i';

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
                $roots[] = $this->relative($path);
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

    /**
     * Termasuk berkas tersembunyi, ekstensi berhuruf kapital, dan direktori symlink: berkas seperti itu tetap
     * bisa di-require dari kode produksi.
     *
     * @return list<string>|null null bila path tak ada
     */
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
        foreach (Finder::create()->files()->ignoreDotFiles(false)->followLinks()->in($path)->sortByName() as $file) {
            $pathname = $file->getPathname();
            $isExcluded = array_filter($excluded, static fn (string $dir): bool => str_starts_with($pathname, $dir)) !== [];
            if (strtolower($file->getExtension()) === 'php' && ! $isExcluded) {
                $files[] = $pathname;
            }
        }

        return $files;
    }

    /** @return list<string> */
    private function scan(string $file): array
    {
        $relative = $this->relative($file);
        $blade = str_ends_with(strtolower($file), '.blade.php');
        $tokens = array_values(array_filter(
            PhpToken::tokenize($this->source($file, $blade)),
            static fn (PhpToken $token): bool => ! $token->isIgnorable(),
        ));
        // Blade::compileString menambah baris (echo di akhir baris, komponen), jadi nomornya milik hasil kompilasi.
        $where = static fn (PhpToken $token): string => $relative.':'.$token->line.($blade ? ' (hasil kompilasi Blade)' : '');
        $allowed = self::ALLOWED_REFERENCES[$relative] ?? [];

        [$aliases, $violations] = $this->imports($tokens, $where, $allowed);
        $inUse = false;
        foreach ($tokens as $i => $token) {
            $prev = $tokens[$i - 1] ?? null;
            $next = $tokens[$i + 1] ?? null;

            // Pernyataan `use` (import & trait) sudah diurai imports(); `function () use ($x)` bukan import.
            if ($token->is(T_USE) && $next?->text !== '(') {
                $inUse = true;
            } elseif ($token->text === ';') {
                $inUse = false;
            }

            if ($token->text === '`') {
                $violations[] = $where($token).' — operator backtick (eksekusi shell)';

                continue;
            }

            if ($token->is([T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE])
                && preg_match(self::FORBIDDEN_DSN, ltrim($token->text, "\"' \t\n\r")) === 1) {
                $violations[] = $where($token).' — DSN transport mail terlarang (sendmail/mail/native)';

                continue;
            }

            if ($inUse || ! $token->is([T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NAME_RELATIVE])) {
                continue;
            }

            $name = ltrim(strtolower($token->text), '\\');
            $display = $token->text;
            if (str_starts_with($name, 'namespace\\')) {
                $name = substr($name, strlen('namespace\\'));
            }

            // `SC\Process\Process` dengan `use Symfony\Component as SC;` → diperluas ke nama lengkap dulu.
            if ($token->is(T_NAME_QUALIFIED)) {
                $first = strstr($name, '\\', true);
                if ($first !== false && isset($aliases[$first])) {
                    [$aliasLower, $aliasText] = $aliases[$first];
                    $name = $aliasLower.substr($name, strlen($first));
                    $display = $aliasText.substr($token->text, strlen($first));
                }
            }

            if ($name === 'ffi' && ! $prev?->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_CASE, T_CONST, T_FUNCTION])) {
                $violations[] = $where($token).' — FFI (pemanggilan kode native)';

                continue;
            }

            if ($this->isForbiddenNamespace($name) && ! in_array($name, $allowed, true)) {
                $violations[] = $where($token)." — pustaka terlarang {$display}";

                continue;
            }

            if ($name === 'process' && $next?->is(T_DOUBLE_COLON)) {
                $violations[] = $where($token).' — facade Process';

                continue;
            }

            $isCall = $next?->text === '(' && ! $prev?->is(self::NOT_A_CALL_BEFORE);
            if (! $isCall) {
                continue;
            }

            if ($this->isForbiddenFunction($name)) {
                $violations[] = $where($token)." — fungsi terlarang {$name}()";
            } elseif ($name === 'error_log' && $this->hasMoreThanOneArgument($tokens, $i + 1)) {
                $violations[] = $where($token).' — error_log() dengan tujuan (tipe 1 = email lewat sendmail)';
            }
        }

        return $violations;
    }

    /**
     * Mengurai setiap pernyataan `use` — tunggal, alias, dan group `A\{B, C as D}` — menjadi nama lengkap,
     * sehingga import terlarang tak bisa disamarkan dan alias namespace bisa diperluas saat dipakai.
     *
     * @param  list<PhpToken>  $tokens
     * @param  Closure(PhpToken): string  $where
     * @param  list<string>  $allowed
     * @return array{0: array<string, array{0: string, 1: string}>, 1: list<string>} [alias → [nama kecil, nama asli]], pelanggaran
     */
    private function imports(array $tokens, Closure $where, array $allowed): array
    {
        $aliases = [];
        $violations = [];
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            if (! $tokens[$i]->is(T_USE) || ($tokens[$i + 1] ?? null)?->text === '(') {
                continue;
            }

            $j = $i + 1;
            $kind = 'class';
            if (($tokens[$j] ?? null)?->is(T_FUNCTION)) {
                $kind = 'function';
                $j++;
            } elseif (($tokens[$j] ?? null)?->is(T_CONST)) {
                $kind = 'const';
                $j++;
            }

            $prefix = '';
            $current = null;
            $alias = null;
            $expectAlias = false;
            for (; $j < $count; $j++) {
                $token = $tokens[$j];
                if ($token->is([T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED])) {
                    if ($expectAlias) {
                        $alias = $token->text;
                        $expectAlias = false;
                    } else {
                        $current = $token;
                    }
                } elseif ($token->is(T_AS)) {
                    $expectAlias = true;
                } elseif ($token->text === '{' && $current !== null) {
                    $prefix = $current->text;
                    $current = null;
                } elseif (in_array($token->text, [',', '}', ';'], true)) {
                    if ($current !== null) {
                        array_push($violations, ...$this->checkImport($kind, $prefix, $current, $alias, $where, $allowed, $aliases));
                    }
                    $current = null;
                    $alias = null;
                    if ($token->text === ';') {
                        break;
                    }
                }
            }
            $i = $j;
        }

        return [$aliases, $violations];
    }

    /**
     * @param  Closure(PhpToken): string  $where
     * @param  list<string>  $allowed
     * @param  array<string, array{0: string, 1: string}>  $aliases
     * @return list<string>
     */
    private function checkImport(string $kind, string $prefix, PhpToken $name, ?string $alias, Closure $where, array $allowed, array &$aliases): array
    {
        $fqn = ltrim(($prefix !== '' ? $prefix.'\\' : '').$name->text, '\\');
        $lower = strtolower($fqn);
        $last = ltrim((string) strrchr('\\'.$lower, '\\'), '\\');

        if ($kind === 'function') {
            if ($this->isForbiddenFunction($last)) {
                return [$where($name)." — impor fungsi terlarang {$lower}"];
            }
            if ($alias !== null && $last === 'error_log') {
                return [$where($name).' — impor alias error_log (argumennya tak bisa diperiksa)'];
            }

            return [];
        }

        if ($kind === 'const') {
            return [];
        }

        $aliases[strtolower($alias ?? $last)] = [$lower, $fqn];
        if ($lower === 'ffi' || ($this->isForbiddenNamespace($lower) && ! in_array($lower, $allowed, true))) {
            return [$where($name)." — pustaka terlarang {$fqn}"];
        }

        return [];
    }

    private function isForbiddenNamespace(string $name): bool
    {
        foreach (self::NAMESPACES as $namespace) {
            if (str_starts_with($name, $namespace)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Argumen kedua error_log() bisa bernilai 1 (kirim email lewat sendmail); spread `...` dianggap bisa.
     *
     * @param  list<PhpToken>  $tokens
     */
    private function hasMoreThanOneArgument(array $tokens, int $open): bool
    {
        $depth = 0;
        for ($j = $open, $count = count($tokens); $j < $count; $j++) {
            $token = $tokens[$j];
            if (in_array($token->text, ['(', '[', '{'], true) || $token->is([T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES])) {
                $depth++;
            } elseif (in_array($token->text, [')', ']', '}'], true)) {
                if (--$depth === 0) {
                    return false;
                }
            } elseif ($depth === 1 && ($token->is(T_ELLIPSIS) || ($token->text === ',' && ($tokens[$j + 1] ?? null)?->text !== ')'))) {
                return true;
            }
        }

        return false;
    }

    private function source(string $file, bool $blade): string
    {
        $code = (string) file_get_contents($file);

        return $blade ? Blade::compileString($code) : $code;
    }

    private function relative(string $path): string
    {
        return str_replace(base_path().'/', '', $path);
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
