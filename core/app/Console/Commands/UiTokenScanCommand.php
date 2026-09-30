<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Symfony\Component\Finder\Finder;

/**
 * docs/26: nilai warna/ukuran/font hanya boleh hidup di resources/css/tokens.css; berkas lain memakai var(--…).
 * Ikon Tabler di resources/icons disalin apa adanya dan dijaga tes asal-usul, jadi tak dipindai di sini.
 */
class UiTokenScanCommand extends Command
{
    protected $signature = 'sadmin:ui-token-scan {paths?* : Berkas/direktori (bawaan: resources/views, resources/css, resources/js)}';

    protected $description = 'Gagal bila ada nilai warna/ukuran/font di luar resources/css/tokens.css';

    public const DEFAULT_PATHS = ['resources/views', 'resources/css', 'resources/js'];

    private const TOKENS_FILE = 'resources/css/tokens.css';

    private const RULES = [
        'warna hex' => '/(?<![&\w])#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})\b/',
        'fungsi warna' => '/\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color-mix)\(/i',
        'ukuran berunit' => '/(?<![\w.-])\d*\.?\d+(?:px|rem|em|pt|vh|vw|vmin|vmax|ch|ex)\b/',
        'font di luar token' => '/font(?:-family)?\s*:(?!\s*var\()/i',
    ];

    public function handle(): int
    {
        /** @var list<string> $requested */
        $requested = $this->argument('paths');
        $paths = $requested !== [] ? $requested : array_map(base_path(...), self::DEFAULT_PATHS);

        $violations = [];
        $count = 0;
        foreach ($paths as $path) {
            if (! file_exists($path)) {
                $this->error("Path tak ditemukan: {$path}");

                return self::INVALID;
            }
            foreach ($this->files($path) as $file) {
                $count++;
                array_push($violations, ...$this->scan($file));
            }
        }

        if ($violations === []) {
            $this->info("Bersih: {$count} berkas UI dipindai, semua nilai visual dari tokens.css.");

            return self::SUCCESS;
        }

        foreach ($violations as $violation) {
            $this->error($violation);
        }
        $this->line(count($violations).' pelanggaran. Pakai var(--token) dari resources/css/tokens.css (docs/26).');

        return self::FAILURE;
    }

    /** @return list<string> */
    private function files(string $path): array
    {
        if (is_file($path)) {
            return [$path];
        }

        $files = [];
        foreach (Finder::create()->files()->ignoreDotFiles(false)->in($path)->name(['*.php', '*.css', '*.js'])->sortByName() as $file) {
            if ($file->getPathname() !== base_path(self::TOKENS_FILE)) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /** @return list<string> */
    private function scan(string $file): array
    {
        $relative = str_replace(base_path().'/', '', $file);
        $violations = [];
        foreach (preg_split('/\R/', (string) file_get_contents($file)) ?: [] as $number => $line) {
            foreach (self::RULES as $rule => $pattern) {
                if (preg_match($pattern, $line, $match) === 1) {
                    $violations[] = $relative.':'.($number + 1)." — {$rule} \"{$match[0]}\"";
                }
            }
        }

        return $violations;
    }
}
