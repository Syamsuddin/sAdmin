<?php

namespace App\Domain\Fleet\Services;

use DomainException;

/**
 * Pembaca katalog aksi (../catalog/CATALOG.md): rumah tunggal definisi aksi, tidak ditulis ulang di PHP (CLAUDE.md).
 * Saat ini hanya tabel §3, karena berkas YAML per aksi belum ada (CATALOG.md menyebut M1). Berkas YAML menang atas
 * tabel begitu ada, dan pembaca ini harus diperluas lebih dulu. Gagal tertutup bila katalog tak terbaca.
 */
final class ActionCatalog
{
    /** Tabel §3 tak memuat kolom versi: seluruh aksi MVP masih versi pertamanya (CATALOG.md §2: `version` naik saat perilaku berubah). */
    public const INITIAL_VERSION = 1;

    /**
     * Aksi berrisiko tepat `L0`, terurut menurut key. Baris dengan risiko campuran (mis. "L2 (L3 bila …)") tidak ikut.
     *
     * @return list<array{key: string, version: int, risk: string}>
     */
    public function l0Actions(): array
    {
        $path = (string) config('sadmin.catalog_path');
        $text = $path !== '' && is_file($path) ? file_get_contents($path) : false;
        if ($text === false) {
            throw new DomainException('Katalog aksi tak terbaca (SADMIN_CATALOG_PATH, docs/10); kebijakan awal tak dapat disusun.');
        }

        // Berkas YAML per aksi menang atas tabel (CATALOG.md). Kebijakan awal tersemat selamanya di agen, jadi pembaca
        // ini wajib diperluas lebih dulu daripada diam-diam memakai risiko dari tabel yang usang.
        if (glob(dirname($path).'/*/*.yaml') !== [] && glob(dirname($path).'/*/*.yaml') !== false) {
            throw new DomainException('Katalog memuat berkas YAML aksi, yang menang atas tabel; perluas ActionCatalog lebih dulu (ADR 0008 §2.5).');
        }

        $start = strpos($text, "\n## 3. Aksi MVP");
        if ($start === false) {
            throw new DomainException('Bagian "3. Aksi MVP" tak ditemukan di katalog aksi.');
        }
        $section = substr($text, $start + 1);
        $end = strpos($section, "\n## ", 4);
        if ($end !== false) {
            $section = substr($section, 0, $end);
        }

        $keys = [];
        foreach (explode("\n", $section) as $line) {
            if (! str_starts_with($line, '|')) {
                continue;
            }
            $cells = array_map('trim', explode('|', trim($line, '| ')));
            if (count($cells) < 2 || $cells[1] !== 'L0') {
                continue;
            }
            if (preg_match_all('/`([a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)`/', $cells[0], $matches) > 0) {
                array_push($keys, ...$matches[1]);
            }
        }

        $keys = array_values(array_unique($keys));
        sort($keys, SORT_STRING);
        if ($keys === []) {
            throw new DomainException('Katalog aksi tak memuat aksi L0; kebijakan awal tak dapat disusun.');
        }

        return array_map(fn (string $key): array => ['key' => $key, 'version' => self::INITIAL_VERSION, 'risk' => 'L0'], $keys);
    }
}
