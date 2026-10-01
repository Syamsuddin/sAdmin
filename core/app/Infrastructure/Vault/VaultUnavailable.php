<?php

namespace App\Infrastructure\Vault;

use RuntimeException;

/**
 * Kunci induk tak dapat dimuat, atau baris memakai versi kunci induk lain. Galat infrastruktur core (docs/14):
 * operasi rahasia gagal tertutup, bagian console lain tetap jalan. Pesannya tak pernah memuat kunci atau nilai.
 */
final class VaultUnavailable extends RuntimeException {}
