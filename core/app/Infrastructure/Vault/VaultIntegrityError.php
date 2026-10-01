<?php

namespace App\Infrastructure\Vault;

use RuntimeException;

/**
 * Ciphertext atau kunci data gagal dibuka: kunci induk salah, atau baris secrets/key_wraps diubah di luar brankas.
 * Kelas galat Integritas (docs/14). Pesannya tak pernah memuat kunci atau nilai.
 */
final class VaultIntegrityError extends RuntimeException {}
