<?php

namespace App\Domain\Fleet\Data;

use RuntimeException;

/** Dokumen kepercayaan di basis data tak cocok dengan hash-nya: baris diubah di luar core. Gagal tertutup, tak dikirim ke agen. */
final class TrustDocumentCorrupt extends RuntimeException {}
