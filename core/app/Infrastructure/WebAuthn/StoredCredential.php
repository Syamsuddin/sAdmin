<?php

namespace App\Infrastructure\WebAuthn;

/** Kredensial tersimpan yang dicocokkan terhadap assertion; `userHandle` = ID admin saat didaftarkan. */
final readonly class StoredCredential
{
    public function __construct(
        public string $credentialId,
        public string $publicKeyCose,
        public string $userHandle,
        public int $signCount,
    ) {}
}
