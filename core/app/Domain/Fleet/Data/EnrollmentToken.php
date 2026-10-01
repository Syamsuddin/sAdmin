<?php

namespace App\Domain\Fleet\Data;

use Carbon\CarbonImmutable;
use LogicException;
use SensitiveParameter;

/**
 * Token enrolment sekali pakai yang baru diterbitkan. Teksnya hanya hidup di objek ini untuk ditampilkan sekali ke
 * admin; core menyimpan hash-nya saja (docs/07 `servers.enroll_token_hash`). Properti token privat, sehingga konteks
 * log (Monolog menormalkan objek lewat json_encode) dan serialisasi JSON tak pernah membawanya; print_r/var_dump
 * memakai __debugInfo, dan serialize() ditolak. Alat dev yang membaca properti privat (dump()/dd(), var_export)
 * tetap membukanya, jadi jangan dipakai pada objek ini.
 */
final readonly class EnrollmentToken
{
    public function __construct(
        public string $serverId,
        public string $serverName,
        #[SensitiveParameter] private string $token,
        public CarbonImmutable $expiresAt,
        public EnrollmentTarget $target,
    ) {}

    public function token(): string
    {
        return $this->token;
    }

    /** Perintah yang dijalankan admin di server (../edge/docs/11_COMMANDS.md §Enrol). */
    public function command(): string
    {
        return "sudo sadmin-agent enroll --gateway {$this->target->gateway} --ca-sha256 {$this->target->caSha256} --token {$this->token}";
    }

    /** @return never */
    public function __serialize(): array
    {
        throw new LogicException('Token enrolment tak boleh diserialisasi.');
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return ['serverId' => $this->serverId, 'serverName' => $this->serverName, 'token' => '[disamarkan]', 'expiresAt' => $this->expiresAt];
    }
}
