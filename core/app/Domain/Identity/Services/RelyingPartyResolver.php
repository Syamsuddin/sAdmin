<?php

namespace App\Domain\Identity\Services;

use App\Infrastructure\WebAuthn\RelyingParty;
use App\Models\Institution;
use DomainException;

/** RP ID = institutions.console_hostname (docs/07, docs/21); MVP satu instansi. */
final class RelyingPartyResolver
{
    public function institution(): Institution
    {
        return Institution::query()->first()
            ?? throw new DomainException('Instansi belum diinisialisasi: jalankan sadmin:institution-init.');
    }

    public function resolve(): RelyingParty
    {
        $institution = $this->institution();
        $origin = config('sadmin.webauthn.origin') ?: 'https://'.$institution->console_hostname;

        return new RelyingParty($institution->console_hostname, 'sAdmin', $origin);
    }
}
