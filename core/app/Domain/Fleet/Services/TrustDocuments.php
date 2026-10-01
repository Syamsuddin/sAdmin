<?php

namespace App\Domain\Fleet\Services;

use App\Domain\Fleet\Data\TrustDocumentCorrupt;
use App\Domain\Identity\Services\RelyingPartyResolver;
use App\Infrastructure\Jcs\Jcs;
use App\Models\Admin;
use App\Models\Authenticator;
use App\Models\PolicyBundle;
use App\Models\Roster;
use Carbon\CarbonImmutable;
use DomainException;

/**
 * Roster dan kebijakan awal agen (ADR 0008 §2.4–2.5). Hanya versi 1 yang dibuat di sini, tanpa persetujuan passkey:
 * ia dipercaya karena sidik jari dicocokkan admin saat enrolment. Versi berikutnya wajib lewat RosterUpdate /
 * PolicyBundle (M2). Bentuk dokumen dimiliki ../kontrak/KONTRAK.md §3. Wajib dipanggil dalam transaksi yang menahan
 * kunci advisory `AcceptEnrollment::TRUST_LOCK_KEY`, supaya dua enrolment pertama tak membuat versi 1 ganda.
 */
final class TrustDocuments
{
    /** Field `kontrak` di badan dokumen: `major.minor` selama 0.x (KONTRAK §1). Dijaga tes terhadap kontrak/VERSION. */
    public const CONTRACT = '0.6';

    public const INITIAL_APPROVALS_REQUIRED = ['L2' => 1, 'L3' => 1];

    public const INITIAL_L3_DELAY_SECONDS = 900;

    public function __construct(
        private readonly RelyingPartyResolver $relyingParty,
        private readonly ActionCatalog $catalog,
    ) {}

    /** Roster aktif tenant; membuat versi 1 bila belum ada. @throws DomainException bila prasyarat roster awal tak terpenuhi */
    public function activeRoster(string $tenantId): Roster
    {
        $roster = Roster::query()->where('tenant_id', $tenantId)->where('status', 'active')->first();
        if ($roster === null) {
            $document = $this->initialRosterDocument($tenantId);
            $roster = Roster::query()->create([
                'tenant_id' => $tenantId,
                'version' => 1, // Batasan: bila kelak ada v1 non-aktif tanpa dokumen aktif (M2), versi ini harus max(version)+1.
                'document' => $document,
                'document_hash' => self::hash($document),
                'status' => 'active',
                'effective_at' => CarbonImmutable::now(),
            ]);
        }

        return self::verified($roster);
    }

    /** Kebijakan aktif tenant; membuat versi 1 bila belum ada. */
    public function activePolicy(string $tenantId): PolicyBundle
    {
        $policy = PolicyBundle::query()->where('tenant_id', $tenantId)->where('status', 'active')->first();
        if ($policy === null) {
            $document = $this->initialPolicyDocument($tenantId);
            $policy = PolicyBundle::query()->create([
                'tenant_id' => $tenantId,
                'version' => 1,
                'document' => $document,
                'document_hash' => self::hash($document),
                'status' => 'active',
                'effective_at' => CarbonImmutable::now(),
            ]);
        }

        return self::verified($policy);
    }

    /**
     * Bentuk di badan EnrollAccept (KONTRAK §3). Dokumen dibaca dari baris yang sudah diverifikasi hash-nya.
     *
     * @return array{document: array<string, mixed>, document_hash: string, approvals: list<never>}
     */
    public static function envelope(Roster|PolicyBundle $trust): array
    {
        self::verified($trust);

        // Hanya versi 1 yang lahir tanpa persetujuan; versi berikutnya membawa approvals dari RosterUpdate/PolicyBundle (M2).
        return ['document' => $trust->document, 'document_hash' => $trust->document_hash, 'approvals' => []];
    }

    /**
     * SHA-256 byte JCS dokumen, 64 hex huruf kecil (KONTRAK §3).
     *
     * @param  array<string, mixed>  $document
     */
    public static function hash(array $document): string
    {
        return hash('sha256', Jcs::canonicalize($document));
    }

    /** @return array<string, mixed> */
    private function initialRosterDocument(string $tenantId): array
    {
        $enoughKeys = Admin::query()
            ->where('tenant_id', $tenantId)->where('status', 'active')
            ->whereHas('authenticators', fn ($q) => $q->where('status', 'active'), '>=', 2)
            ->exists();
        if (! $enoughKeys) {
            throw new DomainException('Roster awal butuh minimal satu admin aktif dengan dua passkey aktif (docs/05).');
        }

        $credentials = Authenticator::query()
            ->where('tenant_id', $tenantId)->where('status', 'active')
            ->whereHas('admin', fn ($q) => $q->where('status', 'active'))
            ->get()
            ->map(fn (Authenticator $a): array => [
                'credential_id' => self::base64url((string) $a->credential_id),
                'public_key_cose' => self::base64url((string) $a->public_key_cose),
                'alg' => $a->alg,
                'admin_id' => $a->admin_id,
            ])
            ->all();
        // Urutan menurut byte credential_id (KONTRAK §3); base64url tak menjaga urutan byte, jadi urutkan byte mentahnya.
        usort($credentials, fn (array $x, array $y): int => strcmp(self::unbase64url($x['credential_id']), self::unbase64url($y['credential_id'])));

        // Mode Tunggal (docs/02): satu instansi per instalasi, jadi RP tak dipilih menurut $tenantId. Multi-tenant (Fase 4) wajib memilihnya.
        $relyingParty = $this->relyingParty->resolve();

        return [
            'kontrak' => self::CONTRACT,
            'version' => 1,
            'tenant_id' => $tenantId,
            'rp_id' => $relyingParty->id,
            'origin' => $relyingParty->origin,
            'credentials' => $credentials,
        ];
    }

    /** @return array<string, mixed> */
    private function initialPolicyDocument(string $tenantId): array
    {
        return [
            'kontrak' => self::CONTRACT,
            'version' => 1,
            'tenant_id' => $tenantId,
            'actions' => $this->catalog->l0Actions(),
            'approvals_required' => self::INITIAL_APPROVALS_REQUIRED,
            'l3_delay_seconds' => self::INITIAL_L3_DELAY_SECONDS,
        ];
    }

    private static function verified(Roster|PolicyBundle $trust): Roster|PolicyBundle
    {
        if (self::hash($trust->document) !== $trust->document_hash) {
            throw new TrustDocumentCorrupt('Dokumen kepercayaan tak cocok dengan hash-nya; baris diubah di luar core.');
        }

        return $trust;
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function unbase64url(string $text): string
    {
        return (string) base64_decode(strtr($text, '-_', '+/'), true);
    }
}
