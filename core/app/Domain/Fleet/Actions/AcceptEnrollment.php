<?php

namespace App\Domain\Fleet\Actions;

use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Audit\Services\CheckpointSigner;
use App\Domain\Execution\Dispatch\ServiceSigner;
use App\Domain\Fleet\Data\AcceptedEnrollment;
use App\Domain\Fleet\Data\AgentConnection;
use App\Domain\Fleet\Data\CertificateRequestRejected;
use App\Domain\Fleet\Data\EnrollmentRejected;
use App\Domain\Fleet\Data\ServerStatus;
use App\Domain\Fleet\Services\CertificateAuthority;
use App\Domain\Fleet\Services\TrustDocuments;
use App\Domain\Fleet\Services\TrustFingerprint;
use App\Infrastructure\Vault\Ed25519;
use App\Infrastructure\Vault\VaultUnavailable;
use App\Models\Agent;
use App\Models\Server;
use Carbon\CarbonImmutable;
use DomainException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SensitiveParameter;

/**
 * Menukar token enrolment menjadi `EnrollAccept` (ADR 0008, ../kontrak/KONTRAK.md §3, §5). Tidak melakukan I/O
 * jaringan: transport (gateway) memanggilnya dengan badan `Enroll` yang sudah lolos skema.
 *
 * Seluruh langkah satu transaksi yang menahan baris server: kegagalan di mana pun, termasuk CSR yang salah,
 * membatalkan semuanya dan tidak membakar token. Token salah, kedaluwarsa, atau terpakai tak dibedakan.
 */
final class AcceptEnrollment
{
    public const PLATFORM = 'ubuntu-24.04';

    /** Mengunci pembuatan roster dan kebijakan versi 1 (ADR 0008 §2.4); RegisterServer memakai 7301007. */
    public const TRUST_LOCK_KEY = 7301008;

    public function __construct(
        private readonly CertificateAuthority $authority,
        private readonly TrustDocuments $trust,
        private readonly ServiceSigner $signer,
        private readonly CheckpointSigner $auditSigner,
        private readonly AppendAuditEntry $audit,
    ) {}

    /**
     * @param  array<array-key, mixed>  $enroll  badan `Enroll`: kontrak, token, csr, platform_id, hostname, agent_version
     *
     * @throws EnrollmentRejected
     */
    public function handle(#[SensitiveParameter] array $enroll): AcceptedEnrollment
    {
        $input = self::validatedShape($enroll);
        if ($input['kontrak'] !== TrustDocuments::CONTRACT) {
            throw new EnrollmentRejected('E_KONTRAK_VERSION', 'unknown_major');
        }

        try {
            return DB::transaction(fn (): AcceptedEnrollment => $this->exchange($input));
        } catch (VaultUnavailable) {
            // Kunci induk tak termuat: sementara, token utuh (transaksi dibatalkan). Integritas brankas yang rusak
            // (VaultIntegrityError) sengaja tidak dipetakan: itu bukan galat sementara.
            throw new EnrollmentRejected('E_CORE_UNAVAILABLE', 'vault_unavailable');
        }
    }

    /**
     * @param  array{kontrak: string, token: string, csr: string, platform_id: string, hostname: string, agent_version: string}  $input
     */
    private function exchange(#[SensitiveParameter] array $input): AcceptedEnrollment
    {
        $server = $this->redeemableServer($input['token']);
        if ($input['platform_id'] !== self::PLATFORM) {
            throw new EnrollmentRejected('E_PLATFORM', 'unsupported_platform');
        }

        try {
            $issued = $this->authority->issueAgentCertificate($server->tenant_id, $server->id, $input['csr']);
        } catch (CertificateRequestRejected $e) {
            throw new EnrollmentRejected('E_CSR', $e->reason);
        } catch (DomainException) {
            // Tak ada CA aktif: bukan salah agen (gateway menjawab sementara).
            throw new EnrollmentRejected('E_CORE_UNAVAILABLE', 'no_ca');
        }

        DB::select('SELECT pg_advisory_xact_lock(?)', [self::TRUST_LOCK_KEY]);
        try {
            $roster = $this->trust->activeRoster($server->tenant_id);
            $policy = $this->trust->activePolicy($server->tenant_id);
            $serviceKeyId = $this->signer->activeKeyId($server->tenant_id) ?? throw new DomainException('Tak ada kunci layanan.');
            $auditKeyId = $this->auditSigner->activeKeyId($server->tenant_id) ?? throw new DomainException('Tak ada kunci audit.');
        } catch (DomainException) {
            // Roster awal belum bisa dibuat (tak ada admin ber-dua-passkey), katalog tak terbaca, atau kunci belum dibuat.
            throw new EnrollmentRejected('E_CORE_UNAVAILABLE', 'trust_not_ready');
        }
        $servicePubkey = Ed25519::encode($this->signer->publicKey($serviceKeyId, $server->tenant_id));
        $auditPubkey = Ed25519::encode($this->auditSigner->publicKey($auditKeyId, $server->tenant_id));

        $fingerprint = TrustFingerprint::compute([
            'roster_hash' => $roster->document_hash,
            'policy_hash' => $policy->document_hash,
            'service_pubkey' => $servicePubkey,
            'audit_pubkey' => $auditPubkey,
            'server_id' => $server->id,
        ]);

        $server->update(['status' => ServerStatus::Offline, 'enroll_token_hash' => null, 'enroll_token_expires_at' => null]);
        Agent::query()->create([
            'tenant_id' => $server->tenant_id,
            'server_id' => $server->id,
            'agent_version' => $input['agent_version'],
            'cert_serial' => $issued->serial,
            'cert_expires_at' => CarbonImmutable::instance($issued->notAfter),
            'roster_version' => $roster->version,
            'policy_version' => $policy->version,
            'connection' => AgentConnection::Disconnected,
            'trust_fingerprint' => $fingerprint,
        ]);

        $this->audit->handle(new AuditEntryData(
            tenantId: $server->tenant_id,
            actorType: ActorType::Agent,
            actorId: $server->id,
            actionKey: 'server.enroll',
            outcome: AuditOutcome::Ok,
            target: "server:{$server->id}",
            paramsRedacted: [
                'serial' => $issued->serial,
                'cert_expires_at' => CarbonImmutable::instance($issued->notAfter)->utc()->format('Y-m-d\TH:i:s\Z'),
                'agent_version' => $input['agent_version'],
                'roster_hash' => $roster->document_hash,
                'policy_hash' => $policy->document_hash,
                'platform_id' => $input['platform_id'],
                'reported_hostname' => $input['hostname'],
                'trust_fingerprint' => $fingerprint,
            ],
        ));

        // Disusun dalam transaksi: kegagalan menyusun bingkai membatalkan semuanya, token tak terbakar (ADR 0008 §2.2).
        $frame = $this->signer->frame($server->tenant_id, 'EnrollAccept', strtolower((string) Str::ulid()), [
            'kontrak' => TrustDocuments::CONTRACT,
            'server_id' => $server->id,
            'cert' => $issued->certificatePem,
            'ca_cert' => $this->authority->certificatePem($server->tenant_id),
            'roster' => TrustDocuments::envelope($roster),
            'policy' => TrustDocuments::envelope($policy),
            'service_pubkey' => $servicePubkey,
            'audit_pubkey' => $auditPubkey,
        ]);

        // Bingkai harus lolos dengan kunci yang masuk badan (dan sidik jari), bukan hanya kunci aktif saat ini: bila
        // kelak ada rotasi di antara dua pembacaan, agen menolak sig dan token terbakar.
        if (! ServiceSigner::verifyFrame($this->signer->publicKey($serviceKeyId, $server->tenant_id), $frame)
            || $this->signer->activeKeyId($server->tenant_id) !== $serviceKeyId) {
            throw new EnrollmentRejected('E_CORE_UNAVAILABLE', 'service_key_changed');
        }

        return new AcceptedEnrollment($server->id, $frame, $fingerprint);
    }

    /** Server `enrolling` bertoken cocok dan belum kedaluwarsa, ditahan dengan kunci baris. Semua kegagalan identik. */
    private function redeemableServer(#[SensitiveParameter] string $token): Server
    {
        $server = preg_match('/\A[0-9a-f]{64}\z/', $token) === 1
            ? Server::query()
                ->where('enroll_token_hash', hash('sha256', $token))
                ->where('status', ServerStatus::Enrolling->value)
                ->where('enroll_token_expires_at', '>', CarbonImmutable::now())
                ->lockForUpdate()
                ->first()
            : null;

        return $server ?? throw new EnrollmentRejected('E_ENROLL_TOKEN', 'invalid');
    }

    /**
     * Bentuk badan `Enroll` (KONTRAK §5). Data dari agen tak tepercaya: hostname dan versi masuk audit, jadi dibatasi.
     *
     * @param  array<array-key, mixed>  $enroll
     * @return array{kontrak: string, token: string, csr: string, platform_id: string, hostname: string, agent_version: string}
     */
    private static function validatedShape(#[SensitiveParameter] array $enroll): array
    {
        $rules = [
            'kontrak' => '/\A\d{1,4}\.\d{1,4}(\.\d{1,4})?\z/',
            'token' => '/\A.{0,256}\z/s',
            // Batas kasar pelindung memori; aturan 4096 byte (`size`) dimiliki CA dan dijawab E_CSR (KONTRAK §2).
            'csr' => '/\A.*\z/s',
            'platform_id' => '/\A[a-z0-9][a-z0-9.\-]{0,63}\z/',
            'hostname' => '/\A[A-Za-z0-9][A-Za-z0-9.\-]{0,252}\z/',
            'agent_version' => '/\A[0-9A-Za-z][0-9A-Za-z.+~_\-]{0,63}\z/',
        ];
        $clean = [];
        foreach ($rules as $field => $pattern) {
            $value = $enroll[$field] ?? null;
            if (! is_string($value) || ($field === 'csr' && strlen($value) > 65536) || preg_match($pattern, $value) !== 1) {
                throw new EnrollmentRejected('E_SCHEMA', $field);
            }
            $clean[$field] = $value;
        }

        // `kontrak` berisi `major.minor` selama 0.x (KONTRAK §1); bentuk x.y.z diterima di sini lalu ditolak sebagai versi tak dikenal.
        /** @var array{kontrak: string, token: string, csr: string, platform_id: string, hostname: string, agent_version: string} $clean */
        return $clean;
    }
}
