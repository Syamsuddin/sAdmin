<?php

namespace App\Livewire\Servers;

use App\Domain\Fleet\Actions\IssueEnrollmentToken;
use App\Domain\Fleet\Actions\RegisterServer;
use App\Domain\Fleet\Data\EnrollmentToken;
use App\Domain\Fleet\Data\ServerRegistrationRejected;
use App\Domain\Fleet\Data\ServerStatus;
use App\Domain\Fleet\Services\EnrollmentInstructions;
use App\Livewire\Concerns\FormatsInstitutionTime;
use App\Models\Admin;
use App\Models\Server;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Livewire\Attributes\Locked;
use Livewire\Attributes\Title;
use Livewire\Component;

/**
 * Tambah server dan token enrolment (docs/26 `Servers\Enroll`). Perintah enrolment berisi token sekali pakai,
 * jadi hanya tampil sekali sesudah diterbitkan; core menyimpan hash-nya saja.
 */
#[Title('Tambah server — sAdmin')]
class Enroll extends Component
{
    use FormatsInstitutionTime;

    /** Diisi bila halaman menerbitkan token baru untuk server yang sudah terdaftar. */
    #[Locked]
    public ?string $serverId = null;

    public string $name = '';

    public string $hostname = '';

    public string $ip = '';

    #[Locked]
    public ?string $command = null;

    #[Locked]
    public ?string $issuedFor = null;

    #[Locked]
    public ?string $expiresAt = null;

    #[Locked]
    public ?string $errorReason = null;

    #[Locked]
    public ?string $correlationId = null;

    public function mount(?Server $server = null): void
    {
        if ($server !== null) {
            abort_unless($server->tenant_id === $this->admin()->tenant_id, 404);
            $this->serverId = $server->id;
        }
    }

    public function save(RegisterServer $register): void
    {
        $this->start();
        try {
            $token = $register->handle($this->admin(), $this->name, $this->hostname, $this->ip);
        } catch (ServerRegistrationRejected $e) {
            $this->reject($e);

            return;
        }
        $this->reset('name', 'hostname', 'ip');
        $this->show($token);
    }

    public function reissue(IssueEnrollmentToken $issue): void
    {
        $this->start();
        if ($this->serverId === null) {
            return;
        }
        try {
            $token = $issue->handle($this->admin(), $this->serverId);
        } catch (ServerRegistrationRejected $e) {
            $this->reject($e);

            return;
        }
        $this->show($token);
    }

    private function start(): void
    {
        $this->resetErrorBag();
        $this->reset('command', 'issuedFor', 'expiresAt', 'errorReason', 'correlationId');
    }

    private function show(EnrollmentToken $token): void
    {
        $this->command = $token->command();
        $this->issuedFor = $token->serverName;
        $this->expiresAt = $this->institutionTime($token->expiresAt);
    }

    /** Masukan yang salah tampil per field; prasyarat dan batas tampil sebagai state Gagal ber-ID korelasi (docs/14). */
    private function reject(ServerRegistrationRejected $e): void
    {
        $field = $e->field();
        if ($field !== null) {
            $this->addError($field, $this->message($e->reason));

            return;
        }
        $this->errorReason = $e->reason;
        $this->correlationId = $e->correlationId;
        Log::warning('server_registration_rejected', [
            'reason' => $e->reason,
            'correlation_id' => $e->correlationId,
            'detail' => $e->getPrevious()?->getMessage(),
        ]);
    }

    public function message(string $reason): string
    {
        $parts = __("errors.server.{$reason}");

        return __('errors.format', is_array($parts) ? $parts : []);
    }

    private function admin(): Admin
    {
        /** @var Admin $admin */
        $admin = Auth::user();

        return $admin;
    }

    public function render(EnrollmentInstructions $instructions): View
    {
        $server = $this->serverId === null ? null
            : Server::query()->where('tenant_id', $this->admin()->tenant_id)->find($this->serverId);

        // Prasyarat diperiksa sebelum formulir tampil: admin tak mengisi formulir yang pasti ditolak.
        $blocked = null;
        if ($this->command === null && $this->errorReason === null) {
            try {
                $instructions->target($this->admin()->tenant_id);
                if ($this->serverId !== null && $server?->status !== ServerStatus::Enrolling) {
                    throw new ServerRegistrationRejected('not_enrolling');
                }
            } catch (ServerRegistrationRejected $e) {
                $blocked = $e;
                Log::warning('server_registration_unavailable', [
                    'reason' => $e->reason,
                    'correlation_id' => $e->correlationId,
                    'detail' => $e->getPrevious()?->getMessage(),
                ]);
            }
        }

        $reason = $this->errorReason ?? $blocked?->reason;

        return view('livewire.servers.enroll', [
            'server' => $server,
            'failure' => $reason === null ? null : $this->message($reason),
            'failureId' => $this->correlationId ?? $blocked?->correlationId,
        ])->title($this->serverId === null ? 'Tambah server — sAdmin' : 'Token enrolment — sAdmin');
    }
}
