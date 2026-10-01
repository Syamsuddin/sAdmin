<?php

namespace App\Livewire\Servers;

use App\Domain\Fleet\Actions\RegisterServer;
use App\Domain\Fleet\Data\ServerStatus;
use App\Livewire\Concerns\FormatsInstitutionTime;
use App\Models\Admin;
use App\Models\Server;
use Illuminate\Contracts\View\View;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Livewire\Attributes\Lazy;
use Livewire\Attributes\Title;
use Livewire\Component;

/** Inventaris server (docs/26 `Servers\Index`). Empat state: memuat (placeholder), kosong, gagal, sukses. */
#[Lazy]
#[Title('Server — sAdmin')]
class Index extends Component
{
    use FormatsInstitutionTime;

    public function placeholder(): View
    {
        return view('livewire.servers.index-placeholder');
    }

    public function render(): View
    {
        try {
            /** @var Admin $admin */
            $admin = Auth::user();
            $servers = Server::query()->with('agent')->where('tenant_id', $admin->tenant_id)->orderBy('created_at')->orderBy('id')->get()
                ->map(fn (Server $server): array => [
                    'id' => $server->id,
                    'name' => $server->name,
                    'hostname' => $server->hostname,
                    'ip' => $server->ip,
                    'status' => $server->status,
                    'agent' => $server->agent === null ? null : $server->agent->connection->label().' · '.$server->agent->agent_version,
                    'token' => $server->status === ServerStatus::Enrolling ? $this->tokenState($server) : null,
                ]);
            $errorId = null;
        } catch (QueryException $e) {
            $errorId = (string) Str::ulid();
            Log::error('servers_load_failed', ['correlation_id' => $errorId, 'detail' => $e->getMessage()]);
            $servers = collect();
        }

        $active = $servers->filter(fn (array $server): bool => $server['status'] !== ServerStatus::Retired)->count();

        return view('livewire.servers.index', [
            'servers' => $servers,
            'errorId' => $errorId,
            'canAdd' => $errorId === null && $active < RegisterServer::MAX_SERVERS,
            'max' => RegisterServer::MAX_SERVERS,
        ]);
    }

    private function tokenState(Server $server): string
    {
        $expiresAt = $server->enroll_token_expires_at;
        if ($expiresAt === null) {
            return 'Tidak ada token aktif.';
        }

        return $expiresAt->isPast()
            ? 'Token kedaluwarsa '.$this->institutionTime($expiresAt).'.'
            : 'Token berlaku sampai '.$this->institutionTime($expiresAt).'.';
    }
}
