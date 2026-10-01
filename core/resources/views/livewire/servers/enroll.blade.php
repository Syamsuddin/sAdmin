<div class="container-xl py-4">
    <div class="card">
        <div class="card-header">
            <h1 class="card-title">{{ $serverId === null ? 'Tambah server' : 'Token enrolment baru' }}</h1>
        </div>
        <div class="card-body">
            @if ($command !== null)
                <p>Jalankan perintah ini sebagai root di server <strong>{{ $issuedFor }}</strong> setelah biner sadmin-agent terpasang:</p>
                <pre class="ui-command" aria-label="Perintah enrolment"><code>{{ $command }}</code></pre>
                <p class="mb-1">Token berlaku sampai <strong>{{ $expiresAt }}</strong> dan hanya bisa dipakai sekali.</p>
                <p class="text-secondary">
                    Perintah ini hanya tampil sekali. Bila token kedaluwarsa, terbitkan token baru dari daftar server.
                </p>
                <a href="{{ route('servers.index') }}">Kembali ke daftar server</a>
                <x-ui.toast :message="'Token enrolment untuk '.$issuedFor.' diterbitkan.'" />
            @elseif ($failure !== null)
                @include('livewire.partials.error-state', ['message' => $failure, 'correlationId' => $failureId, 'retry' => 'refresh'])
                <a href="{{ route('servers.index') }}">Kembali ke daftar server</a>
            @elseif ($server !== null)
                <dl class="row">
                    <dt class="col-sm-3">Nama</dt><dd class="col-sm-9">{{ $server->name }}</dd>
                    <dt class="col-sm-3">Hostname</dt><dd class="col-sm-9">{{ $server->hostname }}</dd>
                    <dt class="col-sm-3">Alamat IP</dt><dd class="col-sm-9">{{ $server->ip }}</dd>
                </dl>
                <p class="text-secondary">Token baru langsung membatalkan token sebelumnya untuk server ini.</p>
                <div wire:loading wire:target="reissue" class="ui-skeleton mb-3" aria-busy="true"></div>
                <x-ui.button wire:click="reissue" wire:loading.attr="disabled"><x-ui.icon name="terminal" /> Terbitkan token baru</x-ui.button>
                <a href="{{ route('servers.index') }}" class="btn btn-link">Batal</a>
            @else
                <form wire:submit="save" novalidate>
                    <x-ui.field.text label="Nama server" name="name" wire:model="name" maxlength="63"
                        hint="Huruf kecil, angka, dan tanda hubung, mis. web1." />
                    <x-ui.field.text label="Hostname" name="hostname" wire:model="hostname" maxlength="253"
                        hint="Nama host server, mis. web1.instansi.go.id." />
                    <x-ui.field.text label="Alamat IP" name="ip" wire:model="ip" maxlength="45"
                        hint="Alamat IPv4 atau IPv6 server." />
                    <div wire:loading wire:target="save" class="ui-skeleton mb-3" aria-busy="true"></div>
                    <x-ui.button type="submit" wire:loading.attr="disabled">Simpan</x-ui.button>
                    <a href="{{ route('servers.index') }}" class="btn btn-link">Batal</a>
                </form>
            @endif
        </div>
    </div>
</div>
