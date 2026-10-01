<div class="container-xl py-4">
    <div class="card">
        <div class="card-header">
            <h1 class="card-title">Server</h1>
            @if ($canAdd && $servers->isNotEmpty())
                <div class="card-actions">
                    <a href="{{ route('servers.enroll') }}" class="btn btn-primary"><x-ui.icon name="plus" /> Tambah server</a>
                </div>
            @endif
        </div>
        <div class="card-body">
            @if ($errorId)
                @php($parts = __('errors.load.servers'))
                @include('livewire.partials.error-state', ['message' => __('errors.format', $parts), 'correlationId' => $errorId, 'retry' => 'refresh'])
            @elseif ($servers->isEmpty())
                <x-ui.empty icon="server" message="Belum ada server terdaftar.">
                    <a href="{{ route('servers.enroll') }}" class="btn btn-primary"><x-ui.icon name="plus" /> Tambah server</a>
                </x-ui.empty>
            @else
                <div class="table-responsive">
                    <table class="table table-vcenter">
                        <thead>
                            <tr><th>Nama</th><th>Hostname</th><th>Alamat IP</th><th>Status</th><th>Agen</th></tr>
                        </thead>
                        <tbody>
                            @foreach ($servers as $server)
                                <tr>
                                    <td>{{ $server['name'] }}</td>
                                    <td>{{ $server['hostname'] }}</td>
                                    <td>{{ $server['ip'] }}</td>
                                    <td><x-ui.status-badge :tone="$server['status']->tone()" :label="$server['status']->label()" /></td>
                                    <td>
                                        @if ($server['token'] !== null)
                                            <span class="text-secondary">{{ $server['token'] }}</span>
                                            <a href="{{ route('servers.reenroll', $server['id']) }}">Terbitkan token baru</a>
                                        @else
                                            {{ $server['agent'] ?? '—' }}
                                        @endif
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
                @unless ($canAdd)
                    <p class="text-secondary mt-3 mb-0">Batas Mode Tunggal tercapai: paling banyak {{ $max }} server terkelola.</p>
                @endunless
            @endif
        </div>
    </div>
</div>
