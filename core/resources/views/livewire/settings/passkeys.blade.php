<div class="container-xl py-4">
    <div class="card">
        <div class="card-header">
            <h1 class="card-title">Passkey Anda</h1>
        </div>
        <div class="card-body">
            @if ($errorId)
                @php($parts = __('errors.load.passkeys'))
                @include('livewire.partials.error-state', ['message' => __('errors.format', $parts), 'correlationId' => $errorId, 'retry' => 'refresh'])
            @elseif ($passkeys->isEmpty())
                <x-ui.empty icon="key" message="Belum ada passkey aktif untuk akun ini.">
                    <p class="mb-0">Minta pemegang root menjalankan sadmin:admin-invite untuk mendaftar ulang.</p>
                </x-ui.empty>
            @else
                <table class="table table-vcenter">
                    <thead>
                        <tr><th>Nama perangkat</th><th>Algoritme</th><th>Didaftarkan</th></tr>
                    </thead>
                    <tbody>
                        @foreach ($passkeys as $passkey)
                            <tr><td>{{ $passkey['label'] }}</td><td>{{ $passkey['algorithm'] }}</td><td>{{ $passkey['created'] }}</td></tr>
                        @endforeach
                    </tbody>
                </table>
            @endif
            <p class="text-secondary mt-3 mb-0">
                Menambah atau mencabut passkey mengubah roster yang diverifikasi agen, jadi harus lewat perubahan
                roster L3; fitur itu belum tersedia di versi ini.
            </p>
        </div>
    </div>
</div>
