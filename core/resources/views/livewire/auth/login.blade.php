<div class="card card-md">
    <div class="card-body" x-data="passkeyCeremony('get')">
        <h1 class="h2 text-center mb-3">Masuk ke console sAdmin</h1>

        @if (session('status'))
            <div class="alert alert-info" role="status">{{ session('status') }}</div>
        @endif

        @if ($errorReason)
            @include('livewire.partials.error-state', ['message' => $this->errorMessage(), 'correlationId' => $correlationId, 'retry' => 'passkey'])
        @endif

        <p class="text-secondary">Sentuh passkey yang terdaftar untuk akun admin Anda. Console hanya terbuka lewat WireGuard.</p>
        <x-ui.passkey-button label="Masuk dengan passkey" />
    </div>
</div>
