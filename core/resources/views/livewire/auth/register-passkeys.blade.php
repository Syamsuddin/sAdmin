<div class="card card-md">
    <div class="card-body" x-data="passkeyCeremony('create')">
        <h1 class="h2 mb-2">Daftarkan passkey</h1>
        <p class="text-secondary">
            Halo, {{ $admin->display_name }}. Daftarkan {{ $required }} passkey pada dua autentikator berbeda
            (mis. kunci keamanan dan ponsel) agar akun tetap bisa dipakai bila satu hilang.
        </p>

        @if ($errorReason)
            @include('livewire.partials.error-state', ['message' => $this->errorMessage(), 'correlationId' => $correlationId, 'retry' => 'passkey'])
        @endif

        @if ($registered->isEmpty())
            <x-ui.empty icon="key" message="Belum ada passkey terdaftar.">
                <p class="mb-0">Isi nama perangkat, lalu daftarkan passkey pertama.</p>
            </x-ui.empty>
        @else
            <ul class="list-unstyled mb-3" aria-label="Passkey terdaftar">
                @foreach ($registered as $passkey)
                    <li class="d-flex gap-2"><x-ui.icon name="circle-check" /> {{ $passkey->label }}</li>
                @endforeach
            </ul>
        @endif

        @if ($registered->count() >= $required)
            <div class="alert alert-success" role="status">
                Kedua passkey tersimpan. <a href="{{ route('login') }}">Masuk ke console</a>.
            </div>
        @else
            <x-ui.field.text label="Nama perangkat" name="label" wire:model="label" hint="Mis. YubiKey kantor" maxlength="60" />
            <x-ui.passkey-button :label="'Daftarkan passkey ke-'.($registered->count() + 1)" />
        @endif

        @if ($savedLabel)
            <x-ui.toast :message="'Passkey “'.$savedLabel.'” tersimpan.'" />
        @endif
    </div>
</div>
