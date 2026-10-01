{{-- State "Gagal" (docs/26): penyebab + tindakan + ID korelasi (docs/14) + tombol Coba lagi. --}}
<div class="alert alert-danger" role="alert">
    <div class="d-flex gap-2">
        <x-ui.icon name="alert-triangle" />
        <div>
            <p class="mb-1">{{ $message }}</p>
            <p class="mb-2 text-secondary">ID: {{ $correlationId }}</p>
            @if (($retry ?? 'refresh') === 'passkey')
                <x-ui.button variant="secondary" x-on:click="run()" x-bind:disabled="busy">Coba lagi</x-ui.button>
            @elseif (($retry ?? 'refresh') === 'method')
                {{-- Komponen yang menyimpan kegagalan di properti terkunci menghapusnya sendiri lewat retry(). --}}
                <x-ui.button variant="secondary" wire:click="retry">Coba lagi</x-ui.button>
            @else
                <x-ui.button variant="secondary" wire:click="$refresh">Coba lagi</x-ui.button>
            @endif
        </div>
    </div>
</div>
