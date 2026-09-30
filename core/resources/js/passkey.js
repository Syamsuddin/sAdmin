// Ceremony WebAuthn di browser. Opsi datang sebagai JSON dari server (ADR 0002); jawaban dikirim balik sebagai
// JSON berkolom base64url. Konversi ditulis manual agar tak bergantung pada parse*FromJSON yang belum merata.

const toBuffer = (value) => {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0)).buffer;
};

const toBase64Url = (buffer) => {
    let binary = '';
    new Uint8Array(buffer).forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const descriptors = (list) => (list || []).map((item) => ({ ...item, id: toBuffer(item.id) }));

const serialize = (credential) => {
    const response = credential.response;
    const json = {
        id: credential.id,
        rawId: toBase64Url(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment ?? null,
        clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
        response: { clientDataJSON: toBase64Url(response.clientDataJSON) },
    };

    if (response.attestationObject) {
        json.response.attestationObject = toBase64Url(response.attestationObject);
        json.response.transports = response.getTransports ? response.getTransports() : [];
    } else {
        json.response.authenticatorData = toBase64Url(response.authenticatorData);
        json.response.signature = toBase64Url(response.signature);
        json.response.userHandle = response.userHandle ? toBase64Url(response.userHandle) : null;
    }

    return JSON.stringify(json);
};

const passkey = {
    async create(optionsJson) {
        const options = JSON.parse(optionsJson);
        options.challenge = toBuffer(options.challenge);
        options.user.id = toBuffer(options.user.id);
        options.excludeCredentials = descriptors(options.excludeCredentials);
        return serialize(await navigator.credentials.create({ publicKey: options }));
    },

    async get(optionsJson) {
        const options = JSON.parse(optionsJson);
        options.challenge = toBuffer(options.challenge);
        options.allowCredentials = descriptors(options.allowCredentials);
        return serialize(await navigator.credentials.get({ publicKey: options }));
    },
};

// Komponen Alpine (dibundel Livewire): `ceremony` = 'create' | 'get'. Galat browser (dibatalkan, waktu habis)
// dilaporkan ke server tanpa isi, hanya namanya.
document.addEventListener('alpine:init', () => {
    window.Alpine.data('passkeyCeremony', (ceremony) => ({
        busy: false,
        async run() {
            this.busy = true;
            try {
                const options = await this.$wire.begin();
                if (options) {
                    await this.$wire.complete(await passkey[ceremony](options));
                }
            } catch (error) {
                await this.$wire.clientFailed(String(error?.name ?? 'Error'));
            } finally {
                this.busy = false;
            }
        },
    }));
});
