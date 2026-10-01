<?php

namespace Tests\Support;

/**
 * Kunci induk uji: berkas 32 byte acak bermode 0600 lewat SADMIN_VAULT_DEV_KEY (ADR 0003 §2.1), sehingga tes
 * memakai jalur pemuatan sungguhan dan tak pernah memakai kunci dev milik pengembang dari .env.
 */
trait InteractsWithVault
{
    private string $vaultKeyDir;

    protected function setUpInteractsWithVault(): void
    {
        $this->vaultKeyDir = sys_get_temp_dir().'/sadmin-vault-test-'.bin2hex(random_bytes(6));
        mkdir($this->vaultKeyDir, 0700);
        $this->useVaultKey();
    }

    protected function tearDownInteractsWithVault(): void
    {
        foreach (glob($this->vaultKeyDir.'/*') ?: [] as $file) {
            unlink($file);
        }
        rmdir($this->vaultKeyDir);
    }

    /** Memasang kunci induk baru (acak bila $key null) dan mengembalikan path berkasnya. */
    protected function useVaultKey(?string $key = null, int $mode = 0600): string
    {
        $path = $this->vaultKeyDir.'/master-'.bin2hex(random_bytes(4)).'.key';
        file_put_contents($path, $key ?? random_bytes(32));
        chmod($path, $mode);
        config(['sadmin.vault.dev_key_file' => $path]);

        return $path;
    }

    protected function withoutVaultKey(): void
    {
        config(['sadmin.vault.dev_key_file' => '']);
    }
}
