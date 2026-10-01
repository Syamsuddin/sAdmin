<?php

namespace App\Console\Commands;

use App\Domain\Alerts\Actions\AddNotificationChannel;
use App\Domain\Alerts\Data\ChannelKind;
use App\Domain\Audit\Data\ActorType;
use App\Infrastructure\Vault\SecretValue;
use App\Infrastructure\Vault\VaultIntegrityError;
use App\Infrastructure\Vault\VaultUnavailable;
use DomainException;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;

class NotifyChannelAddCommand extends Command
{
    protected $signature = 'sadmin:notify-channel-add
        {kind : telegram atau smtp}
        {--chat-id= : Telegram: ID chat (angka) atau @nama_kanal}
        {--host= : SMTP: host server}
        {--port= : SMTP: port}
        {--tls=starttls : SMTP: implicit (biasanya port 465) atau starttls (biasanya 587)}
        {--username= : SMTP: nama pengguna}
        {--from= : SMTP: alamat pengirim}
        {--to=* : SMTP: alamat penerima, boleh diulang}';

    protected $description = 'Tambah kanal notifikasi peringatan; token/kata sandi dibaca dari prompt tersembunyi (ADR 0005 §2.5)';

    public function handle(AddNotificationChannel $add): int
    {
        $kind = ChannelKind::tryFrom((string) $this->argument('kind'));
        if ($kind === null) {
            $this->error('Jenis kanal harus telegram atau smtp.');

            return self::FAILURE;
        }

        $config = match ($kind) {
            ChannelKind::Telegram => ['chat_id' => $this->option('chat-id')],
            ChannelKind::Smtp => [
                'host' => $this->option('host'),
                'port' => $this->option('port'),
                'tls' => $this->option('tls'),
                'username' => $this->option('username'),
                'from' => $this->option('from'),
                'to' => $this->option('to'),
            ],
        };

        try {
            // Isian ditolak sebelum rahasia diminta, agar admin tak mengetik token untuk percobaan yang pasti gagal.
            $config = $add->validateConfig($kind, $config);

            // Rahasia tak pernah lewat argumen: riwayat shell dan `ps` bisa membacanya (ADR 0005 §2.5).
            $raw = $this->secret($kind === ChannelKind::Telegram ? 'Token bot Telegram' : 'Kata sandi SMTP');
            if (! is_string($raw) || $raw === '') {
                $this->error('Rahasia kanal wajib diisi lewat prompt tersembunyi; jalankan perintah ini secara interaktif.');

                return self::FAILURE;
            }

            $channel = $add->handle($kind, $config, new SecretValue($raw), ActorType::LocalRoot, null);
        } catch (ValidationException $e) {
            foreach ($e->errors() as $messages) {
                foreach ($messages as $message) {
                    $this->error($message);
                }
            }

            return self::FAILURE;
        } catch (DomainException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        } catch (VaultUnavailable $e) {
            Log::error('notify_channel_add_failed', ['reason' => 'brankas tak tersedia: '.$e->getMessage()]);
            $this->error('Brankas tak tersedia: '.$e->getMessage());
            $this->line('Tindakan: jalankan sadmin:vault-check dan pastikan kunci induk termuat (ADR 0003 §2.1).');

            return self::FAILURE;
        } catch (VaultIntegrityError $e) {
            Log::critical('notify_channel_add_failed', ['reason' => 'brankas gagal membuka rahasia yang baru disimpan: '.$e->getMessage()]);
            $this->error('Brankas gagal membuka rahasia kanal yang baru disimpan: '.$e->getMessage());
            $this->line('Tindakan: perlakukan sebagai insiden integritas; jalankan sadmin:vault-check dan jangan ubah baris secrets/key_wraps.');

            return self::FAILURE;
        }

        $this->info("Kanal {$kind->value} {$channel->id} ditambahkan dan aktif.");
        $this->line('Kirim pesan uji: php artisan sadmin:notify-test');

        return self::SUCCESS;
    }
}
