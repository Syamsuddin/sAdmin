<?php

namespace App\Domain\Alerts\Actions;

use App\Domain\Alerts\Data\ChannelKind;
use App\Domain\Alerts\Data\ChannelStatus;
use App\Domain\Audit\Actions\AppendAuditEntry;
use App\Domain\Audit\Data\ActorType;
use App\Domain\Audit\Data\AuditEntryData;
use App\Domain\Audit\Data\AuditOutcome;
use App\Domain\Vault\Actions\StoreSecret;
use App\Infrastructure\Notify\TelegramNotifier;
use App\Infrastructure\Vault\SecretValue;
use App\Models\Institution;
use App\Models\NotificationChannel;
use DomainException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use SensitiveParameter;

/**
 * Menambah satu kanal notifikasi (ADR 0005 §2.5): rahasia ke brankas, `config` tanpa rahasia, dan entri audit
 * `notification_channel.create` dalam satu transaksi. Audit hanya memuat jenis kanal: chat ID dan alamat email
 * adalah data pribadi, sedangkan audit tak bisa dihapus (docs/21).
 */
final class AddNotificationChannel
{
    public function __construct(
        private readonly StoreSecret $store,
        private readonly AppendAuditEntry $audit,
    ) {}

    /**
     * @param  array<string, mixed>  $config
     *
     * @throws ValidationException
     */
    public function handle(ChannelKind $kind, array $config, #[SensitiveParameter] SecretValue $secret, ActorType $actorType, ?string $actorId): NotificationChannel
    {
        $tenantId = Institution::query()->value('tenant_id');
        if (! is_string($tenantId)) {
            throw new DomainException('Instansi belum diinisialisasi; jalankan sadmin:institution-init lebih dulu.');
        }

        $config = $this->validateConfig($kind, $config);
        if ($kind === ChannelKind::Telegram && ! TelegramNotifier::isValidToken($secret)) {
            throw ValidationException::withMessages(['token' => self::text('alerts.validation.token')]);
        }

        return DB::transaction(function () use ($tenantId, $kind, $config, $secret, $actorType, $actorId): NotificationChannel {
            $stored = $this->store->handle($tenantId, $kind->secretPurpose(), $secret, $actorType, $actorId);

            $channel = NotificationChannel::query()->create([
                'tenant_id' => $tenantId,
                'kind' => $kind,
                'config' => $config,
                'secret_id' => $stored->id,
                'status' => ChannelStatus::Active,
            ]);

            $this->audit->handle(new AuditEntryData(
                tenantId: $tenantId,
                actorType: $actorType,
                actorId: $actorId,
                actionKey: 'notification_channel.create',
                outcome: AuditOutcome::Ok,
                target: "notification_channel:{$channel->id}",
                paramsRedacted: ['kind' => $kind->value],
            ));

            return $channel;
        });
    }

    /**
     * Hanya kunci yang dikenal yang tersimpan; port jadi bilangan bulat. Publik agar perintah bisa menolak isian
     * yang salah sebelum meminta rahasia.
     *
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     *
     * @throws ValidationException
     */
    public function validateConfig(ChannelKind $kind, array $config): array
    {
        $rules = match ($kind) {
            ChannelKind::Telegram => [
                'chat_id' => ['required', 'string', 'regex:/^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$/'],
            ],
            ChannelKind::Smtp => [
                'host' => ['required', 'string', 'max:253', 'regex:/^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/'],
                'port' => ['required', 'integer', 'between:1,65535'],
                'tls' => ['required', 'string', Rule::in(['implicit', 'starttls'])],
                'username' => ['required', 'string', 'max:320', 'regex:/^[^\x00-\x1F\x7F]+$/'],
                'from' => ['required', 'string', 'email'],
                'to' => ['required', 'array', 'min:1', 'max:10'],
                'to.*' => ['required', 'string', 'email', 'distinct'],
            ],
        };

        $messages = __('alerts.validation', [], 'id');
        $attributes = __('alerts.attributes', [], 'id');
        $valid = Validator::make($config, $rules, is_array($messages) ? $messages : [], is_array($attributes) ? $attributes : [])->validate();

        if ($kind === ChannelKind::Smtp) {
            $valid['port'] = (int) $valid['port'];
            $valid['to'] = array_values($valid['to']);
        }

        return $valid;
    }

    private static function text(string $key): string
    {
        $line = __($key, [], 'id');

        return is_string($line) ? $line : $key;
    }
}
