<?php

namespace Database\Factories;

use App\Domain\Fleet\Data\ServerStatus;
use App\Models\Server;
use App\Models\Tenant;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * Server tanpa token untuk tes tampilan; server menunggu enrolment dibuat lewat RegisterServer.
 *
 * @extends Factory<Server>
 */
class ServerFactory extends Factory
{
    public function definition(): array
    {
        $name = fake()->unique()->regexify('web[0-9]{3}');

        return [
            'tenant_id' => Tenant::factory(),
            'name' => $name,
            'hostname' => $name.'.example.org',
            'ip' => fake()->unique()->ipv4(),
            'status' => ServerStatus::Online,
        ];
    }
}
