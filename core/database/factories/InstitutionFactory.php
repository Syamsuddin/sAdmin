<?php

namespace Database\Factories;

use App\Models\Institution;
use App\Models\Tenant;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Institution>
 */
class InstitutionFactory extends Factory
{
    public function definition(): array
    {
        return [
            'tenant_id' => Tenant::factory(),
            'name' => 'Instansi '.fake()->city(),
            'maintenance_window' => ['days' => [], 'start' => '22:00', 'end' => '04:00'],
            'backup_retention' => ['daily' => 7, 'weekly' => 4, 'monthly' => 6],
            'console_hostname' => 'sadmin.localhost',
        ];
    }
}
