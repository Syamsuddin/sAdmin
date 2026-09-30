<?php

namespace Database\Factories;

use App\Models\Admin;
use App\Models\Tenant;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Admin>
 */
class AdminFactory extends Factory
{
    public function definition(): array
    {
        return [
            'tenant_id' => Tenant::factory(),
            'display_name' => fake()->firstName(),
            'status' => 'active',
        ];
    }
}
